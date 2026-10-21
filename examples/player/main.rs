//! AirPlay receiver that plays audio through the system's default output device.
//!
//! Demonstrates handling sample rate mismatches in the application layer:
//! the library delivers audio at the source's native rate, and the example
//! automatically resamples to the output device's rate using rubato whenever
//! the two differ. FLUSH (e.g. a seek) discards pending input, resampler history
//! and queued output.
//!
//! Usage:
//!   cargo run --example player
//!   cargo run --example player -- --name "My Speaker"
//!   cargo run --example player -- --bind 192.168.1.100
//!   cargo run --example player -- --bind 192.168.1.100 --bind fd00::1
//!   cargo run --example player -- --persist state.json
//!
//! `--resample` is still accepted for compatibility but has no effect: resampling
//! is automatic.
//!
//! Then select the speaker as AirPlay output on your iPhone/Mac.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use rubato::audioadapter_buffers::direct::SequentialSliceOfVecs;
use rubato::{
    Async, FixedAsync, Resampler, SincInterpolationParameters, SincInterpolationType,
    WindowFunction,
};

/// Simple streaming resampler for the example app (uses rubato directly).
struct ExampleResampler {
    resampler: Async<f32>,
    channels: usize,
    chunk_size: usize,
    pending: Vec<f32>,
}

impl ExampleResampler {
    fn new(from_rate: u32, to_rate: u32, channels: usize) -> Option<Self> {
        if from_rate == to_rate {
            return None;
        }
        let params = SincInterpolationParameters {
            sinc_len: 64,
            f_cutoff: 0.95,
            interpolation: SincInterpolationType::Linear,
            oversampling_factor: 128,
            window: WindowFunction::BlackmanHarris2,
        };
        let chunk_size = 128;
        let resampler = Async::<f32>::new_sinc(
            to_rate as f64 / from_rate as f64,
            1.0,
            &params,
            chunk_size,
            channels,
            FixedAsync::Input,
        )
        .ok()?;
        Some(Self {
            resampler,
            channels,
            chunk_size,
            pending: Vec::new(),
        })
    }

    fn process(&mut self, input: &[f32]) -> Vec<f32> {
        self.pending.extend_from_slice(input);
        let samples_per_chunk = self.chunk_size * self.channels;
        let mut output = Vec::new();
        while self.pending.len() >= samples_per_chunk {
            let chunk: Vec<f32> = self.pending.drain(..samples_per_chunk).collect();
            let mut ch_vecs: Vec<Vec<f32>> = (0..self.channels)
                .map(|_| Vec::with_capacity(self.chunk_size))
                .collect();
            for frame in chunk.chunks_exact(self.channels) {
                for (ch, &s) in frame.iter().enumerate() {
                    ch_vecs[ch].push(s);
                }
            }
            if let Ok(input) = SequentialSliceOfVecs::new(&ch_vecs, self.channels, self.chunk_size)
                && let Ok(result) = self.resampler.process(&input, 0, None)
            {
                output.extend(result.take_data());
            }
        }
        output
    }

    /// Discard pending input and the resampler's filter history.
    fn reset(&mut self) {
        self.pending.clear();
        self.resampler.reset();
    }
}
use shairplay::{AudioFormat, AudioHandler, AudioSession, BindConfig, RaopServer};
use std::net::IpAddr;
use std::path::PathBuf;

#[cfg(feature = "ap2")]
use shairplay::PairingStore;

#[cfg(feature = "video")]
mod video_display;

// --- HLS playback via mpv subprocess ---

#[cfg(feature = "hls")]
struct MpvHlsHandler;

#[cfg(feature = "hls")]
impl shairplay::HlsHandler for MpvHlsHandler {
    fn on_play(&self, url: &str, start_position: f32) -> Box<dyn shairplay::HlsSession> {
        eprintln!("🎬 HLS: playing {url}");
        let mut cmd = std::process::Command::new("mpv");
        cmd.arg(url).arg("--force-window=yes");
        if start_position > 0.0 {
            cmd.arg(format!("--start={start_position}"));
        }
        let child = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match child {
            Ok(child) => Box::new(MpvHlsSession {
                child: std::sync::Mutex::new(Some(child)),
                start: std::time::Instant::now(),
                rate: std::sync::atomic::AtomicU32::new(1_f32.to_bits()),
            }),
            Err(e) => {
                eprintln!("⚠️  Failed to start mpv: {e}");
                eprintln!("   Install mpv: brew install mpv (macOS) or apt install mpv (Linux)");
                Box::new(MpvHlsSession {
                    child: std::sync::Mutex::new(None),
                    start: std::time::Instant::now(),
                    rate: std::sync::atomic::AtomicU32::new(0_f32.to_bits()),
                })
            }
        }
    }
}

#[cfg(feature = "hls")]
struct MpvHlsSession {
    child: std::sync::Mutex<Option<std::process::Child>>,
    start: std::time::Instant,
    rate: std::sync::atomic::AtomicU32,
}

#[cfg(feature = "hls")]
impl shairplay::HlsSession for MpvHlsSession {
    fn duration(&self) -> f32 {
        0.0
    } // unknown for live/streaming
    fn position(&self) -> f32 {
        self.start.elapsed().as_secs_f32()
    }
    fn rate(&self) -> f32 {
        f32::from_bits(self.rate.load(std::sync::atomic::Ordering::Relaxed))
    }
    fn seek(&mut self, _position: f32) { /* mpv subprocess doesn't support seek via API */
    }
    fn set_rate(&mut self, rate: f32) {
        self.rate
            .store(rate.to_bits(), std::sync::atomic::Ordering::Relaxed);
        if rate == 0.0 {
            self.kill_child();
        }
    }
    fn stop(&mut self) {
        self.kill_child();
    }
}

#[cfg(feature = "hls")]
impl MpvHlsSession {
    fn kill_child(&mut self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
            *guard = None;
        }
        eprintln!("🎬 HLS: stopped");
    }
}

#[cfg(feature = "hls")]
impl Drop for MpvHlsSession {
    fn drop(&mut self) {
        self.kill_child();
    }
}

/// Persistent device identity + paired keys, stored as JSON.
#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
struct PersistState {
    mac: Option<[u8; 6]>,
    /// Accessory's long-term Ed25519 identity seed — keeps `pk` stable across
    /// restarts so paired devices don't re-pair. Generated by the library on
    /// first run and saved here via `PairingStore::save_identity`.
    #[cfg(feature = "ap2")]
    #[serde(default)]
    identity_seed: Option<[u8; 32]>,
    #[cfg(feature = "ap2")]
    #[serde(default)]
    paired_keys: std::collections::HashMap<String, [u8; 32]>,
}

impl PersistState {
    fn load(path: &PathBuf) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &PathBuf) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }
}

#[cfg(feature = "ap2")]
struct FilePairingStore {
    path: PathBuf,
    /// Full persisted state (mac + identity seed + paired keys) behind one lock,
    /// so every save writes the whole file and no field clobbers another.
    state: std::sync::Mutex<PersistState>,
}

#[cfg(feature = "ap2")]
impl FilePairingStore {
    fn new(path: PathBuf, state: PersistState) -> Self {
        Self {
            path,
            state: std::sync::Mutex::new(state),
        }
    }
}

#[cfg(feature = "ap2")]
impl PairingStore for FilePairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.state.lock().ok()?.paired_keys.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut state) = self.state.lock() {
            state.paired_keys.insert(device_id.to_string(), public_key);
            state.save(&self.path);
        }
    }
    fn has_any_pairing(&self) -> bool {
        self.state
            .lock()
            .map(|s| !s.paired_keys.is_empty())
            .unwrap_or(false)
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.paired_keys.remove(device_id);
            state.save(&self.path);
        }
    }
    fn load_identity(&self) -> Option<[u8; 32]> {
        self.state.lock().ok()?.identity_seed
    }
    fn save_identity(&self, seed: [u8; 32]) {
        if let Ok(mut state) = self.state.lock() {
            state.identity_seed = Some(seed);
            state.save(&self.path);
        }
    }
}

/// Ring buffer shared between the AirPlay audio callback and the cpal output callback.
struct AudioRing {
    buffer: VecDeque<f32>,
}

impl AudioRing {
    fn new() -> Self {
        Self {
            buffer: VecDeque::with_capacity(48000 * 4),
        }
    }

    fn push_samples(&mut self, samples: &[f32]) {
        self.buffer.extend(samples);
    }

    fn pop_sample(&mut self) -> f32 {
        self.buffer.pop_front().unwrap_or(0.0)
    }

    fn clear(&mut self) {
        self.buffer.clear();
    }
}

struct Handler {
    ring: Arc<Mutex<AudioRing>>,
    device_rate: u32,
    device_channels: u16,
}

impl AudioHandler for Handler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        eprintln!(
            "🎵 New stream: {}ch {}bit {}Hz",
            format.channels, format.bits, format.sample_rate
        );

        let resampler = if format.sample_rate == self.device_rate {
            eprintln!("✅ Source rate matches device — no resampling needed");
            None
        } else {
            let resampler = ExampleResampler::new(
                format.sample_rate,
                self.device_rate,
                format.channels as usize,
            );
            if resampler.is_some() {
                eprintln!(
                    "🔄 Resampling {}Hz → {}Hz for the output device",
                    format.sample_rate, self.device_rate
                );
            } else {
                eprintln!(
                    "⚠️  Could not initialize resampling for {}Hz → {}Hz",
                    format.sample_rate, self.device_rate
                );
            }
            resampler
        };

        Box::new(Session {
            ring: self.ring.clone(),
            resampler: resampler.map(Mutex::new),
            source_channels: format.channels as usize,
            device_channels: self.device_channels as usize,
        })
    }
}

struct Session {
    ring: Arc<Mutex<AudioRing>>,
    resampler: Option<Mutex<ExampleResampler>>,
    source_channels: usize,
    device_channels: usize,
}

impl AudioSession for Session {
    fn audio_process(&mut self, samples: &[f32]) {
        let mut samples = samples.to_vec();

        // Resample if needed
        if let Some(ref rs) = self.resampler {
            samples = rs.lock().unwrap().process(&samples);
        }

        // CPAL needs samples for every output channel; preserve stereo and pad
        // each frame so audio remains aligned on multichannel devices.
        let output_channels = self.device_channels.max(1);
        let mut final_samples =
            Vec::with_capacity(samples.len() / self.source_channels.max(1) * output_channels);
        for frame in samples.chunks_exact(self.source_channels.max(1)) {
            if output_channels == 1 {
                final_samples.push(frame.iter().copied().sum::<f32>() / frame.len().max(1) as f32);
            } else {
                let copied = frame.len().min(output_channels);
                final_samples.extend_from_slice(&frame[..copied]);
                final_samples.resize(final_samples.len() + output_channels - copied, 0.0);
            }
        }
        self.ring.lock().unwrap().push_samples(&final_samples);
    }

    /// FLUSH (e.g. a seek): drop everything derived from audio before the flush point.
    fn audio_flush(&mut self) {
        if let Some(ref rs) = self.resampler {
            rs.lock().unwrap().reset();
        }
        self.ring.lock().unwrap().clear();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        eprintln!("🔇 Stream ended");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shairplay=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let name = args
        .iter()
        .position(|a| a == "--name")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("Shairplay Rust");
    let bind_addrs: Vec<IpAddr> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--bind")
        .filter_map(|(i, _)| args.get(i + 1)?.parse().ok())
        .collect();
    let persist_path: Option<PathBuf> = args
        .iter()
        .position(|a| a == "--persist")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    // Persistent HomeKit pairing (M1–M6) is the DEFAULT — it gives the fast
    // trusted-reconnect path (pair once, then pair-verify). `--pin <code>` sets
    // the setup code (default 3939); `--transient` opts into PIN-less transient
    // pairing (no prompt, but a slower connect). Pair once and keep it across
    // restarts by also passing `--persist <file>`.
    let pin: Option<String> = if args.iter().any(|a| a == "--transient") {
        None
    } else {
        Some(
            args.iter()
                .position(|a| a == "--pin")
                .and_then(|i| args.get(i + 1))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "3939".to_string()),
        )
    };
    #[cfg(not(feature = "ap2"))]
    let _ = &pin;
    if args.iter().any(|a| a == "--resample") {
        eprintln!("ℹ️  --resample is no longer needed: resampling is automatic");
    }

    // Detect output device and its native sample rate
    let host = cpal::default_host();
    let (device_rate, device_channels) = host
        .default_output_device()
        .and_then(|d| d.default_output_config().ok())
        .map(|c| (c.sample_rate(), c.channels()))
        .unwrap_or((44100, 2));

    let (ring, _stream) = match host.default_output_device() {
        Some(device) => {
            eprintln!(
                "🔈 Output device: {} ({}Hz, {}ch)",
                device
                    .description()
                    .map(|d| d.name().to_string())
                    .unwrap_or_default(),
                device_rate,
                device_channels
            );

            let config = cpal::StreamConfig {
                channels: device_channels,
                sample_rate: device_rate,
                buffer_size: cpal::BufferSize::Default,
            };

            let ring = Arc::new(Mutex::new(AudioRing::new()));
            let ring_for_cpal = ring.clone();

            match device.build_output_stream(
                &config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    let mut ring = ring_for_cpal.lock().unwrap();
                    for sample in data.iter_mut() {
                        *sample = ring.pop_sample();
                    }
                },
                |err| eprintln!("⚠️  Audio error: {err}"),
                None,
            ) {
                Ok(stream) => {
                    stream.play()?;
                    (ring, Some(stream))
                }
                Err(e) => {
                    eprintln!("⚠️  Cannot open audio device ({e}) — PCM data will be discarded");
                    (Arc::new(Mutex::new(AudioRing::new())), None)
                }
            }
        }
        None => {
            eprintln!("⚠️  No audio output device — PCM data will be discarded");
            (Arc::new(Mutex::new(AudioRing::new())), None)
        }
    };

    // Load or generate device identity
    let mut state = persist_path
        .as_ref()
        .map(PersistState::load)
        .unwrap_or_default();
    let mac = match state.mac {
        Some(mac) => {
            eprintln!(
                "🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (persistent)",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
            mac
        }
        None => {
            let mut mac = [0u8; 6];
            mac[0] = 0x02;
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut mac[1..]);
            state.mac = Some(mac);
            if let Some(path) = &persist_path {
                state.save(path);
                eprintln!(
                    "🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (saved to {})",
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5],
                    path.display()
                );
            } else {
                eprintln!(
                    "🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (random, use --persist to save)",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            }
            mac
        }
    };

    // Build server — no output_sample_rate(), resampling handled in this example
    let handler = Arc::new(Handler {
        ring,
        device_rate,
        device_channels,
    });
    let mut builder = RaopServer::builder();
    builder = builder.name(name).hwaddr(mac);

    #[cfg(feature = "ap2")]
    if let Some(path) = &persist_path {
        let store = Arc::new(FilePairingStore::new(path.clone(), state));
        builder = builder.pairing_store(store);
    }

    #[cfg(feature = "ap2")]
    if let Some(ref code) = pin {
        builder = builder.pin(code.clone());
    }

    if !bind_addrs.is_empty() {
        eprintln!("🔗 Binding to {:?}", bind_addrs);
        builder = builder.bind(BindConfig::new().addrs(bind_addrs));
    }

    #[cfg(feature = "video")]
    let video_frame = {
        let vh = video_display::DisplayVideoHandler::new();
        let frame = vh.frame_buffer();
        builder = builder.video_handler(Arc::new(vh));
        eprintln!("📺 Video (screen mirroring) enabled");
        Some(frame)
    };
    #[cfg(feature = "hls")]
    {
        builder = builder.hls_handler(Arc::new(MpvHlsHandler));
        eprintln!("🎬 HLS video playback enabled (requires mpv)");
    }

    let mut server = builder.build(handler)?;

    server.start().await?;

    let mode = if cfg!(feature = "ap2") {
        "AirPlay 2"
    } else {
        "AirPlay 1 (Classic)"
    };
    eprintln!(
        "✅ {} server '{}' running on port {}",
        mode,
        name,
        server.service_info().port
    );
    eprintln!("   Select it as AirPlay output on your Apple device");
    #[cfg(feature = "ap2")]
    match &pin {
        Some(code) => {
            eprintln!(
                "🔐 PIN: {code} (persistent HomeKit pairing — enter once on iPhone; fast reconnects after)"
            )
        }
        None => eprintln!(
            "🔐 Transient (PIN-less) pairing — no prompt, but slower to connect (--transient)"
        ),
    }
    eprintln!("   Press Ctrl+C to stop");

    // If video is enabled, run the window loop on the main thread (required on macOS).
    // The window loop blocks until closed; Ctrl+C still works via signal handler.
    #[cfg(feature = "video")]
    if let Some(frame) = video_frame {
        video_display::run_window(frame);
        eprintln!("\n🛑 Shutting down...");
        server.stop().await;
        return Ok(());
    }

    tokio::signal::ctrl_c().await?;
    eprintln!("\n🛑 Shutting down...");
    server.stop().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_RATE: u32 = 44100;
    const DEVICE_RATE: u32 = 48000;
    const CHANNELS: usize = 2;

    /// The example's actual stereo session, resampling 44.1 kHz to a 48 kHz device.
    fn resampling_session(ring: &Arc<Mutex<AudioRing>>) -> Box<dyn AudioSession> {
        let handler = Handler {
            ring: ring.clone(),
            device_rate: DEVICE_RATE,
            device_channels: CHANNELS as u16,
        };
        handler.audio_init(AudioFormat {
            codec: shairplay::AudioCodec::Pcm,
            bits: 32,
            channels: CHANNELS as u8,
            sample_rate: SOURCE_RATE,
        })
    }

    fn frames(value: f32, count: usize) -> Vec<f32> {
        vec![value; count * CHANNELS]
    }

    fn drain(ring: &Arc<Mutex<AudioRing>>) -> Vec<f32> {
        ring.lock().unwrap().buffer.drain(..).collect()
    }

    fn peak(samples: &[f32]) -> f32 {
        samples.iter().fold(0.0, |peak, s| peak.max(s.abs()))
    }

    /// Feed `before` frames of full-scale audio, optionally flush, then 128 silent frames,
    /// returning the output queued after the flush point.
    fn output_after_silence(before: usize, flush: bool) -> Vec<f32> {
        let ring = Arc::new(Mutex::new(AudioRing::new()));
        let mut session = resampling_session(&ring);
        session.audio_process(&frames(1.0, before));
        if flush {
            session.audio_flush();
        } else {
            drain(&ring);
        }
        session.audio_process(&frames(0.0, 128));
        drain(&ring)
    }

    #[test]
    fn resampler_history_reaches_silence_without_flush() {
        // Guards the tests below: without FLUSH the prior audio is still audible.
        assert!(peak(&output_after_silence(128, false)) > 0.5);
    }

    #[test]
    fn flush_discards_resampler_history() {
        let output = output_after_silence(128, true);
        assert!(!output.is_empty(), "silence should still be resampled");
        assert_eq!(peak(&output), 0.0);
    }

    #[test]
    fn flush_discards_pending_input_and_history() {
        // 200 frames: one 128-frame chunk enters the resampler, 72 frames stay pending.
        let output = output_after_silence(200, true);
        assert!(!output.is_empty(), "silence should still be resampled");
        assert_eq!(peak(&output), 0.0);
    }

    #[test]
    fn flush_discards_queued_output() {
        let ring = Arc::new(Mutex::new(AudioRing::new()));
        let mut session = resampling_session(&ring);
        session.audio_process(&frames(1.0, 256));
        assert!(!ring.lock().unwrap().buffer.is_empty());

        session.audio_flush();

        assert!(ring.lock().unwrap().buffer.is_empty());
    }
}

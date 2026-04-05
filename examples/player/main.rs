//! AirPlay receiver that plays audio through the system's default output device.
//!
//! Demonstrates handling sample rate mismatches in the application layer:
//! the library delivers audio at the source's native rate, and the example
//! resamples to the output device's rate using rubato.
//!
//! Usage:
//!   cargo run --example player
//!   cargo run --example player -- --name "My Speaker"
//!   cargo run --example player -- --bind 192.168.1.100
//!   cargo run --example player -- --bind 192.168.1.100 --bind fd00::1
//!   cargo run --example player -- --persist state.json
//!   cargo run --example player -- --resample
//!
//! Then select the speaker as AirPlay output on your iPhone/Mac.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use rubato::audioadapter_buffers::direct::SequentialSliceOfVecs;
use rubato::{Async, FixedAsync, Resampler, SincInterpolationParameters, SincInterpolationType, WindowFunction};

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
            if let Ok(input) = SequentialSliceOfVecs::new(&ch_vecs, self.channels, self.chunk_size) {
                if let Ok(result) = self.resampler.process(&input, 0, None) {
                    output.extend(result.take_data());
                }
            }
        }
        output
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
        self.rate.store(rate.to_bits(), std::sync::atomic::Ordering::Relaxed);
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
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PersistState {
    mac: Option<[u8; 6]>,
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
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
}

#[cfg(feature = "ap2")]
impl FilePairingStore {
    fn new(path: PathBuf, keys: std::collections::HashMap<String, [u8; 32]>) -> Self {
        Self {
            path,
            keys: std::sync::Mutex::new(keys),
        }
    }
}

#[cfg(feature = "ap2")]
impl PairingStore for FilePairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), public_key);
            let state = PersistState {
                mac: None,
                #[cfg(feature = "ap2")]
                paired_keys: keys.clone(),
            };
            state.save(&self.path);
        }
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
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
}

struct Handler {
    ring: Arc<Mutex<AudioRing>>,
    device_rate: u32,
    device_channels: u16,
    use_resample: bool,
}

impl AudioHandler for Handler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        eprintln!(
            "🎵 New stream: {}ch {}bit {}Hz",
            format.channels, format.bits, format.sample_rate
        );

        let resampler = if self.use_resample && format.sample_rate != self.device_rate {
            eprintln!(
                "🔄 Resampling {}Hz → {}Hz (in example app)",
                format.sample_rate, self.device_rate
            );
            ExampleResampler::new(format.sample_rate, self.device_rate, format.channels as usize)
        } else {
            if format.sample_rate != self.device_rate {
                eprintln!(
                    "⚠️  Source {}Hz ≠ device {}Hz — use --resample to convert",
                    format.sample_rate, self.device_rate
                );
            } else {
                eprintln!("✅ Source rate matches device — no resampling needed");
            }
            None
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

        // Mix down to device channels if needed
        let final_samples: Vec<f32> = if self.source_channels > self.device_channels {
            samples
                .chunks_exact(self.source_channels)
                .flat_map(|frame| &frame[..self.device_channels])
                .copied()
                .collect()
        } else {
            samples
        };

        self.ring.lock().unwrap().push_samples(&final_samples);
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "shairplay=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let name = args
        .iter()
        .position(|a| a == "--name")
        .map(|i| args[i + 1].as_str())
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
        .map(|i| PathBuf::from(&args[i + 1]));
    let use_resample = args.iter().any(|a| a == "--resample");

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
                device.description().map(|d| d.name().to_string()).unwrap_or_default(),
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
    let mut state = persist_path.as_ref().map(PersistState::load).unwrap_or_default();
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
        use_resample,
    });
    let mut builder = RaopServer::builder();
    builder = builder.name(name).hwaddr(mac);

    #[cfg(feature = "ap2")]
    if let Some(path) = &persist_path {
        let store = Arc::new(FilePairingStore::new(path.clone(), state.paired_keys));
        builder = builder.pairing_store(store);
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
    #[cfg(not(feature = "video"))]
    let _video_frame: Option<()> = None;

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
    eprintln!("🔐 PIN: 3939 (enter on iPhone when prompted)");
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

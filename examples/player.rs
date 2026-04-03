//! AirPlay receiver that plays audio through the system's default output device.
//!
//! Usage:
//!   cargo run --example player
//!   cargo run --example player -- --name "My Speaker"
//!   cargo run --example player -- --bind 192.168.1.100
//!   cargo run --example player -- --bind 192.168.1.100 --bind fd00::1
//!   cargo run --example player -- --persist state.json
//!
//! Then select "My Speaker" as AirPlay output on your iPhone/Mac.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::net::IpAddr;
use std::path::PathBuf;
use shairplay::{AudioFormat, AudioHandler, AudioSession, BindConfig, RaopServer};

#[cfg(feature = "ap2")]
use shairplay::PairingStore;

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
        Self { path, keys: std::sync::Mutex::new(keys) }
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
                mac: None, // MAC saved separately
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
        Self { buffer: VecDeque::with_capacity(48000 * 8 * 2) } // ~2s buffer, up to 7.1
    }

    fn push_samples(&mut self, pcm: &[u8]) {
        // PCM is F32LE interleaved
        for chunk in pcm.chunks_exact(4) {
            let sample = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            self.buffer.push_back(sample);
        }
    }

    fn pop_sample(&mut self) -> f32 {
        self.buffer.pop_front().unwrap_or(0.0)
    }
}

struct Handler {
    ring: Arc<Mutex<AudioRing>>,
}

impl AudioHandler for Handler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        eprintln!("🎵 New stream: {}ch {}bit {}Hz codec={:?}", format.channels, format.bits, format.sample_rate, format.codec);
        Box::new(Session { ring: self.ring.clone() })
    }
}

struct Session {
    ring: Arc<Mutex<AudioRing>>,

}

impl AudioSession for Session {
    fn audio_process(&mut self, buffer: &[u8]) {
        self.ring.lock().unwrap().push_samples(buffer);
    }

    fn audio_set_volume(&mut self, volume: f32) {
        tracing::info!(volume, "Volume changed");
    }

    fn audio_set_metadata(&mut self, _metadata: &[u8]) {
        tracing::info!("Track metadata received");
    }

    fn audio_set_coverart(&mut self, coverart: &[u8]) {
        tracing::info!(bytes = coverart.len(), "Cover art received");
    }

    fn audio_set_progress(&mut self, start: u32, current: u32, end: u32) {
        let total = end.saturating_sub(start) as f64 / 44100.0;
        let pos = current.saturating_sub(start) as f64 / 44100.0;
        tracing::info!(pos_s = pos as u32, total_s = total as u32, "Playback progress");
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        eprintln!("🔇 Stream ended");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable tracing output (set RUST_LOG=debug for verbose protocol logs)
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "shairplay=info".parse().unwrap()))
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let name = args.iter().position(|a| a == "--name")
        .map(|i| args[i + 1].as_str())
        .unwrap_or("Shairplay Rust");
    let bind_addrs: Vec<IpAddr> = args.iter().enumerate()
        .filter(|(_, a)| *a == "--bind")
        .filter_map(|(i, _)| args.get(i + 1)?.parse().ok())
        .collect();
    let persist_path: Option<PathBuf> = args.iter().position(|a| a == "--persist")
        .map(|i| PathBuf::from(&args[i + 1]));

    // Set up cpal audio output (fallback to /dev/null if no device)
    let host = cpal::default_host();
    let (ring, _stream) = match host.default_output_device() {
        Some(device) => {
            eprintln!("🔈 Output device: {}", device.name().unwrap_or_default());

            let config = cpal::StreamConfig {
                channels: 2,
                sample_rate: cpal::SampleRate(44100),
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
                    if let Some(supported) = device.default_output_config().ok() {
                        eprintln!("🎛️  Device config: {} ch, {} Hz, {:?}",
                            supported.channels(), supported.sample_rate().0, supported.sample_format());
                    }
                    stream.play()?;
                    (ring, Some(stream))
                }
                Err(e) => {
                    eprintln!("⚠️  Cannot open audio device ({e}) — PCM data will be discarded");
                    (ring, None)
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
            eprintln!("🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (persistent)",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            mac
        }
        None => {
            let mut mac = [0u8; 6];
            mac[0] = 0x02;
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut mac[1..]);
            state.mac = Some(mac);
            if let Some(path) = &persist_path {
                state.save(path);
                eprintln!("🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (saved to {})",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], path.display());
            } else {
                eprintln!("🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (random, use --persist to save)",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
            mac
        }
    };

    let handler = Arc::new(Handler { ring });
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
    let mut server = builder.build(handler)?;

    server.start().await?;

    let mode = if cfg!(feature = "ap2") { "AirPlay 2" } else { "AirPlay 1 (Classic)" };
    eprintln!("✅ {} server '{}' running on port {}", mode, name, server.service_info().port);
    eprintln!("   Select it as AirPlay output on your Apple device");
    #[cfg(feature = "ap2")]
    eprintln!("🔐 PIN: 3939 (enter on iPhone when prompted)");
    eprintln!("   Press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    eprintln!("\n🛑 Shutting down...");
    server.stop().await;
    Ok(())
}

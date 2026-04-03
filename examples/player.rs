//! AirPlay receiver that plays audio through the system's default output device.
//!
//! Usage:
//!   cargo run --example player
//!   cargo run --example player -- --name "My Speaker"
//!   cargo run --example player -- --bind 192.168.1.100
//!   cargo run --example player -- --bind 192.168.1.100 --bind fd00::1
//!
//! Then select "My Speaker" as AirPlay output on your iPhone/Mac.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::net::IpAddr;
use shairplay::{AudioFormat, AudioHandler, AudioSession, BindConfig, RaopServer};

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

    // Start AirPlay server — key is baked into the library
    let handler = Arc::new(Handler { ring });
    let mut builder = RaopServer::builder();
    builder = builder.name(name)
        .hwaddr({
            let mut mac = [0u8; 6];
            mac[0] = 0x02;
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut mac[1..]);
            eprintln!("🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (random, no key persistence yet)",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            mac
        });
    if !bind_addrs.is_empty() {
        eprintln!("🔗 Binding to {:?}", bind_addrs);
        builder = builder.bind(BindConfig::new().addrs(bind_addrs));
    }
    let mut server = builder.build(handler)?;

    server.start().await?;

    let mode = if cfg!(feature = "airplay2") { "AirPlay 2" } else { "AirPlay 1 (Classic)" };
    eprintln!("✅ {} server '{}' running on port {}", mode, name, server.service_info().port);
    eprintln!("   Select it as AirPlay output on your Apple device");
    #[cfg(feature = "airplay2")]
    eprintln!("🔐 PIN: 3939 (enter on iPhone when prompted)");
    eprintln!("   Press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    eprintln!("\n🛑 Shutting down...");
    server.stop().await;
    Ok(())
}

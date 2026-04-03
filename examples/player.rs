//! AirPlay receiver that plays audio through the system's default output device.
//!
//! Usage:
//!   cargo run --example player
//!   cargo run --example player -- --name "My Speaker"
//!
//! Then select "My Speaker" as AirPlay output on your iPhone/Mac.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer};

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
        eprintln!("🔊 Volume: {:.1} dB", volume);
    }

    fn audio_set_metadata(&mut self, _metadata: &[u8]) {
        eprintln!("📝 Got track metadata");
    }

    fn audio_set_coverart(&mut self, coverart: &[u8]) {
        eprintln!("🖼️  Got cover art ({} bytes)", coverart.len());
    }

    fn audio_set_progress(&mut self, start: u32, current: u32, end: u32) {
        let total = end.saturating_sub(start) as f64 / 44100.0;
        let pos = current.saturating_sub(start) as f64 / 44100.0;
        eprintln!("⏱️  Progress: {:.0}s / {:.0}s", pos, total);
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

    // Set up cpal audio output
    let host = cpal::default_host();
    let device = host.default_output_device().expect("no output device");
    eprintln!("🔈 Output device: {}", device.name().unwrap_or_default());

    let supported = device.default_output_config().expect("no supported output config");
    eprintln!("🎛️  Device config: {} ch, {} Hz, {:?}",
        supported.channels(), supported.sample_rate().0, supported.sample_format());

    let config = cpal::StreamConfig {
        channels: 2,
        sample_rate: cpal::SampleRate(44100), // AirPlay always sends 44100 Hz
        buffer_size: cpal::BufferSize::Default,
    };

    let ring = Arc::new(Mutex::new(AudioRing::new()));
    let ring_for_cpal = ring.clone();

    let stream = device.build_output_stream(
        &config,
        move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
            let mut ring = ring_for_cpal.lock().unwrap();
            for sample in data.iter_mut() {
                *sample = ring.pop_sample();
            }
        },
        |err| eprintln!("⚠️  Audio error: {err}"),
        None,
    )?;
    stream.play()?;

    // Start AirPlay server — key is baked into the library
    let handler = Arc::new(Handler { ring });
    let mut server = RaopServer::builder()
        .name(name)
        .hwaddr({
            // Random MAC each run until we implement key persistence
            let mut mac = [0u8; 6];
            mac[0] = 0x02; // locally administered
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut mac[1..]);
            eprintln!("🔑 Device MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (random, no key persistence yet)",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            mac
        })
        .build(handler)?;

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

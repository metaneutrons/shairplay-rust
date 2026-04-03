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
use shairplay::{AudioCodec, AudioFormat, AudioHandler, AudioSession, RaopServer};

/// Ring buffer shared between the AirPlay audio callback and the cpal output callback.
struct AudioRing {
    buffer: VecDeque<i16>,
}

impl AudioRing {
    fn new() -> Self {
        Self { buffer: VecDeque::with_capacity(44100 * 2 * 2) } // ~2s buffer
    }

    fn push_samples(&mut self, pcm: &[u8]) {
        // PCM is 16-bit little-endian interleaved stereo
        for chunk in pcm.chunks_exact(2) {
            let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
            self.buffer.push_back(sample);
        }
    }

    fn pop_sample(&mut self) -> i16 {
        self.buffer.pop_front().unwrap_or(0) // silence if buffer empty
    }
}

struct Handler {
    ring: Arc<Mutex<AudioRing>>,
}

impl AudioHandler for Handler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        eprintln!("🎵 New stream: {}ch {}bit {}Hz codec={:?}", format.channels, format.bits, format.sample_rate, format.codec);
        Box::new(Session { ring: self.ring.clone(), aac_decoder: None, codec: format.codec })
    }
}

struct Session {
    ring: Arc<Mutex<AudioRing>>,
    aac_decoder: Option<Box<dyn symphonia::core::codecs::Decoder>>,
    codec: AudioCodec,
}

impl AudioSession for Session {
    fn audio_process(&mut self, buffer: &[u8]) {
        match self.codec {
            AudioCodec::Pcm => self.ring.lock().unwrap().push_samples(buffer),
            #[cfg(feature = "airplay2")]
            AudioCodec::AacAdts => self.decode_aac(buffer),
        }
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

impl Session {
    fn decode_aac(&mut self, adts_frame: &[u8]) {
        use symphonia::core::audio::SampleBuffer;
        use symphonia::core::codecs::{DecoderOptions, CODEC_TYPE_AAC, CodecParameters};
        use symphonia::core::formats::Packet;

        if adts_frame.len() <= 7 { return; }

        // Lazy init: parse ADTS header for sample rate
        if self.aac_decoder.is_none() {
            let freq_idx = (adts_frame[2] >> 2) & 0x0F;
            let sr = match freq_idx { 3 => 48000, 4 => 44100, _ => 44100 };
            let chan = ((adts_frame[2] & 1) << 2) | ((adts_frame[3] >> 6) & 3);
            eprintln!("🎧 ADTS: freq_idx={freq_idx} sr={sr} chan={chan}");

            let mut params = CodecParameters::new();
            params.for_codec(CODEC_TYPE_AAC)
                .with_sample_rate(sr)
                .with_channels(symphonia::core::audio::Channels::FRONT_LEFT | symphonia::core::audio::Channels::FRONT_RIGHT);

            match symphonia::default::get_codecs().make(&params, &DecoderOptions::default()) {
                Ok(d) => { self.aac_decoder = Some(d); }
                Err(e) => { eprintln!("⚠️  AAC decoder failed: {e}"); return; }
            }
        }

        let decoder = self.aac_decoder.as_mut().unwrap();
        let raw = &adts_frame[7..];
        let packet = Packet::new_from_slice(0, 0, 1024, raw);

        match decoder.decode(&packet) {
            Ok(decoded) => {
                let spec = *decoded.spec();
                let dur = decoded.capacity() as u64;
                let mut sbuf = SampleBuffer::<i16>::new(dur, spec);
                sbuf.copy_interleaved_ref(decoded);
                let samples = sbuf.samples();
                let mut pcm = Vec::with_capacity(samples.len() * 2);
                for &s in samples {
                    pcm.extend_from_slice(&s.to_le_bytes());
                }
                self.ring.lock().unwrap().push_samples(&pcm);
            }
            Err(e) => {
                tracing::debug!("AAC decode error: {e}");
            }
        }
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
                *sample = ring.pop_sample() as f32 / 32768.0;
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
    eprintln!("   Press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    eprintln!("\n🛑 Shutting down...");
    server.stop().await;
    Ok(())
}

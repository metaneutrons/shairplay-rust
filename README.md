<div align="center">

# shairplay

**Pure Rust AirPlay server library**

[![CI](https://github.com/metaneutrons/shairplay-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/metaneutrons/shairplay-rust/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/shairplay.svg)](https://crates.io/crates/shairplay)
[![docs.rs](https://docs.rs/shairplay/badge.svg)](https://docs.rs/shairplay)
[![License: LGPL-3.0](https://img.shields.io/badge/license-LGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

A complete AirPlay audio receiver as a Rust library. Supports both classic AirPlay (AP1) and AirPlay 2 (AP2) with buffered audio, encrypted transport, and HomeKit pairing. `#![forbid(unsafe_code)]`.

</div>

---

## Features

|  | Feature | Details |
|--|---------|---------|
| 🎵 | **AirPlay 1 (Classic)** | ALAC decode, AES encryption, DACP remote control — rock solid |
| 🎵 | **AirPlay 2** | Buffered AAC, SRP-6a pairing, ChaCha20-Poly1305 encrypted RTSP |
| 🔊 | **Multichannel** | 5.1 and 7.1 AAC decode with ITU-R BS.775 mixdown to stereo |
| 🔄 | **Resampling** | Automatic sample rate conversion via rubato |
| 🔐 | **HomeKit pairing** | Transient (PIN 3939) and normal (persistent key storage) |
| 📺 | **Video** | Screen mirroring — experimental, behind `video` feature gate |
| 🌐 | **Cross-platform** | macOS (Bonjour) + Linux (mdns-sd) mDNS support |
| 🔒 | **Pure safe Rust** | `#![forbid(unsafe_code)]`, no C dependencies |
| ⚡ | **Async** | Built on [tokio](https://tokio.rs) |

## Quick Start

### AirPlay 1 (Classic)

```rust
use std::sync::Arc;
use shairplay::{RaopServer, AudioHandler, AudioSession, AudioFormat};

struct MyHandler;
impl AudioHandler for MyHandler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        println!("Stream: {}ch {}bit {}Hz", format.channels, format.bits, format.sample_rate);
        Box::new(MySession)
    }
}

struct MySession;
impl AudioSession for MySession {
    fn audio_process(&mut self, buffer: &[u8]) {
        // 16-bit PCM samples (little-endian, interleaved stereo)
    }
}

#[tokio::main]
async fn main() -> Result<(), shairplay::ShairplayError> {
    let mut server = RaopServer::builder()
        .name("My Speaker")
        .build(Arc::new(MyHandler))?;
    server.start().await?;
    tokio::signal::ctrl_c().await.unwrap();
    server.stop().await;
    Ok(())
}
```

### AirPlay 2

```rust
use shairplay::{AudioCodec, AudioFormat};

// AP2: always AudioCodec::Pcm, 32-bit F32LE interleaved
// The library decodes AAC, resamples, and mixes down internally
let mut server = RaopServer::builder()
    .name("My Speaker")
    .output_sample_rate(48000)
    .output_max_channels(2)
    .build(Arc::new(MyHandler))?;
```

## Builder Options

| Method | Default | Feature | Description |
|--------|---------|---------|-------------|
| `.name()` | `"Shairplay"` | | AirPlay display name |
| `.hwaddr()` | random | | 6-byte MAC address for mDNS |
| `.port()` | `5000` | | RTSP listening port |
| `.password()` | none | | HTTP Digest auth password |
| `.max_clients()` | `10` | | Maximum concurrent connections |
| `.bind()` | all interfaces | | Bind to specific IPs (multi-interface) |
| `.output_sample_rate()` | source rate | `airplay2` | Resample all audio to this rate |
| `.output_max_channels()` | source channels | `airplay2` | Mix down to this channel count |
| `.pin()` | `"3939"` | `airplay2` | PIN for HomeKit pairing |
| `.pairing_store()` | `MemoryPairingStore` | `airplay2` | Persistent key storage |
| `.video_handler()` | none | `video` | Video session factory |

## Feature Flags

| Flag | Dependencies | Description |
|------|-------------|-------------|
| *(default)* | — | AirPlay 1 only |
| `airplay2` | chacha20poly1305, hkdf, symphonia, rubato, … | Full AirPlay 2 audio |
| `video` | (implies `airplay2`) | Screen mirroring (experimental) |

## Implementation Status

### ✅ AirPlay 1 — Production Ready

Rock solid. ALAC decoding, AES encryption, DACP remote control, metadata (artwork, progress, track info). Works with iPhone, iPad, Mac, iTunes.

### ✅ AirPlay 2 Audio — Production Ready

Full pipeline: SRP-6a pairing → encrypted RTSP → FairPlay → PTP timing → buffered AAC decode → F32LE PCM output. Multichannel 5.1/7.1 with ITU-R BS.775 mixdown. Automatic resampling.

**Known issue:** ~10 second delay between selecting the AirPlay target and audio starting. The iPhone opens a Remote Control connection first and waits before starting audio. This appears to be related to companion-link integration that third-party receivers cannot replicate. Audio playback itself is fast once connected. See [AP2-STATUS.md](AP2-STATUS.md).

### 🧪 Video (Screen Mirroring) — Experimental

Behind the `video` feature gate. The library receives encrypted H.264/H.265 video packets, decrypts them (AES-128-CTR), and delivers raw NAL units to the application. The app is responsible for decoding and rendering. Not yet tested with real devices.

### 🔬 Remote Control — Research Complete

Third-party AP2 receivers cannot send playback commands (play/pause/skip) to the iPhone. All paths require Apple ecosystem trust:

- **Type 130 MRP data channel** — requires HomeKit seed (Home app pairing)
- **Companion-link protocol** — requires same Apple ID
- **DACP** — iPhone doesn't send Active-Remote header in AP2

AP1 DACP remote control is fully implemented and works. See [AP2-REMOTE.md](AP2-REMOTE.md) for the full research.

## Architecture

```
src/
├── raop/              RAOP server, RTSP handlers, RTP streaming
│   ├── buffered_audio   AP2 timed playout buffer with decrypt/decode/resample
│   ├── event_channel    AP2 encrypted event channel
│   ├── video            Video handler traits (experimental)
│   └── video_stream     Video stream receiver (experimental)
├── crypto/            RSA, Ed25519+Curve25519, AES, FairPlay
│   ├── pairing_homekit  AP2 SRP-6a + HomeKit pairing + pair-verify
│   ├── chacha_transport AP2 ChaCha20-Poly1305 encrypted RTSP
│   ├── video_cipher     AES-128-CTR streaming cipher for video
│   └── tlv              AP2 TLV codec for pairing messages
├── codec/             Audio decoders
│   ├── alac             ALAC decoder (AP1)
│   ├── aac              AAC decoder via symphonia (AP2)
│   └── resample         Sample rate conversion + channel mixdown (AP2)
├── proto/             SDP, HTTP/RTSP, binary plist, HTTP Digest auth
├── net/               Async TCP server, mDNS, PTP timing, feature flags
├── dacp/              DACP remote control client (AP1)
└── error/             Error types
```

## Test Coverage

130 tests including 17 C-verified vectors from the [pair_ap](https://github.com/ejurgensen/pair_ap) reference implementation:

```
cargo test                    # AP1 tests
cargo test --features airplay2  # AP1 + AP2 tests
cargo test --features video     # All tests
```

## Acknowledgments

This project builds on the work of many contributors to the AirPlay open-source ecosystem:

- **[shairplay](https://github.com/juhovh/shairplay)** — Original C library this project is a complete rewrite of
- **[shairport-sync](https://github.com/mikebrady/shairport-sync)** — AirPlay 2 C reference implementation by Mike Brady
- **[pair_ap](https://github.com/ejurgensen/pair_ap)** — HomeKit pairing reference (SRP-6a, TLV, HKDF) by Scott Ickle / ejurgensen. 17 C-verified test vectors generated from this codebase
- **[AirPlay 2 Internals](https://emanuelecozzi.net/docs/airplay2/)** — Protocol documentation by Emanuele Cozzi
- **[Unofficial AirPlay Specification](https://openairplay.github.io/airplay-spec/)** — Legacy protocol documentation
- **[rairplay](https://github.com/r4v3n6101/rairplay)** — Rust AirPlay 2 receiver with video support
- **[pyatv](https://github.com/postlund/pyatv)** — Python Apple TV library (companion-link protocol research)
- **[Dissecting the Media Remote Protocol](https://edc.me/posts/dissecting-the-media-remote-protocol/)** — Evan Coleman's Apple TV reverse engineering

## License

LGPL-3.0-or-later

## Disclaimer

All resources in this repository are written using only freely available information from the internet. The code and related resources are meant for educational purposes only. It is the responsibility of the user to make sure all local laws are adhered to.

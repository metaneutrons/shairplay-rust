#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::redundant_closure)]
#![warn(clippy::implicit_clone)]
#![warn(clippy::uninlined_format_args)]
#![doc = "Pure Rust AirPlay server library.

`shairplay` is a complete reimplementation of the [shairplay](https://github.com/juhovh/shairplay)
C library in safe Rust. It provides an AirPlay (RAOP) server that can receive audio streams
from Apple devices on the local network.

# Quick Start

```rust,no_run
use std::sync::Arc;
use shairplay::{RaopServer, AudioHandler, AudioSession, AudioFormat};

struct MyHandler;
impl AudioHandler for MyHandler {
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
        Box::new(MySession)
    }
}

struct MySession;
impl AudioSession for MySession {
    fn audio_process(&mut self, samples: &[f32]) {
        // F32 interleaved PCM — same format for AP1 and AP2
    }
}

# async fn run() -> Result<(), shairplay::ShairplayError> {
let handler = Arc::new(MyHandler);
let mut server = RaopServer::builder()
    .name(\"My Speaker\")
    .hwaddr([0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22])
    .port(5000)
    .build(handler)?;

server.start().await?;
// Server is now discoverable via AirPlay on the local network
# Ok(())
# }
```

# Architecture

- [`raop`] — RAOP/AirPlay server, RTSP handlers, RTP streaming, audio buffering
- [`crypto`] — RSA, Ed25519/Curve25519 pairing, AES-CTR, FairPlay DRM, ChaCha20-Poly1305
- `codec` — Audio decoders (ALAC, AAC) and resampling (internal)
- [`proto`] — SDP, HTTP/RTSP, binary plist, HTTP Digest auth
- [`net`] — Async TCP server (tokio), mDNS service registration, PTP timing
- [`error`] — Error types

# Feature Flags

- `ap2` — AirPlay 2 support (SRP-6a pairing, buffered AAC, encrypted transport)
- `video` — Experimental screen mirroring (implies `ap2`)
"]

pub(crate) mod codec;
#[doc(hidden)]
pub mod crypto;
#[doc(hidden)]
pub mod dacp;
pub mod error;
#[doc(hidden)]
pub mod net;
#[doc(hidden)]
pub mod proto;
#[doc(hidden)]
pub mod raop;
pub(crate) mod util;

pub use error::ShairplayError;
pub use net::mdns::AirPlayServiceInfo;
pub use net::server::BindConfig;
#[cfg(feature = "hls")]
pub use raop::hls::{HlsHandler, HlsSession};
#[cfg(feature = "video")]
pub use raop::video::{PacketKind, VideoHandler, VideoPacket, VideoSession};
#[cfg(feature = "ap2")]
pub use raop::{AirPlayMode, MemoryPairingStore, PairingStore};
pub use raop::{
    AudioCodec, AudioFormat, AudioHandler, AudioSession, RaopServer, RaopServerBuilder, RemoteCommand, RemoteControl,
    TrackMetadata,
};

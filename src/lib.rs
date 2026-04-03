#![forbid(unsafe_code)]
#![allow(clippy::needless_range_loop, clippy::too_many_arguments, clippy::while_immutable_condition, clippy::explicit_counter_loop)]
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
    fn audio_process(&mut self, buffer: &[u8]) {
        // Handle decoded PCM audio data
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
- [`crypto`] — RSA, Ed25519/Curve25519 pairing, AES-CTR, FairPlay DRM
- [`codec`] — ALAC (Apple Lossless) audio decoder
- [`proto`] — SDP, HTTP/RTSP, binary plist, HTTP Digest auth
- [`net`] — Async TCP server (tokio), mDNS service registration
- [`error`] — Error types
"]

pub mod codec;
pub mod crypto;
pub mod dacp;
pub mod error;
pub mod net;
pub mod proto;
pub mod raop;
pub(crate) mod util;

pub use error::ShairplayError;
pub use net::mdns::AirPlayServiceInfo;
pub use net::server::BindConfig;
pub use raop::{AudioCodec, AudioFormat, AudioHandler, AudioSession, RaopServer, RaopServerBuilder, RemoteCommand, RemoteControl};
#[cfg(feature = "airplay2")]
pub use raop::{PairingStore, MemoryPairingStore};

// AirPlay 2 re-exports are internal — crypto modules not part of public API

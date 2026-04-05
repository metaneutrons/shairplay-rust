# Project: shairplay

Pure Rust AirPlay server library. Published on crates.io as `shairplay`.

## Repository

- GitHub: `metaneutrons/shairplay-rust`
- Local: `~/Source/shairplay`
- License: LGPL-3.0-or-later

## Architecture

```
src/
├── raop/           Server core: RTSP dispatch, RTP audio, buffered audio
│   ├── types.rs        Public API types and traits
│   ├── server.rs       RaopServer builder + lifecycle
│   ├── connection.rs   Per-connection state + dispatch
│   ├── rtsp.rs         Route-table RTSP dispatch
│   ├── handlers_ap1.rs AP1 RTSP handlers
│   ├── handlers_ap2.rs AP2 RTSP handlers
│   ├── rtp.rs          AP1 RTP streaming
│   ├── ntp.rs          NTP timing responder
│   ├── buffer.rs       RTP packet buffer + AES-CBC decrypt + ALAC decode
│   ├── buffered_audio  AP2 timed playout buffer
│   ├── realtime_audio  AP2 realtime ALAC
│   └── event_channel   AP2 encrypted event channel
├── video/          Screen mirroring (experimental)
├── hls/            HLS video playback (YouTube)
├── crypto/         RSA, Ed25519, AES, FairPlay, SRP-6a, ChaCha20
├── codec/          ALAC decoder, AAC decoder, resampler
├── proto/          SDP, HTTP/RTSP, DMAP, binary plist, HTTP Digest
├── net/            Async TCP server, mDNS, PTP timing, feature flags
├── dacp/           DACP remote control (AP1)
└── error/          Error types (thiserror)
```

## Feature Flags

| Flag | Implies | Description |
|------|---------|-------------|
| *(default)* | — | AP1 only |
| `resample` | — | Sample rate conversion + channel mixdown (optional) |
| `ap2` | — | Full AirPlay 2 audio |
| `video` | `ap2` | Legacy audio for screen mirroring |
| `hls` | `video` | HLS video playback |

## Public API

All types re-exported from `lib.rs`. Users write `shairplay::RaopServer`, never `shairplay::raop::*`.

Key traits:
- `AudioHandler` — factory for audio sessions + lifecycle callbacks
- `AudioSession` — receives PCM samples, metadata, volume, progress
- `HlsHandler` / `HlsSession` — HLS URL relay + playback state
- `VideoHandler` / `VideoSession` — video NAL unit delivery
- `PairingStore` — persistent HomeKit key storage

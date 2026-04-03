# AirPlay 2 Remote Control — Research & Implementation Status

## Unified Remote Control API (Implemented)

The library exposes a unified `RemoteControl` trait that works identically for AP1 and AP2:

```rust
pub trait RemoteControl: Send + Sync {
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), ShairplayError>;
    fn available_commands(&self) -> Vec<RemoteCommand>;
}

pub enum RemoteCommand {
    Play, Pause, NextTrack, PreviousTrack,
    SetVolume(u8), ToggleShuffle, ToggleRepeat, Stop,
}
```

Apps receive `Arc<dyn RemoteControl>` via `AudioSession::remote_control_available()`.

## AP1 Remote Control — DACP (Fully Implemented)

| Aspect | Details |
|--------|---------|
| Protocol | HTTP to iPhone port 3689 |
| Discovery | `DACP-ID` + `Active-Remote` RTSP headers |
| Transport | Outbound TCP from receiver to sender |
| Commands | Static set: play/pause, next, prev, volume, shuffle, repeat |
| Implementation | `DacpRemoteControl` wraps `DacpClient` |
| Status | ✅ Complete |

The iPhone advertises a `_dacp._tcp` mDNS service. When it connects via AirPlay,
it sends `DACP-ID` and `Active-Remote` headers. Our library creates a `DacpClient`
and delivers it as `Arc<dyn RemoteControl>` to the app.

## AP2 Remote Control — Definitive Conclusion

**AP2 remote control from a third-party receiver is not possible** without being
a real HomeKit accessory or sharing the same Apple ID.

### All Paths Investigated

| Path | Mechanism | Result |
|------|-----------|--------|
| DACP | `Active-Remote` RTSP header | Not sent in AP2 (iOS 18+) |
| Type 130 MRP | Encrypted data channel with `seed` | Seed requires HomeKit trust |
| Event channel | RTSP `POST /command` over encrypted TCP | One-way only (status updates). iPhone returns 200 OK but ignores commands |
| Companion-link | `_companion-link._tcp` OPACK protocol | Requires same Apple ID (always-on `rapportd` connection) |
| HAP pairing | `_hap._tcp` HomeKit accessory | Apple TV/HomePod don't use HAP for AirPlay — trust is from Home app setup |

### Why It Works for Apple Devices

- **Mac**: Uses `_companion-link._tcp` (Rapport daemon). iPhone connects because
  they share the same Apple ID. This is an always-on connection, not AirPlay-specific.
- **HomePod/Apple TV**: Added to Home app during initial setup. HomeKit trust stored
  in iCloud. iPhone sends `seed` in type 130 SETUP because the device is in the
  same Home. This trust cannot be established through AirPlay protocol alone.

### Recommendation

For third-party AP2 receivers, remote control is not available. The library should:
1. Document this limitation clearly
2. Focus on receiving `updateMRSupportedCommands` for informational purposes
3. Forward now-playing metadata (artwork, progress, track info) from SET_PARAMETER
4. Consider AP1 DACP as fallback if the sender provides headers (older iOS versions)

### Known Command Constants (from MediaRemote.framework)

```
kMRMediaRemoteCommandPlay           = 0
kMRMediaRemoteCommandPause          = 1
kMRMediaRemoteCommandTogglePlayPause = 2
kMRMediaRemoteCommandStop           = 3
kMRMediaRemoteCommandNextTrack      = 4
kMRMediaRemoteCommandPreviousTrack  = 5
kMRMediaRemoteCommandSetVolume      = ?
kMRMediaRemoteCommandToggleShuffle  = ?
kMRMediaRemoteCommandToggleRepeat   = ?
```

### File Locations

| File | Purpose |
|------|---------|
| `src/raop/mod.rs` | `RemoteControl` trait, `RemoteCommand` enum, `DacpRemoteControl` |
| `src/raop/handlers.rs` | Type 130 stream setup, `/command` handler |
| `src/raop/event_channel.rs` | Event channel (sends `updateInfo` to iPhone) |
| `src/dacp/mod.rs` | DACP HTTP client |
| `src/crypto/chacha_transport.rs` | Data channel encryption |


## References

- [AirPlay 2 Internals — Service Discovery](https://emanuelecozzi.net/docs/airplay2/discovery/) — mDNS TXT record format
- [AirPlay 2 Internals — Features](https://emanuelecozzi.net/docs/airplay2/features/) — Feature bitmask documentation
- [AirPlay 2 Internals — RTSP](https://emanuelecozzi.net/docs/airplay2/rtsp/) — RTSP headers and endpoints (note: shows DACP-ID on AP2 requests, but modern iOS 18+ no longer sends them)
- [Unofficial AirPlay Specification](https://openairplay.github.io/airplay-spec/service_discovery.html) — Legacy AirPlay protocol
- [MediaRemoteTV Protocol](https://jeanregisser.gitbooks.io/mediaremotetv-protocol/content/communication/) — MRP protobuf format (Apple TV, not AirPlay data channel)
- [Dissecting the Media Remote Protocol](https://edc.me/posts/dissecting-the-media-remote-protocol/) — Evan Coleman's reverse engineering of Apple TV MRP (length-prefixed protobuf over TCP, SRP-encrypted)
- [pyatv](https://github.com/postlund/pyatv) — Python Apple TV library (MRP implementation)
- [shairport-sync](https://github.com/mikebrady/shairport-sync) — C AirPlay 2 reference implementation
- [pair_ap](https://github.com/ejurgensen/pair_ap) — C HomeKit pairing library (SRP-6a, TLV, HKDF, pair-verify, MFi-SAP). Primary reference for our pairing implementation. 17 C-verified test vectors generated from this codebase.
- [SteeBono/airplayreceiver](https://github.com/SteeBono/airplayreceiver/wiki/AirPlay2-Protocol) — AirPlay 2 protocol overview wiki

## Feature Flag Findings

The `seed` for the type 130 encrypted data channel is **definitively** gated by
HomeKit pairing (device added to Apple Home app), not by features or model.

### Tested Combinations (all produce type 130 without seed)

| Features | Model | et | Result |
|----------|-------|----|--------|
| `0x1C340405D4A00` (shairport-sync) | AppleTV2,1 | 0,1 | ✅ audio, no seed |
| `0x1C340405D4A00` (shairport-sync) | AppleTV2,1 | 0,3,5 | ✅ audio, no seed |
| `0x38174FDE4A7FCFD5` (Mac) | Mac15,6 | 0,3,5 | ✅ audio, no seed |
| `0x1C340405D4A00` + bit 58 | AudioAccessory5,1 | 0,1 | ✅ audio, no seed |

### Mac Emulation Research

Full Mac mDNS emulation was tested (features, model, srcvers, flags, act, fex,
rsf, at, psi — all matching real Mac byte-for-byte). Key finding: `et=0,3,5`
is required for discovery with Mac features. Without it (et=0,1), the iPhone
rejects the device entirely. With correct `et`, Mac emulation works for both
discovery and audio.

### DACP Headers in AP2

Emanuelecozzi's docs (AirPlay/409.16, ~2019) show `DACP-ID` and `Active-Remote`
headers on AP2 RTSP requests. Modern iOS (AirPlay/935.7.1, iOS 18) does NOT send
these headers during AP2 sessions. DACP remote control is AP1-only.

### AP2 Remote Control Path: Event Channel

The iPhone sends `updateMRSupportedCommands` via `POST /command` with 31 MR
commands as nested binary plists. Each contains `kCommandInfoCommandKey` (integer
command ID) and `kCommandInfoEnabledKey` (boolean). The event channel is
bidirectional encrypted TCP — the path for sending commands back to the iPhone.

### Known MR Command IDs (from iPhone updateMRSupportedCommands)

```
0  = Play                    10 = StartForwardSeek
1  = Pause                   11 = StartBackwardSeek
2  = TogglePlayPause         17 = SkipForward (disabled)
3  = Stop                    18 = SkipBackward (disabled)
4  = NextTrack               19 = ChangePlaybackRate (disabled)
5  = PreviousTrack           21 = RateTrack
8  = ToggleShuffle           22 = LikeTrack
9  = ToggleRepeat            24 = DislikeTrack
121 = SetPlaybackPosition    127 = PrepareForSetQueue
122 = SetPlaybackQueue       128-135 = Queue/session management
125 = PlayItemInQueue        143 = SetVolume
149 = ChangePlaybackMode
```

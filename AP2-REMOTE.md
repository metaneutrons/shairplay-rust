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

## AP2 Remote Control — MediaRemote (Research Needed)

### What We Have

1. **Type 130 stream setup**: The iPhone opens an encrypted TCP data channel
   during SETUP on the RC (Remote Control Only) connection. We accept the
   connection and can read/write on it.

2. **`/command` POST**: The iPhone sends `mrSupportedCommandsFromSender` — a
   binary plist containing an array of supported commands. Each command is a
   nested binary plist with `kCommandInfoCommandKey` and `kCommandInfoEnabledKey`.

3. **Event channel**: The server sends `updateInfo` plists to the iPhone with
   device state (via the event channel, not the data channel).

4. **Encryption**: The data channel uses ChaCha20-Poly1305 with a cipher derived
   from the shared secret + a `seed` value from the SETUP plist:
   ```
   salt = "DataStream-Salt" + str(seed)
   write_key = HKDF(shared_secret, salt, "DataStream-Output-Encryption-Key")
   read_key  = HKDF(shared_secret, salt, "DataStream-Input-Encryption-Key")
   ```

### What We Don't Know

1. **Command format for sending**: The binary plist structure for sending a
   playback command (e.g., "next track") from receiver to sender over the
   type 130 data channel is undocumented.

2. **Framing**: How commands are framed on the data channel TCP stream
   (length-prefixed? RTSP-like? raw plist concatenation?).

3. **Command identifiers**: The `kCommandInfoCommandKey` values map to
   MediaRemote framework constants (e.g., `kMRMediaRemoteCommandPlay`).
   The numeric values are known from Apple's private framework headers,
   but the plist structure for invoking them is not.

### Related Protocols (Not Directly Applicable)

- **MRP (MediaRemote Protocol)**: Used between Apple TV Remote app and Apple TV.
  Uses protobuf over TCP port 49152. Documented by pyatv project. Different
  protocol from the AirPlay 2 data channel (which uses binary plists).

- **DACP**: AP1 remote control. HTTP-based, well-documented, fully implemented.
  Works alongside AP2 audio — the iPhone still runs a DACP service even during
  AP2 streaming.

### Research Approaches

1. **Wireshark capture**: Set up a HomePod (or HomePod Mini) and capture traffic
   while using Siri or the Home app to control playback. The HomePod is a real
   AirPlay 2 receiver that sends commands back to the iPhone.

2. **Apple framework headers**: `MediaRemote.framework` private headers contain
   command constants. Combined with the `mrSupportedCommandsFromSender` plist
   structure, the command format might be inferrable.

3. **Hybrid approach**: Use AP1 DACP for remote control even during AP2 audio
   sessions. The iPhone's DACP service is always available. This is the pragmatic
   solution until the AP2 data channel protocol is reverse-engineered.

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

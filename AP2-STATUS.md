# AirPlay 2 — Implementation Status & Research

## Complete

| Feature | Stream Type | Details |
|---------|-------------|---------|
| mDNS discovery | — | `_airplay._tcp` + `_raop._tcp`, `et=0,3,5` |
| HomeKit pairing (persistent) | — | Configurable PIN, PairingStore key persistence — **default** in the example |
| SRP-6a transient pairing | — | PIN 3939, automatic, no persistence — example opt-in via `--transient` |
| Paired-state statusFlags | — | Advertises `sf` = 0x004 transient / 0x204 PIN-unpaired / 0x604 PIN-paired, gated by `has_any_pairing()` so paired controllers reconnect via pair-verify |
| Session handoff | — | A new audio SETUP stops the previous session (`set_active_audio`), so playback never lingers after a disconnect/switch |
| Encrypted RTSP transport | — | ChaCha20-Poly1305, HKDF-SHA512 key derivation |
| FairPlay handshake | — | Full fp-setup M1/M2 |
| PTP timing | — | ⚠ Listener now runs (binds + drains 319/320 to kill the connect stall); offsets still **not wired** to playout — see [Open / Unwired](#open--unwired--scaffolding-present-not-connected) |
| Buffered audio | 103 | AAC decode (symphonia), per-packet ChaCha20 decrypt |
| Multichannel | 103 | 5.1/7.1 AAC → stereo mixdown (ITU-R BS.775) |
| Resampling | 103 | rubato StreamResampler, any rate → output rate |
| Timed playout buffer | 103 | Pause/resume/flush, stale frame discard |
| Metadata forwarding | — | Volume, artwork, progress, DMAP track info |
| Event channel | — | Bidirectional encrypted TCP; `updateInfo` sent on connect. Ongoing outbound event reporting **unwired** (see Open) |
| Realtime audio | 96 | ALAC decode, ChaCha20 decrypt, immediate delivery |
| **Video (screen mirroring)** | **110** | **AES-128-CTR decrypt, H.264 decode, working on iOS 18** |
| Unified output | — | Always F32LE interleaved PCM to app |

## MFi `/auth-setup` — Not Implemented

The AP2 profile implements FairPlay (`/fp-setup`) and HomeKit pairing
(`/pair-setup`, `/pair-verify`), but not MFi-SAP receiver authentication. It
advertises `et=0,3,5`; `et=5` is FairPlay SAP 2.5, while the commonly documented
MFi-SAP value `et=4` is absent. Feature bits 26 and 51 are also not set.

`/auth-setup` is not exclusively an AP1 or AP2 mechanism: public
reverse-engineering sources place it in both classic RAOP compatibility and
AirPlay 2 contexts. A forced PipeWire `auth_setup` sender currently receives
`404` after the Digest check, or `401` for missing/invalid required authorization,
and aborts. The normal advertised profiles do not select that path.
A status-only PipeWire workaround would not constitute MFi
authentication. See the dedicated
[`/auth-setup` protocol status](docs/protocol/auth-setup.md) for evidence levels,
security boundaries, unknowns, and required regression coverage.

## Open / Unwired — scaffolding present, not connected

Implemented building blocks that are **not** wired into the runtime path. Kept
deliberately (behind `#[allow(dead_code)]`) as the foundation for these features —
do **not** delete them as "dead code"; they are unfinished AP2 capabilities.

- **PTP timing → real clock sync / multi-room** — `src/net/ptp.rs` is a complete
  IEEE-1588 / Apple-aPTP client (Sync/Follow_Up/Announce parsing, `OffsetSmoother`,
  `PtpAnchor`). As of the fast-connect work a **PTP sink now runs**: `spawn_ptp_sink()`
  binds and drains ports 319/320 (IPv6-unspecified) so the sender no longer stalls on
  ICMP port-unreachable — this is purely the connect-latency fix and can be disabled
  with `SHAIRPLAY_NO_PTP`. What is still **not connected to playout** is the timing
  itself: the parsed Follow_Up/Announce timestamps are only logged (`debug`) — no
  offset is computed and `PtpClock`/`OffsetSmoother` stay unused — so the receiver
  plays out on best-effort local timing and there is **no true clock sync and no
  multi-room sync**. To finish wiring: compute offsets from the drained Sync/Follow_Up
  stream, feed them into `PtpClock`, and schedule buffered/realtime playout via
  `PtpAnchor::delay_until_playout` instead of immediate delivery. (Binding 319/320 may
  need root / `CAP_NET_BIND_SERVICE`, esp. on Linux; the bind is best-effort and
  degrades gracefully — a failed bind just logs one line and leaves the slow-connect
  behaviour. The sink is IPv6-only today.)

- **Outbound event reporting** — the encrypted event channel is established and the
  initial `updateInfo` is pushed at SETUP, but the receiver never sends events
  afterward. `EventSender::send` (held in `RaopConnection::event_sender`,
  `src/raop/event_channel.rs`) is the API for this; wire calls to it on receiver-side
  state changes (volume / now-playing / progress) for fuller AP2 event reporting.

> Related already-wired gap closed in 0.6.0: `AudioHandler::on_error` was defined but
> never called — now wired. The two items above are the remaining "built but unwired"
> AP2 capabilities.

## Video — Working (iOS 18)

**Screen mirroring is working.** iPhone screen successfully mirrored and
displayed in a window. The full pipeline is proven:

1. FairPlay key exchange (fp-setup M1/M2)
2. AES-128-CTR video decryption
3. H.264 decode (openh264) + display (minifb)

### Key Discovery: UxPlay Feature Set

The breakthrough was using UxPlay's exact feature bitmask:

```
Features = 0x527FFEE6 (bit 27 "legacy pairing" OFF)
```

With this feature set:
- iPhone **skips pair-setup and pair-verify entirely**
- iPhone sends `ekey` (72 bytes, FairPlay-encrypted) directly in SETUP
- No ECDH hash needed — raw FairPlay-decrypted key goes to Stage 3
- No AP2 bits (40, 41, 46, 48) — pure legacy protocol for video

### Video Key Derivation (Working)

Two-step process (no ECDH hash when bit 27 is off):

```
Step 1: aeskey = playfair_decrypt(keymsg_164, ekey_72)              → 16 bytes
Step 2: key    = SHA-512("AirPlayStreamKey{id}" || aeskey)[0..16]   → 16 bytes
        iv     = SHA-512("AirPlayStreamIV{id}"  || aeskey)[0..16]   → 16 bytes
```

Where `{id}` is the `streamConnectionID` from the type 110 SETUP, formatted
as unsigned decimal (`PRIu64`).

### Critical Bug Found: Truncated FairPlay Tables

The Rust port of `playfair_decrypt` had **6 truncated lookup tables** from the
original C-to-Rust conversion. Rust zero-filled the missing bytes, causing
`playfair_decrypt` to produce wrong keys silently:

| Table | Declared | Actual | Missing |
|-------|----------|--------|---------|
| TABLE_S1 | 10240 | 9600 | 640 |
| TABLE_S2 | 36864 | 34560 | 2304 |
| TABLE_S3 | 4096 | 3840 | 256 |
| TABLE_S4 | 36864 | 34560 | 2304 |
| TABLE_S9 | 1024 | 256 | 768 |
| TABLE_S10 | 4096 | 3840 | 256 |
| STATIC_SOURCE_2 | 47 | 46 | 1 |

Tables regenerated from original C source (`playfair/omg_hax.c`).

**⚠️ This bug invalidated ALL previous video decryption research.** Every
"tested approach" that failed was tested with a broken `playfair_decrypt`.
The previous conclusion that "iOS 18 doesn't send ekey" was wrong — it does
send ekey, but only with UxPlay's feature set (no AP2 bits).

### Current FairPlay Status

FairPlay decryption is implemented in safe Rust. The generated lookup tables are
checked in as Rust constants and are covered by test vectors.

### Previous Research — Needs Re-verification

Earlier video-key research was conducted with the broken `playfair_decrypt`
implementation and may no longer be accurate:

- "iOS 18 doesn't send ekey for screen mirroring" — **WRONG.** It does, with
  UxPlay features (`0x527FFEE6`).
- "ECDH hash is required for video key" — **WRONG for legacy mode.** With bit 27
  off, no pairing occurs and the raw FairPlay key is used directly.
- "All 13+ key derivation variants failed" — **All tested with wrong FairPlay key.**
  Need to re-test with AP2 features if AP2+video is desired.
- "Screen mirroring audio (type 96 usingScreen) has no shk" — Needs re-testing
  with UxPlay features.

### Current Limitations

- **No AP2 audio with video** — UxPlay features disable AP2 buffered audio
- **openh264 decode errors** — Software decoder struggles at 30fps in debug mode
- **No screen mirroring audio** — Type 96 `usingScreen` audio not yet wired up

### Stream Type 120 — Video Relay (Not Implemented)

Sent by YouTube, Apple Music (music videos), and other video apps. The SETUP
contains only `{"type": Integer(120)}` with no additional fields. Likely HLS
video relay where the app sends a video URL for the receiver to fetch directly.

### TODO
- [ ] Test AP2+video hybrid features (can we have both AP2 audio and video?)
- [ ] Wire up screen mirroring audio (type 96 `usingScreen`)
- [ ] Improve H.264 decode stability (release build, error recovery)
- [ ] Re-test previous key derivation approaches with correct FairPlay key

### Hypothesis: HLS with AP2 Audio

HLS video playback (`/play`, `/playback-info`) is pure HTTP — it relays an
m3u8 URL to the application and doesn't use the RTP audio pipeline. It may
be possible to run HLS alongside AP2 buffered audio (type 103) instead of
requiring the UxPlay legacy feature set. The iPhone could send the video URL
via HLS while streaming audio via AP2.

Currently untested: all open-source implementations (UxPlay, AirShow) use
legacy features for HLS. The `hls` feature implies `video` (legacy features)
as a safe default. Decoupling `hls` from `video` to test with AP2 features
is a potential future experiment.

## Known Issues (Resolved)

### AP2 audio connect 5–11s → ~0.5s — FULLY RESOLVED ✅

Starting an AP2 audio session (and switching receivers mid-playback) took 5–11
seconds versus near-instant on a real Apple TV. Root-caused to four independent
causes, all fixed:

1. **PTP ICMP stall.** Nothing bound the PTP ports, so every timing packet from
   the sender drew an ICMP port-unreachable and the sender backed off. Fixed by
   `spawn_ptp_sink()` binding + draining 319/320 (see [Open / Unwired](#open--unwired--scaffolding-present-not-connected)).
2. **statusFlags nudged paired controllers back into setup.** The `sf` value did
   not reflect paired state, so iOS re-probed pair-setup on reconnect. Fixed with
   `ap2_status_flags()`: 0x004 transient / 0x204 PIN-unpaired / **0x604 PIN-paired**
   (keep `OneTimePairingRequired` bit 9 **and** add `DeviceSetupForHKAccessControl`
   bit 10 once paired — matches a real Apple TV's `0x18644`), gated by
   `PairingStore::has_any_pairing()`. **Do not guess flag bit names — this was
   pulled from real-device mDNS (`dns-sd -Z _airplay._tcp local.`).**
3. **Transient pairing was the default.** Transient sessions are untrusted, so iOS
   waited out an ~11s remote-control timeout before falling back. The example now
   defaults to **persistent** pairing (`--transient` to opt out).
4. **Overlapping sessions on switch.** A new SETUP left the previous audio session
   running (audio kept playing after disconnect and the new one connected slowly).
   Fixed with `RaopShared::set_active_audio()`, which stops the prior session when
   the next one starts.

### RC Connection Delay (~10s) — FULLY RESOLVED ✅

Previously, the iPhone opened a "Remote Control Only" RTSP connection ~10 seconds before starting the audio connection. 

This has been **fully resolved** by:
1. Deriving a **stable and deterministic Pairing Identifier (`pi`)** from the receiver's MAC address (advertised consistently in mDNS).
2. Correctly completing the GET `/info` response plist payload to return `"pi"`, `"name"`, `"macAddress"`, and `"deviceID"`.
3. Binding and returning a proper `eventPort` in the `isRemoteControlOnly` SETUP response plist, and spawning the encrypted event channel handler.

With these changes, the trust relationship is established instantly, and audio streaming begins in under 50ms without any delay!

## AP2 Remote Control — Research

Third-party AP2 receivers cannot send playback commands (play/pause/skip) to
the iPhone. AP1 DACP remote control is fully implemented and works.

See previous sections for full remote control research (unchanged).

## Test Coverage

175 tests, 17 C-verified vectors from pair_ap reference implementation:
- TLV codec, HKDF-SHA512, ChaCha20 transport framing
- ADTS framing, audio packet decryption, server keypair
- Anchor time calculation, channel mixdown, SSRC mapping
- Full M1→M4 SRP integration test over real TCP
- Video cipher streaming AES-CTR partial block tests
- FairPlay cross-validation test against C `playfair_decrypt` output

## References

- [AirPlay 2 Internals — Features](https://emanuelecozzi.net/docs/airplay2/features/)
- [AirPlay 2 Internals — RTSP](https://emanuelecozzi.net/docs/airplay2/rtsp/)
- [Unofficial AirPlay Specification](https://openairplay.github.io/airplay-spec/)
- [UxPlay](https://github.com/FDH2/UxPlay) — working screen mirroring reference
- [pair_ap](https://github.com/ejurgensen/pair_ap)
- [shairport-sync](https://github.com/mikebrady/shairport-sync)

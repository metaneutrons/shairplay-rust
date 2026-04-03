# AirPlay 2 — Implementation Status & Research

## Complete

| Feature | Stream Type | Details |
|---------|-------------|---------|
| mDNS discovery | — | `_airplay._tcp` + `_raop._tcp`, `et=0,3,5` |
| SRP-6a transient pairing | — | PIN 3939, automatic, no persistence |
| Normal HomeKit pairing | — | Configurable PIN, PairingStore key persistence |
| Encrypted RTSP transport | — | ChaCha20-Poly1305, HKDF-SHA512 key derivation |
| FairPlay handshake | — | Full fp-setup M1/M2 |
| PTP timing | — | Offset smoothing, anchor-based playout |
| Buffered audio | 103 | AAC decode (symphonia), per-packet ChaCha20 decrypt |
| Multichannel | 103 | 5.1/7.1 AAC → stereo mixdown (ITU-R BS.775) |
| Resampling | 103 | rubato StreamResampler, any rate → output rate |
| Timed playout buffer | 103 | Pause/resume/flush, stale frame discard |
| Metadata forwarding | — | Volume, artwork, progress, DMAP track info |
| Event channel | — | Bidirectional encrypted TCP, updateInfo |
| Video (experimental) | 110 | AES-128-CTR decrypt, raw H.264/H.265 NAL delivery |
| Unified output | — | Always F32LE interleaved PCM to app |

## Known Issues

### RC Connection Delay (~10s)

The iPhone opens a "Remote Control Only" RTSP connection ~10 seconds before
the audio connection, even when a song is already playing. The Mac's built-in
AirPlay receiver has no delay — it uses `rapportd` (companion-link) which
provides an always-on trust relationship with the iPhone.

Tested and ruled out:
- Returning `dataPort` in type 130 stream response (no effect)
- Adding `eventPort` + `updateInfo` to RC connection (no effect)
- Empty vs populated `/feedback` response on RC connection (no effect)
- Returning `eventPort: 0, timingPort: 0` in RC SETUP response (no effect)
- Shairport-sync has the same feedback behavior (empty when not playing)

The delay does not affect audio quality or playback once connected.

## Not Implemented

### Realtime ALAC (Stream Type 96)

Low-latency audio over UDP. Used for Siri responses, phone calls, and system
sounds. The iPhone rarely requests type 96 for music — it prefers type 103.

Currently a stub: we bind a UDP port and return it in the SETUP response so the
iPhone doesn't error, but no audio receiver is spawned.

Implementation would require a UDP receiver with ChaCha20-Poly1305 decryption
and ALAC decoding. The AP1 RTP pipeline cannot be reused directly (AES-CBC vs
ChaCha20), but the packet parsing and ALAC decoder are reusable.

Priority: Low. Only needed for non-music audio passthrough.

## AP2 Remote Control — Research

Third-party AP2 receivers cannot send playback commands (play/pause/skip) to
the iPhone. AP1 DACP remote control is fully implemented and works.

### All Paths Investigated

| Path | Mechanism | Result |
|------|-----------|--------|
| DACP | `Active-Remote` RTSP header | Not sent in AP2 (iOS 18+) |
| Type 130 MRP | Encrypted data channel with `seed` | Seed requires HomeKit trust |
| Event channel | RTSP `POST /command` over encrypted TCP | One-way only. iPhone returns 200 OK but ignores commands |
| Companion-link | `_companion-link._tcp` OPACK protocol | Requires same Apple ID (`rapportd` always-on) |
| HAP pairing | `_hap._tcp` HomeKit accessory | Apple TV/HomePod don't use HAP for AirPlay trust |

### Why It Works for Apple Devices

- **Mac**: Uses `_companion-link._tcp` (Rapport daemon). iPhone connects because
  they share the same Apple ID. Always-on connection, not AirPlay-specific.
- **HomePod/Apple TV**: Added to Home app during initial setup. HomeKit trust
  stored in iCloud. iPhone sends `seed` in type 130 SETUP because the device
  is in the same Home.

### Event Channel Discovery

The event channel accepts RTSP-framed requests (`POST /command`) and the iPhone
responds with `RTSP/1.0 200 OK`. Shairport-sync uses this for `updateInfo`
status messages. We tested sending `sendMediaRemoteCommand`, `sendCommand`, and
`cycleRemoteCommand` — all returned 200 OK but none triggered playback actions.
The event channel is for status updates only, not command delivery.

### MR Supported Commands

The iPhone sends `updateMRSupportedCommands` via `POST /command` with 31 MR
commands as nested binary plists:

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

### Feature Flag Research

Tested combinations (all produce type 130 without seed):

| Features | Model | et | Result |
|----------|-------|----|--------|
| `0x1C340405D4A00` (shairport-sync) | AppleTV2,1 | 0,1 | ✅ audio, no seed |
| `0x1C340405D4A00` (shairport-sync) | AppleTV2,1 | 0,3,5 | ✅ audio, no seed |
| `0x38174FDE4A7FCFD5` (Mac) | Mac15,6 | 0,3,5 | ✅ audio, no seed |
| `0x1C340405D4A00` + bit 58 | AudioAccessory5,1 | 0,1 | ✅ audio, no seed |

### Companion-Link Protocol

Investigated via pyatv source. Uses OPACK encoding (not plist, not protobuf)
with frame format `[1B type][3B BE length][payload]`. Commands:
`{"_i": "_mcc", "_t": 1, "_c": {"_mcc": <cmd_id>}}`. Requires same Apple ID —
the iPhone connects to the receiver's `_companion-link._tcp` service only if
they share an iCloud account.

## Test Coverage

130 tests, 17 C-verified vectors from pair_ap reference implementation:
- TLV codec, HKDF-SHA512, ChaCha20 transport framing
- ADTS framing, audio packet decryption, server keypair
- Anchor time calculation, channel mixdown, SSRC mapping
- Full M1→M4 SRP integration test over real TCP
- Video cipher streaming AES-CTR partial block tests

## References

- [AirPlay 2 Internals — Features](https://emanuelecozzi.net/docs/airplay2/features/)
- [AirPlay 2 Internals — RTSP](https://emanuelecozzi.net/docs/airplay2/rtsp/)
- [Unofficial AirPlay Specification](https://openairplay.github.io/airplay-spec/)
- [Dissecting the Media Remote Protocol](https://edc.me/posts/dissecting-the-media-remote-protocol/)
- [pair_ap](https://github.com/ejurgensen/pair_ap)
- [shairport-sync](https://github.com/mikebrady/shairport-sync)
- [pyatv](https://github.com/postlund/pyatv)
- [rairplay](https://github.com/r4v3n6101/rairplay)
- [SteeBono/airplayreceiver](https://github.com/SteeBono/airplayreceiver/wiki/AirPlay2-Protocol)

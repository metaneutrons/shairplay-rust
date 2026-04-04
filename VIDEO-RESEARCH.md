# ⚠️ OUTDATED — This research was conducted with a broken FairPlay implementation

The conclusions in this document are **invalid**. The Rust `playfair_decrypt` had
truncated lookup tables and a `modified_md5` swap order bug, causing all key
derivation attempts to fail regardless of the approach used.

**The actual solution**: Use UxPlay's feature set (`0x527FFEE6`, no AP2 bits).
The iPhone sends `ekey` directly, no pairing needed. See [AP2-STATUS.md](AP2-STATUS.md)
for the working implementation.

---

# Research: AirPlay 2 Screen Mirroring Video Decryption Key

## Problem

AirPlay 2 screen mirroring (stream type 110) delivers H.264 video encrypted with AES-128-CTR. We cannot derive the correct decryption key. The video pipeline works end-to-end (TCP stream, packet parsing, H.264 decoder, display window) — only the decryption key is wrong.

## What We Know

### Protocol Flow (observed with iOS 18)

```
iPhone → Receiver:
1. GET /info                          → receiver capabilities + displays array
2. POST /pair-setup M1→M5            → normal HomeKit pairing (stores Ed25519 key)
3. POST /pair-verify M1→M3→M4        → X25519 ECDH key agreement (32-byte shared secret)
4. POST /fp-setup M1                  → FairPlay mode selection (16 bytes)
5. POST /fp-setup M2                  → FairPlay key message (164 bytes, stored as keymsg)
6. SETUP (isScreenMirroringSession)   → event channel, timing — NO ekey/eiv
7. SETUP streams type=110             → streamConnectionID, latencyMs — NO ekey/eiv
8. TCP video stream                   → 128-byte headers + encrypted H.264 payloads
```

### Key Material Available

| Material | Source | Size | Available |
|----------|--------|------|-----------|
| ECDH shared secret | pair-verify M1 (X25519 DH) | 32 bytes | ✅ |
| SRP session key | transient pair-setup M3 | 64 bytes | ✅ |
| FairPlay keymsg | fp-setup M2 | 164 bytes | ✅ |
| FairPlay decrypted key | `playfair_decrypt(keymsg, ekey)` | 16 bytes | ❌ no ekey |
| ekey | SETUP plist field | 72 bytes | ❌ not sent for screen mirroring |
| eiv | SETUP plist field | 16 bytes | ❌ not sent for screen mirroring |

### Known Working Derivation (airplayreceiver, C#)

For AP1-style connections where `ekey` IS available:

```
Step 1: eaesKey   = SHA-512(fairplay_decrypt(keymsg, ekey), ecdh_shared)[0..16]
Step 2: streamKey = SHA-512("AirPlayStreamKey" + stream_connection_id, eaesKey)[0..16]
Step 3: streamIV  = SHA-512("AirPlayStreamIV" + stream_connection_id, eaesKey)[0..16]
```

This works in airplayreceiver because they use AP1 audio (ANNOUNCE with SDP `fpaeskey` field) which provides the 72-byte encrypted key. They don't support AP2 buffered audio.

### What Doesn't Work

All tested with iOS 18, verified by checking if decrypted NAL type bytes are valid H.264 (1, 5, 6, 7, 8) vs random (0-31 uniform):

1. **No decryption** — raw bytes are random, data IS encrypted
2. **SHA-512("AirPlayStreamKey{id}", ecdh_shared)** — wrong key
3. **SHA-512("AirPlayStreamKey{id}", srp_session_key)** — wrong key
4. **Legacy pairing (remove HomeKit bits 46, 48)** — still encrypted, still no ekey
5. **Disable FairPlay bit 14** — would break AP2 audio

## Questions to Research

1. **How does Apple TV derive the video key?** Apple TV uses persistent HomeKit pairing (added via Home app). Does the HomeKit "seed" (from type 130 MRP channel) provide the FairPlay key material?

2. **Is there a way to derive the FairPlay key without ekey?** The FairPlay keymsg (164 bytes) contains key material. Can the 16-byte AES key be derived from keymsg alone (without the 72-byte encrypted input)?

3. **Does the pair-verify shared secret serve as the FairPlay key?** Some implementations use `SHA-512(ecdh_shared, keymsg[144..164])` or similar combinations.

4. **Is there a different SETUP field for screen mirroring keys?** The `timestampInfo` array in the type 110 SETUP contains 5 entries (SubSu, BePxT, AfPxT, BefEn, EmEnc). Could "EmEnc" relate to encryption material?

5. **Does the `/info` response need additional fields?** Apple TV's `/info` includes fields we don't send (like `initialVolume`, `audioLatencies`, etc.). Could missing fields cause the iPhone to use a different encryption path?

6. **What about the `streamConnectionID` as key material?** The stream connection ID is a signed 64-bit integer. Could it be used as part of the key derivation (XOR with ECDH, etc.)?

## Reference Implementations

- **airplayreceiver** (C#): https://github.com/SteeBono/airplayreceiver — AP1 audio + video, uses `ekey` from SDP
- **rairplay** (Rust): https://github.com/r4v3n6101/rairplay — legacy pairing, claims unencrypted video (not confirmed on iOS 18)
- **shairport-sync** (C): https://github.com/mikebrady/shairport-sync — audio only, no video
- **openairplay/airplay2-receiver** (Python): https://github.com/openairplay/airplay2-receiver — may have video support

## Repository

https://github.com/metaneutrons/shairplay-rust — `video` branch, `src/raop/handlers.rs` type 110 handler, `src/raop/video_stream.rs` stream receiver.

## UxPlay Wiki Finding (iOS 12 vs iOS 18)

The [UxPlay AirPlay2 wiki](https://github.com/FDH2/UxPlay/wiki/AirPlay2) from 2019
shows that iOS 12 DID send `ekey` in the screen mirroring SETUP:

```xml
<key>ekey</key>
<data>RlBMWQECAQAAAAA8AAAA... (FairPlay-wrapped, starts with "FPLY")</data>
```

iOS 18 no longer sends this field. The protocol changed between iOS 12 and iOS 18
to remove the explicit `ekey` from screen mirroring SETUP when HomeKit pairing is used.

This confirms the key derivation must use a different mechanism on iOS 18.

## Airplay-SDK Binary Analysis

The commercial [Airplay-SDK](https://github.com/xfirefly/Airplay-SDK) binary
(`macOS&Linux/airdemo`) contains these relevant strings:

- `Pair-Verify-AES-Key` and `Pair-Verify-AES-IV` — used as separate derivations
- `AirPlayStreamKey` and `AirPlayStreamIV` — standard stream key labels
- `%s%llu` near `streamConnectionID` — confirms unsigned 64-bit formatting
- `et=0,3,5` — encryption types (0=none, 3=FairPlay, 5=FairPlay SAPv2.5)
- `Unknown encryption method! et=%d` — encryption type selection logic
- `Decrypting: messageType=%i, messageSeq=%i, cipherType=%i` — multiple cipher types

The binary implements working video decryption but the source is not available.
Reverse engineering with Ghidra/IDA would be needed to extract the exact key
derivation function.

## Definitive Finding: UxPlay + AirShow Source Analysis

Both UxPlay (C) and AirShow (embeds UxPlay) use the same 3-stage pipeline:

```
Stage 1: aeskey_base  = fairplay_decrypt(keymsg_164, ekey_72)           → 16 bytes
Stage 2: aeskey_audio = SHA-512(aeskey_base || ecdh_secret)[0..16]      → 16 bytes
Stage 3: video_key    = SHA-512("AirPlayStreamKey{id}" || aeskey_audio)[0..16]
         video_iv     = SHA-512("AirPlayStreamIV{id}"  || aeskey_audio)[0..16]
```

**All existing open-source implementations require `ekey` from the SETUP plist.**
iOS 18 does not send `ekey` when HomeKit pairing (bits 46, 48) is used.
There is NO fallback in any known implementation.

This is an unsolved problem across the entire open-source AirPlay community.

## Screen Mirroring Audio (Type 96 with usingScreen=true)

Screen mirroring also sends type 96 realtime audio with `"usingScreen": true`,
`"ct": 4` (AAC), `"sr": 44100`. Like video, it sends **no `shk`** (shared key).

The type 96 SETUP for screen mirroring contains:
- `usingScreen: true`
- `audioFormat: 4194304`
- `streamConnectionID` (signed i64)
- `redundantAudio: 2`
- `controlPort` (for UDP)
- `latencyMax/latencyMin`
- `isMedia: true`
- NO `shk` field

This confirms iOS 18 expects ALL screen mirroring keys (audio + video) to be
derived from the pair-verify ECDH secret, not from explicit key fields.

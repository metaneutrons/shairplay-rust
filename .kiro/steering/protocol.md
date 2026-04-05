# AirPlay Protocol Knowledge

## Feature Bitmask

- AP1/AP2 audio: `0x0001C340405D4A00` (bits 9,11,14,16,18-22,30,38,40,41,46-48)
- Video/HLS (UxPlay legacy): `0x5A7FFEE6` (bits 1-7,9-22,25,27,28,30)
- Video adds NO AP2 bits — pure legacy protocol
- Bit 27 (legacy pairing) must be OFF when using FairPlay ekey without ECDH hash

## Connection Flows

### AP1 (Classic)
```
OPTIONS → ANNOUNCE (SDP) → SETUP (Transport header) → RECORD → audio RTP
```

### AP2 (AirPlay 2)
```
/pair-setup (SRP-6a) → /pair-verify (Ed25519+X25519) → encrypted RTSP →
/fp-setup → SETUP (plist, type 103/96) → RECORD → audio RTP
```

### Legacy (Video/HLS features)
```
/fp-setup → SETUP (plist, ekey/eiv) → NTP timing exchange →
SETUP (plist, type 96 streams) → audio RTP
```
- No pair-setup/verify — iPhone skips pairing entirely
- eventPort must be 0 (iPhone blocks on encrypted event channel)
- NTP timing responder required (active requests + passive responses)
- ekey is FairPlay-decrypted directly (no ECDH hash — no pairing happened)

### HLS
```
GET /server-info → POST /play (m3u8 URL) → GET /playback-info (polling)
POST /scrub, /rate, /stop
```

## Video Decryption (UNSOLVED on iOS 18)

iOS 18 does NOT send `ekey`, `eiv`, or `shk` for screen mirroring video.
The 3-stage FairPlay key derivation is implemented but produces wrong keys.
All open-source implementations are affected. See VIDEO-RESEARCH.md.

## Key Files for Protocol Research

- `AP2-STATUS.md` — implementation status + research findings
- `VIDEO-RESEARCH.md` — video decryption research prompt
- `~/Source/UxPlay/` — working C reference (screen mirroring + HLS)

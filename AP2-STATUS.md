# AirPlay 2 Implementation Status

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
| Unified output | — | Always F32LE interleaved PCM to app |

## Not Implemented

### Realtime ALAC (Stream Type 96)

Low-latency audio over UDP. Used for Siri responses, phone calls, and system
sounds. The iPhone rarely requests type 96 for music streaming — it prefers
type 103 (buffered AAC).

Currently a stub: we bind a UDP port and return it in the SETUP response so the
iPhone doesn't error, but no audio receiver is spawned.

Implementation would require:
1. UDP socket receiver (tokio)
2. RTP packet parsing (12-byte header, same as AP1)
3. ChaCha20-Poly1305 per-packet decryption (same `shk` key as type 103)
4. ALAC decoding (we have this from AP1 in `codec/alac.rs`)
5. Resample/mixdown to output format (we have this in `codec/resample.rs`)

The AP1 RTP pipeline (`raop/rtp.rs`) cannot be reused directly because it uses
AES-CBC encryption, not ChaCha20-Poly1305. The packet parsing and ALAC decoding
are reusable; the encryption layer and setup path are not.

Priority: Low. Only needed for non-music audio passthrough.

### AP2 Remote Control

Third-party AP2 receivers cannot send playback commands (play/pause/skip) to the
iPhone. See [AP2-REMOTE.md](AP2-REMOTE.md) for the full research.

All investigated paths require Apple ecosystem trust:
- **Type 130 MRP data channel**: requires `seed` from HomeKit pairing (Home app)
- **Companion-link protocol**: requires same Apple ID (`rapportd` always-on connection)
- **DACP**: iPhone doesn't send `Active-Remote` header in AP2 (iOS 18+)
- **Event channel**: one-way (server→client status updates only)

AP1 DACP remote control works and is fully implemented for AP1 sessions.

## Test Coverage

129 tests, 17 C-verified vectors from pair_ap reference implementation:
- TLV codec, HKDF-SHA512, ChaCha20 transport framing
- ADTS framing, audio packet decryption, server keypair
- Anchor time calculation, channel mixdown, SSRC mapping
- Full M1→M4 SRP integration test over real TCP

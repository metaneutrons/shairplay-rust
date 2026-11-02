# Golden-Vector Capture Plan

This crate is empirically verified against a real iPhone (pairing + playback work).
The vectors below are **regression anchors**: they lock in that known-good behavior so a
future refactor of the crypto/DRM internals can't silently break real-device interop.

A coverage audit found that the **encoding/framing layers are well-pinned** to authoritative
oracles (TLV8 ← `pair-tlv.c`, AES-CTR ← C `AES_ctr_encrypt`, ChaCha transport ← OpenSSL, ADTS ←
`addADTStoPacket()`, Digest, HKDF-SHA512 ← OpenSSL, Ed25519 ← libsodium, ALAC compressed ←
Apple `afconvert`). The gaps are at the **asymmetric-crypto / DRM / key-derivation handshakes** —
exactly where a byte mismatch breaks interop. This file lists, per gap, *what* to capture and *how*.

## Oracle types (in order of preference)

1. **Reproducible** — derivable right now with `openssl`/`afconvert`, no C build or device needed.
   Anyone can add these. Marked 🟢.
2. **Real-session capture** — capture inputs+outputs from a *successful* iPhone session. A value
   that produced working playback/pairing **is** proven correct (the iPhone accepted it / audio
   decoded), so it is a legitimate golden. Needs a one-time capture with trace logging. Marked 📱.
3. **C-reference capture** — instrument the C `shairplay`/`shairport-sync` source and printf the
   relevant function's I/O. Most faithful for the bespoke DRM. Marked 🔧.

## Conventions

- Put binary fixtures under `tests/data/<area>/` (see `tests/data/alac/` for the pattern, incl. a
  `gen_*.py`/`README` describing how each was produced).
- Add a `c_vector_*` / `golden_*` test that loads the fixture, calls the **production** function,
  and asserts the pinned output. Never re-implement the algorithm in the test (that was the
  `decrypt_rtp_chacha` mistake — fixed).
- Record provenance in a comment: tool + exact command, or "captured from iOS <ver> session, audio
  verified playing".

---

## Priority gaps

### 1. `RsaKey::sign_challenge` — AP1 Apple-Response 🟢 (reproducible)
Signs `challenge ‖ ip ‖ hwaddr` (zero-padded to 32 B) with PKCS#1 v1.5, **no** hash-OID prefix —
deterministic for a fixed key, so OpenSSL is an independent oracle.

```sh
# data = challenge_bytes || ip || hwaddr, zero-padded to 32 bytes (see sign_challenge)
printf '<32 raw bytes>' > data.bin
openssl pkeyutl -sign -inkey airport.key -pkeyopt rsa_padding_mode:pkcs1 -in data.bin \
  | base64 -w0       # -> expected Apple-Response (unpadded base64)
```
Test: `sign_challenge(b64_challenge, ip, hwaddr)` == that base64. Pin one vector with a fixed
challenge/ip/hwaddr.

### 2. `RsaKey::decrypt` — rsaaeskey OAEP-SHA1 🟢 (reproducible)
RSA-OAEP(SHA-1) decrypt that recovers the AP1 audio AES key. Build the input by encrypting a known
16-byte key with the airport **public** key:

```sh
openssl rsa -in airport.key -pubout -out airport.pub
printf '<16 known AES key bytes>' > aeskey.bin
openssl pkeyutl -encrypt -pubin -inkey airport.pub \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -in aeskey.bin | base64 -w0  # -> rsaaeskey
```
Test: `decrypt(rsaaeskey_b64)` == the 16 known bytes.

### 3. FairPlay key recovery — `FairPlay::decrypt` 📱 / 🔧 (highest value)
The whole DRM is currently pinned to golden vectors from the C reference on **pseudo-random** inputs
(`tests/data/fairplay_golden.txt`), not to a real session. One real `(keymsg_164B, ekey_72B) →
aes_key_16B` triple anchors the entire pipeline (MD5 variant, scrambling hash with the blender,
unwrap cipher, session key, constant tables).

- **📱 easiest, given your setup:** add `trace!` of the M2 `keymsg` (in `FairPlay::handshake`), the
  ANNOUNCE `ekey` (the 72-byte FairPlay-encrypted key), and the recovered `aes_key` (out of
  `FairPlay::decrypt`). Play audio from a real iPhone; if it **plays correctly**, the recovered key
  is provably right (the audio is AES-encrypted under it). Save the three hex blobs to
  `tests/data/fairplay/ios_session.txt`.
- **🔧 most faithful:** build the C reference separately (it is not part of this repository), print
  its inputs `message3` and `cipher_text` and the output `key`, then run any fp-setup.

Test: `let mut fp = FairPlay::new(); fp.handshake(&keymsg)?; assert_eq!(fp.decrypt(&ekey)?, aes_key);`

### 4. `video_key::derive_eaes_key` / `derive_stream_key_iv` 📱 (only if `video` used)
SHA-512 key/IV derivation for AP2 screen mirroring; no test today. Capture a working mirroring
session's `(shared_secret, stream_id) → (key, iv)` via trace logging, or pin against
SteeBono/openairplay `airplayreceiver`. Low priority unless mirroring is a target.

### 5. AP2 pair-setup SRP-6a (M1–M6) 📱 / 🔧
Self-tested only against a mock built from the same constants. Capture a real iOS pair-setup:
`(PIN, salt, B, A, M1) → (server proof M2, session_key)`. With trace logging on a successful pair,
pin: client `A` + proof `M1` ⇒ accepted, and the derived `session_key` ⇒ a subsequent M5 decrypt
succeeds. (RFC-5054 covers the raw SRP math but not HomeKit's SHA-512 + TLV framing, so a real
capture is more useful.)

### 6. `EncryptedChannel` HKDF — Control/Events keys 🟢 (reproducible)
Derive each direction with OpenSSL HKDF from a fixed `shared_secret` and the exact salt/info labels
the code uses (Control-Salt / Events-Salt / *-Read/Write-Encryption-Key):

```sh
openssl kdf -keylen 32 -kdfopt digest:SHA512 -kdfopt key:<hex> \
  -kdfopt salt:<label> -kdfopt info:<label> HKDF | tr -d ':'   # -> expected 32-byte key
```
Test each direction's derived key == expected; guards against a swapped read/write or salt.

---

## Secondary (codec stream variants)

- **ALAC 24-bit + `deinterlace_24`** 🟢 — all fixtures are 16-bit; add a 24-bit `afconvert` ALAC
  fixture (extend `tests/data/alac/gen_alac.py`) and bit-compare decoded PCM.
- **`AacDecoder::decode` (symphonia → PCM)** 🟢 — add an `afconvert`/iOS AAC frame → reference PCM
  fixture; only ADTS *framing* is pinned today, not decode output.
- **`VideoCipher` cross-packet keystream** 📱 — pin a multi-packet AES-CTR sequence to catch
  leftover-keystream-state bugs.
- **PTP/NTP timing** 🔧 — pin a real NQPTP `Follow_Up`/`Announce` packet and a legacy NTP timing
  exchange; the anchor-time *formula* is already C-pinned, but the parsers/call-sites aren't.

## Suggested order

1–2 and 6 are **🟢 do-now** (OpenSSL, no device). 3 and 5 are the **highest-value 📱 captures** and
cheap given a working iPhone — one fp-setup + one pairing session covers both. The rest are
nice-to-have per feature in use.

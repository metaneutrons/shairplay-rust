# `/auth-setup` Protocol Status

Last reviewed: 2026-09-06

This document describes receiver-side `POST /auth-setup` support and the
evidence available for implementing it. No public Apple endpoint specification
was found during this review. Claims below distinguish project facts,
externally verified behavior, and reverse-engineered information.

## Evidence Levels

| Level | Meaning |
|-------|---------|
| **Project fact** | Directly established by this repository's current source and tests. |
| **Source-verified** | Directly established by a pinned external implementation's source. This proves that implementation's behavior, not a universal protocol rule. |
| **Corroborated** | Consistent across Apple's public security description and multiple independent implementations or protocol notes, but not backed by a public Apple endpoint specification. |
| **Unknown** | Not established by public documentation, an authorized specification, or a successful real-device test. |

## Executive Conclusion

`/auth-setup` is a receiver-authentication exchange associated with MFi-SAP. It
is not synonymous with HomeKit `pair-setup`, `pair-verify`, or FairPlay
`fp-setup`. The endpoint can occur in classic RAOP compatibility flows and in
AirPlay 2 contexts, so classifying it as exclusively AP1 or AP2 is misleading.

shairplay currently neither implements `/auth-setup` nor advertises the
well-established `et=4` discovery value. Well-formed requests reaching route
resolution return `404`. Digest authentication runs first: when a password is
configured, missing or invalid authorization produces `401` instead. The
current advertised profiles do not intentionally invite this exchange:

- AP1 defaults to `et=0` and can explicitly advertise only `0`, `1`, or `3`.
- AP2 advertises `et=0,3,5`; `5` denotes FairPlay SAP 2.5, not MFi-SAP.
- The AP2 feature mask does not set bit 26 (`Authentication_8`) or bit 51
  (`SupportsUnifiedPairSetupAndMFi`) under the naming used by AirPlay 2
  Internals and OwnTone.

A manually configured PipeWire sender using
`raop.encryption.type=auth_setup` will nevertheless call the endpoint and abort
after shairplay's non-success response, as reported in
[#38](https://github.com/metaneutrons/shairplay-rust/issues/38). Supporting that
sender is a narrowly defined compatibility feature, not a complete MFi
implementation.

## What Is Established

### MFi-SAP purpose and primitives

**Corroborated.** Apple's public Platform Security guide states that AirPlay
uses an Apple authentication IC to verify approved receivers. It describes
MFi-SAP as using Curve25519 ECDH, an RSA-1024 signature from the authentication
IC, and AES-128-CTR. Apple does not identify `/auth-setup` or publish its wire
format on that page.

The receiver proves its identity to the sender. Returning success without an
MFi certificate and valid signature does not authenticate the receiver, even
when a particular sender accepts that response.

### Discovery values

**Corroborated.** PipeWire, pyatv, and other independent implementations map
the `_raop._tcp` `et` values as follows:

| Value | Commonly documented meaning | shairplay advertisement |
|-------|-----------------------------|-------------------------|
| `0` | No audio-payload encryption | AP1 default; AP2 profile |
| `1` | RSA session-key exchange | Optional AP1 mode |
| `3` | FairPlay | Optional AP1 mode; AP2 profile |
| `4` | MFi-SAP via `/auth-setup` | Not available |
| `5` | FairPlay SAP 2.5 | AP2 profile |

The exact sender-selection policy is not standardized publicly. Current
PipeWire checks for `5`, then `4`, then `1`, and otherwise chooses `0`; it does
not simply select the numerically highest value.

### Conflicting feature-bit names

The [OpenAirPlay feature table](https://openairplay.github.io/airplay-spec/features.html)
and [OwnTone's pinned feature map](https://github.com/owntone/owntone-server/blob/306a7332dedce7fccb7af03da9df935a7b7a6291/src/outputs/airplay.c#L410-L428)
use different names for the same numeric positions:

| Bit | OpenAirPlay | OwnTone and shairplay |
|-----|-------------|----------------------|
| 26 | `HasUnifiedAdvertiserInfo` | `Authentication_8` (MFi) |
| 30 | `RAOP` | `HasUnifiedAdvertiserInfo` |
| 51 | `SupportsUnifiedPairSetupAndMFi` | `SupportsUnifiedPairSetupAndMFi` |

OpenAirPlay's endpoint description refers to `HasUnifiedAdvertiserInfo` when
discussing MFi. Translating that name directly into shairplay's enum would select
bit 30 instead of bit 26. The current profiles set bit 30 and clear 26 and 51;
these numeric values are project facts. Their universal interpretation remains
reverse-engineered. Preserve numeric positions and source provenance when
comparing profiles, and require sender tests before changing advertisements.

### PipeWire behavior

**Source-verified** against PipeWire commit
[`b0b792f`](https://github.com/PipeWire/pipewire/commit/b0b792fa72451fd9a068c1a8f877d21d4c67cd3f):

1. Discovery maps `et=4` to `auth_setup` and `et=5` to `fp_sap25`.
2. `auth_setup` sends a fixed 33-byte body: `0x01` followed by a fixed 32-byte
   value.
3. Its response callback checks only for status `200`; it does not consume the
   response headers or body.
4. After `200`, PipeWire sends `ANNOUNCE`. In this mode that SDP has no
   `rsaaeskey` or `aesiv`, so the subsequent audio payload is unencrypted.
5. Any other status schedules destruction of the PipeWire RAOP sink.

These facts justify a PipeWire regression test. They do not establish that an
empty or truncated response is valid MFi-SAP, nor that other senders behave the
same way.

### Reverse-engineered wire format

**Corroborated, not normative.** The Unofficial AirPlay Specification describes
this standalone exchange:

- Request: one mode byte followed by the sender's 32-byte Curve25519 public
  key.
- Response: the receiver's 32-byte public key, a big-endian certificate length,
  a PKCS#7 DER MFi certificate, a big-endian signature length, and an encrypted
  signature.
- Signature input: receiver public key followed by sender public key.
- Signature protection: AES-128-CTR using key and IV material derived from the
  Curve25519 shared secret with SHA-1 and the labels `AES-KEY` and `AES-IV`.

The same source assigns request mode `0x01` to an unencrypted result and
`0x10` to an MFi-SAP-encrypted AES key. These byte-level details require either
an authorized Apple specification or real-device vectors before they can be
treated as conformant.

## Current Repository Status

| Area | Current behavior | Evidence |
|------|------------------|----------|
| RTSP routing | No `/auth-setup` route; `404` after the Digest check, otherwise `401` for missing/invalid required authorization | Project fact |
| AP1 discovery | Defaults to `et=0`; API exposes `0`, `1`, `3` only | Project fact |
| AP2 discovery | Fixed `et=0,3,5`; feature bits 26 and 51 are clear | Project fact |
| FairPlay | `/fp-setup` implemented separately | Project fact |
| HomeKit pairing | `/pair-setup` and `/pair-verify` implemented separately | Project fact |
| MFi certificate/signing | No provider API, certificate, or authentication-IC integration | Project fact |
| PipeWire forced `auth_setup` | Fails because PipeWire requires `200` | Source-verified consequence |
| Apple/MFi sender interoperability | Not tested | Unknown |

The draft implementation in
[#44](https://github.com/metaneutrons/shairplay-rust/pull/44) returns only an
ephemeral 32-byte X25519 public key. That is enough for the current PipeWire
status-only check, but it is not the corroborated MFi-SAP response structure: it
omits both lengths, the MFi certificate, and the encrypted signature. Its
ephemeral private key is also discarded, so no shared secret can be used
afterward. It must not be described or exposed as MFi authentication.

## Safe Implementation Boundaries

These are proposals for subsequent work; no compatibility feature or MFi
backend is implemented by this documentation change.

Two capabilities must remain separate in code, features, API, tests, and
documentation.

### PipeWire compatibility mode

A compatibility mode may acknowledge PipeWire's status-only probe without
claiming MFi authentication. Enterprise-grade constraints are:

- Disabled by default behind a clearly named compile-time feature such as
  `pipewire-auth-setup-compat`.
- Requires an explicit runtime builder policy; compiling the feature alone
  must not silently enable the route or advertise `et=4`.
- Keeps discovery unchanged initially. Manually configured PipeWire senders
  can use the enabled endpoint without `et=4`; advertising it requires a
  separate decision and interoperability tests because it affects other senders.
- Accepts only the documented PipeWire request shape and rejects malformed
  bodies deterministically.
- Returns an intentionally minimal response rather than a malformed object
  that resembles successful MFi authentication.
- Documents that audio is unencrypted and that the sender receives no proof of
  receiver identity.
- Emits no log or API state claiming authentication success.

The feature name should identify the tested interoperability target. Names such
as `mfi`, `mfi-auth`, or `auth-setup` alone would overstate its security and
compatibility properties.

### Conformant MFi-SAP mode

A real implementation requires a separate backend abstraction that can obtain
the MFi certificate and perform the authentication-IC signature operation. The
library must not embed accessory credentials. The protocol layer should own
strict parsing, framing, key derivation, secret zeroization, and response
construction; a provider trait should isolate hardware- or platform-specific
certificate and signing operations.

This mode must not be declared complete without authorized specification
review, independent cryptographic vectors, and successful negative and
positive tests against validating hardware.

## Required Regression Coverage

For a PipeWire compatibility implementation:

1. Feature absent: `/auth-setup` remains `404` after the Digest check and `et=4`
   cannot be advertised; required authorization still produces `401` when invalid.
2. Feature present but runtime policy disabled: the same fail-closed behavior.
3. Policy enabled: the exact current PipeWire 33-byte request receives `200`.
4. Missing body, wrong length, unsupported mode byte, and oversized body are
   rejected without panic or allocation abuse.
5. Existing AP1 and AP2 advertisements remain byte-for-byte unchanged. Any later
   opt-in `et=4` advertisement needs its own sender-selection regression tests.
6. A sender simulation proceeds through `ANNOUNCE`, `SETUP`, and `RECORD` with
   unencrypted audio after the compatibility acknowledgement.
7. Builds and tests cover default features, the compatibility feature, `ap2`,
   and their supported combination on macOS and Linux.

For conformant MFi-SAP, add parser and serializer boundary tests, independent
KDF/signature vectors, invalid-certificate and invalid-signature tests, and an
authorized real-device interoperability test.

## Unknowns and Open Questions

- No public Apple document found during this review specifies the endpoint URI,
  complete wire format, status codes, or discovery-bit semantics.
- Public feature-bit tables are reverse engineered. They should be treated as
  implementation guidance, not a stable standard.
- It is unknown which current Apple senders issue standalone `/auth-setup`,
  which validate its response, and which use unified pairing instead.
- It is unknown whether all validating senders accept the exact SHA-1 labels
  and framing documented by OpenAirPlay across protocol generations.
- The correct error status for each malformed request is not publicly
  specified.
- No successful `/auth-setup` exchange with validating MFi hardware has been
  captured for this repository.

## Sources

- [Apple Platform Security: Verifying accessories](https://support.apple.com/guide/security/verifying-accessories-sec70a4f377d/web) - public, authoritative for MFi-SAP purpose and cryptographic primitives; no endpoint wire format.
- [PipeWire RAOP Discover documentation](https://docs.pipewire.org/1.4/page_module_raop_discover.html) - official PipeWire configuration surface.
- [PipeWire discovery mapping](https://github.com/PipeWire/pipewire/blob/b0b792fa72451fd9a068c1a8f877d21d4c67cd3f/src/modules/module-raop-discover.c#L315-L330) - pinned implementation of `et` selection.
- [PipeWire `/auth-setup` request and callback](https://github.com/PipeWire/pipewire/blob/b0b792fa72451fd9a068c1a8f877d21d4c67cd3f/src/modules/module-raop-sink.c#L1270-L1312) - pinned sender behavior.
- [PipeWire `ANNOUNCE` construction](https://github.com/PipeWire/pipewire/blob/b0b792fa72451fd9a068c1a8f877d21d4c67cd3f/src/modules/module-raop-sink.c#L1191-L1267) - pinned encryption-mode behavior.
- [Unofficial AirPlay Specification: `POST /auth-setup`](https://openairplay.github.io/airplay-spec/audio/rtsp_requests/post_auth_setup.html) - detailed reverse-engineered wire format; not an Apple specification.
- [AirPlay 2 Internals: features](https://emanuelecozzi.net/docs/airplay2/features/) - reverse-engineered feature-bit names and conditions.
- [pyatv protocol documentation](https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md#raop) - independent reverse-engineered `et` value mapping.
- [OwnTone RAOP sender](https://github.com/owntone/owntone-server/blob/306a7332dedce7fccb7af03da9df935a7b7a6291/src/outputs/raop.c#L1634-L1698) - independent sender implementation that intentionally does not validate the response.

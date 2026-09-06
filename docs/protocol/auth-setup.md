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

### PipeWire password challenge limitation

**Source-verified behavior, inferred interoperability limitation.** The pinned
sender handles `401` in `rtsp_options_reply` by learning the challenge and
retrying `OPTIONS`. Its `/auth-setup` callback instead aborts on every non-200
status. shairplay currently exempts `OPTIONS` from Digest authentication and
challenges subsequent requests when a password is configured.

Consequently, enabling the compatibility acknowledgement alone is not expected
to make that sender work with a password-protected receiver. This is not a
reason to bypass Digest or change the existing `OPTIONS` policy in this work.
The first live qualification must distinguish a passwordless positive case
from the protected negative case. A synthetic client successfully answering a
Digest challenge proves server behavior, not PipeWire password interoperability.

Source: [PipeWire authentication callbacks](https://github.com/PipeWire/pipewire/blob/b0b792fa72451fd9a068c1a8f877d21d4c67cd3f/src/modules/module-raop-sink.c#L1270-L1412).

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

## First Compatibility Contract

This is the implementation contract for the first increment, **not implemented
endpoint behavior or a normative MFi-SAP specification**. The current-state
table above remains authoritative about what is shipped. Work and acceptance
evidence are tracked in [epic #62](https://github.com/metaneutrons/shairplay-rust/issues/62);
this document is the single behavioral specification, not a progress checklist.

### Activation and scope

The Cargo feature is `pipewire-auth-setup-compat`, excluded from defaults and
independent of `ap2`. A feature-gated builder policy defaults to disabled;
merely compiling the feature, including through Cargo feature unification, must
not activate the endpoint. There is no debug-build exception to these gates.

The first interoperability claim is an explicitly configured PipeWire sender
using classic RAOP, unencrypted PCM and the transport actually qualified in the
live test. The library stays platform-neutral. Compiling `ap2` does not imply
support for MFi or additional AP2 authentication flows. Existing AP1/AP2
advertisements and feature bits remain unchanged in every gate combination.

### Request and response

Only `POST /auth-setup` in origin form, without a query or fragment, is eligible
for the new handler. Other requests retain existing routing, including wildcard
`OPTIONS`; this rule must not introduce a new global routing policy.

The enabled endpoint requires exactly one decimal `Content-Length` declaring
33 bytes, no `Transfer-Encoding`, and one `Content-Type` whose media type is
`application/octet-stream` (ASCII case-insensitive, surrounding whitespace
allowed, no parameters). Its body must exactly match
[`tests/fixtures/pipewire-auth-setup.hex`](../../tests/fixtures/pipewire-auth-setup.hex).
The fixture contains the fixed probe from `rtsp_do_post_auth_setup` at PipeWire
commit `b0b792fa72451fd9a068c1a8f877d21d4c67cd3f`. It is source-derived data, not
a captured exchange, secret, credential or authenticated client identifier.

An enabled, authorized, matching probe receives `RTSP/1.0 200 OK`, the normal
`CSeq` and `Server` headers, explicit `Content-Length: 0`, and no body. The
handler creates no key material and changes no pairing, encryption, stream or
authentication state. It must not log authentication success. Repeated probes
are independent; later RTSP requests still go through their normal checks.

### Rejection and resource boundaries

| Condition | Contract |
|-----------|----------|
| Feature absent or runtime disabled; well-framed request passes Digest | Existing `404`, no compatibility acknowledgement |
| Bounded, otherwise valid request without valid required authorization | Existing `401` challenge, regardless of whether the compatibility policy is enabled |
| Enabled path with missing/invalid/duplicate length, transfer encoding, unsupported media type, wrong length/mode or any differing probe byte | `400`, no success payload, close the connection |
| Invalid generic HTTP/RTSP framing or global parser limit exceeded | Existing transport rejection takes precedence; no dispatch or success acknowledgement |
| Enabled probe body incomplete after its absolute body deadline | Close the connection and release the client slot; no success acknowledgement |

The error codes above are project policy, not an assertion about Apple's
unspecified error semantics. Endpoint size/framing rejection may happen before
Digest; the `401` guarantee applies to bounded, well-framed requests. Never
bypass required authorization to obtain `200`.

The enabled probe has a 33-byte body budget enforced once its headers are known,
before further body accumulation, including when a network read contains both
headers and body. Its body-completion deadline is five seconds after headers
complete; individual bytes must not reset it. Header/global limits still apply.
Bytes beyond a correctly framed body may belong to a pipelined next request:
do not count them as part of the probe or discard them on a successful request.
On early rejection, close rather than draining an unbounded declared body.

This is deliberately not a global 33-byte cap: legitimate larger requests on
other endpoints must remain supported. The shared parser's 32 MiB body limit
alone does not satisfy this enabled-endpoint budget. Header-arrival timeouts and other
pre-existing global transport limitations must not be described as fixed by a
probe-body deadline.

### Ingestion foundation (B)

The parser now retains at most 64 KiB of headers, independently of a coalesced
body. It rejects invalid or duplicate `Content-Length`, duplicate `Content-Type`
and all `Transfer-Encoding` values; it does not implement chunked decoding.
These framing checks apply to every request, including when compatibility is
disabled. An absent length still means no body unless a connection policy
requires one. The global body ceiling remains 32 MiB.

After parsing complete headers, the connection selects a `RequestBodyPolicy`
exactly once, before the parser retains any body bytes. This internal hook can
require header metadata, lower the body ceiling and set an absolute body deadline.
The same hook applies to plaintext, decrypted input and pipelined requests.
Framing/policy failures return `400` with `Connection: close`; body deadlines
close without a success response. No draining of a rejected body is attempted.

**Not yet enabled:** the production RAOP handler still uses the default policy
(32 MiB, no body deadline). `/auth-setup` remains absent. The 33-byte/five-second
policy is exercised by a test handler, not by a production route. Step C must
select it through the route's compile-time and runtime gates, implement the
remaining header/probe validation and retain existing Digest authorization.
This foundation does not duplicate routing or authentication in the transport.

The transport reads 4096-byte chunks. Encrypted input has a separate 1 MiB raw
buffer ceiling checked before copying; the existing cipher may materialize a
decrypted chunk before the request policy runs. Thus the per-request body ceiling
is not a claim that total connection memory is only 33 bytes. Following pipelined
bytes are retained separately from the current body. Header-arrival, idle and
response-write deadlines remain outside this change; an incomplete encrypted
frame before complete request headers does not start a body deadline.

### Test obligations

The fixture and baseline tests in `tests/integration/auth_setup.rs` establish
the source-derived probe, every request split and one-byte ingestion, pipelined response framing,
Digest precedence and unchanged discovery while the endpoint is absent. They
do **not** qualify the future enabled handler. Future production validation
must be tested against this independent fixture rather than importing the
implementation's expected probe constant as the test oracle.

The former failure at byte 18 of `POST /auth-setup RTSP/1.0` is covered by the
full split-point sweep. Parsing waits for complete headers and translates only
the request-line version; RTSP-like bytes in the URI, headers or body stay intact.
Parser regressions cover ordinary HTTP, invalid versions, framing ambiguity,
exact bounds and pre-body policy rejection. Transport regressions cover absolute
deadlines, real TCP client-slot release, large-body positive controls and the
existing AP2 control cipher with bytewise frame ingestion and encrypted replies.
The HTTP fuzz target compares whole-input and fragmented parsing. These are
mechanism tests, not evidence that PipeWire playback or AP2 `/auth-setup` works.

The implementation adds tests for feature/runtime gates, every rejection row,
byte mutations, lengths around 33, conflicting framing, repeated requests,
deadline/slot release, and unchanged larger requests. Exercise default,
compatibility-only, `ap2`, their combination and all features on the supported
platform matrix. A simulated sender must reach actual expected decoded samples
through `ANNOUNCE`, `SETUP`, `RECORD`, teardown and reconnect.

Only a real PipeWire run with recorded version, configuration and expected
audio establishes the supported live scope. Record password protection as a
negative case until separately proven otherwise; record David's external
confirmation or its absence. Neither a 200-only test nor this fixture closes
the original interoperability report. No complete MFi or broad Apple-device
claim follows from this milestone.

## Later MFi Regression Coverage

Beyond the compatibility test obligations above, conformant MFi-SAP needs
parser and serializer boundary tests, independent
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

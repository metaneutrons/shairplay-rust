# Real PipeWire Qualification

The endpoint contract lives in [auth-setup.md](auth-setup.md). This document
records work package [D / #65](https://github.com/metaneutrons/shairplay-rust/issues/65),
its reproducible test and its deliberately narrow interoperability target.

**Status: qualification blocked, not ready for merge or a compatibility claim.**
Short exploratory UDP runs delivered all three seconds of expected stereo audio
and reconnected successfully. Other runs lost source samples, including in the
release profile. The final regression uses 25 seconds of non-silent content to
exercise a complete sender ring-buffer wraparound. A partial success or a green
short run must not close #38 or #65. [Versioned aarch64 evidence](evidence/pipewire-1.6.7-aarch64/README.md)
records all five configurations: gate-only cases pass; all six positive-path
audio sessions fail. [#72](https://github.com/metaneutrons/shairplay-rust/issues/72)
tracks the remaining investigation; [draft #73](https://github.com/metaneutrons/shairplay-rust/pull/73)
contains this harness and is not ready for merge.

## Tested Configuration

| Property | Scope |
|----------|-------|
| Sender | Unmodified PipeWire 1.6.7, commit `3b2cb4fb037bf6033b87d3c87ee917b2f686d309` |
| Receiver | Classic AirPlay 1, compile-time compatibility feature plus explicit runtime opt-in |
| Transport | IPv4 loopback UDP; manual RAOP sink configuration |
| Sender codec | `raop.audio.codec=PCM`: uncompressed ALAC frames, `AppleLossless` SDP |
| Decoded audio | f32, stereo, 44100 Hz; exact S16 source values divided by 32768 |
| Security | Passwordless, unencrypted audio, no MFi receiver authentication |
| Lifecycle | Two connections using the same daemon and receiver, each with native `TEARDOWN` |
| Negative cases | Runtime off: 404; feature absent: 404; required password: 401 and sender abort |

This is not a desktop/WirePlumber, physical audio device, automatic-discovery,
network-loss, IPv6, resampling, AP2 or Apple/MFi-device qualification. David's
confirmation against the original #38 environment remains outstanding. The
existing native Linux/macOS tests and Windows cross-check remain in place.

## Reproduce

From a repository checkout with Docker available, run:

```sh
bash scripts/pipewire/run.sh
```

The script builds the pinned sender and runs default, compatibility-only,
AP2-only, combined AP2/compatibility, and release-profile compatibility builds.
With AP2 compiled, the receiver is explicitly configured for AirPlay 1. A clean
checkout is required for release evidence; exploratory dirty runs are marked as
such in the report. Generated JSON is placed in a unique directory under
`target/pipewire-qualification/`. Reports include `passed: false` and a precise
sample mismatch when audio validation fails; the script runs the remaining
configurations, exports all available reports and exits nonzero. CI runs the
same strict script on Linux x86_64, blocks merge on failure and retains these
reports as artifacts for 30 days, including failed qualification. Local validation uses
Linux aarch64 through Docker on macOS.

Normal `cargo test` does not launch PipeWire: the live test is Linux-only and
ignored unless explicitly requested. Its oracle/subprocess self-tests run
normally on Linux. No production dependency or public API is added.

The [Dockerfile](../../scripts/pipewire/Dockerfile) pins the Rust image digest,
PipeWire commit, source archive SHA-256 and direct Debian build-package versions;
Cargo uses `Cargo.lock`. Transitive Debian packages still come from live Bookworm
repositories, so this is not a bit-for-bit hermetic
image build. Evidence identifies the image, source, toolchain and runtime
package versions. Network access is allowed only during image/dependency
acquisition. The actual tests run without external networking, capabilities,
host audio devices or host PipeWire configuration, as UID 10001 with a read-only
root and repository mount. Private temporary sockets/configuration are deleted
and subprocesses are killed/reaped on success, failure or cancellation.

The script retains only two Docker build caches, `shairplay-pw-cargo` and
`shairplay-pw-target`, plus the built image. Per-run containers and the evidence
volume are removed on exit. Run one qualification script at a time per Docker
daemon, and avoid heavy concurrent workloads: this is a real-time audio test,
not a virtual-time simulation. Failures are not retried or silently tolerated.

## What Is Verified

The checked-in [sender configuration](../../tests/pipewire/pipewire.conf.in)
uses a dummy clock and explicit graph links, without a session manager.
`pw-cat` plays a generated 27-second WAV: one second of silence, 25 seconds
of deterministic non-silent stereo data, then one second of silence. The
preroll permits both graph channels to link; the postroll drains queued audio.
Every non-silent source sample must arrive in order and bit-exactly, with no
missing, duplicated, altered or swapped samples. Only surrounding silence may
vary. The oracle has independent corruption, truncation and channel-order tests.

A bounded RTSP observer forwards bytes unchanged. It checks the exact public
probe, empty acknowledgement, explicit success `Content-Length: 0`, matching
`CSeq`, `Server`, unencrypted `AppleLossless` SDP, and the successful ordered
`OPTIONS -> /auth-setup -> ANNOUNCE -> SETUP -> RECORD -> TEARDOWN` sequence.
After playback the harness sends PipeWire's native `Suspend` command, which
causes the sender to perform `TEARDOWN`; a second playback reconnects. Receiver
TXT records must remain unchanged. Audio must never initialize after rejection.

Reports contain versions, hashes, gate/profile flags, sanitized method/status
records, sample counts and cleanup/discovery assertions. They contain no raw
RTSP headers, SDP, network captures, sender identifiers, credentials or audio
recordings. The synthetic test password is not a credential. Failure diagnostics
are bounded local logs from this isolated synthetic environment.

## Open Findings

### UDP sample discontinuities

Full-payload checks failed intermittently in the initial three-second runs.
For example, one release run jumped from source frame 60075 to 60156, losing
80 stereo frames. Forcing `rtp.framecount=256` and a 256-frame graph quantum
did not reliably eliminate the problem: another run lost 18 frames. That
experimental configuration was removed; it is not a supported workaround.

The pinned [RAOP callback](https://github.com/PipeWire/pipewire/blob/3b2cb4fb037bf6033b87d3c87ee917b2f686d309/src/modules/module-raop-sink.c#L454-L520)
encodes only `iov[1]`. The [RTP audio producer](https://github.com/PipeWire/pipewire/blob/3b2cb4fb037bf6033b87d3c87ee917b2f686d309/src/modules/module-rtp/audio.c#L503-L575)
can provide two audio segments at ring-buffer wraparound and advances by the
entire packet length. Losing the second segment is a source-verified defect
consistent with the observed short gaps, but the exact causal link still needs
a packet-level trace or an independently tested upstream fix. Some failing
runs also reported late timers; neither all timing failures nor the receiver
can be ruled out from these observations alone.

The 25-second regression exceeds the sender's 4 MiB S16 stereo ring capacity.
Do not shorten the test, permit missing samples, retry until green, patch the
sender silently, or claim that one successful short run qualifies playback.

### Password protection

The same synthetic password is configured at both ends. PipeWire 1.6.7 receives
401 on `/auth-setup` and aborts without `ANNOUNCE` or audio. Its probe callback
does not perform the Digest retry implemented for `OPTIONS`. This is an
observed interoperability limitation, not permission to bypass authentication.

### TCP

An exploratory live TCP run reaches the RTSP sequence but delivers no decoded
audio and fails the exact-audio oracle. It is **not qualified**. In the pinned
[sender's `stream_send_packet`](https://github.com/PipeWire/pipewire/blob/3b2cb4fb037bf6033b87d3c87ee917b2f686d309/src/modules/module-raop-sink.c#L454-L520),
the TCP length is ORed into `out[0]` (encoded audio), while `tcp_pkt[0]` remains
`0x24000000`, declaring zero interleaved payload length. This is a source-verified
defect and a plausible explanation for the live failure, not a captured-wire
diagnosis. TCP also logs attempts to send UDP sync on an invalid descriptor.
Do not weaken the receiver's framing checks or change upstream source in this
qualification to manufacture a successful result.

For investigation, the same strict test can be run with
`QUALIFICATION_TRANSPORT=tcp bash scripts/pipewire/run.sh`; it is expected to
fail with this sender version; its reports retain the failure. The library's
synthetic raw L16 TCP tests do not override this
real-sender limitation.

### Version and codec boundaries

The earlier source review used commit `b0b792f` from 1.7.0 development. The live
test deliberately uses the 1.6.7 release instead. Neither evidence source
establishes behavior of every PipeWire version. Despite its name, this version's
`PCM` encoder is [uncompressed ALAC](https://github.com/PipeWire/pipewire/blob/3b2cb4fb037bf6033b87d3c87ee917b2f686d309/src/modules/module-raop-sink.c#L406-L442),
not the raw L16 codec used by the earlier simulated sender tests. Encrypted
audio, compressed ALAC modes and other sample formats remain outside this test.

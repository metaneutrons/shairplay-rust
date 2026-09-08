# Real PipeWire Qualification

The endpoint contract lives in [auth-setup.md](auth-setup.md). This document
records work package [D / #65](https://github.com/metaneutrons/shairplay-rust/issues/65),
its reproducible test and its deliberately narrow interoperability target.

**Status: qualified for the merged upstream source commit; no released fixed PipeWire baseline yet.**
The 25-second regression exercises a complete sender ring-buffer wraparound.
[Clean aarch64 evidence for PipeWire commit `bc7d1cba`](evidence/pipewire-upstream-bc7d1cba-aarch64/README.md)
records all five feature/profile configurations. The six passwordless UDP
sessions pass bit-exactly, including release and reconnect; the required 404
and 401 probes also pass. The commit is compiled as PipeWire 1.7.0 and contains
[PipeWire MR !2984](https://gitlab.freedesktop.org/pipewire/pipewire/-/merge_requests/2984),
but it was not in a release tag when tested. Local TCP and password candidates
are documented below. This establishes a narrow
source-commit qualification, not a released-baseline compatibility claim.

The [controlled before/after experiment](evidence/pipewire-iovec-aarch64/README.md)
remains the causal record: the unmodified 1.6.7 baseline fails all six audio
sessions, while the same matrix with the original scatter/gather patch passes
all six bit-exactly. Upstream merged that fix as part of `bc7d1cba`. TCP,
password playback and confirmation in the original desktop setup remain open.
[#65](https://github.com/metaneutrons/shairplay-rust/issues/65),
[#72](https://github.com/metaneutrons/shairplay-rust/issues/72), and
[draft #73](https://github.com/metaneutrons/shairplay-rust/pull/73) remain open
until a supported fixed PipeWire baseline is selected and qualified.

## Tested Configuration

| Property | Scope |
|----------|-------|
| Sender | PipeWire upstream merge commit `bc7d1cba6dee390beba0785e50935275d3f1d484` (compiled as 1.7.0); the historical 1.6.7 baseline is documented separately |
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

From a repository checkout with Docker available, run the historical 1.6.7
baseline with:

```sh
bash scripts/pipewire/run.sh
```

To reproduce the merged upstream source-commit qualification, run:

```sh
PIPEWIRE_VARIANT=upstream-merged bash scripts/pipewire/run.sh
```

The script builds the selected pinned sender and runs default, compatibility-only,
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

### Controlled sender experiment

The default remains the **unmodified baseline**. To test only the suspected
scatter/gather defect in the sender, run the same matrix separately:

```sh
PIPEWIRE_VARIANT=iovec-fix bash scripts/pipewire/run.sh
```

This applies the checked-in [candidate patch](../../scripts/pipewire/raop-iovec.patch)
to the same pinned source before compilation. It iterates every frame-aligned
audio iovec while retaining one ALAC header/end tag; it adds no allocation or
audio copy. Neither receiver code, waveform, graph configuration, test duration,
oracle nor feature matrix changes between variants. TCP framing and password
handling are deliberately untouched. This is a historical local diagnostic patch. The equivalent sender fix is
merged upstream, but the tested upstream source commit is not an official
PipeWire release.

Both images compile a [callback regression](../../scripts/pipewire/test-raop-iovec.c)
against the actual source, with AddressSanitizer and UndefinedBehaviorSanitizer.
It sends one contiguous 352-frame packet plus every possible frame-aligned
two-segment split, including empty head/tail, through the real callback and
`sendmsg` over a local datagram socketpair. Each datagram must be byte-identical
to the contiguous packet.
The build checks the exact expected baseline result (352 failures / 354 cases)
or patched result (zero failures). A compiler, sanitizer or unexpected test
failure stops the build; sanitizer failures use distinct exit codes. Recognizing
the known baseline defect here does **not**
convert failed live qualification to success.

Schema-2 reports add `pipewire.source`: variant, patch SHA-256 (null for baseline),
callback source SHA-256, regression source SHA-256 and regression counts.
Image tags, run directories and CI artifacts distinguish `baseline` from
`iovec-fix`. CI runs both without fail-fast, and neither is allowed to fail
silently. Historical schema-1 evidence remains unchanged. A patched success
establishes only the explicitly identified experimental combination; it must
not be reported as an unmodified 1.6.7 qualification pass.

The patch also passes `git apply --check` against 1.6.8
(`b741e0c74f5436f0c925f7741140db0efd32cf4e`) and the then-checked development
head (`b0b792fa72451fd9a068c1a8f877d21d4c67cd3f`). That historical result was
source applicability only. The minimal fix and reproducible callback/live tests
were submitted on 2026-09-06 as
[PipeWire MR !2984](https://gitlab.freedesktop.org/pipewire/pipewire/-/merge_requests/2984),
then merged as `bc7d1cba6dee390beba0785e50935275d3f1d484`.

The merged source commit includes the native `pw-test-raop-iovec` regression
that exercises the actual sender callback. On Linux aarch64 with ASan/UBSan and
`b_ndebug=true`, it passes all 354 cases; the existing
`pw-test-raop-rtsp-client` also passes. The same commit now passes the complete
live UDP matrix in [clean aarch64 evidence](evidence/pipewire-upstream-bc7d1cba-aarch64/README.md).
This is not evidence for a released PipeWire baseline.

Selection and qualification of a supported fixed sender baseline, and the
original desktop confirmation remain outstanding. #65, #72 and draft #73 stay
open; TCP and password playback are separate limitations.

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
uses a dummy clock and explicit graph links, without a session manager. It loads
`libpipewire-module-scheduler-v1` with `ifexists nofail`: PipeWire master
requires that graph scheduler, while the historical 1.6.7 image does not ship
it.
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
entire packet length. Losing the second segment is reproduced directly in the
sender callback for every split boundary. In the controlled 25-second live
comparison, fixing only this defect changes all six failures to bit-exact
passes. PipeWire merged the fix; the merged source commit also passes the same
strict live matrix. This establishes a causal sender defect for the tested
configuration; it does not rule out unrelated timing, network or receiver
defects. Some earlier exploratory runs also reported late timers.

The 25-second regression exceeds the sender's 4 MiB S16 stereo ring capacity.
Do not shorten the test, permit missing samples, retry until green, patch the
sender silently, or claim that one successful short run qualifies playback.

### Password protection

The same synthetic password is configured at both ends. PipeWire 1.6.7 receives
401 on `/auth-setup` and aborts without `ANNOUNCE` or audio. Its probe callback
does not perform the Digest retry implemented for `OPTIONS`. This is an
observed interoperability limitation, not permission to bypass authentication.

A separate [local password candidate](pipewire-auth-mr-draft.md), based on
`c73df14f`, now passes the strict matrix with
`PIPEWIRE_VARIANT=auth-fix QUALIFICATION_PASSWORD_PLAYBACK=1`.
[Five clean reports](evidence/pipewire-auth-c73df14f-aarch64/README.md) record six
protected and six passwordless bit-exact UDP sessions, including release and
reconnect. The sender retries `/auth-setup` once with the correct Digest URI;
missing and incorrect credentials still fail closed. This candidate remains
local and does not include the independent TCP patch or establish a supported
fixed release baseline.

### TCP

The TCP framing defect is now reproduced against upstream master
`c73df14f03e30c41f6430acd82c6250dcdb168d8`. The sender writes the packet length
into the first ALAC payload word while the interleaved prefix declares zero
length. An extension of the native callback regression fails all 353 TCP cases
on unmodified master and passes all 707 UDP/TCP cases with the small header fix.

The [local before/after evidence](evidence/pipewire-tcp-c73df14f-aarch64/README.md)
records the strict matrix: the unmodified sender fails all audio configurations;
the fixed sender passes all five configurations and six bit-exact TCP sessions,
including release and reconnect. These are separate, explicitly patched sender
variants (`tcp-baseline` and `tcp-fix`), selected with
`QUALIFICATION_TRANSPORT=tcp`. The original baseline remains unchanged.

A [local MR draft](pipewire-tcp-mr-draft.md) is ready for review. The branch and MR
have not been sent upstream. Supported-release and x86_64 TCP qualification,
password playback and original desktop confirmation remain outstanding. TCP
also attempts UDP sync on an invalid descriptor; this framing fix does not
change synchronization or partial-write handling.

### Version and codec boundaries

The historical comparison used PipeWire 1.6.7; the merged UDP qualification
uses `bc7d1cba`, and the local TCP comparison uses `c73df14f` plus the explicitly
identified patch. These results do not establish behavior of every PipeWire
version. Despite its name, this version's
`PCM` encoder is [uncompressed ALAC](https://github.com/PipeWire/pipewire/blob/3b2cb4fb037bf6033b87d3c87ee917b2f686d309/src/modules/module-raop-sink.c#L406-L442),
not the raw L16 codec used by the earlier simulated sender tests. Encrypted
audio, compressed ALAC modes and other sample formats remain outside this test.

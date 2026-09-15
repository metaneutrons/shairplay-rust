# Final combined candidate qualification — 2026-09-08

Both native Linux architectures (aarch64 and x86_64) pass all five feature/profile
configurations for each UDP/TCP transport setting: **20 reports, 68 scenarios and 48 bit-exact
audio sessions**, split evenly between matching-password and passwordless
playback. Every second session reconnects; all native TEARDOWN checks pass.
Missing/incorrect passwords produce no audio with bounded 401 responses, and
feature/runtime gates remain 404. All three native tests pass with ASan/UBSan
on both architectures, including 707 packet cases with zero failures. Default
and AP2-only builds exercise UDP 404 gates; compatibility, combined and release
builds provide the selected transport’s audio sessions.

| Native Linux architecture | Transport | Feature/profile builds | Exact audio sessions | Result |
|---|---|---:|---:|---|
| aarch64 | UDP | 5 | 12 | Passed |
| aarch64 | TCP | 5 | 12 | Passed |
| x86_64 | UDP | 5 | 12 | Passed |
| x86_64 | TCP | 5 | 12 | Passed |

The unedited reports are under `final/`; complete run logs are included in the
reproduction package. `provenance.json`
records the clean receiver revision, exact independent and combined candidate
commits, source/patch/test hashes, per-transport image IDs and native execution
environments. ARM64's cached BuildKit exports have different attestation/index
IDs but the identical image manifest and config. Native sanitizer logs and the
independent review record are retained alongside the reports.

- Base: `c73df14f03e30c41f6430acd82c6250dcdb168d8`.
- TCP candidate: `ddf13a8c6c15d273d3a8f3deaa9be195d2744a94`.
- `61446aa7c72341fec9b64dbea666395c9c4438e1`: authentication candidate.
- Combined tested tree: `bc1550df93fc87e43959c3248872e3898c7cd624`.
- Receiver/test revision: `ced748a8fbd9d5b3a8ff2c9513139d5a4d508f40`.

The [reproduction package](https://gitlab.freedesktop.org/-/project/4753/uploads/b8f28728edc5f040b3ac70cad3d9e7be/pipewire-raop-pre-submission-20260908.tar.gz)
contains those reports plus independent/combined patches, historical baseline
evidence, a checksum manifest, a verification script, and an offline Git bundle
of the exact test checkout. Its README gives native and live reproduction
commands without relying on an unpublished GitHub branch. The public download
returns HTTP 200 and matches SHA-256
`a190cd478a63600faabc43aa8dae19fb30c21a9e59b4e2dd0dc0830d21531cc2`.
The candidates are submitted as [TCP !2987](https://gitlab.freedesktop.org/pipewire/pipewire/-/merge_requests/2987)
and [authentication !2988](https://gitlab.freedesktop.org/pipewire/pipewire/-/merge_requests/2988).

The Basic scheme error was exposed by the new native OPTIONS regression; the
independent reviewer identified the OPTIONS error-path stall. Both were fixed
before these final live runs. The reproduction package records their failure
and recovery logs under `review/`; `review.md` records the independent
resolution review. Earlier combined runs
were superseded after the OPTIONS fix and are not included in `final/`.

The packet verifier confirms all 20 reports, 68 scenarios and 48 sessions and
matches them to the current source/test hashes. Applying both independent
patches to the base reproduces the exact combined Git tree; an offline clone of
the supplied bundle is clean and includes the exact combined patch.

Coverage remains classic RAOP, uncompressed ALAC, unencrypted audio and IPv4
loopback; AP2-enabled builds use AirPlay 1 mode. Basic is tested by the native
protocol regression, while live password authentication uses Digest. TCP
backpressure/short writes, MFi/encrypted playback and the original desktop setup
are outside these runs. Select a supported fixed PipeWire baseline and rerun
the strict matrix before claiming released compatibility. PR #73 remains draft
and issues #65/#72 remain open until qualification and desktop confirmation.


Both official merge-request pipelines pass with all 62 jobs successful:
[TCP pipeline 1742474](https://gitlab.freedesktop.org/metaneutrons/pipewire/-/pipelines/1742474)
and [auth pipeline 1742477](https://gitlab.freedesktop.org/metaneutrons/pipewire/-/pipelines/1742477).
`publication.json` records the final open MR states, exact source heads, pipeline
results and public attachment identity. Initial push pipelines were rejected by
freedesktop runner gating before build/test execution; the official MR pipelines
completed normally without changing the patches or runner permissions.

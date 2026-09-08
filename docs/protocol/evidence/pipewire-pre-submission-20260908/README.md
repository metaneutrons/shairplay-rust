# Final combined candidate qualification — 2026-09-08

Both native Linux architectures (aarch64 and x86_64) pass all five feature/profile
configurations over both UDP and TCP: **20 reports, 68 scenarios and 48 bit-exact
audio sessions**, split evenly between matching-password and passwordless
playback. Every second session reconnects; all native TEARDOWN checks pass.
Missing/incorrect passwords produce no audio with bounded 401 responses, and
feature/runtime gates remain 404. All three native tests pass with ASan/UBSan
on both architectures, including 707 packet cases with zero failures.

| Native Linux architecture | Transport | Feature/profile builds | Exact audio sessions | Result |
|---|---|---:|---:|---|
| aarch64 | UDP | 5 | 12 | Passed |
| aarch64 | TCP | 5 | 12 | Passed |
| x86_64 | UDP | 5 | 12 | Passed |
| x86_64 | TCP | 5 | 12 | Passed |

The unedited reports and complete run logs are under `final/`. `provenance.json`
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

The local reproduction package `pipewire-raop-pre-submission-20260908.tar.gz`
contains those reports plus independent/combined patches, historical baseline
evidence, a checksum manifest, a verification script, and an offline Git bundle
of the exact test checkout. Its README gives native and live reproduction
commands without relying on an unpublished GitHub branch. Publication references
will be recorded when the upstream MRs are created.

The Basic scheme error was exposed by the new native OPTIONS regression; the
independent reviewer identified the OPTIONS error-path stall. Both were fixed
before these final live runs. `review/` records their failures and correction;
`review.md` records the independent resolution review. Earlier combined runs
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

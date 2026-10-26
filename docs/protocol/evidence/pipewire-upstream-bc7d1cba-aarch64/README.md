# PipeWire upstream merge commit: Live Qualification

Recorded on 2026-09-07 using clean receiver/test revision
`509f6d3fc82601f05a046a5d71a741e4e1f06488` on Linux aarch64 through Docker.
The sender is PipeWire upstream merge commit
`bc7d1cba6dee390beba0785e50935275d3f1d484` (compiled as 1.7.0). That commit
contains PipeWire MR !2984 and is on `master`; it was not contained in a release
tag when this evidence was recorded.

| Report | Result |
|--------|--------|
| [default.json](default.json) | Compatibility feature absent: required `404`, no audio |
| [compat.json](compat.json) | Required `404` and `401` negatives; two passwordless UDP sessions pass bit-exactly |
| [ap2.json](ap2.json) | AP2 compiled without compatibility: required `404`, no audio |
| [combined.json](combined.json) | AP2 compiled with explicit AirPlay-1 compatibility: two UDP sessions pass bit-exactly |
| [release.json](release.json) | Optimized compatibility build: two UDP sessions pass bit-exactly |

All six passwordless UDP sessions complete `OPTIONS`, `/auth-setup`,
`ANNOUNCE`, `SETUP`, `RECORD`, `SET_PARAMETER`, and `TEARDOWN`; each delivers
the 1,102,500 non-silent stereo source frames in order. Each compatibility run
also verifies the protected `401` probe, where PipeWire aborts before audio.
The native upstream Meson regressions pass: `pw-test-raop-iovec` finds zero
failures across 354 cases and `pw-test-raop-rtsp-client` passes.

This is source-commit evidence, not a qualification of a released PipeWire
baseline. TCP playback, password-protected playback, desktop/WirePlumber setup
and confirmation in the original #38 environment remain outside this result.

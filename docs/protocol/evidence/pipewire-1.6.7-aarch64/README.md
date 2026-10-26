# PipeWire 1.6.7: Failed Live Qualification

Recorded on 2026-09-06 using receiver/test revision
`311a4fd2956d81e6330f39df7fd82576ae8d6cf3` on Linux aarch64 through Docker.
These are unedited generated reports, not golden expected-pass fixtures.
They deliberately retain the failure evidence for [#72](https://github.com/metaneutrons/shairplay-rust/issues/72).

| Report | Result |
|--------|--------|
| [default.json](default.json) | Required 404 without compatibility feature; no audio |
| [ap2.json](ap2.json) | Required 404 with AP2 compiled but no compatibility feature; classic receiver mode |
| [compat.json](compat.json) | 404/401 negatives and control lifecycle pass; exact audio fails on both connections |
| [combined.json](combined.json) | Same failures with AP2 and compatibility compiled together, classic receiver mode |
| [release.json](release.json) | Same failures in optimized release profile |

All six positive-path sessions reached native teardown, but all failed the
25-second exact-payload comparison. A `passed: true` in a gate-only report is
not a playback qualification. The script exited 1, exported all five reports
and removed its per-run containers/evidence volume.

The subsequent infrastructure hardening pins the direct Debian package versions
that this image already used and replaces manual temporary-directory management
with `tempfile`. These reports retain their original revision/image provenance;
they must not be relabelled as results of a newer checkout. See CI artifacts for
later runs and [the methodology](../../pipewire-qualification.md) for limitations.

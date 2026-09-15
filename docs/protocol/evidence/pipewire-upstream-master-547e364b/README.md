# Unmodified upstream-master qualification — 2026-09-08

PipeWire upstream commit
[547e364b247636a4ea091afe07773ec035b7ecfc](https://gitlab.freedesktop.org/pipewire/pipewire/-/commit/547e364b247636a4ea091afe07773ec035b7ecfc)
contains all three RAOP fixes:

- ring-buffer wrap handling, bc7d1cba;
- TCP interleaved-frame length handling, ddf13a8c;
- password-protected /auth-setup, ending at ded91963.

The sender is unmodified: every report records a null patch SHA-256 and a
clean receiver worktree. The pinned source archive SHA-256 is
0c664bfd2b68ba90d08f92ed07cbc9cb7fb1994fd237d6115b60463e0c8e749b.

Both native Linux architectures completed five feature/profile reports for each
selected transport setting: **20 passing reports, 68 scenarios, and 48
bit-exact 25-second audio sessions**. The default and AP2-only configurations
exercise the UDP 404 gate. Compatibility-only, combined and release
configurations each include passwordless and Digest-protected playback over the
selected UDP or TCP transport, with teardown and reconnect. Missing and
incorrect passwords fail closed with bounded 401 responses and no audio.

| Architecture | UDP reports | TCP reports | Exact audio sessions |
|---|---:|---:|---:|
| aarch64 | 5 | 5 | 24 |
| x86_64 | 5 | 5 | 24 |

The image build runs PipeWire's iovec, RTSP-client and auth regressions under
ASan/UBSan before the live matrix. The resulting packet regression records
707 cases with zero failures, and the reports record the auth regression as
passed.

Reproduce the two transports serially from this receiver revision:

~~~sh
PIPEWIRE_VARIANT=upstream-master QUALIFICATION_PASSWORD_PLAYBACK=1 QUALIFICATION_TRANSPORT=udp bash scripts/pipewire/run.sh
PIPEWIRE_VARIANT=upstream-master QUALIFICATION_PASSWORD_PLAYBACK=1 QUALIFICATION_TRANSPORT=tcp bash scripts/pipewire/run.sh
~~~

This is qualification of an identified development commit, not of a supported
PipeWire release or maintenance backport. It also does not substitute for
confirmation in the original desktop setup or validate MFi/encrypted playback.

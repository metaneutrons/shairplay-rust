# Local TCP framing preparation — Linux aarch64, 2026-09-08

This is a local before/after experiment against PipeWire master
`c73df14f03e30c41f6430acd82c6250dcdb168d8`, retrieved on 2026-09-08.
The source archive SHA-256 is
`9f8d2b0f8d034a3ee4c19192a33e3a36daaeedf677a764c347b55c8cd33dc854`.
The candidate is local PipeWire commit
`ddf13a8c6c15d273d3a8f3deaa9be195d2744a94` on `fix/raop-tcp-framing`.
No branch was pushed and no upstream MR was submitted.

## Native regression

The existing `pw-test-raop-iovec` now captures TCP framing as well as UDP output.
It compares the `$`, channel and network-order length prefix and every byte of
the RTP/ALAC payload against the UDP reference for all 353 frame-aligned splits.
Datagram socketpairs preserve each callback output for inspection; this native
test does not simulate TCP segmentation or backpressure.

| Sender | Native cases | Failures | Existing RTSP client test |
|---|---:|---:|---|
| Unmodified c73df14f plus new test | 707 | 353 | Pass |
| c73df14f plus TCP fix and test | 707 | 0 | Pass |
| Fixed, ASan/UBSan, `b_ndebug=true` | 707 | 0 | Pass |

The fix moves the length into the TCP prefix and stops modifying the first
encoded payload word. Production scope is only that header construction.

## Strict live matrix

Reproduce the two sender variants serially:

```sh
PIPEWIRE_VARIANT=tcp-baseline QUALIFICATION_TRANSPORT=tcp bash scripts/pipewire/run.sh
PIPEWIRE_VARIANT=tcp-fix QUALIFICATION_TRANSPORT=tcp bash scripts/pipewire/run.sh
```

The baseline leaves production source untouched and applies only the new native
test. Its image build accepts precisely the known 353 native failures; this does
not make a failed live run pass. The fixed image applies the complete
`raop-tcp.patch`. Source, archive, patch and native-test hashes are in each report.
Receiver code, waveform, exact-audio oracle, graph, duration and profile matrix
are identical. Feature-absent/runtime-off 404 and password-protected 401 probes
continue to run over UDP; successful playback uses real TCP.

Baseline reports in `baseline/` are unedited exploratory JSON with
`working_tree_dirty: true`, because the variant scripts were being prepared.
Default and AP2-only gate checks pass. Compatibility and combined configurations
each record two sessions with zero decoded audio. Release also records zero
audio in its first session, then loses the control connection and times out
waiting for the sink during reconnect. It exits before JSON export; the exact
failure excerpt is retained in `baseline/release-failure.txt`. There is no
release JSON and this run must not be described as six completed sessions.

All five fixed configurations pass. Compatibility, combined and release each
complete two TCP sessions with exactly 1,102,500 non-silent stereo frames in
order and bit-for-bit intact. Each session includes native TEARDOWN and the
second session reconnects to the same receiver and daemon. Default/AP2-only
404 gates and the existing protected 401 rejection also pass.

The unedited `fixed/` reports identify clean receiver/test revision
`e81e0a17112a08e85f0007c6244e01b2529febbb` (`working_tree_dirty: false`).
They establish the local candidate's TCP behavior on Linux aarch64, including
the release profile; no CI or x86_64 TCP run was triggered.

## Scope

This experiment is not release qualification or upstream acceptance. Supported
fixed-baseline selection, original desktop confirmation, password playback and
Linux x86_64 live TCP qualification remain outstanding. PR #73 remains draft;
issues #65/#72 remain open. The separate password work must retain Digest
verification and fail closed for missing or incorrect credentials.

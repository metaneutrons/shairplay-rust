# Local password playback preparation — Linux aarch64, 2026-09-08

This qualifies the production change in local PipeWire commit
`a64092b4589e202403331c2d312dfc30044ba142`, branch
`fix/raop-auth-setup-digest`, based on upstream master
`c73df14f03e30c41f6430acd82c6250dcdb168d8`.
Master was checked again after testing and still pointed to that base.
The branch and MR have not been sent upstream. This candidate is independent
of the TCP framing change and the live password test uses UDP.

## Result

All five feature/profile configurations pass. Compatibility, combined AP2/compat
(in classic AirPlay 1 mode) and release each run two protected sessions plus two
passwordless sessions: **six protected and six passwordless sessions**, each
with exactly 1,102,500 non-silent stereo frames in order and bit-for-bit intact.
Every second session reconnects to the same receiver and daemon; each session
includes native TEARDOWN.

| Case | Observed auth-setup statuses | Audio |
|---|---|---|
| Feature absent or runtime disabled | 404 | None |
| Receiver protected, sender password absent | 401, then disconnect | None |
| Incorrect sender password | 401, 401, then disconnect | None |
| Matching password, each connection | 401, 200 | Bit-exact, twice |
| Passwordless, runtime enabled | 200 | Bit-exact, twice |

The receiver still validates Digest independently for every authenticated
request. The wire observer checks the exact 33-byte body on both POSTs, response
framing, the bounded retry and the ordered ANNOUNCE/SETUP/RECORD/TEARDOWN flow.
No receiver production code changed. The strict waveform, oracle and 25-second
non-silent duration remain unchanged.

## Evidence and provenance

The five unedited JSON reports identify clean receiver/test revision
`867a18a422427e54ab4f552a1994edf3535c858e` and
`working_tree_dirty: false`. The live-tested patch SHA-256 is
`de71a30ceee1c95bb9e35da1e96d20bc2136d029edf4cb1a9b155808374a2e52`.
That revision retains the exact original patch used for the run.

After the live run, only the native regression was strengthened: it now checks
ANNOUNCE's new Digest, observes scheduled destruction through a test seam and
covers repeated 401 plus missing/malformed/unsupported challenges. The final
checked-in patch SHA-256 is
`b9c3eba2f53d60767b736f4bd46e6354b22ebc004355f3634ecafb59a7d07b76`;
its native auth-test SHA-256 is
`d1795ee0f92795c3e3f28f6e7325fe89c7f1d2b063730a0b9008dba5243fd56b`.
The final Docker image is rebuilt and its three native tests pass. A second live
run is not claimed for that test-only refresh.

The production callback SHA-256 is identical in the live image, all reports,
and the final PipeWire candidate:
`9b8ca2e26e7fa8fd6ef9bc7e837262107d210f483d6e036434ec04c2ec5bfb0f`.
Both variants use source archive SHA-256
`9f8d2b0f8d034a3ee4c19192a33e3a36daaeedf677a764c347b55c8cd33dc854`.

## Native before/after

The final `pw-test-raop-auth` uses real loopback RTSP I/O and an independent
EVP-based Digest calculation. Only module-destruction scheduling is intercepted,
so rejected states can be observed without creating a full module. Actual
module teardown is exercised by the live negative cases.

The same final native regression compiles against unmodified c73df14f and fails
at `destroy_count == 0`: the sender schedules destruction on the first 401
instead of sending the authenticated POST. This is an assertion failure, not
a null-module crash. With the candidate it passes successful retry/ANNOUNCE,
repeated rejection, missing challenge, malformed Digest, unsupported scheme and
missing password. Native auth, existing iovec (354 cases) and RTSP-client tests
all pass with ASan/UBSan and `b_ndebug=true`. Summaries are retained in
`native-master.txt` and `native-fixed.txt`.

The new live password oracle also fails against unmodified master because the
second authenticated POST is absent (`live-master-failure.txt`). The earlier
TCP baseline reports contain the matching-password 401-and-abort observation.
No successful baseline password playback is implied.

## Reproduce and scope

```sh
PIPEWIRE_VARIANT=auth-fix QUALIFICATION_PASSWORD_PLAYBACK=1 bash scripts/pipewire/run.sh
```

The default qualification mode preserves the historical 401-and-abort
expectation; use the explicit password-playback flag with the authenticated
candidate. Testing covers classic RAOP, uncompressed ALAC, unencrypted audio
and IPv4 loopback UDP on Linux aarch64. The TCP candidate and password candidate
were qualified independently; their combined behavior has not been claimed.
No x86_64 CI or original desktop test was triggered. Supported release/backport
selection and qualification remain outstanding; PR #73 stays draft and issues
#65/#72 stay open.

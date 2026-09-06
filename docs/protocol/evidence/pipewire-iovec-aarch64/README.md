# Controlled PipeWire Scatter/Gather Experiment

These are unedited generated reports from two sequential Linux aarch64 Docker
runs against clean receiver revision
`1f757f399aacb8c14f787d063bd986c414e18436` on 2026-09-06:

- `baseline/`: `shairplay-pw-baseline-20260906T120528-68607`, exit 1.
- `iovec-fix/`: `shairplay-pw-iovec-fix-20260906T120837-70498`, exit 0.

Both use the same pinned PipeWire 1.6.7 archive, receiver, synthetic WAV, sender
configuration template, compiler and runtime package versions. The only sender
source difference is the explicit [candidate patch](../../../../scripts/pipewire/raop-iovec.patch).
Each JSON identifies its own container image, callback source, patch (null for
baseline), regression source, feature/profile flags and full RTSP lifecycle.
These historical reports identify the tested revision, not a later documentation
or build-wrapper revision.

| Check | Unmodified baseline | Explicit iovec fix |
|-------|---------------------|--------------------|
| Actual callback datagrams: contiguous plus all 353 split positions | 352 failures / 354 cases | 354 / 354 pass |
| Feature absent / runtime disabled | 404, no audio | 404, no audio |
| Password required | 401, sender abort, no audio | 401, sender abort, no audio |
| Compatibility-only, two connections | Both audio comparisons fail | Both bit-exact |
| AP2 compiled, explicit AP1 mode, two connections | Both audio comparisons fail | Both bit-exact |
| Release compatibility, two connections | Both audio comparisons fail | Both bit-exact |
| Native teardown, session cleanup, unchanged discovery | Pass | Pass |

Every positive session must deliver all 1,102,500 non-silent stereo frames in
order. No retries, sample tolerances or duration changes were used. The callback
regression uses the actual pinned C implementation under ASan/UBSan, not a copy
of its encoder. The live receiver independently decodes the sender's
uncompressed ALAC and compares every expected sample.

The independent Linux x86_64 [CI run 34032100890](https://github.com/metaneutrons/shairplay-rust/actions/runs/34032100890)
reproduces the same six baseline failures and six patched passes. Its reports
identify GitHub test-merge revision `88b55f089deb312f94c256a9af31bbd7734c90c7`
for PR head `1f757f3`; they are available in the separate baseline/iovec-fix
artifacts for 30 days. The local reports here have not been relabelled as CI runs.

The result confirms the ignored second iovec as a causal sender defect in this
configuration. It does not qualify unmodified PipeWire 1.6.7, TCP, password
playback, physical devices, other sender versions or MFi authentication. The
upstream patch has not been submitted or accepted. See the
[qualification document](../../pipewire-qualification.md) and
[#72](https://github.com/metaneutrons/shairplay-rust/issues/72) for remaining work.

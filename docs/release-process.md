# Release qualification and recovery

The release identity is the immutable tag and its exact commit. Cargo's package
version and the Release Please manifest must match the tag's version core.
Production tags are `vX.Y.Z`. Historical `shairplay-v*` tags remain unchanged;
both namespaces are protected against updates and deletion. Display titles and
release-note links may be corrected independently of the tag.

Stable releases from `0.9.0` onward contain the exact `.crate` package and its
`SHA256SUMS`. Older releases have release notes and GitHub-generated source
archives, but no separately uploaded crate assets. A source archive is not the
same artifact as the package on crates.io. Test-prerelease artifacts likewise
must not be substituted for a historical registry package.

## Local gates

Run these before creating any qualification tag:

```bash
bash scripts/release/tests/verify-metadata.sh
bash scripts/release/tests/verify-candidate.sh
bash scripts/release/tests/verify-registry.sh
actionlint
```

The identity tests use an isolated Git repository and real lightweight and
annotated tags. They check version syntax, commit and checkout identity,
manifest agreement, and the boundary between prerelease and build metadata.
Candidate and registry tests include corrupted payloads, invalid inventories,
missing versions, transport failures and bounded exhaustion. None publishes.

On the clean candidate commit, also run:

```bash
cargo package --workspace --locked
cargo publish --workspace --locked --dry-run
```

## Non-publishing qualification

After the exact candidate commit passes PR CI, create a new qualification tag
whose core equals the current manifest version and whose suffix is
`repo-standard-test.N`. Check remote tags first; never reuse or move a test tag.
Creating it is an explicitly authorized, permanent public mutation, not a
temporary cleanup operation.

Dispatch `release.yml` at that tag with `verify-registry=true`. The workflow
must verify the tag identity, package the candidate, obtain a short-lived
crates.io credential in the `release` environment, and publish only a GitHub
prerelease. The `publish-crate` and `promote` jobs must be skipped. Read back the
complete asset inventory and compare the downloaded archive and checksum file
byte-for-byte with the candidate. Verify that the existing stable/latest
release and its assets are unchanged.

A successful test-prerelease qualifies those stages, but does not prove an
actual registry upload or stable promotion. Only the next explicitly approved
production release can complete that end-to-end evidence. Record the exact
commit, tag, workflow run, artifact checksum and comparison results in the
change PR. A green ordinary CI run is not a substitute for a release run.

## Production qualification

Release Please creates the production tag and draft; do not create either by
hand. After merging the reviewed release PR, follow the exact dispatched run.
Success requires all production stages, a non-yanked Cargo index entry with the
candidate checksum, matching public package bytes, and GitHub stable/latest
pointing at that same release. Record this evidence with the release PR.

## Recovery after a partial publication

Stop before retrying. Read the exact failed run, tag commit, draft/public state,
candidate artifact inventory and Cargo index entry. Never infer absence from a
failed request or replace public assets to make a checksum check pass.

1. If no crate is published, resolve the failed gate first. A public prerelease
   is not authorization to upload an unverified package. The workflow rejects
   already-public releases; do not bypass that guard or automatically rerun
   the publication path.
2. If the version exists on crates.io, do not publish it again. Verify the
   crate name, version, `yanked=false` and checksum through the Cargo index.
   Download the immutable registry archive and compare it byte-for-byte with
   both the original CI candidate and the GitHub asset. Check the package's
   `.cargo_vcs_info.json` against the release-tag commit as well.
3. A missing candidate, mismatched byte, unexpected source commit, yanked entry
   or unverified registry response blocks recovery. Do not rewrite a tag,
   replace assets, or claim the release is qualified.
4. Only after those checks and explicit operator authorization, promote the
   existing verified GitHub prerelease without modifying its tag or assets.
   Read back `draft=false`, `prerelease=false`, the latest-release tag, and the
   unchanged asset inventory and digests.
5. Document the failed run, reason, original candidate identity, comparison
   evidence and manual action. The historical run remains failed; a manual
   recovery does not make it a successful automated qualification. Repair the
   pipeline through a reviewed PR and qualify its next release separately.

The `0.9.0` recovery is documented in
[release PR #56](https://github.com/metaneutrons/shairplay-rust/pull/56#issuecomment-5555439885).
The upload succeeded; a subsequent request to the crates.io website API failed
with HTTP 403. Registry verification now uses Cargo's sparse index and bounded
read retries. Publication itself is never retried automatically.

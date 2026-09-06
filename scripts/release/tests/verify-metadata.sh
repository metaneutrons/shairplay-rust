#!/bin/bash
set -euo pipefail

test_dir=$(cd "$(dirname "$0")" && pwd)
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT

# Real refs and Cargo metadata, isolated from the caller's repository and hooks.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME='Release Test' GIT_AUTHOR_EMAIL='release-test@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git init --quiet "$workspace"
cd "$workspace"
mkdir src
printf '// Test fixture.\n' > src/lib.rs
printf '[package]\nname = "release-fixture"\nversion = "1.2.3"\nedition = "2024"\n' > Cargo.toml
printf '{".":"1.2.3"}\n' > .release-please-manifest.json
cargo generate-lockfile --offline --quiet
git add Cargo.toml Cargo.lock src/lib.rs .release-please-manifest.json
git -c commit.gpgsign=false commit --quiet -m 'chore: create release fixture'
commit=$(git rev-parse HEAD)
git -c commit.gpgsign=false commit --quiet --allow-empty -m 'chore: advance release fixture'
other_commit=$(git rev-parse HEAD)
git checkout --quiet --detach "$commit"

run_case() {
    name=$1
    tag=$2
    result=$3
    detail=$4
    ref_type=${5:-tag}
    verify_registry=${6:-false}
    expected_commit=${7:-$commit}
    : > outputs
    if bash "$test_dir/../verify-metadata.sh" "$tag" "$ref_type" \
        "$expected_commit" "$verify_registry" outputs > log 2>&1; then
        actual=success
    else
        actual=failure
    fi
    if [[ "$actual" != "$result" ]]; then
        printf 'FAIL %s: expected %s, got %s\n' "$name" "$result" "$actual" >&2
        cat log >&2
        exit 1
    fi
    if [[ "$result" == success ]]; then
        printf 'crate_name=release-fixture\nis_prerelease=%s\ntag=%s\nversion=1.2.3\n' \
            "$detail" "$tag" > expected
        cmp expected outputs
    elif [[ -s outputs ]] || ! grep -Fq "Release identity rejected: $detail" log; then
        printf 'FAIL %s: wrong rejection reason or outputs written on failure\n' "$name" >&2
        cat log >&2
        exit 1
    fi
    printf 'PASS %s\n' "$name"
}

for tag in v1.2.3 v1.2.3+build.1 v1.2.3+build-1 v1.2.3+build--1 \
    v1.2.3-rc.1 v1.2.3-rc.1+build-1 v1.2.3-0 v1.2.3-0alpha; do
    git -c tag.gpgSign=false tag "$tag" "$commit"
done
git -c tag.gpgSign=false tag --annotate v1.2.3+annotated -m 'Annotated fixture' "$commit"
git -c tag.gpgSign=false tag v1.2.3+wrong-commit "$other_commit"
git -c tag.gpgSign=false tag v1.2.4 "$commit"
git -c tag.gpgSign=false tag v1.2.3+blob 'HEAD:src/lib.rs'

run_case stable v1.2.3 success false
run_case build-metadata v1.2.3+build.1 success false
run_case hyphen-in-build-metadata v1.2.3+build-1 success false
run_case multiple-build-hyphens v1.2.3+build--1 success false
run_case prerelease v1.2.3-rc.1 success true
run_case prerelease-with-build-metadata v1.2.3-rc.1+build-1 success true
run_case numeric-prerelease v1.2.3-0 success true
run_case alphanumeric-prerelease v1.2.3-0alpha success true
run_case annotated-tag v1.2.3+annotated success false
run_case trusted-publishing-preflight v1.2.3-rc.1 success true tag true
run_case no-stable-test-bypass v1.2.3 failure \
    'registry verification is reserved for non-publishing prerelease tests' tag true
run_case no-build-metadata-test-bypass v1.2.3+build-1 failure \
    'registry verification is reserved for non-publishing prerelease tests' tag true
run_case invalid-boolean v1.2.3 failure 'registry verification must be true or false' tag yes
run_case branch-dispatch v1.2.3 failure 'expected a canonical v-prefixed SemVer tag' branch
run_case missing-tag v1.2.3+missing failure 'tag must resolve to a commit'
run_case non-commit-tag v1.2.3+blob failure 'tag must resolve to a commit'
run_case wrong-tag-commit v1.2.3+wrong-commit failure 'tag does not resolve to the expected commit'
run_case missing-expected-commit v1.2.3 failure \
    'expected commit must resolve to a commit' tag false nonexistent
run_case wrong-package-version v1.2.4 failure \
    'tag core, Cargo package version, and release manifest must match'
for tag in 1.2.3 shairplay-v1.2.3 v01.2.3 v1.02.3 v1.2.03 v1.2 v1.2.3-01 \
    v1.2.3-rc..1 v1.2.3- v1.2.3+ v1.2.3+build..1 v1.2.3+build+1; do
    run_case "invalid-$tag" "$tag" failure 'expected a canonical v-prefixed SemVer tag'
done

git checkout --quiet --detach "$other_commit"
run_case wrong-checkout v1.2.3 failure 'checkout does not match the expected commit'
git checkout --quiet --detach "$commit"
printf '{".":"1.2.4"}\n' > .release-please-manifest.json
run_case wrong-release-manifest v1.2.3 failure \
    'tag core, Cargo package version, and release manifest must match'
printf '{".":"1.2.3"}\n' > .release-please-manifest.json
mkdir -p second/src
printf '// Second fixture.\n' > second/src/lib.rs
printf '[package]\nname = "second-fixture"\nversion = "1.2.3"\nedition = "2024"\n' > second/Cargo.toml
printf '\n[workspace]\nmembers = ["second"]\n' >> Cargo.toml
cargo generate-lockfile --offline --quiet
run_case multiple-packages v1.2.3 failure 'workspace must contain exactly one package'

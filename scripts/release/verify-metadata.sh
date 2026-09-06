#!/bin/bash
# Verify that a release tag names the checked-out package version and commit.
set -euo pipefail

tag=${1:?release tag is required}
ref_type=${2:?Git ref type is required}
expected_commit=${3:?expected commit is required}
verify_registry=${4:-false}
output=${5:-/dev/null}
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

fail() {
    printf 'Release identity rejected: %s\n' "$1" >&2
    exit 1
}

[[ "$ref_type" == tag && "$tag" =~ $semver ]] ||
    fail 'expected a canonical v-prefixed SemVer tag'
[[ "$verify_registry" == true || "$verify_registry" == false ]] ||
    fail 'registry verification must be true or false'
tag_commit=$(git rev-parse --verify "refs/tags/${tag}^{commit}") ||
    fail 'tag must resolve to a commit'
expected_commit=$(git rev-parse --verify "${expected_commit}^{commit}") ||
    fail 'expected commit must resolve to a commit'
[[ "$tag_commit" == "$expected_commit" ]] ||
    fail 'tag does not resolve to the expected commit'
[[ "$(git rev-parse --verify 'HEAD^{commit}')" == "$expected_commit" ]] ||
    fail 'checkout does not match the expected commit'

version=${tag#v}
# A hyphen inside build metadata is not a prerelease separator.
release_version=${version%%+*}
core=${release_version%%-*}
metadata=$(cargo metadata --locked --no-deps --format-version 1)
[[ "$(jq '.packages | length' <<< "$metadata")" -eq 1 ]] ||
    fail 'workspace must contain exactly one package'
crate_name=$(jq -r '.packages[0].name' <<< "$metadata")
package_version=$(jq -r '.packages[0].version' <<< "$metadata")
manifest_version=$(jq -r '.["."]' .release-please-manifest.json)
[[ "$package_version" == "$core" && "$manifest_version" == "$core" ]] ||
    fail 'tag core, Cargo package version, and release manifest must match'

is_prerelease=false
[[ "$release_version" == *-* ]] && is_prerelease=true
[[ "$verify_registry" != true || "$is_prerelease" == true ]] ||
    fail 'registry verification is reserved for non-publishing prerelease tests'

{
    printf 'crate_name=%s\n' "$crate_name"
    printf 'is_prerelease=%s\n' "$is_prerelease"
    printf 'tag=%s\n' "$tag"
    printf 'version=%s\n' "$core"
} >> "$output"

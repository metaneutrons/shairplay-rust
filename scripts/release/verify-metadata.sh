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
[[ "$(git rev-parse "${tag}^{}")" == "$(git rev-parse "$expected_commit")" ]] ||
    fail 'tag does not resolve to the expected commit'

version=${tag#v}
core=${version%%[-+]*}
metadata=$(cargo metadata --no-deps --format-version 1)
[[ "$(jq '.packages | length' <<< "$metadata")" -eq 1 ]] ||
    fail 'workspace must contain exactly one package'
crate_name=$(jq -r '.packages[0].name' <<< "$metadata")
package_version=$(jq -r '.packages[0].version' <<< "$metadata")
manifest_version=$(jq -r '.["."]' .release-please-manifest.json)
[[ "$package_version" == "$core" && "$manifest_version" == "$core" ]] ||
    fail 'tag core, Cargo package version, and release manifest must match'

is_prerelease=false
[[ "$version" == *-* ]] && is_prerelease=true
[[ "$verify_registry" != true || "$is_prerelease" == true ]] ||
    fail 'registry verification is reserved for non-publishing prerelease tests'

{
    printf 'crate_name=%s\n' "$crate_name"
    printf 'is_prerelease=%s\n' "$is_prerelease"
    printf 'tag=%s\n' "$tag"
    printf 'version=%s\n' "$core"
} >> "$output"

#!/bin/bash
# Verify the complete release candidate inventory and its checksum.
set -euo pipefail

candidate_dir=${1:?candidate directory is required}
crate_name=${2:?crate name is required}
version=${3:?crate version is required}
crate="${crate_name}-${version}.crate"

fail() {
    printf 'Release candidate rejected: %s\n' "$1" >&2
    exit 1
}

[[ -d "$candidate_dir" && ! -L "$candidate_dir" ]] ||
    fail 'candidate must be a directory, not a symlink'
shopt -s nullglob dotglob
entries=("$candidate_dir"/*)
[[ "${#entries[@]}" -eq 2 ]] || fail 'expected exactly two candidate entries'
[[ -f "$candidate_dir/$crate" && ! -L "$candidate_dir/$crate" \
    && -f "$candidate_dir/SHA256SUMS" && ! -L "$candidate_dir/SHA256SUMS" ]] ||
    fail 'expected a regular crate archive and checksum file'
[[ "$(wc -l < "$candidate_dir/SHA256SUMS" | tr -d ' ')" -eq 1 ]] ||
    fail 'expected exactly one checksum line'
checksum_line=$(< "$candidate_dir/SHA256SUMS")
checksum=${checksum_line%% *}
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || fail 'expected a SHA-256 checksum'
[[ "$checksum_line" == "$checksum  $crate" ]] ||
    fail 'checksum must name the expected crate archive'
(cd "$candidate_dir" && sha256sum --check SHA256SUMS) || fail 'checksum verification failed'

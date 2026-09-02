#!/bin/bash
# Verify the complete release candidate inventory and its checksum.
set -euo pipefail

candidate_dir=${1:?candidate directory is required}
crate_name=${2:?crate name is required}
version=${3:?crate version is required}
crate="${crate_name}-${version}.crate"

[[ "$(find "$candidate_dir" -maxdepth 1 -type f | wc -l | tr -d ' ')" -eq 2 ]]
[[ -f "$candidate_dir/$crate" && -f "$candidate_dir/SHA256SUMS" ]]
[[ "$(wc -l < "$candidate_dir/SHA256SUMS" | tr -d ' ')" -eq 1 ]]
[[ "$(awk '{ print $2 }' "$candidate_dir/SHA256SUMS")" == "$crate" ]]
(cd "$candidate_dir" && sha256sum --check SHA256SUMS)

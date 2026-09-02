#!/bin/bash
# Build the exact crate archive and checksum file used by the release workflow.
set -euo pipefail

output_dir=${1:?output directory is required}
crate_name=${2:?crate name is required}
version=${3:?crate version is required}
crate="${crate_name}-${version}.crate"

cargo package --workspace --locked
[[ -f "target/package/$crate" ]]
mkdir -p "$output_dir"
cp "target/package/$crate" "$output_dir/"
(cd "$output_dir" && sha256sum "$crate" > SHA256SUMS)

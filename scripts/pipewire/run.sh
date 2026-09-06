#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd "$(dirname "$0")/../.." && pwd -P)
revision=$(git -C "$root" rev-parse HEAD)
dirty=false
if [[ -n $(git -C "$root" status --porcelain) ]]; then dirty=true; fi
run_id="shairplay-pw-$(date -u +%Y%m%dT%H%M%S)-$$"
image=shairplay-pipewire-qualification:1.6.7
output="$root/target/pipewire-qualification/$run_id"
evidence="$run_id-evidence"
container=""
status=0

# Invoked by the EXIT trap, including after a failed matrix run.
# shellcheck disable=SC2329
cleanup() {
    if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
    docker volume rm "$evidence" >/dev/null 2>&1 || true
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker build --tag "$image" --file "$root/scripts/pipewire/Dockerfile" "$root/scripts/pipewire"
image_id=$(docker image inspect --format '{{.Id}}' "$image")
common=(--init --cap-drop=ALL --security-opt=no-new-privileges
    --mount "type=bind,source=$root,target=/repo,readonly"
    --mount "type=volume,source=shairplay-pw-cargo,target=/cargo"
    --mount "type=volume,source=shairplay-pw-target,target=/target")

# Only dependency acquisition has network access. No host audio service is used.
container="$run_id-fetch"
docker run --name "$container" "${common[@]}" "$image" cargo fetch --locked
docker rm "$container" >/dev/null
container=""
mkdir -p "$output"

qualify() {
    local name=$1
    shift
    container="$run_id-$name"
    docker run --name "$container" "${common[@]}" --network none --read-only \
        --tmpfs /tmp:rw,nosuid,nodev,size=128m \
        --mount "type=volume,source=$evidence,target=/evidence" \
        -e "QUALIFICATION_REVISION=$revision" -e "QUALIFICATION_DIRTY=$dirty" \
        -e "QUALIFICATION_IMAGE=$image_id" -e "QUALIFICATION_REPORT=/evidence/$name.json" \
        -e "QUALIFICATION_TRANSPORT=${QUALIFICATION_TRANSPORT:-udp}" \
        "$image" cargo test --test pipewire --locked --offline "$@" -- --include-ignored --nocapture || status=1
    docker rm "$container" >/dev/null
    container=""
}

qualify default --no-default-features
qualify compat --features pipewire-auth-setup-compat
qualify ap2 --features ap2
qualify combined --features ap2,pipewire-auth-setup-compat
qualify release --release --features pipewire-auth-setup-compat

container="$run_id-evidence"
docker create --name "$container" --network none \
    --mount "type=volume,source=$evidence,target=/evidence,readonly" "$image" true >/dev/null
docker cp "$container:/evidence/." "$output/"
printf 'Qualification evidence: %s\n' "$output"
exit "$status"

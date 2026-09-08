#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd "$(dirname "$0")/../.." && pwd -P)
revision=$(git -C "$root" rev-parse HEAD)
dirty=false
if [[ -n $(git -C "$root" status --porcelain) ]]; then dirty=true; fi
variant=${PIPEWIRE_VARIANT:-baseline}
case "$variant" in
    baseline|iovec-fix)
        pipewire_version=1.6.7
        pipewire_commit=3b2cb4fb037bf6033b87d3c87ee917b2f686d309
        pipewire_sha256=c8746b3c3408becb27e40cf67a5587105f057cd540769db4c345a67bf45c86df
        source_id=1.6.7
        ;;
    upstream-merged)
        pipewire_version=1.7.0
        pipewire_commit=bc7d1cba6dee390beba0785e50935275d3f1d484
        pipewire_sha256=b57315ef2b9fe0062469752bc12be2edac70ab88dbabf35b69be843665969fcb
        source_id=upstream-bc7d1cba
        ;;
    tcp-baseline|tcp-fix)
        pipewire_version=1.7.0
        pipewire_commit=c73df14f03e30c41f6430acd82c6250dcdb168d8
        pipewire_sha256=9f8d2b0f8d034a3ee4c19192a33e3a36daaeedf677a764c347b55c8cd33dc854
        source_id=upstream-c73df14f
        ;;
    *) printf 'Invalid PipeWire variant\n' >&2; exit 2 ;;
esac
run_id="shairplay-pw-$variant-$(date -u +%Y%m%dT%H%M%S)-$$"
image="shairplay-pipewire-qualification:$source_id-$variant"
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

docker build --tag "$image" --build-arg "PIPEWIRE_VARIANT=$variant" \
    --build-arg "PIPEWIRE_COMMIT=$pipewire_commit" \
    --build-arg "PIPEWIRE_SHA256=$pipewire_sha256" \
    --build-arg "PIPEWIRE_QUALIFICATION_VERSION=$pipewire_version" \
    --file "$root/scripts/pipewire/Dockerfile" "$root/scripts/pipewire"
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

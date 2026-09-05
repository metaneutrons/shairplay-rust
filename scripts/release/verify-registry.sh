#!/bin/bash
# Verify against Cargo's registry index, not the crates.io website API.
# Index layout and checksum: https://doc.rust-lang.org/cargo/reference/registry-index.html
set -euo pipefail
export LC_ALL=C

crate_name=${1:?crate name is required}
version=${2:?crate version is required}
expected=${3:?expected SHA-256 is required}

if [[ ! "$crate_name" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,63}$ \
   || ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Invalid crate name or expected SHA-256." >&2
  exit 1
fi

name=$(printf '%s' "$crate_name" | tr '[:upper:]' '[:lower:]')
case ${#name} in
  1) path="1/$name" ;;
  2) path="2/$name" ;;
  3) path="3/${name:0:1}/$name" ;;
  *) path="${name:0:2}/${name:2:2}/$name" ;;
esac

for attempt in {1..12}; do
  # Transport failures and index propagation delays must not bypass retries via errexit.
  if index=$(curl --fail --silent --show-error --location \
      --connect-timeout 10 --max-time 30 "https://index.crates.io/$path"); then
    actual=$(printf '%s\n' "$index" | jq --slurp --raw-output \
      --arg name "$crate_name" --arg version "$version" '
      map(select(.name == $name and .vers == $version))
      | if length == 0 then ""
        elif length != 1 then error("duplicate registry version")
        elif .[0].yanked != false then error("registry version is yanked or missing yank metadata")
        elif (.[0].cksum | type) != "string" then error("missing registry checksum")
        elif (.[0].cksum | test("^[0-9a-f]{64}$") | not) then error("invalid registry checksum")
        else .[0].cksum end')
    if [[ -n "$actual" ]]; then
      if [[ "$actual" != "$expected" ]]; then
        echo "crates.io checksum does not match the release candidate." >&2
        exit 1
      fi
      printf 'Verified crates.io checksum for %s %s: %s\n' "$crate_name" "$version" "$actual"
      exit 0
    fi
  fi
  if [[ "$attempt" -lt 12 ]]; then
    sleep 10
  fi
done

echo "Could not verify the published version in the crates.io index after 12 attempts." >&2
exit 1

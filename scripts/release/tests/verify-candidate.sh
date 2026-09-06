#!/bin/bash
set -euo pipefail

test_dir=$(cd "$(dirname "$0")" && pwd)
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
crate=release-fixture-1.2.3.crate
mkdir "$workspace/baseline"
printf 'Deterministic archive fixture.\n' > "$workspace/baseline/$crate"
(cd "$workspace/baseline" && sha256sum "$crate" > SHA256SUMS)

run_case() {
    name=$1
    expected_result=$2
    reason=${3:-}
    candidate="$workspace/$name"
    mkdir "$candidate"
    cp "$workspace/baseline/$crate" "$workspace/baseline/SHA256SUMS" "$candidate/"
    case "$name" in
        valid) ;;
        corrupted) printf 'corruption' >> "$candidate/$crate" ;;
        missing-crate) rm "$candidate/$crate" ;;
        missing-checksum) rm "$candidate/SHA256SUMS" ;;
        extra-file) touch "$candidate/extra" ;;
        hidden-file) touch "$candidate/.extra" ;;
        extra-directory) mkdir "$candidate/extra" ;;
        archive-directory) rm "$candidate/$crate"; mkdir "$candidate/$crate" ;;
        symlink-archive) rm "$candidate/$crate"; ln -s "$workspace/baseline/$crate" "$candidate/$crate" ;;
        symlink-checksum) rm "$candidate/SHA256SUMS"; ln -s "$workspace/baseline/SHA256SUMS" "$candidate/SHA256SUMS" ;;
        empty-checksum) : > "$candidate/SHA256SUMS" ;;
        duplicate-checksum) cat "$workspace/baseline/SHA256SUMS" >> "$candidate/SHA256SUMS" ;;
        wrong-name) printf '%064d  other.crate\n' 0 > "$candidate/SHA256SUMS" ;;
        malformed-checksum) printf 'invalid  %s\n' "$crate" > "$candidate/SHA256SUMS" ;;
        symlink-directory) candidate="$workspace/linked"; ln -s "$workspace/baseline" "$candidate" ;;
        missing-directory) candidate="$workspace/nonexistent" ;;
    esac
    if bash "$test_dir/../verify-candidate.sh" "$candidate" release-fixture 1.2.3 \
        > "$workspace/output" 2>&1; then
        result=success
    else
        result=failure
    fi
    if [[ "$result" != "$expected_result" ]] || \
        { [[ "$result" == failure ]] && ! grep -Fq "Release candidate rejected: $reason" "$workspace/output"; }; then
        printf 'FAIL %s: result=%s\n' "$name" "$result" >&2
        cat "$workspace/output" >&2
        exit 1
    fi
    printf 'PASS %s\n' "$name"
}

run_case valid success
run_case corrupted failure 'checksum verification failed'
run_case missing-crate failure 'expected exactly two candidate entries'
run_case missing-checksum failure 'expected exactly two candidate entries'
run_case extra-file failure 'expected exactly two candidate entries'
run_case hidden-file failure 'expected exactly two candidate entries'
run_case extra-directory failure 'expected exactly two candidate entries'
run_case archive-directory failure 'expected a regular crate archive and checksum file'
run_case symlink-archive failure 'expected a regular crate archive and checksum file'
run_case symlink-checksum failure 'expected a regular crate archive and checksum file'
run_case empty-checksum failure 'expected exactly one checksum line'
run_case duplicate-checksum failure 'expected exactly one checksum line'
run_case wrong-name failure 'checksum must name the expected crate archive'
run_case malformed-checksum failure 'expected a SHA-256 checksum'
run_case symlink-directory failure 'candidate must be a directory, not a symlink'
run_case missing-directory failure 'candidate must be a directory, not a symlink'

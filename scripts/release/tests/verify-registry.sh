#!/bin/bash
set -euo pipefail

test_dir=$(cd "$(dirname "$0")" && pwd)
export PATH="$test_dir/bin:$PATH"
TEST_STATE_DIR=$(mktemp -d)
export TEST_STATE_DIR
trap 'rm -rf "$TEST_STATE_DIR"' EXIT
export TEST_CHECKSUM=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

run_case() {
  export TEST_SCENARIO=$1
  expected_result=$2
  expected_requests=$3
  expected_sleeps=$4
  export TEST_NAME=${5:-shairplay}
  export TEST_INDEX_URL="https://index.crates.io/${6:-sh/ai/shairplay}"
  checksum=${7:-$TEST_CHECKSUM}
  : > "$TEST_STATE_DIR/requests"
  : > "$TEST_STATE_DIR/sleeps"
  if bash "$test_dir/../verify-registry.sh" "$TEST_NAME" 0.9.0 "$checksum" \
      > "$TEST_STATE_DIR/output" 2>&1; then
    result=success
  else
    result=failure
  fi
  requests=$(wc -l < "$TEST_STATE_DIR/requests" | tr -d ' ')
  sleeps=$(wc -l < "$TEST_STATE_DIR/sleeps" | tr -d ' ')
  if [[ "$result" != "$expected_result" || "$requests" != "$expected_requests" \
      || "$sleeps" != "$expected_sleeps" ]]; then
    printf 'FAIL %s (%s): result=%s requests=%s sleeps=%s\n' \
      "$TEST_SCENARIO" "$TEST_NAME" "$result" "$requests" "$sleeps" >&2
    cat "$TEST_STATE_DIR/output" >&2
    exit 1
  fi
  printf 'PASS %s (%s)\n' "$TEST_SCENARIO" "$TEST_NAME"
}

run_case success success 1 0
run_case transport-retry success 2 1
run_case delayed success 2 1
run_case unavailable failure 12 11
run_case missing failure 12 11
run_case wrong-name failure 12 11
run_case mismatch failure 1 0
run_case yanked failure 1 0
run_case missing-yank failure 1 0
run_case duplicate failure 1 0
run_case malformed failure 1 0
run_case missing-checksum failure 1 0
run_case malformed-checksum failure 1 0
run_case invalid-name failure 0 0 ../escape
run_case invalid-expected-checksum failure 0 0 shairplay sh/ai/shairplay invalid-checksum
run_case success success 1 0 a 1/a
run_case success success 1 0 Ab 2/ab
run_case success success 1 0 AbC 3/a/abc
run_case success success 1 0 AbCd ab/cd/abcd

#!/usr/bin/env bash

set -euo pipefail

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0
FAILED_TESTS=()

assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-assert_eq failed}"
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: $msg" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        return 1
    fi
}

assert_ne() {
    local actual="$1"
    local unexpected="$2"
    local msg="${3:-assert_ne failed}"
    if [[ "$actual" == "$unexpected" ]]; then
        echo "FAIL: $msg" >&2
        echo "  should not equal: $unexpected" >&2
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-assert_contains failed}"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "FAIL: $msg" >&2
        echo "  expected to contain: $needle" >&2
        echo "  in: $haystack" >&2
        return 1
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-assert_not_contains failed}"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "FAIL: $msg" >&2
        echo "  expected NOT to contain: $needle" >&2
        echo "  in: $haystack" >&2
        return 1
    fi
}

assert_file_exists() {
    local path="$1"
    local msg="${2:-file should exist: $path}"
    if [[ ! -f "$path" ]]; then
        echo "FAIL: $msg" >&2
        return 1
    fi
}

assert_file_not_empty() {
    local path="$1"
    local msg="${2:-file should not be empty: $path}"
    if [[ ! -s "$path" ]]; then
        echo "FAIL: $msg" >&2
        return 1
    fi
}

assert_yaml_valid() {
    local path="$1"
    local msg="${2:-file should be valid YAML: $path}"
    if ! python3 -c "import yaml, sys; yaml.safe_load(sys.stdin)" < "$path" 2>/dev/null; then
        echo "FAIL: $msg" >&2
        return 1
    fi
}

assert_lt() {
    local actual="$1"
    local threshold="$2"
    local msg="${3:-assert_lt failed}"
    if [[ "$actual" -ge "$threshold" ]]; then
        echo "FAIL: $msg" >&2
        echo "  expected: < $threshold" >&2
        echo "  actual:   $actual" >&2
        return 1
    fi
}

assert_summary_valid() {
    local path="$1"
    assert_file_exists "$path" "summary file should exist"
    assert_file_not_empty "$path" "summary file should not be empty"
    assert_yaml_valid "$path" "summary should be valid YAML"
}

setup_crypto_dir() {
    local workdir="$1"
    shift
    local crypto_dir="${workdir}/crypto"
    mkdir -p "$crypto_dir"
    for f in "$@"; do
        cp "${FIXTURES_DIR}/$f" "${crypto_dir}/$f"
    done
    echo "$crypto_dir"
}

precheck_cert() {
    local path="$1"
    local msg="${2:-valid cert: $path}"
    if ! openssl x509 -noout -in "$path" 2>/dev/null; then
        echo "PRECHECK FAIL: $msg" >&2
        return 1
    fi
}

precheck_key() {
    local path="$1"
    local msg="${2:-valid key: $path}"
    if ! openssl pkey -noout -in "$path" 2>/dev/null; then
        echo "PRECHECK FAIL: $msg" >&2
        return 1
    fi
}

precheck_etcd_key() {
    local key="$1"
    local msg="${2:-etcd key exists: $key}"
    local value
    value=$(etcdctl get --endpoints=localhost:2379 "$key" --print-value-only 2>/dev/null)
    if [[ -z "$value" ]]; then
        echo "PRECHECK FAIL: $msg" >&2
        return 1
    fi
    echo "$value"
}

precheck_etcd_json_field() {
    local key="$1"
    local pointer="$2"
    local msg="${3:-etcd key $key has field $pointer}"
    local value
    value=$(etcdctl get --endpoints=localhost:2379 "$key" --print-value-only 2>/dev/null)
    if ! python3 -c "import json,sys; d=json.loads(sys.stdin.read()); v=d; [v:=v[p] for p in '${pointer}'.strip('/').split('/')]; print(v)" <<< "$value" 2>/dev/null; then
        echo "PRECHECK FAIL: $msg" >&2
        return 1
    fi
}

cert_key_algorithm() {
    openssl x509 -noout -text -in "$1" 2>/dev/null | grep "Public Key Algorithm:" | head -1 | awk '{print $NF}'
}

cert_key_size() {
    openssl x509 -noout -text -in "$1" 2>/dev/null | grep "Public-Key:" | head -1 | sed 's/.*(\([0-9]*\) bit).*/\1/'
}

cert_ec_curve() {
    openssl x509 -noout -text -in "$1" 2>/dev/null | grep "ASN1 OID:" | head -1 | awk '{print $NF}'
}

assert_cert_regenerated() {
    local label="$1"
    local crypto_dir="$2"
    local cert_file="$3"
    local key_file="$4"
    local orig_cert_hash="$5"
    local orig_key_hash="$6"
    local expected_algo="$7"
    local expected_detail="${8:-}"

    assert_ne "$(sha256_file "${crypto_dir}/${cert_file}")" "$orig_cert_hash" \
        "${label} cert should have been regenerated"
    assert_ne "$(sha256_file "${crypto_dir}/${key_file}")" "$orig_key_hash" \
        "${label} key should have been regenerated"

    local actual_algo
    actual_algo=$(cert_key_algorithm "${crypto_dir}/${cert_file}")
    assert_eq "$actual_algo" "$expected_algo" \
        "${label} cert should preserve key algorithm"

    if [[ -n "$expected_detail" ]]; then
        if [[ "$expected_algo" == "rsaEncryption" ]]; then
            local actual_size
            actual_size=$(cert_key_size "${crypto_dir}/${cert_file}")
            assert_eq "$actual_size" "$expected_detail" \
                "${label} cert should preserve RSA key size"
        elif [[ "$expected_algo" == "id-ecPublicKey" ]]; then
            local actual_curve
            actual_curve=$(cert_ec_curve "${crypto_dir}/${cert_file}")
            assert_eq "$actual_curve" "$expected_detail" \
                "${label} cert should preserve EC curve"
        fi
    fi
}

run_recert_expect_success() {
    local output
    local rc=0
    output=$("$RECERT_BIN" "$@" 2>&1) || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "FAIL: recert exited with code $rc (expected 0)" >&2
        echo "  args: $*" >&2
        echo "  output: $output" >&2
        return 1
    fi
    echo "$output"
}

run_recert_expect_failure() {
    local output
    local rc=0
    output=$("$RECERT_BIN" "$@" 2>&1) || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "FAIL: recert exited with code 0 (expected non-zero)" >&2
        echo "  args: $*" >&2
        echo "  output: $output" >&2
        return 1
    fi
    echo "$output"
}

setup_test_workdir() {
    local test_name="$1"
    local workdir
    workdir=$(mktemp -d "${ARTIFACTS_DIR}/${test_name}.XXXXXX")
    echo "$workdir"
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

record_result() {
    local test_name="$1"
    local rc="$2"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    if [[ $rc -eq 0 ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "  PASS: $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        echo "  FAIL: $test_name"
    fi
}

print_summary() {
    echo ""
    echo "=============================="
    echo "Integration Test Results"
    echo "=============================="
    echo "Total:  $TESTS_TOTAL"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        echo ""
        echo "Failed tests:"
        for t in "${FAILED_TESTS[@]}"; do
            echo "  - $t"
        done
    fi
    echo "=============================="
    return $TESTS_FAILED
}

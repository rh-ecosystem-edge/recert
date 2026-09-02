#!/usr/bin/env bash

set -euo pipefail

INTEGRATION_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

assert_gt() {
    local actual="$1"
    local threshold="$2"
    local msg="${3:-assert_gt failed}"
    if [[ "$actual" -le "$threshold" ]]; then
        echo "FAIL: $msg" >&2
        echo "  expected: > $threshold" >&2
        echo "  actual:   $actual" >&2
        return 1
    fi
}

assert_match() {
    local actual="$1"
    local pattern="$2"
    local msg="${3:-assert_match failed}"
    if [[ ! "$actual" =~ $pattern ]]; then
        echo "FAIL: $msg" >&2
        echo "  expected to match: $pattern" >&2
        echo "  actual: $actual" >&2
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

setup_webhook_authenticator() {
    local crypto_dir="$1"
    mkdir -p "${crypto_dir}/kube-apiserver-pod-1/webhook-authenticator"
    cat > "${crypto_dir}/kube-apiserver-pod-1/webhook-authenticator/kubeConfig" <<'KUBECONFIG'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: local
KUBECONFIG
}

run_crypto_algo_test() {
    local label="$1"
    local prefix="$2"
    local expected_algo="$3"
    local expected_detail="$4"

    local workdir
    workdir=$(setup_test_workdir "crypto_${prefix}")
    local crypto_dir
    crypto_dir=$(setup_crypto_dir "$workdir" \
        "${prefix}-ca.crt" "${prefix}-ca.key" \
        "${prefix}-server.crt" "${prefix}-server.key")

    local ca_cert_hash ca_key_hash server_cert_hash server_key_hash
    ca_cert_hash=$(sha256_file "${crypto_dir}/${prefix}-ca.crt")
    ca_key_hash=$(sha256_file "${crypto_dir}/${prefix}-ca.key")
    server_cert_hash=$(sha256_file "${crypto_dir}/${prefix}-server.crt")
    server_key_hash=$(sha256_file "${crypto_dir}/${prefix}-server.key")

    cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

    RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

    assert_cert_regenerated "${label} CA" "$crypto_dir" "${prefix}-ca.crt" "${prefix}-ca.key" \
        "$ca_cert_hash" "$ca_key_hash" "$expected_algo" "$expected_detail"
    assert_cert_regenerated "${label} server" "$crypto_dir" "${prefix}-server.crt" "${prefix}-server.key" \
        "$server_cert_hash" "$server_key_hash" "$expected_algo" "$expected_detail"

    # P-384 signing on main uses SHA-256, so openssl verify would fail
    if [[ "$expected_detail" != "secp384r1" ]]; then
        assert_chain_valid "${crypto_dir}/${prefix}-ca.crt" "${crypto_dir}/${prefix}-server.crt" \
            "${label} regenerated leaf should verify against regenerated CA"
    fi

    assert_summary_valid "${workdir}/summary.yaml"
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
    value=$(etcdctl get --endpoints="${ETCD_ENDPOINT:-localhost:2379}" "$key" --print-value-only 2>/dev/null)
    if [[ -z "$value" ]]; then
        echo "PRECHECK FAIL: $msg" >&2
        return 1
    fi
    echo "$value"
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

assert_pem_tag() {
    local path="$1"
    local expected_tag="$2"
    local msg="${3:-PEM tag mismatch: $path}"
    local actual
    actual=$(head -1 "$path" | tr -d '\r')
    assert_eq "$actual" "-----BEGIN ${expected_tag}-----" "$msg"
}

assert_chain_valid() {
    local ca="$1"
    local leaf="$2"
    local msg="${3:-leaf should verify against CA}"
    if ! openssl verify -no_check_time -CAfile "$ca" "$leaf" >/dev/null 2>&1; then
        echo "FAIL: $msg" >&2
        openssl verify -no_check_time -CAfile "$ca" "$leaf" >&2 || true
        return 1
    fi
}

assert_file_unchanged() {
    local path="$1"
    local orig_hash="$2"
    local msg="${3:-file should be unchanged: $path}"
    assert_eq "$(sha256_file "$path")" "$orig_hash" "$msg"
}

cert_subject_cn() {
    openssl x509 -noout -subject -nameopt RFC2253 -in "$1" 2>/dev/null | sed 's/.*CN=//'
}

cert_san_text() {
    openssl x509 -noout -text -in "$1" 2>/dev/null | grep -A2 "Subject Alternative Name"
}

etcd_get() {
    etcdctl get --endpoints="${ETCD_ENDPOINT:-localhost:2379}" "$1" --print-value-only
}

etcd_put_json() {
    local key="$1"
    local completed
    completed=$(printf '%s' "$2" | python3 "${INTEGRATION_LIB_DIR}/k8s_json.py" complete)
    etcdctl put --endpoints="${ETCD_ENDPOINT:-localhost:2379}" "$key" "$completed" >/dev/null
}

etcd_put_tls_secret() {
    local ns="$1"
    local name="$2"
    local cert="$3"
    local key="$4"
    local completed
    completed=$(python3 "${INTEGRATION_LIB_DIR}/k8s_json.py" tls-secret "$ns" "$name" "$cert" "$key")
    etcdctl put --endpoints="${ETCD_ENDPOINT:-localhost:2379}" "/kubernetes.io/secrets/${ns}/${name}" "$completed" >/dev/null
}

etcd_secret_pems() {
    local key="$1"
    local cert_out="$2"
    local key_out="$3"
    etcd_get "$key" | python3 "${INTEGRATION_LIB_DIR}/k8s_json.py" extract-tls "$cert_out" "$key_out"
}

b64url_decode_to_file() {
    local data="$1"
    local dest="$2"
    local padded="$data"
    local mod=$(( ${#padded} % 4 ))
    if [[ $mod -eq 2 ]]; then
        padded="${padded}=="
    elif [[ $mod -eq 3 ]]; then
        padded="${padded}="
    fi
    printf '%s' "$padded" | tr '_-' '/+' | openssl base64 -d -A > "$dest"
}

assert_jwt_verifies() {
    local cert="$1"
    local token="$2"
    local msg="${3:-JWT should verify with cert}"
    local header payload sig
    IFS='.' read -r header payload sig <<< "$token"
    local tmpdir
    tmpdir=$(mktemp -d)
    printf '%s.%s' "$header" "$payload" > "${tmpdir}/signing_input"
    b64url_decode_to_file "$sig" "${tmpdir}/sig.bin"
    openssl x509 -in "$cert" -pubkey -noout > "${tmpdir}/pub.pem" 2>/dev/null
    if ! openssl dgst -sha256 -verify "${tmpdir}/pub.pem" -signature "${tmpdir}/sig.bin" \
        "${tmpdir}/signing_input" >/dev/null 2>&1; then
        echo "FAIL: $msg" >&2
        rm -rf "$tmpdir"
        return 1
    fi
    rm -rf "$tmpdir"
}

jwt_header_kid() {
    local token="$1"
    local header
    header="${token%%.*}"
    local tmp
    tmp=$(mktemp)
    b64url_decode_to_file "$header" "$tmp"
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("kid",""))' < "$tmp"
    rm -f "$tmp"
}

write_kubeconfig() {
    local dest="$1"
    local cert="$2"
    local key="$3"
    local ca="${4:-}"
    python3 - "$dest" "$cert" "$key" "$ca" <<'PY'
import base64, sys
dest, cert, key, ca = sys.argv[1:5]
def b64(path):
    return base64.b64encode(open(path, "rb").read()).decode()
ca_block = ""
if ca:
    ca_block = f"    certificate-authority-data: {b64(ca)}\n"
open(dest, "w").write(f"""apiVersion: v1
kind: Config
clusters:
- cluster:
{ca_block}    server: https://api.old-cluster.example.com:6443
  name: cluster
users:
- name: admin
  user:
    client-certificate-data: {b64(cert)}
    client-key-data: {b64(key)}
contexts:
- context:
    cluster: cluster
    user: admin
  name: admin
current-context: admin
""")
PY
}

kubeconfig_extract_client_pem() {
    local kube="$1"
    local cert_out="$2"
    local key_out="$3"
    python3 - "$kube" "$cert_out" "$key_out" <<'PY'
import base64, sys, yaml
kube, cert_out, key_out = sys.argv[1:4]
user = yaml.safe_load(open(kube))["users"][0]["user"]
open(cert_out, "wb").write(base64.b64decode(user["client-certificate-data"]))
open(key_out, "wb").write(base64.b64decode(user["client-key-data"]))
PY
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

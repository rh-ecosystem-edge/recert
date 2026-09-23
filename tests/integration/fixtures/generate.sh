#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/generated}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "Generating test PKI fixtures in ${OUT_DIR}..."

b64url() {
    openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

generate_ca() {
    local name="$1"
    local keyargs="$2"
    openssl req -x509 -newkey $keyargs -keyout "${OUT_DIR}/${name}-ca.key" \
        -out "${OUT_DIR}/${name}-ca.crt" -days 365 -nodes \
        -subj "/CN=${name}-root-ca" 2>/dev/null
}

generate_leaf() {
    local name="$1"
    local ca_name="$2"
    local keyargs="$3"
    local cn="${4:-${name}.example.com}"
    local san="${5:-DNS:${cn}}"

    openssl req -newkey $keyargs -keyout "${OUT_DIR}/${name}.key" \
        -out "${OUT_DIR}/${name}.csr" -nodes -subj "/CN=${cn}" 2>/dev/null

    openssl x509 -req -in "${OUT_DIR}/${name}.csr" \
        -CA "${OUT_DIR}/${ca_name}-ca.crt" -CAkey "${OUT_DIR}/${ca_name}-ca.key" \
        -CAcreateserial -out "${OUT_DIR}/${name}.crt" -days 365 \
        -extfile <(printf "subjectAltName=${san}") 2>/dev/null

    rm -f "${OUT_DIR}/${name}.csr"
}

# ── RSA 2048 (most common in OCP) ──
generate_ca "rsa2048" "rsa:2048"
generate_leaf "rsa2048-server" "rsa2048" "rsa:2048" \
    "api.old-cluster.example.com" "DNS:api.old-cluster.example.com,IP:192.168.1.100"

# ── RSA 4096 (used by some OCP components) ──
generate_ca "rsa4096" "rsa:4096"
generate_leaf "rsa4096-server" "rsa4096" "rsa:4096" "rsa4096.example.com"

# ── ECDSA P-256 (prime256v1, common in service-serving certs) ──
generate_ca "ec-p256" "ec -pkeyopt ec_paramgen_curve:prime256v1"
generate_leaf "ec-p256-server" "ec-p256" "ec -pkeyopt ec_paramgen_curve:prime256v1" \
    "ec-p256.example.com"

# ── ECDSA P-384 (secp384r1, used by some OCP components) ──
generate_ca "ec-p384" "ec -pkeyopt ec_paramgen_curve:secp384r1"
generate_leaf "ec-p384-server" "ec-p384" "ec -pkeyopt ec_paramgen_curve:secp384r1" \
    "ec-p384.example.com"

# PKCS#8 copies of P-256 keys (OpenSSL default is SEC1 "EC PRIVATE KEY")
for prefix in ec-p256-ca ec-p256-server; do
    openssl pkcs8 -topk8 -nocrypt -in "${OUT_DIR}/${prefix}.key" \
        -out "${OUT_DIR}/${prefix}-pkcs8.key" 2>/dev/null
done

# ── IPv6 SAN leaf (comma-separated CN/SAN replace rules) ──
generate_leaf "ipv6-server" "rsa2048" "rsa:2048" \
    "ipv6.example.com" "DNS:ipv6.example.com,IP:2001:db8::1"

# ── Cross-algorithm: RSA CA signing ECDSA leaf ──
generate_leaf "cross-ec-under-rsa" "rsa2048" "ec -pkeyopt ec_paramgen_curve:prime256v1" \
    "cross-ec.example.com"

# ── Cross-algorithm: ECDSA CA signing RSA leaf ──
generate_leaf "cross-rsa-under-ec" "ec-p256" "rsa:2048" "cross-rsa.example.com"

# ── Backward compatibility aliases (used by existing tests) ──
cp "${OUT_DIR}/rsa2048-ca.crt" "${OUT_DIR}/ca.crt"
cp "${OUT_DIR}/rsa2048-ca.key" "${OUT_DIR}/ca.key"
cp "${OUT_DIR}/rsa2048-server.crt" "${OUT_DIR}/server.crt"
cp "${OUT_DIR}/rsa2048-server.key" "${OUT_DIR}/server.key"

# Standalone RSA key for --use-key tests
openssl genrsa -out "${OUT_DIR}/custom.key" 2048 2>/dev/null

# Replacement cert (same CN as RSA 2048 CA) for --use-cert tests
openssl req -x509 -newkey rsa:2048 -keyout "${OUT_DIR}/replacement.key" \
    -out "${OUT_DIR}/replacement.crt" -days 365 -nodes -subj "/CN=rsa2048-root-ca" 2>/dev/null

# Ed25519 CA + leaf (JWT EdDSA + algo scenario)
generate_ca "ed25519" "ed25519"
generate_leaf "ed25519-server" "ed25519" "ed25519" "ed25519.example.com"

# Standalone keys + pubs (RSA PKCS#1 PUBLIC KEY and SPKI) for crypto-dir regen
openssl genrsa -out "${OUT_DIR}/standalone-rsa.key" 2048 2>/dev/null
openssl rsa -in "${OUT_DIR}/standalone-rsa.key" -RSAPublicKey_out -out "${OUT_DIR}/standalone-rsa.pub" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_DIR}/standalone-ec.key" 2>/dev/null
openssl pkey -in "${OUT_DIR}/standalone-ec.key" -pubout -out "${OUT_DIR}/standalone-ec.pub" 2>/dev/null
openssl genpkey -algorithm Ed25519 -out "${OUT_DIR}/standalone-ed25519.key" 2>/dev/null
openssl pkey -in "${OUT_DIR}/standalone-ed25519.key" -pubout -out "${OUT_DIR}/standalone-ed25519.pub" 2>/dev/null

# JWTs signed by matching CA keys (copied into crypto dirs as sa/token)
sign_jwt() {
    local alg="$1"
    local key="$2"
    local out="$3"
    local header payload sig tmpdata
    header=$(printf '%s' "{\"alg\":\"${alg}\",\"typ\":\"JWT\",\"kid\":\"fixture\"}" | b64url)
    payload=$(printf '%s' '{"sub":"recert-test","iss":"recert-integration"}' | b64url)
    case "$alg" in
        RS256|ES256)
            sig=$(printf '%s' "${header}.${payload}" | openssl dgst -sha256 -sign "$key" -binary | b64url)
            ;;
        ES384)
            sig=$(printf '%s' "${header}.${payload}" | openssl dgst -sha384 -sign "$key" -binary | b64url)
            ;;
        EdDSA)
            tmpdata=$(mktemp)
            printf '%s' "${header}.${payload}" > "$tmpdata"
            sig=$(openssl pkeyutl -sign -inkey "$key" -rawin -in "$tmpdata" 2>/dev/null | b64url)
            rm -f "$tmpdata"
            ;;
        *)
            echo "unsupported JWT alg for fixture: $alg" >&2
            return 1
            ;;
    esac
    printf '%s' "${header}.${payload}.${sig}" > "$out"
}

sign_jwt "RS256" "${OUT_DIR}/rsa2048-ca.key" "${OUT_DIR}/jwt-rs256"
sign_jwt "ES256" "${OUT_DIR}/ec-p256-ca.key" "${OUT_DIR}/jwt-es256"
sign_jwt "ES384" "${OUT_DIR}/ec-p384-ca.key" "${OUT_DIR}/jwt-es384"
sign_jwt "EdDSA" "${OUT_DIR}/ed25519-ca.key" "${OUT_DIR}/jwt-eddsa"

rm -f "${OUT_DIR}"/*.srl

echo "Fixtures generated:"
ls -la "${OUT_DIR}/"

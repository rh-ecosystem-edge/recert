#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/generated}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "Generating test PKI fixtures in ${OUT_DIR}..."

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

rm -f "${OUT_DIR}"/*.srl

echo "Fixtures generated:"
ls -la "${OUT_DIR}/"

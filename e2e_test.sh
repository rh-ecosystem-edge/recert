#!/usr/bin/env bash
set -euo pipefail

# E2E test for recert crypto regeneration across all key types.
# Generates crypto material, runs recert, and verifies the output.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BINARY="${SCRIPT_DIR}/target/debug/recert"
PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
skip() { echo "  SKIP: $1"; ((SKIP++)) || true; }

# Build the binary
echo "Building recert..."
cargo build --manifest-path "${SCRIPT_DIR}/Cargo.toml" 2>&1 | tail -3

###############################################################################
# Generate crypto fixtures
###############################################################################
generate_ca_and_leaf() {
    local dir="$1" algo="$2"
    mkdir -p "$dir"

    case "$algo" in
        rsa-2048)
            openssl genrsa -out "$dir/ca.key" 2048 2>/dev/null
            openssl genrsa -out "$dir/leaf.key" 2048 2>/dev/null
            openssl genrsa -out "$dir/standalone.key" 2048 2>/dev/null
            # Generate RSA PUBLIC KEY format for standalone pub
            openssl rsa -in "$dir/standalone.key" -RSAPublicKey_out -out "$dir/standalone.pub" 2>/dev/null
            ;;
        rsa-4096)
            openssl genrsa -out "$dir/ca.key" 4096 2>/dev/null
            openssl genrsa -out "$dir/leaf.key" 4096 2>/dev/null
            openssl genrsa -out "$dir/standalone.key" 4096 2>/dev/null
            openssl rsa -in "$dir/standalone.key" -RSAPublicKey_out -out "$dir/standalone.pub" 2>/dev/null
            ;;
        ec-p256)
            openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key" 2>/dev/null
            openssl ecparam -name prime256v1 -genkey -noout -out "$dir/leaf.key" 2>/dev/null
            openssl ecparam -name prime256v1 -genkey -noout -out "$dir/standalone.key" 2>/dev/null
            openssl pkey -in "$dir/standalone.key" -pubout -out "$dir/standalone.pub" 2>/dev/null
            ;;
        ec-p384)
            openssl ecparam -name secp384r1 -genkey -noout -out "$dir/ca.key" 2>/dev/null
            openssl ecparam -name secp384r1 -genkey -noout -out "$dir/leaf.key" 2>/dev/null
            openssl ecparam -name secp384r1 -genkey -noout -out "$dir/standalone.key" 2>/dev/null
            openssl pkey -in "$dir/standalone.key" -pubout -out "$dir/standalone.pub" 2>/dev/null
            ;;
        ed25519)
            openssl genpkey -algorithm Ed25519 -out "$dir/ca.key" 2>/dev/null
            openssl genpkey -algorithm Ed25519 -out "$dir/leaf.key" 2>/dev/null
            openssl genpkey -algorithm Ed25519 -out "$dir/standalone.key" 2>/dev/null
            openssl pkey -in "$dir/standalone.key" -pubout -out "$dir/standalone.pub" 2>/dev/null
            ;;
    esac

    # Self-signed CA cert (Ed25519 doesn't support -sha256)
    local hash_flag="-sha256"
    if [ "$algo" = "ed25519" ]; then hash_flag=""; fi

    # shellcheck disable=SC2086
    openssl req -new -x509 -key "$dir/ca.key" -out "$dir/ca.crt" \
        -days 365 -subj "/CN=test-ca-${algo}" $hash_flag 2>/dev/null

    # Leaf CSR + cert signed by CA
    # shellcheck disable=SC2086
    openssl req -new -key "$dir/leaf.key" -out "$dir/leaf.csr" \
        -subj "/CN=test-leaf-${algo}" $hash_flag 2>/dev/null
    # shellcheck disable=SC2086
    openssl x509 -req -in "$dir/leaf.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
        -CAcreateserial -out "$dir/leaf.crt" -days 365 $hash_flag 2>/dev/null
    rm -f "$dir/leaf.csr" "$dir/ca.srl"

    # Generate a JWT signed by the CA key
    generate_jwt "$dir/ca.key" "$algo" > "$dir/token"
}

generate_jwt() {
    local key_file="$1" algo="$2"
    local header payload header_payload signature

    case "$algo" in
        rsa-*)
            header=$(echo -n '{"alg":"RS256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
        ec-p256)
            header=$(echo -n '{"alg":"ES256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
        ec-p384)
            header=$(echo -n '{"alg":"ES384","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
        ed25519)
            header=$(echo -n '{"alg":"EdDSA","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
    esac

    payload=$(echo -n '{"sub":"test","iss":"recert-e2e","iat":1700000000}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
    header_payload="${header}.${payload}"

    case "$algo" in
        rsa-*)
            signature=$(echo -n "$header_payload" | openssl dgst -sha256 -sign "$key_file" 2>/dev/null | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
        ec-p256)
            signature=$(echo -n "$header_payload" | openssl dgst -sha256 -sign "$key_file" 2>/dev/null | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
        ec-p384)
            signature=$(echo -n "$header_payload" | openssl dgst -sha384 -sign "$key_file" 2>/dev/null | base64 -w0 | tr '+/' '-_' | tr -d '=')
            ;;
        ed25519)
            # Ed25519 requires pkeyutl -rawin
            local tmpdata
            tmpdata=$(mktemp)
            echo -n "$header_payload" > "$tmpdata"
            signature=$(openssl pkeyutl -sign -inkey "$key_file" -rawin -in "$tmpdata" 2>/dev/null | base64 -w0 | tr '+/' '-_' | tr -d '=')
            rm -f "$tmpdata"
            ;;
    esac

    echo -n "${header_payload}.${signature}"
}

verify_jwt() {
    local token_file="$1" key_file="$2" algo="$3"
    local token header_b64 sig_b64 header_payload

    token=$(cat "$token_file")
    header_b64=$(echo "$token" | cut -d. -f1)
    sig_b64=$(echo "$token" | cut -d. -f3)
    header_payload="$(echo "$token" | cut -d. -f1).$(echo "$token" | cut -d. -f2)"

    # Extract the public key from the private key
    local pubkey_file
    pubkey_file=$(mktemp)
    openssl pkey -in "$key_file" -pubout -out "$pubkey_file" 2>/dev/null

    # Decode the signature from base64url
    local sig_file data_file
    sig_file=$(mktemp)
    data_file=$(mktemp)

    # Pad base64url to standard base64
    local padded
    padded=$(echo -n "$sig_b64" | tr -- '-_' '+/')
    local mod4=$((${#padded} % 4))
    if [ "$mod4" -eq 2 ]; then padded="${padded}=="; fi
    if [ "$mod4" -eq 3 ]; then padded="${padded}="; fi

    echo -n "$padded" | base64 -d > "$sig_file" 2>/dev/null
    echo -n "$header_payload" > "$data_file"

    local result=1
    case "$algo" in
        rsa-*|ec-p256)
            openssl dgst -sha256 -verify "$pubkey_file" -signature "$sig_file" "$data_file" >/dev/null 2>&1&& result=0
            ;;
        ec-p384)
            openssl dgst -sha384 -verify "$pubkey_file" -signature "$sig_file" "$data_file" >/dev/null 2>&1 && result=0
            ;;
        ed25519)
            openssl pkeyutl -verify -inkey "$pubkey_file" -pubin -rawin -in "$data_file" -sigfile "$sig_file" >/dev/null 2>&1 && result=0
            ;;
    esac

    rm -f "$pubkey_file" "$sig_file" "$data_file"
    return $result
}

echo ""
echo "=== Generating crypto fixtures ==="

for algo in rsa-2048 rsa-4096 ec-p256 ec-p384 ed25519; do
    echo "  Generating ${algo}..."
    generate_ca_and_leaf "$TMPDIR/$algo" "$algo"
done

# Save copies of originals for comparison
cp -a "$TMPDIR" "${TMPDIR}.orig"

###############################################################################
# Run recert
###############################################################################
echo ""
echo "=== Running recert ==="

# Run recert against the crypto dir (no etcd)
if ! "$BINARY" --crypto-dir "$TMPDIR" 2>"${TMPDIR}.stderr"; then
    echo "recert failed! stderr:"
    cat "${TMPDIR}.stderr"
    exit 1
fi
echo "  recert completed successfully"

###############################################################################
# Verification
###############################################################################
echo ""
echo "=== Verifying results ==="

for algo in rsa-2048 rsa-4096 ec-p256 ec-p384 ed25519; do
    echo ""
    echo "--- ${algo} ---"
    dir="$TMPDIR/$algo"
    orig="${TMPDIR}.orig/$algo"

    # 1. All key files should have changed
    for f in ca.key leaf.key standalone.key; do
        if ! diff -q "$dir/$f" "$orig/$f" >/dev/null 2>&1; then
            pass "${algo}/${f} was regenerated"
        else
            fail "${algo}/${f} was NOT regenerated (unchanged)"
        fi
    done

    # 2. All cert files should have changed
    for f in ca.crt leaf.crt; do
        if ! diff -q "$dir/$f" "$orig/$f" >/dev/null 2>&1; then
            pass "${algo}/${f} was regenerated"
        else
            fail "${algo}/${f} was NOT regenerated (unchanged)"
        fi
    done

    # 3. Certs should be valid
    for f in ca.crt leaf.crt; do
        if openssl x509 -in "$dir/$f" -noout 2>/dev/null; then
            pass "${algo}/${f} is valid X.509"
        else
            fail "${algo}/${f} is NOT valid X.509"
        fi
    done

    # 4. Leaf cert should verify against CA
    if openssl verify -no_check_time -CAfile "$dir/ca.crt" "$dir/leaf.crt" >/dev/null 2>&1; then
        pass "${algo}/leaf.crt verifies against CA"
    else
        fail "${algo}/leaf.crt does NOT verify against CA"
    fi

    # 5. Standalone public key should have changed
    if ! diff -q "$dir/standalone.pub" "$orig/standalone.pub" >/dev/null 2>&1; then
        pass "${algo}/standalone.pub was regenerated"
    else
        fail "${algo}/standalone.pub was NOT regenerated (unchanged)"
    fi

    # 6. Key type preservation
    case "$algo" in
        rsa-*)
            if grep -q "RSA PRIVATE KEY\|BEGIN PRIVATE KEY" "$dir/ca.key"; then
                pass "${algo}/ca.key is RSA"
            else
                fail "${algo}/ca.key is NOT RSA"
            fi
            ;;
        ec-*)
            if grep -q "EC PRIVATE KEY\|BEGIN PRIVATE KEY" "$dir/ca.key"; then
                pass "${algo}/ca.key is EC"
            else
                fail "${algo}/ca.key is NOT EC"
            fi
            ;;
        ed25519)
            if grep -q "BEGIN PRIVATE KEY" "$dir/ca.key"; then
                pass "${algo}/ca.key is PKCS#8 (Ed25519)"
            else
                fail "${algo}/ca.key is NOT PKCS#8 (Ed25519)"
            fi
            ;;
    esac

    # 7. JWT should have changed
    if [ -f "$dir/token" ]; then
        if ! diff -q "$dir/token" "$orig/token" >/dev/null 2>&1; then
            pass "${algo}/token was re-signed"
        else
            fail "${algo}/token was NOT re-signed (unchanged)"
        fi

        # Verify JWT signature against the new CA key
        if verify_jwt "$dir/token" "$dir/ca.key" "$algo"; then
            pass "${algo}/token verifies against new CA key"
        else
            fail "${algo}/token does NOT verify against new CA key"
        fi
    fi
done

###############################################################################
# Summary
###############################################################################
echo ""
echo "=============================="
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
echo "All tests passed!"

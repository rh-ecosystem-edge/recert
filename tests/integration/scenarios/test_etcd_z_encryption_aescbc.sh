#!/usr/bin/env bash
# aescbc encryption round-trip, written as a key rotation from the aesgcm scenario's
# key "1" to aescbc key "2": recert encrypts with the first provider and decrypts
# with all of them, so this passes on its own (plaintext keyspace) and after
# test_etcd_z_encryption (aesgcm keyspace), which sorts first.

set -euo pipefail

aescbc_key_b64="IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
run_encryption_roundtrip aescbc aescbc 'k8s:enc:aescbc:v1:2:' '{
  "kind": "EncryptionConfiguration",
  "apiVersion": "apiserver.config.k8s.io/v1",
  "resources": [
    {
      "resources": ["secrets"],
      "providers": [
        {"aescbc": {"keys": [{"name": "2", "secret": "'"${aescbc_key_b64}"'"}]}},
        {"aesgcm": {"keys": [{"name": "1", "secret": "ERERERERERERERERERERERERERERERERERERERERERE="}]}},
        {"identity": {}}
      ]
    }
  ]
}'

# Independently decrypt the stored value (prefix || 16-byte IV || AES-256-CBC ciphertext
# with PKCS#7 padding) to prove it is real aescbc, not just a matching prefix.
plaintext=$(etcdctl get --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/default/app-tls-enc-aescbc -w json \
    | python3 -c '
import base64, json, subprocess, sys
raw = base64.b64decode(json.load(sys.stdin)["kvs"][0]["value"])
prefix = b"k8s:enc:aescbc:v1:2:"
assert raw.startswith(prefix), raw[:32]
body = raw[len(prefix):]
iv, ct = body[:16], body[16:]
key = base64.b64decode(sys.argv[1])
pt = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()],
                    input=ct, capture_output=True, check=True).stdout
sys.stdout.write(pt.decode("latin-1"))
' "$aescbc_key_b64" | tr -d '\0')
assert_contains "$plaintext" "app-tls-enc-aescbc" "aescbc ciphertext should decrypt to the Secret with the configured key"
assert_contains "$plaintext" "BEGIN CERTIFICATE" "decrypted Secret should carry the regenerated certificate"

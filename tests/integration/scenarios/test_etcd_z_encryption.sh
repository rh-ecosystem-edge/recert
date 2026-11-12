#!/usr/bin/env bash
# aesgcm encryption round-trip. Re-encrypts the whole shared keyspace, so it is named
# test_etcd_z_* to sort after every other serial scenario.

set -euo pipefail

run_encryption_roundtrip aesgcm aesgcm 'k8s:enc:aesgcm:v1:1:' '{
  "kind": "EncryptionConfiguration",
  "apiVersion": "apiserver.config.k8s.io/v1",
  "resources": [
    {
      "resources": ["secrets"],
      "providers": [
        {"aesgcm": {"keys": [{"name": "1", "secret": "ERERERERERERERERERERERERERERERERERERERERERE="}]}},
        {"identity": {}}
      ]
    }
  ]
}'

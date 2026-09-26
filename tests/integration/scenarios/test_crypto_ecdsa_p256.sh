#!/usr/bin/env bash

set -euo pipefail

run_crypto_algo_test "ECDSA P-256" "ec-p256" "id-ecPublicKey" "prime256v1"

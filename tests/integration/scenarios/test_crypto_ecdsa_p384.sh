#!/usr/bin/env bash

set -euo pipefail

run_crypto_algo_test "ECDSA P-384" "ec-p384" "id-ecPublicKey" "secp384r1"

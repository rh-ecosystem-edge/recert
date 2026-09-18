#!/usr/bin/env bash

set -euo pipefail

run_jwt_algo_test "EdDSA" "ed25519-ca.crt" "ed25519-ca.key" "jwt-eddsa" "EdDSA"

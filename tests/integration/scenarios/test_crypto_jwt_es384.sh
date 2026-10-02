#!/usr/bin/env bash

set -euo pipefail

run_jwt_algo_test "ES384" "ec-p384-ca.crt" "ec-p384-ca.key" "jwt-es384" "ES384"

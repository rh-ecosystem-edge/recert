#!/usr/bin/env bash

set -euo pipefail

run_jwt_algo_test "ES256" "ec-p256-ca.crt" "ec-p256-ca.key" "jwt-es256" "ES256"

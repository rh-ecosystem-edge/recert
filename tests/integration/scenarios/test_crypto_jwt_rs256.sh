#!/usr/bin/env bash

set -euo pipefail

run_jwt_algo_test "RS256" "ca.crt" "ca.key" "jwt-rs256" "RS256"

#!/bin/bash
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPENSHIFT_ORIGIN_DIR=${OPENSHIFT_ORIGIN_DIR:-"$SCRIPT_DIR/../origin"}

jq --slurp --from-file ownership.jq <(yq "$SCRIPT_DIR/summary.yaml" -oj) "${OPENSHIFT_ORIGIN_DIR}/tls/ownership/tls-ownership.json"

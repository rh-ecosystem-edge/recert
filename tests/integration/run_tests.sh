#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${RECERT_BIN:?RECERT_BIN must be set to the path of the recert binary}"
: "${FIXTURES_DIR:=${SCRIPT_DIR}/fixtures/generated}"
export RECERT_BIN FIXTURES_DIR

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/recert-integration-tests}"
mkdir -p "$ARTIFACTS_DIR"
export ARTIFACTS_DIR

source "${SCRIPT_DIR}/lib/helpers.sh"

TAG_FILTER=""
EXCLUDE_TAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            TAG_FILTER="$2"
            shift 2
            ;;
        --exclude-tag)
            EXCLUDE_TAG="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

echo "Running integration tests..."
echo "  Binary:   $RECERT_BIN"
echo "  Fixtures: $FIXTURES_DIR"
echo "  Artifacts: $ARTIFACTS_DIR"
[[ -n "$TAG_FILTER" ]] && echo "  Tag filter: $TAG_FILTER"
[[ -n "$EXCLUDE_TAG" ]] && echo "  Exclude tag: $EXCLUDE_TAG"
echo ""

for test_script in "${SCRIPT_DIR}"/scenarios/test_*.sh; do
    test_name="$(basename "$test_script" .sh)"

    if [[ -n "$TAG_FILTER" && "$test_name" != test_${TAG_FILTER}_* ]]; then
        continue
    fi

    if [[ -n "$EXCLUDE_TAG" && "$test_name" == test_${EXCLUDE_TAG}_* ]]; then
        continue
    fi

    set +e
    (
        set -euo pipefail
        source "${SCRIPT_DIR}/lib/helpers.sh"
        source "$test_script"
    )
    rc=$?
    set -e
    record_result "$test_name" "$rc"
done

print_summary

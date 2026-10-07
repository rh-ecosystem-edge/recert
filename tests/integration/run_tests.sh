#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${RECERT_BIN:?RECERT_BIN must be set to the path of the recert binary}"
: "${FIXTURES_DIR:=${SCRIPT_DIR}/fixtures/generated}"
export RECERT_BIN FIXTURES_DIR

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/tmp/recert-integration-tests}"
mkdir -p "$ARTIFACTS_DIR"
export ARTIFACTS_DIR

RESULTS_DIR="${ARTIFACTS_DIR}/.results"
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

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

TEST_TIMEOUT="${TEST_TIMEOUT:-300}"
MAX_PARALLEL="${MAX_PARALLEL:-4}"
SUITE_START=$(date +%s)

is_serial_test() {
    local name="$1"
    [[ "$name" == test_etcd_* && "$name" != "test_etcd_bad_endpoint" ]]
}

run_one_test() {
    local test_script="$1"
    local test_name="$2"
    local start_time
    start_time=$(date +%s)

    set +e
    timeout "$TEST_TIMEOUT" bash -c "
        set -euo pipefail
        source '${SCRIPT_DIR}/lib/helpers.sh'
        source '$test_script'
    " > "${RESULTS_DIR}/${test_name}.log" 2>&1
    local rc=$?
    set -e

    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    echo "$elapsed" > "${RESULTS_DIR}/${test_name}.time"
    if [[ $rc -eq 124 ]]; then
        echo "TIMEOUT" > "${RESULTS_DIR}/${test_name}.status"
    fi
    report_progress "$test_name" "$rc" "$elapsed"
}

render_bar() {
    local completed="$1" failed="$2"
    local width=30
    local filled=$((completed * width / TOTAL_TESTS))
    local suite_elapsed=$(($(date +%s) - SUITE_START))
    local done_part todo_part
    printf -v done_part '%*s' "$filled" ''
    printf -v todo_part '%*s' $((width - filled)) ''
    printf '[%s%s] %3d/%d  (%d failed)  %dm%02ds' "${done_part// /#}" "${todo_part// /-}" \
        "$completed" "$TOTAL_TESTS" "$failed" \
        $((suite_elapsed / 60)) $((suite_elapsed % 60))
}

# The .rc file is written under the lock so that the completed count is exact
# even when parallel tests finish at the same moment.
report_progress() {
    local test_name="$1" rc="$2" elapsed="$3"
    local status="PASS"
    if [[ $rc -eq 124 ]]; then
        status="TIMEOUT"
    elif [[ $rc -ne 0 ]]; then
        status="FAIL"
    fi

    (
        flock 9
        echo "$rc" > "${RESULTS_DIR}/${test_name}.rc"
        rc_files=("$RESULTS_DIR"/*.rc)
        printf -v line '[%2d/%d] %-7s %s (%ss)' "${#rc_files[@]}" "$TOTAL_TESTS" "$status" "$test_name" "$elapsed"
        if [[ -n "$SHOW_BAR" ]]; then
            failed=0
            for f in "${rc_files[@]}"; do
                [[ "$(<"$f")" == 0 ]] || failed=$((failed + 1))
            done
            printf '\r\033[K%s\n' "$line"
            render_bar "${#rc_files[@]}" "$failed"
        else
            echo "$line"
        fi
    ) 9>"${RESULTS_DIR}/.progress.lock"
}

parallel_tests=()
serial_tests=()

for test_script in "${SCRIPT_DIR}"/scenarios/test_*.sh; do
    test_name="$(basename "$test_script" .sh)"

    if [[ -n "$TAG_FILTER" && "$test_name" != test_${TAG_FILTER}_* ]]; then
        continue
    fi

    if [[ -n "$EXCLUDE_TAG" && "$test_name" == test_${EXCLUDE_TAG}_* ]]; then
        continue
    fi

    if is_serial_test "$test_name"; then
        serial_tests+=("$test_script")
    else
        parallel_tests+=("$test_script")
    fi
done

TOTAL_TESTS=$((${#parallel_tests[@]} + ${#serial_tests[@]}))
SHOW_BAR=""
[[ -t 1 ]] && SHOW_BAR=1
echo "Running ${TOTAL_TESTS} tests (${#parallel_tests[@]} parallel x${MAX_PARALLEL}, ${#serial_tests[@]} serial)"
[[ -n "$SHOW_BAR" && $TOTAL_TESTS -gt 0 ]] && render_bar 0 0

running=0
for test_script in "${parallel_tests[@]}"; do
    test_name="$(basename "$test_script" .sh)"
    run_one_test "$test_script" "$test_name" &
    running=$((running + 1))

    if [[ $running -ge $MAX_PARALLEL ]]; then
        wait -n 2>/dev/null || true
        running=$((running - 1))
    fi
done
wait

for test_script in "${serial_tests[@]}"; do
    test_name="$(basename "$test_script" .sh)"
    run_one_test "$test_script" "$test_name"
done

SUITE_END=$(date +%s)
SUITE_ELAPSED=$((SUITE_END - SUITE_START))
[[ -n "$SHOW_BAR" ]] && printf '\n'
echo ""

for rc_file in "$RESULTS_DIR"/*.rc; do
    [[ -f "$rc_file" ]] || continue
    test_name="$(basename "$rc_file" .rc)"
    rc="$(cat "$rc_file")"
    elapsed="$(cat "${RESULTS_DIR}/${test_name}.time" 2>/dev/null || echo "?")"
    if [[ -f "${RESULTS_DIR}/${test_name}.status" ]]; then
        echo "  TIMEOUT: $test_name (exceeded ${TEST_TIMEOUT}s)" >&2
    fi
    if [[ $rc -eq 0 ]]; then
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "  PASS: $test_name (${elapsed}s)"
    else
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        echo "  FAIL: $test_name (${elapsed}s)"
    fi
done

echo ""
echo "=============================="
echo "Integration Test Results"
echo "=============================="
echo "Total:  $TESTS_TOTAL"
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo "Elapsed: ${SUITE_ELAPSED}s"
if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
fi
echo "=============================="
exit $TESTS_FAILED

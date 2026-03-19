#!/bin/bash
# Capture a baseline verification snapshot for Phase 0 safety rails.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [ -f "${ROOT_DIR}/scripts/load_profile.sh" ]; then
    # shellcheck disable=SC1091
    . "${ROOT_DIR}/scripts/load_profile.sh"
    SENTINEL_PROFILE=baseline sentinel_load_profile "${ROOT_DIR}" >/dev/null || true
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${ROOT_DIR}/benchmarks/baselines"
REPORT_FILE="${OUT_DIR}/baseline_${STAMP}.md"
mkdir -p "${OUT_DIR}"

FAILURES=0
RESULTS=()

run_check() {
    local name cmd
    name="$1"
    cmd="$2"

    if bash -lc "${cmd}" >/tmp/sentinel_baseline_${name}.log 2>&1; then
        RESULTS+=("- ${name}: PASS")
    else
        RESULTS+=("- ${name}: FAIL")
        FAILURES=$((FAILURES + 1))
    fi
}

run_check "c_build_and_tests" "cd '${ROOT_DIR}' && make -j2 && make test"
run_check "python_compile" "cd '${ROOT_DIR}' && python3 -m py_compile explain_api.py train_ml.py"
run_check "frontend_lint" "cd '${ROOT_DIR}/frontend' && npm run lint"
run_check "frontend_build" "cd '${ROOT_DIR}/frontend' && npm run build"

{
    echo "# Sentinel Baseline Snapshot"
    echo
    echo "- Timestamp: ${STAMP}"
    echo "- Root: ${ROOT_DIR}"
    echo "- Profile: ${SENTINEL_INTEGRATION_PROFILE:-baseline}"
    echo "- Failures: ${FAILURES}"
    echo
    echo "## Integration Flags"
    echo
    echo "- SENTINEL_INTEGRATION_PROFILE=${SENTINEL_INTEGRATION_PROFILE:-unset}"
    echo "- SENTINEL_ENABLE_INTEL_FEED=${SENTINEL_ENABLE_INTEL_FEED:-unset}"
    echo "- SENTINEL_ENABLE_MODEL_EXTENSION=${SENTINEL_ENABLE_MODEL_EXTENSION:-unset}"
    echo "- SENTINEL_ENABLE_CONTROLLER_EXTENSION=${SENTINEL_ENABLE_CONTROLLER_EXTENSION:-unset}"
    echo "- SENTINEL_ENABLE_SIGNATURE_FEED=${SENTINEL_ENABLE_SIGNATURE_FEED:-unset}"
    echo "- SENTINEL_ENABLE_DATAPLANE_EXTENSION=${SENTINEL_ENABLE_DATAPLANE_EXTENSION:-unset}"
    echo
    echo "## Results"
    echo
    printf '%s\n' "${RESULTS[@]}"
    echo
    echo "## Logs"
    echo
    echo "- /tmp/sentinel_baseline_c_build_and_tests.log"
    echo "- /tmp/sentinel_baseline_python_compile.log"
    echo "- /tmp/sentinel_baseline_frontend_lint.log"
    echo "- /tmp/sentinel_baseline_frontend_build.log"
} >"${REPORT_FILE}"

echo "[BASELINE] Snapshot written: ${REPORT_FILE}"

if [ "${FAILURES}" -gt 0 ]; then
    echo "[BASELINE] One or more checks failed."
    exit 1
fi

echo "[BASELINE] All checks passed."
exit 0

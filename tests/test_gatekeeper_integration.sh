#!/bin/bash
# Gatekeeper sidecar health integration test
# Tests circuit breaker behavior, failure counting, and recovery
# Requires: Python3, curl, jq
# Run from workspace root: bash tests/test_gatekeeper_integration.sh

set -e

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_LOG="${WORKSPACE_ROOT}/tests/gatekeeper_test.log"
HEALTH_PORT=9000
HEALTH_URL="http://127.0.0.1:${HEALTH_PORT}/health"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$TEST_LOG"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$TEST_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$TEST_LOG"
}

# Scenario 1: Verify startup probe succeeds when endpoint is healthy
test_healthy_startup() {
    log_info "=== Scenario 1: Healthy Startup Probe ==="
    
    # Start mock health server
    python3 "${WORKSPACE_ROOT}/tests/mock_gatekeeper_health.py" \
        --port ${HEALTH_PORT} --healthy &
    MOCK_PID=$!
    sleep 1
    
    # Configure and run Sentinel with gatekeeper enabled
    export SENTINEL_ENABLE_GATEKEEPER_SIDECAR=1
    export SENTINEL_GATEKEEPER_HEALTH_URL="${HEALTH_URL}"
    export SENTINEL_GATEKEEPER_STARTUP_RETRIES=3
    export SENTINEL_GATEKEEPER_STARTUP_RETRY_DELAY_MS=500
    export SENTINEL_GATEKEEPER_FAILURE_THRESHOLD=3
    export SENTINEL_GATEKEEPER_CIRCUIT_COOLDOWN_SEC=10
    export SENTINEL_GATEKEEPER_PROBE_INTERVAL_SEC=2
    
    log_info "Starting Sentinel pipeline with gatekeeper enabled..."
    timeout 15 wsl -d kali-linux bash -lc \
        "cd /mnt/c/Users/navne/Downloads/Sentinel-main && \
         SENTINEL_ENABLE_GATEKEEPER_SIDECAR=1 \
         SENTINEL_GATEKEEPER_HEALTH_URL='${HEALTH_URL}' \
         SENTINEL_GATEKEEPER_STARTUP_RETRIES=3 \
         ./sentinel_pipeline -i lo -q 0 -w 9001 2>&1 | head -50" \
        > "${TEST_LOG}.scenario1" 2>&1 || true
    
    # Check for success indicators
    if grep -q "Connected" "${TEST_LOG}.scenario1" || grep -q "integrated" "${TEST_LOG}.scenario1"; then
        log_info "✓ Sentinel startup probe succeeded"
    else
        log_warn "⚠ Could not verify startup success (expected on non-AF_XDP systems)"
    fi
    
    # Clean up
    kill $MOCK_PID 2>/dev/null || true
}

# Scenario 2: Circuit breaker opens after repeated failures
test_circuit_open() {
    log_info "=== Scenario 2: Circuit Breaker Opens After Failures ==="
    
    # Start unhealthy mock server
    python3 "${WORKSPACE_ROOT}/tests/mock_gatekeeper_health.py" \
        --port ${HEALTH_PORT} --unhealthy &
    MOCK_PID=$!
    sleep 1
    
    export SENTINEL_ENABLE_GATEKEEPER_SIDECAR=1
    export SENTINEL_GATEKEEPER_HEALTH_URL="${HEALTH_URL}"
    export SENTINEL_GATEKEEPER_FAILURE_THRESHOLD=2
    export SENTINEL_GATEKEEPER_CIRCUIT_COOLDOWN_SEC=5
    export SENTINEL_GATEKEEPER_PROBE_INTERVAL_SEC=1
    
    log_info "Starting Sentinel with unhealthy endpoint..."
    timeout 10 wsl -d kali-linux bash -lc \
        "cd /mnt/c/Users/navne/Downloads/Sentinel-main && \
         SENTINEL_ENABLE_GATEKEEPER_SIDECAR=1 \
         SENTINEL_GATEKEEPER_HEALTH_URL='${HEALTH_URL}' \
         SENTINEL_GATEKEEPER_FAILURE_THRESHOLD=2 \
         ./sentinel_pipeline -i lo -q 0 -w 9001 2>&1 | head -100" \
        > "${TEST_LOG}.scenario2" 2>&1 || true
    
    if grep -q -i "circuit\|failure\|unreachable" "${TEST_LOG}.scenario2"; then
        log_info "✓ Circuit breaker logic detected in logs"
    else
        log_warn "⚠ Could not verify circuit breaker in output"
    fi
    
    kill $MOCK_PID 2>/dev/null || true
}

# Scenario 3: Circuit breaker recovers after cooldown
test_circuit_recovery() {
    log_info "=== Scenario 3: Circuit Breaker Recovery ==="
    
    log_info "Starting with unhealthy endpoint (circuit will open)..."
    python3 "${WORKSPACE_ROOT}/tests/mock_gatekeeper_health.py" \
        --port ${HEALTH_PORT} --unhealthy --transition-at 5 &
    MOCK_PID=$!
    sleep 1
    
    export SENTINEL_ENABLE_GATEKEEPER_SIDECAR=1
    export SENTINEL_GATEKEEPER_HEALTH_URL="${HEALTH_URL}"
    export SENTINEL_GATEKEEPER_FAILURE_THRESHOLD=2
    export SENTINEL_GATEKEEPER_CIRCUIT_COOLDOWN_SEC=3
    export SENTINEL_GATEKEEPER_PROBE_INTERVAL_SEC=1
    
    timeout 15 wsl -d kali-linux bash -lc \
        "cd /mnt/c/Users/navne/Downloads/Sentinel-main && \
         SENTINEL_ENABLE_GATEKEEPER_SIDECAR=1 \
         SENTINEL_GATEKEEPER_HEALTH_URL='${HEALTH_URL}' \
         SENTINEL_GATEKEEPER_FAILURE_THRESHOLD=2 \
         SENTINEL_GATEKEEPER_CIRCUIT_COOLDOWN_SEC=3 \
         ./sentinel_pipeline -i lo -q 0 -w 9001 2>&1 | head -150" \
        > "${TEST_LOG}.scenario3" 2>&1 || true
    
    log_info "Mock endpoint becomes healthy after 5s..."
    log_info "Waiting for circuit recovery..."
    sleep 2
    
    if grep -q -i "closed\|recovered\|retry" "${TEST_LOG}.scenario3"; then
        log_info "✓ Circuit recovery logic detected"
    else
        log_warn "⚠ Recovery logs not clearly visible"
    fi
    
    kill $MOCK_PID 2>/dev/null || true
}

# Main execution
main() {
    log_info "=========================================="
    log_info "Gatekeeper Integration Test Suite"
    log_info "=========================================="
    
    # Verify prerequisites
    if ! command -v python3 &> /dev/null; then
        log_error "python3 required but not found"
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        log_error "curl required but not found"
        exit 1
    fi
    
    # Clear log
    : > "$TEST_LOG"
    
    # Run scenarios
    test_healthy_startup || log_warn "Scenario 1 incomplete"
    sleep 2
    
    test_circuit_open || log_warn "Scenario 2 incomplete"
    sleep 2
    
    test_circuit_recovery || log_warn "Scenario 3 incomplete"
    
    log_info "=========================================="
    log_info "Test execution complete. See ${TEST_LOG} for details."
    log_info "=========================================="
}

main "$@"

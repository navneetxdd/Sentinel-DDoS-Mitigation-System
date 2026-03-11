#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="$ROOT_DIR/benchmarks/results/$(date +%Y%m%d_%H%M%S)"
OF_PORT="${OF_PORT:-6653}"
mkdir -p "$RESULTS_DIR"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[FAIL] Missing required command: $1" >&2
    exit 1
  }
}

require_cmd curl
require_cmd python3
require_cmd mn

if [[ $EUID -ne 0 ]]; then
  echo "[FAIL] Run as root: sudo benchmarks/run_mininet_benchmark.sh"
  exit 1
fi

cleanup() {
  set +e
  if [[ -n "${RYU_PID:-}" ]]; then
    kill "$RYU_PID" >/dev/null 2>&1 || true
    wait "$RYU_PID" >/dev/null 2>&1 || true
  fi
  mn -c >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[0/6] Pre-clean Mininet state"
mn -c >/dev/null 2>&1 || true

echo "[0/6] Checking Open vSwitch availability"
if ! ovs-vsctl show >/dev/null 2>&1; then
  echo "[FAIL] Open vSwitch is not available/running."
  echo "       Install/start OVS, then retry benchmark."
  echo "       Example: sudo apt install -y openvswitch-switch && sudo service openvswitch-switch start"
  exit 1
fi

echo "[1/6] Building project"
make -C "$ROOT_DIR" -j4 >/dev/null

echo "[2/6] Starting controller"
python3 "$ROOT_DIR/start_ryu.py" >"$RESULTS_DIR/ryu.log" 2>&1 &
RYU_PID=$!

for _ in {1..20}; do
  if curl -sSf "http://127.0.0.1:8080/stats/switches" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -sSf "http://127.0.0.1:8080/stats/switches" >/dev/null

echo "[3/6] Baseline connectivity run (pingall)"
mn --topo single,3 \
  --controller=remote,ip=127.0.0.1,port="$OF_PORT" \
  --switch ovs,protocols=OpenFlow13 \
  --wait \
  --test pingall >"$RESULTS_DIR/baseline_pingall.log" 2>&1

BASELINE_DROP="$(grep -oE '[0-9]+% dropped' "$RESULTS_DIR/baseline_pingall.log" | tail -n1 | awk '{print $1}' || echo "NA")"

echo "[4/6] Flow operation benchmark during active topology"
cat >"$RESULTS_DIR/post.cli" <<EOF
sh "$ROOT_DIR/test_ryu_integration.sh" >/tmp/benchmark_ryu_test.out 2>/tmp/benchmark_ryu_test.err
EOF

mn --topo single,3 \
  --controller=remote,ip=127.0.0.1,port="$OF_PORT" \
  --switch ovs,protocols=OpenFlow13 \
  --wait \
  --test none \
  --post "$RESULTS_DIR/post.cli" >"$RESULTS_DIR/flow_ops.log" 2>&1

cp /tmp/benchmark_ryu_test.out "$RESULTS_DIR/ryu_integration.out" 2>/dev/null || true
cp /tmp/benchmark_ryu_test.err "$RESULTS_DIR/ryu_integration.err" 2>/dev/null || true

echo "[5/6] Collecting controller snapshots"
curl -sS "http://127.0.0.1:8080/stats/switches" >"$RESULTS_DIR/switches.json" || true
curl -sS "http://127.0.0.1:8080/stats/flow/1" >"$RESULTS_DIR/flows_dpid1.json" || true

FLOW_COUNT="$( (grep -o '"cookie":' "$RESULTS_DIR/flows_dpid1.json" 2>/dev/null || true) | wc -l | tr -d ' ' )"
if [[ -z "$FLOW_COUNT" ]]; then FLOW_COUNT="0"; fi

echo "[6/6] Writing summary"
INTEGRATION_PASSED=0
if grep -q "All tests passed" "$RESULTS_DIR/ryu_integration.out" 2>/dev/null; then
  INTEGRATION_PASSED=1
fi

cat >"$RESULTS_DIR/summary.csv" <<EOF
metric,value
baseline_ping_drop,$BASELINE_DROP
controller_flow_count_dpid1,$FLOW_COUNT
integration_script_passed,$INTEGRATION_PASSED
EOF

cat >"$RESULTS_DIR/README.txt" <<EOF
Benchmark run completed.

Artifacts:
- baseline_pingall.log
- flow_ops.log
- ryu.log
- ryu_integration.out / ryu_integration.err
- switches.json
- flows_dpid1.json
- summary.csv

Interpretation:
- baseline_ping_drop: packet loss during baseline pingall test
- controller_flow_count_dpid1: flow entries visible after benchmark
- integration_script_passed: 1 if test_ryu_integration.sh reported success
EOF

echo "[OK] Benchmark artifacts written to: $RESULTS_DIR"

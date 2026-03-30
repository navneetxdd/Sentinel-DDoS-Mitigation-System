#!/usr/bin/env bash
set -euo pipefail

TARGET=""
DURATION=20
MODE="udp"
PPS=10000
PORT=80

usage() {
  cat <<EOF
Usage: $0 --target <ip-or-host> [--duration 20] [--mode udp|syn|icmp] [--pps 10000] [--port 80]

Runs external flood traffic against Sentinel target for verification.
Run this from a separate host outside the Sentinel node.

Examples:
  $0 --target 203.0.113.10 --mode udp --duration 30 --pps 20000 --port 80
  $0 --target 203.0.113.10 --mode syn --duration 15 --pps 5000 --port 443
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --pps) PPS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Missing --target"
  usage
  exit 1
fi

if ! [[ "$PPS" =~ ^[0-9]+$ ]] || [[ "$PPS" -le 0 ]]; then
  echo "--pps must be a positive integer"
  exit 1
fi

HPING_INTERVAL_US=$((1000000 / PPS))
if [[ "$HPING_INTERVAL_US" -lt 1 ]]; then
  HPING_INTERVAL_US=1
fi

if ! command -v hping3 >/dev/null 2>&1; then
  echo "hping3 is required. Install with: sudo apt install -y hping3"
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0 --target <ip> ..."
  exit 1
fi

echo "Starting external flood test"
echo "  target   : $TARGET"
echo "  mode     : $MODE"
echo "  duration : ${DURATION}s"
echo "  pps      : $PPS"
echo "  port     : $PORT"

case "$MODE" in
  udp)
    timeout "$DURATION" hping3 --udp -p "$PORT" -i "u${HPING_INTERVAL_US}" "$TARGET" >/dev/null 2>&1 || true
    ;;
  syn)
    timeout "$DURATION" hping3 -S -p "$PORT" -i "u${HPING_INTERVAL_US}" "$TARGET" >/dev/null 2>&1 || true
    ;;
  icmp)
    timeout "$DURATION" hping3 -1 -i "u${HPING_INTERVAL_US}" "$TARGET" >/dev/null 2>&1 || true
    ;;
  *)
    echo "Unsupported mode: $MODE"
    exit 1
    ;;
esac

echo "Flood generation completed."
echo "Verify on Sentinel host:"
echo "  1) Watch pipeline logs for detections/mitigations"
echo "  2) Confirm WebSocket metrics pps/bps spike and blocked/rate-limited updates"
echo "  3) Confirm SDN rules via controller API (if enabled)"

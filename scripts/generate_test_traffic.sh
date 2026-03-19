#!/usr/bin/env bash
# Generate test traffic for integration testing (Mininet + hping3).
# Use only for test harness; production training uses real datasets (CIC, UNSW, etc.).
# Requires: Mininet topology running, hping3 installed.
# Usage: ./scripts/generate_test_traffic.sh [duration_sec]

set -e
DURATION="${1:-60}"
echo "[*] Generating test traffic for ${DURATION}s (SYN, UDP, ICMP). Use for integration tests only."

# Optional: start a short burst of each type. Uncomment and adjust interface/target for your topology.
# hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood -c 1000 10.0.0.2 &
# hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood -c 500 10.0.0.2 &
# hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood -c 500 10.0.0.2 &
# sleep "$DURATION"
# kill 0 2>/dev/null || true

echo "[*] Script ready. Run Mininet topology and hping3 commands manually for your test target."
echo "    Example (SYN flood): hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood <target_ip>"
echo "    Example (UDP flood): hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood <target_ip>"
echo "    Example (ICMP flood): hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood <target_ip>"

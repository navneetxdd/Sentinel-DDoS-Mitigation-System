#!/usr/bin/env bash
# Optional incident PCAP capture: run tcpdump when mitigation is triggered.
# Set SENTINEL_PCAP_INTERFACE and SENTINEL_PCAP_DIR; call this script from your
# mitigation hook or run it manually during an incident.
# Usage: SENTINEL_PCAP_INTERFACE=eth0 SENTINEL_PCAP_DIR=/var/lib/sentinel/captures ./scripts/incident_pcap.sh [duration_sec]

set -e
INTERFACE="${SENTINEL_PCAP_INTERFACE:-eth0}"
CAPDIR="${SENTINEL_PCAP_DIR:-./captures}"
DURATION="${1:-120}"
STAMP=$(date +%Y%m%d-%H%M%S)
PCAP="${CAPDIR}/incident_${STAMP}.pcap"
mkdir -p "$CAPDIR"
echo "[*] Capturing on ${INTERFACE} for ${DURATION}s -> ${PCAP}"
timeout "$DURATION" tcpdump -i "$INTERFACE" -w "$PCAP" -s 96 2>/dev/null || true
echo "[*] Capture written: ${PCAP}"

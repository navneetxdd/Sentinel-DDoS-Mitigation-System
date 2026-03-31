#!/usr/bin/env bash
set -euo pipefail

# Non-destructive guide for external bridge-mode topology on Kali/Linux.
# This script does not reconfigure networking; it prints verified commands.

EXT_IFACE="${1:-}"

if [[ -z "$EXT_IFACE" ]]; then
  EXT_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
fi

if [[ -z "$EXT_IFACE" ]]; then
  echo "Unable to detect default external interface."
  echo "Usage: $0 <external-iface>"
  exit 1
fi

echo "Bridge-mode topology guide"
echo "Detected external interface: $EXT_IFACE"
echo ""
echo "1) Create bridge and move interface under bridge (run in maintenance window):"
echo "   sudo ip link add br-sentinel type bridge"
echo "   sudo ip link set br-sentinel up"
echo "   sudo ip link set $EXT_IFACE master br-sentinel"
echo ""
echo "2) Attach TC/XDP to bridge-facing dataplane interface:"
echo "   sudo bash scripts/attach_tc_clsact.sh $EXT_IFACE --xdp-native"
echo ""
echo "3) Start pipeline in auto-interface mode (or explicit interface):"
echo "   sudo SENTINEL_INTERFACE=auto ./sentinel_pipeline -i auto -q 0 -w 8765"
echo ""
echo "4) Validate external route and non-loopback capture:"
echo "   ip route show default"
echo "   ip -br link show"
echo ""
echo "5) Run external flood verification from another host:"
echo "   bash scripts/test_external_flood.sh --target <sentinel-public-ip> --mode udp"

#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <interface> <xdp_obj_path>"
  echo "Example: $0 eth0 proxy/sentinel_xdp.o"
  exit 1
fi

IFACE="$1"
XDP_OBJ="$2"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

if [[ ! -f "$XDP_OBJ" ]]; then
  echo "XDP object not found: $XDP_OBJ"
  exit 1
fi

ip link set dev "$IFACE" xdp off 2>/dev/null || true

echo "Attaching XDP program in native/driver mode on $IFACE"
ip link set dev "$IFACE" xdpdrv obj "$XDP_OBJ" sec xdp

echo "Verifying attachment"
ip -details link show dev "$IFACE" | sed -n '/prog\/xdp/p;/xdpdrv/p'

echo "XDP driver-mode attach completed on $IFACE"

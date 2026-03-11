#!/bin/bash
#
# Sentinel DDoS Core - Attach TC clsact BPF for kernel drop fallback
#
# Use when AF_XDP is unavailable (WSL, VMs). The tc classifier drops packets
# from blacklisted IPs using the same blacklist_map that the pipeline populates
# via find_map_fd_by_name("blacklist_map").
#
# Prerequisites:
#   - Linux (native, not WSL for full eBPF support)
#   - Root or CAP_NET_ADMIN
#   - iproute2 with tc
#   - proxy/sentinel_tc.o built (make -C proxy sentinel_tc.o)
#
# Usage:
#   ./scripts/attach_tc_clsact.sh <interface>
#   ./scripts/attach_tc_clsact.sh eth0
#
# Detach:
#   tc qdisc del dev <interface> clsact 2>/dev/null || true
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$(cd "$SCRIPT_DIR/../proxy" && pwd)"
TC_OBJ="$PROXY_DIR/sentinel_tc.o"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <interface>"
    echo "  e.g. $0 eth0"
    exit 1
fi

IFACE="$1"

if [ ! -f "$TC_OBJ" ]; then
    echo "[!] Build sentinel_tc.o first: make -C proxy sentinel_tc.o"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run as root (tc requires CAP_NET_ADMIN)"
    exit 1
fi

# Add clsact qdisc if not present
if ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q clsact; then
    echo "[*] Adding clsact qdisc on $IFACE"
    tc qdisc add dev "$IFACE" clsact
fi

# Attach BPF to ingress
echo "[*] Attaching sentinel_tc to $IFACE ingress"
tc filter add dev "$IFACE" ingress bpf direct-action obj "$TC_OBJ" sec classifier

echo "[*] TC clsact attached. Blacklist map will be populated by the pipeline."
echo "[*] To detach: tc qdisc del dev $IFACE clsact"

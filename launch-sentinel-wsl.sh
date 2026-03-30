#!/bin/bash
# Sentinel DDoS Mitigation System - WSL Kali Launch Script

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${ROOT_DIR}/.venv"
export SENTINEL_PROFILE="${SENTINEL_PROFILE:-production}"
export SENTINEL_INTEGRATION_PROFILE="${SENTINEL_INTEGRATION_PROFILE:-${SENTINEL_PROFILE}}"

# Function to spawn a new shell process in background with logging
spawn_component() {
    local title="$1"
    local command="$2"
    local logfile="/tmp/sentinel_${title// /_}.log"
    echo "[LAUNCH] Starting $title -> $logfile"
    echo "--- [SENTINEL START: $title] ---" > "$logfile"
    nohup bash -c "$command" >> "$logfile" 2>&1 &
}

echo "========================================================"
echo "    Sentinel DDoS Mitigation System - WSL Launcher"
echo "========================================================"

# 1. Compile C Backend
echo "[1/4] Compiling Backend..."
make pipeline

# 2. Frontend Setup
echo "[2/4] Setting up Frontend..."
if [ ! -d "frontend/node_modules" ]; then
    cd frontend && npm install --no-bin-links && cd ..
fi

# 3. Spawn Python Components (using .venv-wsl)
echo "[3/4] Spawning API & Controller..."
export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH}"
if [ -d "$VENV_PATH" ]; then
    spawn_component "Explain API" "${VENV_PATH}/bin/python3 explain_api.py"
    # Start the real SDN Controller (must expose /stats/* on :8080)
    spawn_component "SDN Controller" "${VENV_PATH}/bin/python3 scripts/start_ryu.py"
else
    echo "Error: .venv-wsl not found. Run the setup commands first."
    exit 1
fi

# 4. Wait for SDN Controller
echo "Waiting for SDN controller to start (port 8080)..."
controller_ready=0
for i in $(seq 1 15); do
    if curl -sf http://127.0.0.1:8080/stats/switches >/dev/null 2>&1; then
        echo "SDN controller is ready."
        controller_ready=1
        break
    fi
    sleep 1
done
if [ "$controller_ready" -ne 1 ]; then
    echo "Error: SDN controller failed to expose a real /stats/switches endpoint on :8080."
    echo "Check /tmp/sentinel_SDN_Controller.log for controller startup errors."
    exit 1
fi

# 5. Attach TC eBPF filter for kernel-level dropping (must happen BEFORE pipeline)
IFACE="${SENTINEL_IFACE:-lo}"
TC_OBJ="${ROOT_DIR}/proxy/sentinel_tc.o"
if [ -f "$TC_OBJ" ]; then
    echo "[4/5] Attaching TC eBPF filter on $IFACE..."
    sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
    sudo tc qdisc add dev "$IFACE" clsact
    sudo tc filter add dev "$IFACE" ingress bpf direct-action obj "$TC_OBJ" sec classifier
    echo "[*] TC clsact attached — blacklist_map active."
else
    echo "[WARN] $TC_OBJ not found. Kernel dropping will be disabled."
    echo "[WARN] Build it with: make -C proxy sentinel_tc.o"
fi

# Graceful cleanup on exit
cleanup() {
    echo "[*] Cleaning up TC eBPF filter..."
    sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
    echo "[*] Sentinel shutdown complete."
}
trap cleanup EXIT INT TERM

# 6. Launch Backend (Requires SUDO)
echo "[5/5] Launching Data Plane..."
echo "NOTE: The backend requires sudo. I will attempt to launch it,"
echo "but if it fails due to password, please run this manually:"
echo "sudo ./sentinel_pipeline -i $IFACE -w 8765"
spawn_component "Backend" "sudo ./sentinel_pipeline -i $IFACE -w 8765"

# 6. Launch Frontend
spawn_component "Frontend" "cd frontend && npm run dev"

echo ""
echo "========================================================"
echo "All components launching in background!"
echo "View logs in /tmp/sentinel_*.log"
echo "Dashboard: http://localhost:5173"
echo "========================================================"

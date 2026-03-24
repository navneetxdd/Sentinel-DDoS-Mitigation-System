#!/bin/bash
# Sentinel DDoS Mitigation System - WSL Kali Launch Script

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${ROOT_DIR}/.venv-wsl"
export SENTINEL_ENABLE_CONTROLLER_EXTENSION=1
export SENTINEL_ENABLE_MODEL_EXTENSION=1
export SENTINEL_ENABLE_INTEL_FEED_EXTENSION=1

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
    # Port 8080: Start the SDN REST API bridge
    spawn_component "SDN API" "${VENV_PATH}/bin/python3 scripts/sdn_api.py"
    # Start the SDN Controller logic (OpenFlow only, no WSGI)
    spawn_component "SDN Controller" "${VENV_PATH}/bin/python3 scripts/start_ryu.py"
else
    echo "Error: .venv-wsl not found. Run the setup commands first."
    exit 1
fi

# 4. Wait for SDN Controller
echo "Waiting for SDN controller to start (port 8080)..."
for i in $(seq 1 15); do
    if curl -s http://127.0.0.1:8080/stats/switches >/dev/null 2>&1; then
        echo "SDN controller is ready."
        break
    fi
    sleep 1
done

# 5. Launch Backend (Requires SUDO - user must run manually or have NOPASSWD)
echo "[4/4] Launching Data Plane..."
echo "NOTE: The backend requires sudo. I will attempt to launch it,"
echo "but if it fails due to password, please run this manually:"
echo "sudo ./sentinel_pipeline -i lo -w 8765"
spawn_component "Backend" "sudo ./sentinel_pipeline -i lo -w 8765"

# 6. Launch Frontend
spawn_component "Frontend" "cd frontend && npm run dev"

echo ""
echo "========================================================"
echo "All components launching in background!"
echo "View logs in /tmp/sentinel_*.log"
echo "Dashboard: http://localhost:5173"
echo "========================================================"

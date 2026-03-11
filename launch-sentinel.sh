#!/bin/bash

# ========================================================
#   Sentinel DDoS Mitigation System - Linux Multi-Terminal
# ========================================================

# Function to spawn a new terminal window
spawn_terminal() {
    local title="$1"
    local command="$2"
    
    # Try common terminal emulators found on Kali
    if command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal --title="$title" -e "$command" &
    elif command -v qterminal &> /dev/null; then
        qterminal -e "$command" &
    elif command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$title" -- bash -c "$command" &
    elif command -v x-terminal-emulator &> /dev/null; then
        x-terminal-emulator -e "$command" &
    else
        echo "Error: No supported terminal emulator found."
        exit 1
    fi
}

echo "========================================================"
echo "    Sentinel DDoS Mitigation System - Multi-Launcher"
echo "========================================================"
echo ""

echo "[1/5] Compiling C Backend Pipeline..."
make pipeline

echo ""
echo "[2/5] Building TC clsact fallback (for kernel drops when AF_XDP unavailable)..."
if make -C proxy sentinel_tc.o 2>/dev/null; then
    echo "TC BPF object built."
else
    echo "Warning: TC BPF build skipped (clang or proxy/Makefile missing). Kernel drop fallback will be unavailable."
fi

echo ""
echo "[3/5] Verifying Frontend Environment..."
if [ ! -d "frontend/node_modules" ] || [ ! -f "frontend/node_modules/.bin/vite" ]; then
    echo "Frontend dependencies missing. Running npm install..."
    cd frontend && npm install && cd ..
else
    echo "Frontend dependencies verified."
fi

echo ""
echo "[4/5] Attaching TC clsact for kernel drop fallback (interface: lo)..."
CAPTURE_IFACE="${SENTINEL_CAPTURE_IFACE:-lo}"
TC_OBJ="$(pwd)/proxy/sentinel_tc.o"
TC_SCRIPT="$(pwd)/scripts/attach_tc_clsact.sh"
if [ -f "$TC_OBJ" ] && [ -f "$TC_SCRIPT" ]; then
    if sudo "$TC_SCRIPT" "$CAPTURE_IFACE" 2>/dev/null; then
        echo "TC clsact attached to $CAPTURE_IFACE. Kernel drops enabled."
    else
        echo "Warning: TC attach failed (may need root, or interface not found). Kernel drops may be disabled."
    fi
else
    echo "Skipping TC attach (sentinel_tc.o or attach script not found)."
fi

echo ""
echo "[5/5] Spawning Components..."

# 0. Explain API (SHAP - runs in background)
if [ -f "explain_api.py" ]; then
    spawn_terminal "Sentinel Explain API" "bash -c 'echo \"[SENTINEL EXPLAIN API]\"; python3 explain_api.py --port 5001; exec bash'" &
fi

# 1. Ryu SDN Controller (Crucial for active mitigation)
spawn_terminal "Sentinel SDN Controller" "bash -c 'echo \"[SENTINEL SDN CONTROLLER]\"; python3 scripts/start_ryu.py; exec bash'"

# 2. C Backend (Data Plane)
# We point it to the local controller started above
spawn_terminal "Sentinel Backend" "bash -c 'echo \"[SENTINEL BACKEND]\"; sudo ./sentinel_pipeline -i lo -q 0 --controller http://127.0.0.1:8080 -w 8765; exec bash'"

# 3. Frontend Web UI
spawn_terminal "Sentinel Frontend" "bash -c 'echo \"[SENTINEL FRONTEND]\"; cd frontend && npm run dev; exec bash'"

# 4. Simulation Workspace
spawn_terminal "Sentinel Simulation" "bash -c 'echo \"[SENTINEL SIMULATION]\"; echo \"Run your attacks or topology here.\"; echo \"Example: sudo hping3 -S -p 80 --flood 127.0.0.1\"; exec bash'"

echo ""
echo "========================================================"
echo "All components launching! Look for 5 new windows."
echo "========================================================"
echo "0. Explain API (SHAP at http://localhost:5001)"
echo "1. SDN Controller (Active Mitigation Engine)"
echo "2. Backend (Traffic Analyzer)"
echo "3. Frontend (Dashboard)"
echo "4. Simulation (Attack Terminal)"
echo "========================================================"
echo ""

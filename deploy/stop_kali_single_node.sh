#!/usr/bin/env bash
set -euo pipefail

REPO_PATH="${REPO_PATH:-$PWD}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-path) REPO_PATH="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

STATE_DIR="$REPO_PATH/.sentinel/kali-stack"

if [[ ! -d "$STATE_DIR" ]]; then
  echo "State directory not found: $STATE_DIR"
  exit 0
fi

stop_pid_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    local pid
    pid="$(cat "$file" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$file"
  fi
}

stop_pid_file "$STATE_DIR/frontend.pid"
stop_pid_file "$STATE_DIR/pipeline.pid"
stop_pid_file "$STATE_DIR/explain.pid"
stop_pid_file "$STATE_DIR/sdn.pid"

# Force-kill by name as fallback (clears orphaned processes)
echo "Cleaning up any rogue processes..."
pkill -9 -f sentinel_pipeline || true
pkill -9 -f "explain_api.py" || true
pkill -9 -f "start_ryu.py" || true
pkill -9 -f "osken_manager_compat.py" || true
pkill -9 -f "os_ken" || true
pkill -9 -f "vite preview" || true
pkill -9 -f "node_modules/vite/bin/vite.js" || true
pkill -9 -f "serve_frontend.py" || true
fuser -k 8765/tcp 2>/dev/null || true
fuser -k 8080/tcp 2>/dev/null || true
fuser -k 8081/tcp 2>/dev/null || true
fuser -k 5001/tcp 2>/dev/null || true
for port in $(seq 5200 5220); do
  fuser -k "${port}/tcp" 2>/dev/null || true
done

rm -f \
  "$STATE_DIR/frontend.mode" \
  "$STATE_DIR/frontend_port_actual" \
  "$STATE_DIR/frontend.index.check.html"

echo "Kali single-node stack stopped."

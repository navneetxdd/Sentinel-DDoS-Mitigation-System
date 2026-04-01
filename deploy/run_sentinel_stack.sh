#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_PATH="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_PATH="${REPO_PATH:-$DEFAULT_REPO_PATH}"
STATE_DIR=""
ENV_FILE=""
DEFAULT_FRONTEND_PORT=5200
FRONTEND_PORT_MIN=5200
FRONTEND_PORT_MAX=5220
STOP_ONLY=0
WS_PORT_ARG=""
EXPLAIN_PORT_ARG=""
FRONTEND_PORT_ARG=""
WEB_PORT_ARG=""
WS_API_KEY_ARG=""
FORCE_BOOTSTRAP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-path) REPO_PATH="$2"; shift 2 ;;
    --ws-port) WS_PORT_ARG="$2"; shift 2 ;;
    --explain-port) EXPLAIN_PORT_ARG="$2"; shift 2 ;;
    --frontend-port) FRONTEND_PORT_ARG="$2"; shift 2 ;;
    --web-port) WEB_PORT_ARG="$2"; shift 2 ;;
    --ws-api-key) WS_API_KEY_ARG="$2"; shift 2 ;;
    --force-bootstrap) FORCE_BOOTSTRAP=1; shift ;;
    --stop) STOP_ONLY=1; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0 --repo-path $REPO_PATH"
  exit 1
fi

if [[ ! -d "$REPO_PATH" ]]; then
  echo "Repository path not found: $REPO_PATH"
  exit 1
fi

# Ensure nginx root paths are absolute even if the user passes `--repo-path .`
REPO_PATH="$(cd "$REPO_PATH" && pwd)"

STATE_DIR="$REPO_PATH/.sentinel/kali-stack"
ENV_FILE="$STATE_DIR/env"

echo "============================================"
echo "  SENTINEL STACK LAUNCH"
echo "============================================"

bootstrap_stack_if_needed() {
  local need_bootstrap=0
  local ws_port="${WS_PORT_ARG:-${SENTINEL_WS_PORT:-8765}}"
  local explain_port="${EXPLAIN_PORT_ARG:-${SENTINEL_EXPLAIN_PORT:-5001}}"
  local frontend_port="${FRONTEND_PORT_ARG:-${SENTINEL_FRONTEND_PORT:-5200}}"
  local web_port="${WEB_PORT_ARG:-${SENTINEL_WEB_PORT:-5173}}"
  local ws_api_key="${WS_API_KEY_ARG:-${SENTINEL_WS_API_KEY:-change-me-in-prod}}"

  if [[ "$FORCE_BOOTSTRAP" -eq 1 ]]; then
    need_bootstrap=1
  fi
  [[ ! -f "$ENV_FILE" ]] && need_bootstrap=1
  [[ ! -f "$REPO_PATH/sentinel_pipeline" ]] && need_bootstrap=1
  [[ ! -x "$REPO_PATH/.venv/bin/python3" ]] && need_bootstrap=1
  [[ ! -f "$REPO_PATH/frontend/dist/index.html" ]] && need_bootstrap=1

  if [[ "$need_bootstrap" -eq 0 ]]; then
    return 0
  fi

  echo
  echo "[bootstrap] Missing artifacts detected; running self-healing bootstrap..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    build-essential gcc make clang llvm libelf-dev pkg-config \
    libpcap-dev libpcap0.8-dev libcurl4-openssl-dev libssl-dev \
    python3 python3-venv python3-pip jq curl git nginx redis-server \
    net-tools iproute2

  if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  fi

  cd "$REPO_PATH"
  make clean || true
  make
  make -C proxy sentinel_xdp.o sentinel_tc.o || true

  if [[ ! -x "$REPO_PATH/.venv/bin/python3" ]]; then
    rm -rf "$REPO_PATH/.venv" || true
    python3 -m venv --copies "$REPO_PATH/.venv"
  fi
  # shellcheck disable=SC1091
  source "$REPO_PATH/.venv/bin/activate"
  pip install --upgrade pip
  pip install -r "$REPO_PATH/requirements.txt"
  pip install os-ken eventlet==0.35.2 tinyrpc

  if [[ ! -d "$REPO_PATH/frontend/node_modules/vite" ]]; then
    rm -rf "$REPO_PATH/frontend/node_modules" "$REPO_PATH/frontend/package-lock.json" 2>/dev/null || true
    (cd "$REPO_PATH/frontend" && npm install)
  fi
  (
    cd "$REPO_PATH/frontend"
    VITE_WS_URL="" VITE_EXPLAIN_API_URL="" VITE_WS_API_KEY="$ws_api_key" \
      node node_modules/vite/bin/vite.js build
  )

  mkdir -p "$STATE_DIR"
  cat > "$ENV_FILE" <<EOF
SENTINEL_INTERFACE=auto
SENTINEL_QUEUE_ID=0
SENTINEL_SHARED_STATE_BACKEND=shm
SENTINEL_SHARED_STATE_NAME=/sentinel_state_v1
SENTINEL_SDN_CONTROLLER=http://127.0.0.1:8080
SENTINEL_SDN_DPID=1
SENTINEL_WS_PORT=${ws_port}
SENTINEL_EXPLAIN_PORT=${explain_port}
SENTINEL_FRONTEND_PORT=${frontend_port}
SENTINEL_WEB_PORT=${web_port}
SENTINEL_WS_API_KEY=${ws_api_key}
SENTINEL_PROFILE=production
SENTINEL_INTEGRATION_PROFILE=production
SENTINEL_MAX_CLASSIFICATIONS_PER_SEC=5000
EOF

  cat > /etc/nginx/conf.d/sentinel-local.conf <<EOF
server {
    listen ${web_port};
    server_name localhost 127.0.0.1 _;
    root ${REPO_PATH}/frontend/dist;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:${explain_port}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Sentinel-API-Key "${ws_api_key}";
    }

    location /ws {
        proxy_pass http://127.0.0.1:${ws_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

  nginx -t >/dev/null 2>&1 || true
  systemctl enable nginx redis-server >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || service nginx restart >/dev/null 2>&1 || true
  systemctl restart redis-server >/dev/null 2>&1 || service redis-server restart >/dev/null 2>&1 || true
}

port_busy() {
  local port="$1"
  ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN
}

wait_for_port() {
  local port="$1"
  local attempts="${2:-20}"
  local sleep_seconds="${3:-1}"
  local i

  for ((i = 0; i < attempts; i++)); do
    if port_busy "$port"; then
      return 0
    fi
    sleep "$sleep_seconds"
  done

  return 1
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-20}"
  local sleep_seconds="${3:-1}"
  local i

  for ((i = 0; i < attempts; i++)); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_seconds"
  done

  return 1
}

post_json_ok() {
  local url="$1"
  local payload="$2"
  local expect="${3:-}"
  local response
  local -a curl_args

  curl_args=(-fsS --max-time 5 -H "Content-Type: application/json")
  if [[ -n "${SENTINEL_WS_API_KEY:-}" ]]; then
    curl_args+=(-H "X-Sentinel-API-Key: ${SENTINEL_WS_API_KEY}")
  fi

  if ! response="$(curl "${curl_args[@]}" \
    -d "$payload" \
    "$url" 2>/dev/null)"; then
    return 1
  fi

  if [[ -n "$expect" ]] && ! grep -Fq -- "$expect" <<<"$response"; then
    return 1
  fi

  return 0
}

wait_for_http_post_json() {
  local url="$1"
  local payload="$2"
  local expect="${3:-}"
  local attempts="${4:-20}"
  local sleep_seconds="${5:-1}"
  local i

  for ((i = 0; i < attempts; i++)); do
    if post_json_ok "$url" "$payload" "$expect"; then
      return 0
    fi
    sleep "$sleep_seconds"
  done

  return 1
}

display_url() {
  local web_port="${SENTINEL_WEB_PORT:-80}"
  if [[ "$web_port" == "80" ]]; then
    printf '%s\n' "http://localhost"
  else
    printf 'http://localhost:%s\n' "$web_port"
  fi
}

persist_frontend_port() {
  local port="$1"
  SENTINEL_FRONTEND_PORT="$port"
  export SENTINEL_FRONTEND_PORT
  if grep -q '^SENTINEL_FRONTEND_PORT=' "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^SENTINEL_FRONTEND_PORT=.*/SENTINEL_FRONTEND_PORT=${port}/" "$ENV_FILE"
  else
    printf '\nSENTINEL_FRONTEND_PORT=%s\n' "$port" >> "$ENV_FILE"
  fi
}

reload_nginx() {
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || service nginx reload >/dev/null 2>&1 || true
  fi
}

write_nginx_common_locations() {
  local explain_port="${SENTINEL_EXPLAIN_PORT:-5001}"
  local ws_port="${SENTINEL_WS_PORT:-8765}"
  local ws_api_key="${SENTINEL_WS_API_KEY:-}"

  cat <<EOF
    location /api/ {
        proxy_pass http://127.0.0.1:${explain_port}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Sentinel-API-Key "${ws_api_key}";
    }

    location /ws {
        proxy_pass http://127.0.0.1:${ws_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
EOF
}

configure_nginx_static_frontend() {
  local dist_dir="$REPO_PATH/frontend/dist"
  # Force absolute root to avoid nginx using paths relative to its own working dir.
  dist_dir="$(cd "$dist_dir" && pwd)"
  local web_port="${SENTINEL_WEB_PORT:-80}"
  local conf="/etc/nginx/conf.d/sentinel-local.conf"

  cat > "$conf" <<EOF
server {
    listen ${web_port};
    server_name localhost 127.0.0.1 _;
    root ${dist_dir};
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

$(write_nginx_common_locations)
}
EOF

  reload_nginx
}

configure_nginx_frontend_proxy() {
  local frontend_port="$1"
  local web_port="${SENTINEL_WEB_PORT:-80}"
  local conf="/etc/nginx/conf.d/sentinel-local.conf"

  cat > "$conf" <<EOF
server {
    listen ${web_port};
    server_name localhost 127.0.0.1 _;

    location / {
        proxy_pass http://127.0.0.1:${frontend_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
    }

$(write_nginx_common_locations)
}
EOF

  reload_nginx
}

select_frontend_port() {
  local requested="${SENTINEL_FRONTEND_PORT:-$DEFAULT_FRONTEND_PORT}"
  local candidate

  if ! port_busy "$requested"; then
    printf '%s\n' "$requested"
    return 0
  fi

  for candidate in $(seq "$FRONTEND_PORT_MIN" "$FRONTEND_PORT_MAX"); do
    if ! port_busy "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

start_frontend() {
  local dist_dir="$REPO_PATH/frontend/dist"
  local vite_cli="$REPO_PATH/frontend/node_modules/vite/bin/vite.js"
  local esbuild_pkg="$REPO_PATH/frontend/node_modules/esbuild/package.json"
  local port

  rm -f \
    "$STATE_DIR/frontend.pid" \
    "$STATE_DIR/frontend.mode" \
    "$STATE_DIR/frontend_port_actual" \
    "$STATE_DIR/frontend.index.check.html"
  : > "$STATE_DIR/frontend.out.log"
  : > "$STATE_DIR/frontend.err.log"

  if [[ -f "$dist_dir/index.html" ]]; then
    echo "  Frontend mode: nginx static bundle"
    configure_nginx_static_frontend
    printf '%s\n' "static" > "$STATE_DIR/frontend.mode"
    return 0
  fi

  if ! port="$(select_frontend_port)"; then
    printf '%s\n' "Frontend start failed: no free frontend port is available in ${FRONTEND_PORT_MIN}-${FRONTEND_PORT_MAX}." \
      > "$STATE_DIR/frontend.err.log"
    return 1
  fi

  if [[ "$port" != "${SENTINEL_FRONTEND_PORT:-$DEFAULT_FRONTEND_PORT}" ]]; then
    echo "  [WARN] Frontend port ${SENTINEL_FRONTEND_PORT:-$DEFAULT_FRONTEND_PORT} is busy; switching to ${port}."
  fi

  persist_frontend_port "$port"

  if [[ -f "$vite_cli" && -f "$esbuild_pkg" ]]; then
    echo "  Frontend mode: Vite fallback on port ${port}"
    configure_nginx_frontend_proxy "$port"
    (
      cd "$REPO_PATH/frontend"
      nohup node node_modules/vite/bin/vite.js --host 127.0.0.1 --port "$port" \
        > "$STATE_DIR/frontend.out.log" 2> "$STATE_DIR/frontend.err.log" &
      echo $! > "$STATE_DIR/frontend.pid"
    )
    printf '%s\n' "proxy" > "$STATE_DIR/frontend.mode"
    return 0
  fi

  printf '%s\n' "Frontend start failed: dist/ is missing and the local Vite/esbuild runtime is incomplete." \
    > "$STATE_DIR/frontend.err.log"
  return 1
}

kill_stack_processes() {
  pkill -9 -f sentinel_pipeline 2>/dev/null || true
  pkill -9 -f "explain_api.py" 2>/dev/null || true
  pkill -9 -f "start_ryu.py" 2>/dev/null || true
  pkill -9 -f "osken_manager_compat.py" 2>/dev/null || true
  pkill -9 -f "os_ken" 2>/dev/null || true
  pkill -9 -f "ryu-manager" 2>/dev/null || true
  pkill -9 -f "osken-manager" 2>/dev/null || true
  pkill -9 -f "node_modules/vite/bin/vite.js" 2>/dev/null || true
  pkill -9 -f "vite preview" 2>/dev/null || true
  pkill -9 -f "serve_frontend.py" 2>/dev/null || true

  local port
  for port in 8080 8081 "${SENTINEL_WS_PORT:-8765}" "${SENTINEL_EXPLAIN_PORT:-5001}" $(seq "$FRONTEND_PORT_MIN" "$FRONTEND_PORT_MAX"); do
    fuser -k -9 "${port}/tcp" 2>/dev/null || true
  done
}

cleanup_runtime_state() {
  rm -f \
    "$STATE_DIR/frontend.mode" \
    "$STATE_DIR/frontend_port_actual" \
    "$STATE_DIR/frontend.index.check.html" \
    "$STATE_DIR/frontend.pid" \
    "$STATE_DIR/pipeline.pid" \
    "$STATE_DIR/explain.pid" \
    "$STATE_DIR/sdn.pid"
}

resolve_capture_iface() {
  # Pick the first non-loopback interface with a global IPv4 address.
  # This avoids stale env values (e.g. old 'eth0') when WSL interface naming changes.
  local iface
  local candidates

  candidates="$(
    ip -o -4 addr show scope global 2>/dev/null \
      | awk '{print $2}' \
      | sed 's/:$//' \
      | sort -u
  )"

  # Filter common non-capture interfaces.
  candidates="$(
    echo "$candidates" \
      | grep -Ev '^(lo|tailscale0|docker0|veth.*|br-.*|virbr.*|wg.*)$' \
      || true
  )"

  # Prefer ethX style names.
  for iface in $candidates; do
    if [[ "$iface" =~ ^eth[0-9]+$ ]]; then
      echo "$iface"
      return 0
    fi
  done

  for iface in $candidates; do
    if [[ -n "$iface" ]]; then
      echo "$iface"
      return 0
    fi
  done

  return 1
}

ensure_valid_capture_iface() {
  local iface
  iface="${SENTINEL_INTERFACE:-auto}"

  if [[ -z "$iface" || "$iface" == "auto" ]]; then
    if iface="$(resolve_capture_iface)"; then
      SENTINEL_INTERFACE="$iface"
      echo "  [INFO] Resolved capture interface: ${SENTINEL_INTERFACE}"
    else
      SENTINEL_INTERFACE="lo"
      echo "  [WARN] Could not resolve capture interface; falling back to 'lo'."
    fi
  else
    if ! ip link show dev "$iface" >/dev/null 2>&1; then
      echo "  [WARN] Configured interface '$iface' not found; resolving automatically..."
      if iface="$(resolve_capture_iface)"; then
        SENTINEL_INTERFACE="$iface"
        echo "  [INFO] Resolved capture interface: ${SENTINEL_INTERFACE}"
      else
        SENTINEL_INTERFACE="lo"
        echo "  [WARN] Could not resolve capture interface; falling back to 'lo'."
      fi
    fi
  fi

  # Persist the resolved interface back into the env file (if present) so later runs are stable.
  if [[ -n "${ENV_FILE:-}" && -f "$ENV_FILE" ]]; then
    if grep -q '^SENTINEL_INTERFACE=' "$ENV_FILE" 2>/dev/null; then
      sed -i "s/^SENTINEL_INTERFACE=.*/SENTINEL_INTERFACE=${SENTINEL_INTERFACE}/" "$ENV_FILE" || true
    else
      printf '\nSENTINEL_INTERFACE=%s\n' "$SENTINEL_INTERFACE" >> "$ENV_FILE" || true
    fi
  fi
}

attempt_xdp_then_fallback_tc() {
  if [[ -z "${SENTINEL_INTERFACE:-}" || "${SENTINEL_INTERFACE}" == "auto" ]]; then
    echo "  [INFO] Interface is auto; skipping explicit XDP/TC attach."
    return 0
  fi

  if [[ -f "$REPO_PATH/proxy/sentinel_xdp.o" ]]; then
    echo "  Attempting XDP native attach on ${SENTINEL_INTERFACE}..."
    ip link set dev "${SENTINEL_INTERFACE}" xdp off 2>/dev/null || true
    if ip link set dev "${SENTINEL_INTERFACE}" xdpdrv obj "$REPO_PATH/proxy/sentinel_xdp.o" sec xdp 2>/dev/null; then
      echo "  [OK] XDP native attached on ${SENTINEL_INTERFACE}."
      return 0
    fi
    echo "  [WARN] XDP native attach failed on ${SENTINEL_INTERFACE}; falling back to TC clsact."
  else
    echo "  [WARN] proxy/sentinel_xdp.o missing; falling back to TC clsact."
  fi

  if [[ -x "$REPO_PATH/scripts/attach_tc_clsact.sh" ]]; then
    "$REPO_PATH/scripts/attach_tc_clsact.sh" "${SENTINEL_INTERFACE}" || \
      echo "  [WARN] TC attach failed; kernel dropping may be unavailable."
  fi
}

start_system_services() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl start redis-server >/dev/null 2>&1 || true
    systemctl start nginx >/dev/null 2>&1 || true
  else
    service redis-server start >/dev/null 2>&1 || true
    service nginx start >/dev/null 2>&1 || true
  fi
}

status_tail() {
  local logfile="$1"
  tail -5 "$logfile" 2>/dev/null | sed 's/^/     /'
}

check_pid_service() {
  local name="$1"
  local pidfile="$2"
  local logfile="$3"

  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "  [OK] $name - RUNNING (PID $pid)"
      return 0
    fi
  fi

  echo "  [FAIL] $name - NOT HEALTHY"
  status_tail "$logfile"
  return 1
}

check_pid_port_service() {
  local name="$1"
  local pidfile="$2"
  local logfile="$3"
  local port="$4"

  if check_pid_service "$name" "$pidfile" "$logfile" >/dev/null 2>&1 && port_busy "$port"; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    echo "  [OK] $name - RUNNING (PID $pid, port $port)"
    return 0
  fi

  echo "  [FAIL] $name - NOT HEALTHY"
  status_tail "$logfile"
  return 1
}

check_pid_http_service() {
  local name="$1"
  local pidfile="$2"
  local logfile="$3"
  local url="$4"

  if check_pid_service "$name" "$pidfile" "$logfile" >/dev/null 2>&1 && curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    echo "  [OK] $name - RUNNING (PID $pid)"
    return 0
  fi

  echo "  [FAIL] $name - NOT HEALTHY"
  status_tail "$logfile"
  return 1
}

check_pid_http_post_service() {
  local name="$1"
  local pidfile="$2"
  local logfile="$3"
  local url="$4"
  local payload="$5"
  local expect="${6:-}"

  if check_pid_service "$name" "$pidfile" "$logfile" >/dev/null 2>&1 && post_json_ok "$url" "$payload" "$expect"; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    echo "  [OK] $name - RUNNING (PID $pid)"
    return 0
  fi

  echo "  [FAIL] $name - NOT HEALTHY"
  status_tail "$logfile"
  return 1
}

check_redis_service() {
  if command -v redis-cli >/dev/null 2>&1; then
    if redis-cli ping >/dev/null 2>&1; then
      echo "  [OK] Redis - RUNNING"
      return 0
    fi
  elif port_busy 6379; then
    echo "  [OK] Redis - RUNNING"
    return 0
  fi

  echo "  [FAIL] Redis - NOT HEALTHY"
  return 1
}

check_frontend_service() {
  local web_port="${SENTINEL_WEB_PORT:-80}"
  local root_url="http://127.0.0.1:${web_port}/"
  local html_file="$STATE_DIR/frontend.index.check.html"
  local asset_paths

  if ! curl -fsS --max-time 5 "$root_url" > "$html_file" 2>/dev/null; then
    echo "  [FAIL] Frontend - UNREACHABLE"
    status_tail "$STATE_DIR/frontend.err.log"
    return 1
  fi

  if ! grep -q 'id="root"' "$html_file" || ! grep -Eq 'Sentinel|BAW2M' "$html_file"; then
    echo "  [FAIL] Frontend - WRONG HTML RESPONSE"
    echo "     Expected Sentinel dashboard HTML on ${root_url}"
    return 1
  fi

  asset_paths="$(grep -oE '(src|href)="/[^"]+"' "$html_file" | sed -E 's/^(src|href)="([^"]+)"$/\2/' | sort -u)"
  if [[ -z "$asset_paths" ]]; then
    echo "  [FAIL] Frontend - NO STATIC ASSETS DECLARED"
    return 1
  fi

  while IFS= read -r asset_path; do
    [[ -z "$asset_path" ]] && continue
    if ! curl -fsS --max-time 5 "http://127.0.0.1:${web_port}${asset_path}" >/dev/null 2>&1; then
      echo "  [FAIL] Frontend - ASSET LOAD FAILED"
      echo "     Failed to fetch ${asset_path} through nginx"
      return 1
    fi
  done <<< "$asset_paths"

  echo "  [OK] Frontend - RUNNING ($(display_url))"
  return 0
}

echo
echo "[1/5] Killing stale Sentinel processes..."
mkdir -p "$STATE_DIR"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi
bootstrap_stack_if_needed
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [[ "$STOP_ONLY" -eq 1 ]]; then
  kill_stack_processes
  cleanup_runtime_state
  echo "  [OK] Sentinel stack stopped."
  exit 0
fi

kill_stack_processes
sleep 2
echo "  [OK] Process cleanup complete."

echo
echo "[2/5] Verifying environment..."
if [[ ! -f "$ENV_FILE" ]]; then
  echo "  [FAIL] Missing $ENV_FILE. Re-run with --force-bootstrap."
  exit 1
fi

cd "$REPO_PATH"
# shellcheck disable=SC1090
source "$ENV_FILE"

if [[ -f "$REPO_PATH/scripts/load_profile.sh" ]]; then
  # shellcheck disable=SC1090
  . "$REPO_PATH/scripts/load_profile.sh"
  sentinel_load_profile "$REPO_PATH" || true
fi

if [[ ! -f "$REPO_PATH/sentinel_pipeline" ]]; then
  echo "  [FAIL] sentinel_pipeline binary not found."
  exit 1
fi

if [[ ! -x "$REPO_PATH/.venv/bin/python3" ]]; then
  echo "  [FAIL] $REPO_PATH/.venv/bin/python3 not found."
  exit 1
fi

# Ensure capture interface exists in the current WSL/network environment.
# If the env file contains a stale interface name (e.g. eth0) the pipeline will fail hard.
ensure_valid_capture_iface

EXPLAIN_ANALYZE_SMOKE_PAYLOAD='{"timestamp":"startup-smoke","sourceIp":"127.0.0.1","packetsPerSecond":0,"bytesPerSecond":0,"threatScore":0.05,"activeFlows":1,"topProtocol":"tcp"}'

echo "  [OK] Environment verified."

echo
echo "[3/5] Starting services..."
start_system_services

echo "  Starting SDN controller..."
PYTHONPATH="$REPO_PATH:${PYTHONPATH:-}" \
  nohup "$REPO_PATH/.venv/bin/python3" "$REPO_PATH/scripts/start_ryu.py" \
  > "$STATE_DIR/sdn.out.log" 2> "$STATE_DIR/sdn.err.log" &
echo $! > "$STATE_DIR/sdn.pid"
if ! wait_for_http "http://127.0.0.1:8080/stats/switches" 20 1; then
  echo "  [WARN] SDN controller did not answer /stats/switches within 20s."
fi

echo "  Starting Explain API..."
PYTHONUNBUFFERED=1 nohup "$REPO_PATH/.venv/bin/python3" -u "$REPO_PATH/explain_api.py" \
  --host 127.0.0.1 \
  --port "${SENTINEL_EXPLAIN_PORT:-5001}" \
  --cors-origin "${SENTINEL_EXPLAIN_CORS_ORIGIN:-*}" \
  > "$STATE_DIR/explain.out.log" 2> "$STATE_DIR/explain.err.log" &
echo $! > "$STATE_DIR/explain.pid"
if ! wait_for_port "${SENTINEL_EXPLAIN_PORT:-5001}" 60 1; then
  echo "  [WARN] Explain API port ${SENTINEL_EXPLAIN_PORT:-5001} did not start listening within 60s."
elif ! wait_for_http "http://127.0.0.1:${SENTINEL_EXPLAIN_PORT:-5001}/health" 20 1; then
  echo "  [WARN] Explain API did not pass /health within 20s."
fi
if ! wait_for_http_post_json \
  "http://127.0.0.1:${SENTINEL_EXPLAIN_PORT:-5001}/analyze" \
  "$EXPLAIN_ANALYZE_SMOKE_PAYLOAD" \
  '"analysis"' \
  20 1; then
  echo "  [WARN] Explain API did not pass /analyze within 20s."
fi

# Try XDP native first; if unavailable/fails, fallback to TC clsact attach.
attempt_xdp_then_fallback_tc

echo "  Starting pipeline..."
nohup "$REPO_PATH/sentinel_pipeline" \
  -i "${SENTINEL_INTERFACE:-auto}" \
  -q "${SENTINEL_QUEUE_ID:-0}" \
  -w "${SENTINEL_WS_PORT:-8765}" \
  --controller "${SENTINEL_SDN_CONTROLLER:-http://127.0.0.1:8080}" \
  --dpid "${SENTINEL_SDN_DPID:-1}" \
  > "$STATE_DIR/pipeline.out.log" 2> "$STATE_DIR/pipeline.err.log" &
echo $! > "$STATE_DIR/pipeline.pid"
if ! wait_for_port "${SENTINEL_WS_PORT:-8765}" 20 1; then
  echo "  [WARN] Pipeline WebSocket port ${SENTINEL_WS_PORT:-8765} is not listening yet."
fi

echo "  Starting frontend..."
start_frontend || true
if ! wait_for_http "http://127.0.0.1:${SENTINEL_WEB_PORT:-80}/" 20 1; then
  echo "  [WARN] Dashboard root did not answer on $(display_url) within 20s."
fi

echo "  [OK] Launch sequence complete."

echo
echo "[4/5] Allowing services to settle..."
sleep 5

echo
echo "[5/5] Service status"
echo "  ----------------------------------------"

FAILURES=0
check_redis_service || FAILURES=$((FAILURES + 1))
check_pid_http_service "SDN Ctrl" "$STATE_DIR/sdn.pid" "$STATE_DIR/sdn.err.log" "http://127.0.0.1:8080/stats/switches" || FAILURES=$((FAILURES + 1))
check_pid_http_service "Explain API" "$STATE_DIR/explain.pid" "$STATE_DIR/explain.err.log" "http://127.0.0.1:${SENTINEL_EXPLAIN_PORT:-5001}/health" || FAILURES=$((FAILURES + 1))
check_pid_http_post_service "Explain Analyze" "$STATE_DIR/explain.pid" "$STATE_DIR/explain.err.log" "http://127.0.0.1:${SENTINEL_EXPLAIN_PORT:-5001}/analyze" "$EXPLAIN_ANALYZE_SMOKE_PAYLOAD" '"analysis"' || FAILURES=$((FAILURES + 1))
check_pid_port_service "Pipeline" "$STATE_DIR/pipeline.pid" "$STATE_DIR/pipeline.err.log" "${SENTINEL_WS_PORT:-8765}" || FAILURES=$((FAILURES + 1))
check_frontend_service || FAILURES=$((FAILURES + 1))

echo "  ----------------------------------------"

if [[ "$FAILURES" -eq 0 ]]; then
  echo
  echo "  All Sentinel services are healthy."
  echo "  Dashboard: $(display_url)"
  echo "  Logs: $STATE_DIR/*.log"
else
  echo
  echo "  $FAILURES service(s) failed health checks."
  echo
  echo "  Detailed logs:"
  for name in sdn explain pipeline frontend; do
    if [[ "$name" == "explain" && -s "$STATE_DIR/${name}.out.log" ]]; then
      echo
      echo "  === ${name}.out.log (last 5 lines) ==="
      tail -5 "$STATE_DIR/${name}.out.log" 2>/dev/null | sed 's/^/  /'
    fi
    if [[ -s "$STATE_DIR/${name}.err.log" ]]; then
      echo
      echo "  === ${name}.err.log (last 5 lines) ==="
      tail -5 "$STATE_DIR/${name}.err.log" 2>/dev/null | sed 's/^/  /'
    fi
  done
  exit 1
fi

echo
echo "============================================"

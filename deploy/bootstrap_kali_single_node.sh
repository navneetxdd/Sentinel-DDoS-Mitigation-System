#!/usr/bin/env bash
set -euo pipefail

# Sentinel single-node bootstrap for Kali/Debian-family Linux.
# Installs dependencies, builds artifacts, prepares Python venv and frontend,
# and configures non-destructive nginx reverse-proxy include.

REPO_PATH="${REPO_PATH:-$PWD}"
WS_PORT="${SENTINEL_WS_PORT:-8765}"
EXPLAIN_PORT="${SENTINEL_EXPLAIN_PORT:-5001}"
FRONTEND_PORT="${SENTINEL_FRONTEND_PORT:-5200}"
WEB_PORT="${SENTINEL_WEB_PORT:-80}"
RUN_USER="${SUDO_USER:-$USER}"
WS_API_KEY="${SENTINEL_WS_API_KEY:-change-me-in-prod}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-path) REPO_PATH="$2"; shift 2 ;;
    --ws-port) WS_PORT="$2"; shift 2 ;;
    --explain-port) EXPLAIN_PORT="$2"; shift 2 ;;
    --frontend-port) FRONTEND_PORT="$2"; shift 2 ;;
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --run-user) RUN_USER="$2"; shift 2 ;;
    --ws-api-key) WS_API_KEY="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo $0 [options]"
  exit 1
fi

if [[ ! -d "$REPO_PATH" ]]; then
  echo "Repository path not found: $REPO_PATH"
  exit 1
fi

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

pushd "$REPO_PATH" >/dev/null

make clean || true
make
make -C proxy sentinel_xdp.o sentinel_tc.o || true

if [[ ! -d .venv/bin ]]; then
  rm -rf .venv || true
  python3 -m venv --copies .venv
fi
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# Ensure SDN controller dependencies are in the main production venv
pip install os-ken eventlet==0.35.2 tinyrpc

pushd frontend >/dev/null
# Only wipe node_modules if it doesn't exist or is corrupted
if [[ ! -d node_modules/vite ]]; then
  rm -rf node_modules package-lock.json 2>/dev/null || true
  npm install
fi
VITE_WS_URL="" \
VITE_EXPLAIN_API_URL="" \
VITE_WS_API_KEY="$WS_API_KEY" \
  node node_modules/vite/bin/vite.js build
popd >/dev/null

mkdir -p .sentinel/kali-stack
ENV_FILE=".sentinel/kali-stack/env"
cat > "$ENV_FILE" <<EOF
SENTINEL_INTERFACE=auto
SENTINEL_QUEUE_ID=0
SENTINEL_SHARED_STATE_BACKEND=shm
SENTINEL_SHARED_STATE_NAME=/sentinel_state_v1
SENTINEL_SDN_CONTROLLER=http://127.0.0.1:8080
SENTINEL_SDN_DPID=1
EOF
# Persist production defaults
cat >> "$ENV_FILE" <<EOF
SENTINEL_WS_PORT=${WS_PORT}
SENTINEL_EXPLAIN_PORT=${EXPLAIN_PORT}
SENTINEL_FRONTEND_PORT=${FRONTEND_PORT}
SENTINEL_WEB_PORT=${WEB_PORT}
SENTINEL_WS_API_KEY=${WS_API_KEY}
SENTINEL_PROFILE=production
SENTINEL_INTEGRATION_PROFILE=production
SENTINEL_MAX_CLASSIFICATIONS_PER_SEC=5000
EOF
chown -R "$RUN_USER":"$RUN_USER" .sentinel

cat > /etc/nginx/conf.d/sentinel-local.conf <<EOF
server {
    listen ${WEB_PORT};
    server_name localhost 127.0.0.1 _;

    root ${REPO_PATH}/frontend/dist;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:${EXPLAIN_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Sentinel-API-Key "${WS_API_KEY}";
    }

    location /ws {
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

nginx -t
systemctl enable nginx redis-server >/dev/null 2>&1 || true
systemctl restart nginx >/dev/null 2>&1 || service nginx restart || true
systemctl restart redis-server >/dev/null 2>&1 || service redis-server restart || true

popd >/dev/null

echo "Bootstrap complete for Kali single-node mode."
echo "Next: bash deploy/run_sentinel_stack.sh --repo-path ${REPO_PATH}"

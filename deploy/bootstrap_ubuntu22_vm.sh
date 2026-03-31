#!/usr/bin/env bash
set -euo pipefail

# Sentinel production bootstrap for Ubuntu 22.04
# - Installs dependencies
# - Builds backend and frontend
# - Configures systemd services for pipeline and explain API
# - Configures nginx to serve dashboard and proxy API/WS

REPO_PATH="${REPO_PATH:-$PWD}"
IFACE="${SENTINEL_INTERFACE:-auto}"
QUEUE_ID="${SENTINEL_QUEUE_ID:-0}"
WS_PORT="${SENTINEL_WS_PORT:-8765}"
EXPLAIN_PORT="${SENTINEL_EXPLAIN_PORT:-5001}"
WEB_PORT="${SENTINEL_WEB_PORT:-80}"
RUN_USER="${SUDO_USER:-$USER}"
WS_API_KEY="${SENTINEL_WS_API_KEY:-change-me-in-prod}"
LOG_FILE="${SENTINEL_LOG_FILE:-/var/log/sentinel/pipeline.log}"
FORCE_NON_UBUNTU=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-path) REPO_PATH="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --queue-id) QUEUE_ID="$2"; shift 2 ;;
    --ws-port) WS_PORT="$2"; shift 2 ;;
    --explain-port) EXPLAIN_PORT="$2"; shift 2 ;;
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --run-user) RUN_USER="$2"; shift 2 ;;
    --ws-api-key) WS_API_KEY="$2"; shift 2 ;;
    --force-non-ubuntu) FORCE_NON_UBUNTU=1; shift 1 ;;
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

if ! grep -q "Ubuntu 22.04" /etc/os-release; then
  if [[ "$FORCE_NON_UBUNTU" -ne 1 ]]; then
    echo "ERROR: deploy/bootstrap_ubuntu22_vm.sh is Ubuntu 22.04-specific."
    echo "For Kali/Linux single-node deployment, use deploy/bootstrap_kali_single_node.sh instead."
    echo "If you really want to continue here, rerun with --force-non-ubuntu."
    exit 1
  fi
  echo "Warning: forcing Ubuntu bootstrap on non-Ubuntu host"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  build-essential gcc make clang llvm libelf-dev pkg-config \
  libpcap-dev libpcap0.8-dev libcurl4-openssl-dev libssl-dev \
  python3 python3-venv python3-pip jq curl git nginx redis-server

if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

mkdir -p /var/log/sentinel
chown -R "$RUN_USER":"$RUN_USER" /var/log/sentinel

pushd "$REPO_PATH" >/dev/null

make clean || true
make
make -C proxy sentinel_xdp.o sentinel_tc.o || true

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

pushd frontend >/dev/null
npm ci
npm run build
popd >/dev/null

mkdir -p /etc/sentinel
cat >/etc/sentinel/pipeline.env <<EOF
SENTINEL_INTERFACE=$IFACE
SENTINEL_WS_API_KEY=$WS_API_KEY
SENTINEL_LOG_FILE=$LOG_FILE
SENTINEL_SHARED_STATE_BACKEND=shm
SENTINEL_SHARED_STATE_NAME=/sentinel_state_v1
EOF

cat >/etc/systemd/system/sentinel-pipeline.service <<EOF
[Unit]
Description=Sentinel Pipeline
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$REPO_PATH
EnvironmentFile=/etc/sentinel/pipeline.env
ExecStart=$REPO_PATH/sentinel_pipeline -i ${IFACE} -q ${QUEUE_ID} -w ${WS_PORT}
Restart=always
RestartSec=2
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/sentinel-explain-api.service <<EOF
[Unit]
Description=Sentinel Explain API
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$REPO_PATH
Environment=SENTINEL_WS_API_KEY=$WS_API_KEY
ExecStart=$REPO_PATH/.venv/bin/python explain_api.py --host 127.0.0.1 --port ${EXPLAIN_PORT}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/nginx/sites-available/sentinel <<EOF
server {
    listen ${WEB_PORT} default_server;
    server_name _;

    root $REPO_PATH/frontend/dist;
    index index.html;

    location / {
        try_files \\$uri \\$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:${EXPLAIN_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Host \\$host;
        proxy_set_header X-Real-IP \\$remote_addr;
    }

    location /ws {
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \\$host;
    }
}
EOF

ln -sf /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/sentinel
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
systemctl enable redis-server sentinel-pipeline sentinel-explain-api nginx
systemctl restart redis-server sentinel-pipeline sentinel-explain-api nginx

# Keep WS and Explain local; expose only web entrypoint by default.
ufw allow ${WEB_PORT}/tcp || true

popd >/dev/null

echo "Bootstrap complete."
echo "Web dashboard: http://<vm-public-ip>:${WEB_PORT}"
echo "Pipeline logs: journalctl -u sentinel-pipeline -f"
echo "Explain API logs: journalctl -u sentinel-explain-api -f"

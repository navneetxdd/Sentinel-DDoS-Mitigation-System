#!/bin/bash
# Roll runtime profile back to baseline safety rails.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
. "${ROOT_DIR}/scripts/load_profile.sh"
SENTINEL_PROFILE=baseline sentinel_load_profile "${ROOT_DIR}"

cat <<'EOF'
[ROLLBACK] Baseline profile applied in current shell.

Use one of the commands below from repo root:
  SENTINEL_PROFILE=baseline ./launch-sentinel.sh
  SENTINEL_PROFILE=baseline ./scripts/start_with_ryu.sh

For Windows launcher, set and run:
  set SENTINEL_PROFILE=baseline
  Launch-Sentinel.bat
EOF

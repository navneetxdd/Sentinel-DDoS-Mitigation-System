#!/usr/bin/env bash
# Sentinel ML/RL Status Checker
# Verifies that the ML Baseline Gate and RL Feedback Loop are active.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE="$REPO/.sentinel/kali-stack"
ENV="$STATE/env"

if [[ -f "$ENV" ]]; then
    source "$ENV"
fi

echo "============================================"
echo "  SENTINEL ML/RL ENGINE STATUS"
echo "============================================"

# Check Profile
PROFILE="${SENTINEL_PROFILE:-${SENTINEL_INTEGRATION_PROFILE:-production}}"
echo -n "Integration Profile : "
if [[ "$PROFILE" == "production" || "$PROFILE" == "full" || "$PROFILE" == "progressive" ]]; then
    echo -e "\e[32m$PROFILE\e[0m (Automatic ML/RL runtime)"
else
    echo -e "\e[33m$PROFILE\e[0m (Standard)"
fi

# Check ML Baseline Gate
# Defaults are profile-driven in the C runtime if not set
MODEL_EXT="${SENTINEL_MODEL_EXTENSION_ENABLED:-${SENTINEL_ENABLE_MODEL_EXTENSION:-}}"
if [[ -z "${MODEL_EXT}" ]]; then
    if [[ "$PROFILE" == "baseline" ]]; then
        MODEL_EXT="0"
    else
        MODEL_EXT="1"
    fi
fi
echo -n "ML Baseline Gate    : "
if [[ "$MODEL_EXT" == "1" ]]; then
    echo -e "\e[32mACTIVE\e[0m (ML auto-activates when baseline threat >= 0.30)"
else
    echo -e "\e[31mINACTIVE\e[0m"
fi

# Check RL Feedback Loop
# Defaults are profile-driven in the C runtime if not set
INTEL_FEED="${SENTINEL_INTEL_FEED_ENABLED:-${SENTINEL_ENABLE_INTEL_FEED:-}}"
if [[ -z "${INTEL_FEED}" ]]; then
    if [[ "$PROFILE" == "baseline" ]]; then
        INTEL_FEED="0"
    else
        INTEL_FEED="1"
    fi
fi
echo -n "RL Feedback Loop    : "
if [[ "$INTEL_FEED" == "1" ]]; then
    echo -e "\e[32mACTIVE\e[0m (Policy learner runs automatically)"
else
    echo -e "\e[31mINACTIVE\e[0m"
fi

# Check SDN Connectivity
if curl -fsS --max-time 2 "http://127.0.0.1:8080/stats/switches" >/dev/null 2>&1; then
    echo -e "SDN Controller      : \e[32mONLINE\e[0m"
else
    echo -e "SDN Controller      : \e[31mOFFLINE\e[0m"
fi

# Check Pipeline WebSocket
if ss -ltn "sport = :8765" 2>/dev/null | grep -q LISTEN; then
    echo -e "Pipeline WebSocket  : \e[32mONLINE\e[0m"
else
    echo -e "Pipeline WebSocket  : \e[31mOFFLINE\e[0m"
fi

echo "============================================"

# Optional: pipeline RSS (target: stay under ~200MB for single-queue edge deployments)
if command -v pgrep >/dev/null 2>&1; then
    PID="$(pgrep -f 'sentinel_pipeline|./sentinel_pipeline' 2>/dev/null | head -1)"
    if [[ -n "$PID" && -r "/proc/$PID/status" ]]; then
        RSS_KB="$(awk '/^VmRSS:/ {print $2}' "/proc/$PID/status")"
        if [[ -n "$RSS_KB" ]]; then
            RSS_MB=$((RSS_KB / 1024))
            echo -n "Pipeline RSS (pid $PID) : ${RSS_MB} MB"
            if [[ "$RSS_MB" -le 200 ]]; then
                echo -e " \e[32m(<= 200 MB target)\e[0m"
            else
                echo -e " \e[33m(> 200 MB — review buffers / rings)\e[0m"
            fi
        fi
    fi
fi

echo "To activate production ML/RL mode, run:"
echo "  export SENTINEL_PROFILE=production"
echo "  sudo bash deploy/run_sentinel_stack.sh"
echo "============================================"

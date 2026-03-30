#!/bin/bash
# Load Sentinel integration profile env vars.

sentinel_load_profile() {
    local root_dir profile profile_file

    root_dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
    profile="${SENTINEL_PROFILE:-${SENTINEL_INTEGRATION_PROFILE:-production}}"
    profile_file="${SENTINEL_PROFILE_FILE:-${root_dir}/scripts/profiles/${profile}.env}"

    if [ ! -f "${profile_file}" ]; then
        echo "[WARN] Profile file not found: ${profile_file}" >&2
        return 1
    fi

    set -a
    # shellcheck disable=SC1090
    . "${profile_file}"
    set +a

    export SENTINEL_PROFILE="${profile}"
    export SENTINEL_INTEGRATION_PROFILE="${profile}"
    export SENTINEL_PROFILE_FILE="${profile_file}"

    echo "[PROFILE] Loaded ${profile} from ${profile_file}"
    return 0
}

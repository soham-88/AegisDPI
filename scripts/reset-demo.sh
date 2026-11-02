#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== AegisDPI Demo Reset ==="
read -r -p "Reset all packet logs, ML verdicts, and active blocklist rules? [y/N] " confirm
case "${confirm}" in
    [yY][eE][sS]|[yY])
        ;;
    *)
        echo "Reset aborted."
        exit 0
        ;;
esac

# Read Redis password from middleware/.env
REDIS_PW=""
if [ -f "${REPO_ROOT}/middleware/.env" ]; then
    REDIS_PW=$(grep -E '^REDIS_URL=' "${REPO_ROOT}/middleware/.env" | sed -E 's/.*redis:\/\/:([^@]+)@.*/\1/' || true)
fi
if [ -z "${REDIS_PW}" ]; then
    echo "ERROR: Could not read REDIS_URL from middleware/.env. Run scripts/setup.sh first." >&2
    exit 1
fi

CLI=(redis-cli -a "${REDIS_PW}" --no-auth-warning)

# Verify Redis connection
if ! "${CLI[@]}" ping >/dev/null 2>&1; then
    echo "Error: Cannot connect to Redis at 127.0.0.1:6379." >&2
    echo "Please start Aegis services first: ./scripts/aegis.sh start" >&2
    exit 1
fi

echo "Clearing demo data..."

# 1. Clear ml:verdict_history
VERDICTS_DELETED=$("${CLI[@]}" del ml:verdict_history 2>/dev/null || echo 0)

# 2. Clear dpi:logs
LOGS_DELETED=$("${CLI[@]}" del dpi:logs 2>/dev/null || echo 0)

# 3. For every IP in blocklist:ips:
#    SREM blocklist:ips <ip>
#    PUBLISH blocklist:updates "DEL IP <ip>"
#    HDEL blocklist:meta <ip>
IPS_CLEARED=0
BLOCKED_IPS=$("${CLI[@]}" smembers blocklist:ips 2>/dev/null || true)
if [ -n "${BLOCKED_IPS}" ]; then
    while IFS= read -r ip; do
        [ -z "${ip}" ] && continue
        "${CLI[@]}" srem blocklist:ips "${ip}" >/dev/null
        "${CLI[@]}" publish blocklist:updates "DEL IP ${ip}" >/dev/null
        "${CLI[@]}" hdel blocklist:meta "${ip}" >/dev/null
        IPS_CLEARED=$((IPS_CLEARED + 1))
    done <<< "${BLOCKED_IPS}"
fi

# 4. DEL blocklist:meta and DEL blocklist:ips
"${CLI[@]}" del blocklist:meta >/dev/null || true
"${CLI[@]}" del blocklist:ips >/dev/null || true

# 5. Flush kernel nftables set if present
sudo -n nft flush set inet aegis blocklist 2>/dev/null || true

echo "=== Demo Reset Complete ==="
echo "Cleared items:"
echo "  - ml:verdict_history (keys deleted: ${VERDICTS_DELETED})"
echo "  - dpi:logs stream    (keys deleted: ${LOGS_DELETED})"
echo "  - blocklist rules    (${IPS_CLEARED} IP(s) removed; blocklist:meta deleted)"

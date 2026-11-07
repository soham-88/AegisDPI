#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIDDLEWARE_URL="${MIDDLEWARE_URL:-http://127.0.0.1:4000}"

# Read configuration from .env files without altering them
MW_ENV="${REPO_ROOT}/middleware/.env"
ML_ENV="${REPO_ROOT}/ml-service/.env"

if [ ! -f "${MW_ENV}" ]; then
    echo "ERROR: middleware/.env not found" >&2
    exit 1
fi
if [ ! -f "${ML_ENV}" ]; then
    echo "ERROR: ml-service/.env not found" >&2
    exit 1
fi

ADMIN_USERNAME=$(grep -E '^ADMIN_USERNAME=' "${MW_ENV}" | cut -d= -f2- | tr -d '\r"')
REDIS_URL_RAW=$(grep -E '^REDIS_URL=' "${MW_ENV}" | cut -d= -f2- | tr -d '\r"')
REDIS_PW=$(echo "${REDIS_URL_RAW}" | sed -n 's/.*redis:\/\/:*\([^@]*\)@.*/\1/p')
if [ -z "${REDIS_PW}" ] && [ -f "${REPO_ROOT}/run/redis.pass" ]; then
    REDIS_PW=$(cat "${REPO_ROOT}/run/redis.pass")
fi

ML_SERVICE_USERNAME=$(grep -E '^ML_SERVICE_USERNAME=' "${ML_ENV}" | cut -d= -f2- | tr -d '\r"')
ML_SERVICE_PASSWORD=$(grep -E '^ML_SERVICE_PASSWORD=' "${ML_ENV}" | cut -d= -f2- | tr -d '\r"')

# Prompt for admin password if not provided in environment
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
if [ -z "${ADMIN_PASSWORD}" ]; then
    read -r -s -p "Enter admin password for user '${ADMIN_USERNAME}': " ADMIN_PASSWORD
    echo
fi

echo "=================================================="
echo "AegisDPI Phase 4 Safe Blocking Smoke Test"
echo "Target: ${MIDDLEWARE_URL}"
echo "=================================================="

# Check middleware accessibility
if ! curl -s --connect-timeout 2 "${MIDDLEWARE_URL}/api/auth/login" >/dev/null 2>&1; then
    echo "ERROR: Middleware is not responding on ${MIDDLEWARE_URL}" >&2
    echo "Please ensure services are running: ./scripts/aegis.sh start" >&2
    exit 1
fi

# Obtain admin token
ADMIN_LOGIN_RESP=$(curl -s -X POST "${MIDDLEWARE_URL}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}")
ADMIN_TOKEN=$(echo "${ADMIN_LOGIN_RESP}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [ -z "${ADMIN_TOKEN}" ]; then
    echo "ERROR: Admin authentication failed for user '${ADMIN_USERNAME}'" >&2
    exit 1
fi

# Obtain ML service token
ML_LOGIN_RESP=$(curl -s -X POST "${MIDDLEWARE_URL}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ML_SERVICE_USERNAME}\",\"password\":\"${ML_SERVICE_PASSWORD}\"}")
ML_TOKEN=$(echo "${ML_LOGIN_RESP}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [ -z "${ML_TOKEN}" ]; then
    echo "ERROR: ML service authentication failed for user '${ML_SERVICE_USERNAME}'" >&2
    exit 1
fi

# Helper functions
redis_cmd() {
    if [ -n "${REDIS_PW}" ]; then
        redis-cli -a "${REDIS_PW}" --no-auth-warning "$@"
    else
        redis-cli "$@"
    fi
}

cleanup_test_records() {
    # Remove test IPs from rules via API
    for ip in 192.0.2.10 192.0.2.20 192.0.2.5; do
        curl -s -X DELETE "${MIDDLEWARE_URL}/api/rules" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"type\":\"ip\",\"value\":\"${ip}\"}" >/dev/null 2>&1 || true
    done
    # Remove allowlist entry via API
    curl -s -X DELETE "${MIDDLEWARE_URL}/api/allowlist" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"entry":"192.0.2.0/29"}' >/dev/null 2>&1 || true

    # Clean Redis strikes
    redis_cmd HDEL blocklist:strikes 192.0.2.10 192.0.2.20 192.0.2.5 >/dev/null 2>&1 || true
}

# Run initial cleanup
cleanup_test_records

FAILED=0

# Check a: POST ip "999.1.1.1" -> 400
echo -n "Check A: Reject invalid IP '999.1.1.1' -> "
STATUS_A=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"999.1.1.1"}')
if [ "${STATUS_A}" = "400" ]; then
    echo "PASS (HTTP 400)"
else
    echo "FAIL (HTTP ${STATUS_A}, expected 400)"
    FAILED=$((FAILED + 1))
fi

# Check b: POST ip "010.0.0.1" -> 400
echo -n "Check B: Reject leading zero IP '010.0.0.1' -> "
STATUS_B=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"010.0.0.1"}')
if [ "${STATUS_B}" = "400" ]; then
    echo "PASS (HTTP 400)"
else
    echo "FAIL (HTTP ${STATUS_B}, expected 400)"
    FAILED=$((FAILED + 1))
fi

# Check c: POST a host-local IP (127.0.0.1) -> 400
echo -n "Check C: Reject host-local IP '127.0.0.1' -> "
STATUS_C=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"127.0.0.1"}')
if [ "${STATUS_C}" = "400" ]; then
    echo "PASS (HTTP 400)"
else
    echo "FAIL (HTTP ${STATUS_C}, expected 400)"
    FAILED=$((FAILED + 1))
fi

# Check d: ML token: DELETE /api/rules -> 403; GET /api/capture/status -> 403
echo -n "Check D: ML role enforcement (DELETE rules -> 403, GET capture -> 403) -> "
STATUS_D1=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ML_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.20"}')
STATUS_D2=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${MIDDLEWARE_URL}/api/capture/status" \
    -H "Authorization: Bearer ${ML_TOKEN}")
if [ "${STATUS_D1}" = "403" ] && [ "${STATUS_D2}" = "403" ]; then
    echo "PASS (both 403)"
else
    echo "FAIL (DELETE rules: ${STATUS_D1}, GET capture: ${STATUS_D2}, expected 403)"
    FAILED=$((FAILED + 1))
fi

# Check e: ML token: POST 192.0.2.20 -> 201 with ttl_s 600; admin DELETE; ML POST again -> ttl_s 3600; admin DELETE
echo -n "Check E: Repeat offender TTL escalation (600s -> 3600s) -> "
RESP_E1=$(curl -s -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ML_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.20","reason":"Strike 1 test"}')
TTL_E1=$(echo "${RESP_E1}" | grep -o '"ttl_s":[0-9]*' | cut -d: -f2)

curl -s -X DELETE "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.20"}' >/dev/null 2>&1

RESP_E2=$(curl -s -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ML_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.20","reason":"Strike 2 test"}')
TTL_E2=$(echo "${RESP_E2}" | grep -o '"ttl_s":[0-9]*' | cut -d: -f2)

curl -s -X DELETE "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.20"}' >/dev/null 2>&1

if [ "${TTL_E1}" = "600" ] && [ "${TTL_E2}" = "3600" ]; then
    echo "PASS (1st strike: ${TTL_E1}s, 2nd strike: ${TTL_E2}s)"
else
    echo "FAIL (1st strike: ${TTL_E1}, 2nd strike: ${TTL_E2}, expected 600 and 3600)"
    FAILED=$((FAILED + 1))
fi

# Check f: admin: POST /api/allowlist 192.0.2.0/29; ML POST 192.0.2.5 -> 409; admin POST 192.0.2.5 -> 409; admin DELETE allowlist
echo -n "Check F: Allowlist protection (192.0.2.0/29 -> 409 on 192.0.2.5) -> "
curl -s -X POST "${MIDDLEWARE_URL}/api/allowlist" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"entry":"192.0.2.0/29","note":"Test allowlist"}' >/dev/null 2>&1

STATUS_F1=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ML_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.5"}')

STATUS_F2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.5"}')

curl -s -X DELETE "${MIDDLEWARE_URL}/api/allowlist" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"entry":"192.0.2.0/29"}' >/dev/null 2>&1

if [ "${STATUS_F1}" = "409" ] && [ "${STATUS_F2}" = "409" ]; then
    echo "PASS (both blocked with 409 Conflict)"
else
    echo "FAIL (ML: ${STATUS_F1}, Admin: ${STATUS_F2}, expected 409)"
    FAILED=$((FAILED + 1))
fi

# Check g: admin: POST 192.0.2.10 with ttl_s 60 -> 201; confirm in blocklist:ips; wait expiry + 10s; confirm gone & audit has expire
echo "Check G: TTL expiration & background sweeper (60s TTL + 10s margin)..."
RESP_G=$(curl -s -X POST "${MIDDLEWARE_URL}/api/rules" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"192.0.2.10","ttl_s":60,"reason":"Temporary TTL test"}')

EXPIRES_AT=$(echo "${RESP_G}" | grep -o '"expires_at":"[^"]*"' | cut -d'"' -f4)
IS_MEMBER_BEFORE=$(redis_cmd SISMEMBER blocklist:ips 192.0.2.10)

if [ "${IS_MEMBER_BEFORE}" != "1" ] || [ -z "${EXPIRES_AT}" ]; then
    echo "  -> FAIL: Block was not added or missing expires_at (${RESP_G})"
    FAILED=$((FAILED + 1))
else
    echo "  Block established with expires_at: ${EXPIRES_AT}. Verified in blocklist:ips = 1."
    echo "  Waiting 70 seconds for sweeper to expire rule..."
    for remaining in {70..1}; do
        printf "\r  Countdown: %2d seconds remaining..." "${remaining}"
        sleep 1
    done
    printf "\r  Countdown completed. Checking state...         \n"

    IS_MEMBER_AFTER=$(redis_cmd SISMEMBER blocklist:ips 192.0.2.10)
    AUDIT_LOGS=$(curl -s "${MIDDLEWARE_URL}/api/audit?limit=50" -H "Authorization: Bearer ${ADMIN_TOKEN}")
    EXPIRE_AUDIT=$(echo "${AUDIT_LOGS}" | grep "192.0.2.10" | grep "expire" || true)

    if [ "${IS_MEMBER_AFTER}" = "0" ] && [ -n "${EXPIRE_AUDIT}" ]; then
        echo "  -> PASS: 192.0.2.10 successfully removed by sweeper and recorded in audit:log"
    else
        echo "  -> FAIL: IS_MEMBER_AFTER=${IS_MEMBER_AFTER} (expected 0), EXPIRE_AUDIT present: $([ -n "${EXPIRE_AUDIT}" ] && echo yes || echo no)"
        FAILED=$((FAILED + 1))
    fi
fi

# Check h: GET /api/audit contains block, extend or unblock, block_rejected, allowlist_add, allowlist_remove
echo -n "Check H: Audit stream coverage (all lifecycle actions recorded) -> "
ALL_AUDIT=$(curl -s "${MIDDLEWARE_URL}/api/audit?limit=200" -H "Authorization: Bearer ${ADMIN_TOKEN}")

HAS_BLOCK=$(echo "${ALL_AUDIT}" | grep -q '"action":"block"' && echo 1 || echo 0)
HAS_UNBLOCK_OR_EXTEND=$(echo "${ALL_AUDIT}" | grep -qE '"action":"(unblock|extend)"' && echo 1 || echo 0)
HAS_REJECTED=$(echo "${ALL_AUDIT}" | grep -q '"action":"block_rejected"' && echo 1 || echo 0)
HAS_ALW_ADD=$(echo "${ALL_AUDIT}" | grep -q '"action":"allowlist_add"' && echo 1 || echo 0)
HAS_ALW_REM=$(echo "${ALL_AUDIT}" | grep -q '"action":"allowlist_remove"' && echo 1 || echo 0)

if [ "${HAS_BLOCK}" = "1" ] && [ "${HAS_UNBLOCK_OR_EXTEND}" = "1" ] && [ "${HAS_REJECTED}" = "1" ] && [ "${HAS_ALW_ADD}" = "1" ] && [ "${HAS_ALW_REM}" = "1" ]; then
    echo "PASS (all audit actions verified)"
else
    echo "FAIL (block:${HAS_BLOCK}, unblock/extend:${HAS_UNBLOCK_OR_EXTEND}, rejected:${HAS_REJECTED}, allowlist_add:${HAS_ALW_ADD}, allowlist_remove:${HAS_ALW_REM})"
    FAILED=$((FAILED + 1))
fi

# Final cleanup
cleanup_test_records

echo "=================================================="
if [ ${FAILED} -eq 0 ]; then
    echo "ALL PHASE 4 CHECKS PASSED (8/8)"
    echo "=================================================="
    exit 0
else
    echo "PHASE 4 CHECKS FAILED (${FAILED} failure(s))"
    echo "=================================================="
    exit 1
fi


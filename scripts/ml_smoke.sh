#!/usr/bin/env bash
set -euo pipefail

ML_URL="${ML_URL:-http://127.0.0.1:8000}"

# Check whether ML service is reachable on port 8000
if ! curl -s --connect-timeout 2 "${ML_URL}/model/status" > /dev/null 2>&1; then
    echo "ERROR: ML service is not reachable at ${ML_URL}" >&2
    echo "Please ensure the ML service is running: ./scripts/aegis.sh restart-ml (or ./scripts/aegis.sh start)" >&2
    exit 1
fi

echo "=================================================="
echo "AegisDPI ML Service Smoke Test"
echo "Target: ${ML_URL}"
echo "=================================================="

FAILED=0

# 1. Model Status check
echo "[1/4] Checking /model/status..."
STATUS_JSON=$(curl -s -f "${ML_URL}/model/status")

if python3 - <<EOF
import sys, json

data = json.loads('''${STATUS_JSON}''')
version = data.get("model_version")
mtype = data.get("model_type")
n_est = data.get("n_estimators")
samples = data.get("training_sample_count")
schema = data.get("feature_schema", [])
schema_len = len(schema)

print(f"  Model Version:         {version}")
print(f"  Model Type:            {mtype}")
print(f"  Estimators:            {n_est}")
print(f"  Training Sample Count: {samples}")
print(f"  Feature Schema Length: {schema_len} features")

if version != "v3":
    print(f"  FAIL: expected model_version 'v3', got '{version}'", file=sys.stderr)
    sys.exit(1)
EOF
then
    echo "  -> PASS: /model/status reported valid v3 model"
else
    echo "  -> FAIL: /model/status assertion failed"
    FAILED=$((FAILED + 1))
fi

# 2. Vector a: Normal browsing median vector
echo "[2/4] Testing Vector A: Normal browsing..."
VECTOR_A=$(python3 - <<'EOF'
import json, sys
try:
    with open("ml-service/models/v2/meta.json") as f:
        meta = json.load(f)
    medians = {k: v["median"] for k, v in meta["feature_stats"].items()}
    print(json.dumps({"source_ip": "10.10.0.99", "features": medians}))
except Exception as e:
    print(f"Error loading meta.json: {e}", file=sys.stderr)
    sys.exit(1)
EOF
)
RESP_A=$(curl -s -f -X POST "${ML_URL}/predict" -H "Content-Type: application/json" -d "${VECTOR_A}")

if python3 - <<EOF
import sys, json

resp = json.loads('''${RESP_A}''')
verdict = resp.get("verdict")
trigger = resp.get("trigger")
print(f"  Verdict: {verdict}, Trigger: {trigger}, Confidence: {resp.get('confidence')}")

if verdict is not None:
    print(f"  FAIL: Expected verdict null, got '{verdict}'", file=sys.stderr)
    sys.exit(1)
EOF
then
    echo "  -> PASS: Normal browsing returned verdict=null"
else
    echo "  -> FAIL: Normal browsing vector failed"
    FAILED=$((FAILED + 1))
fi

# 3. Vector b: Heavy download vector
echo "[3/4] Testing Vector B: Heavy download..."
VECTOR_B='{"source_ip": "10.10.0.99", "features": {"log_pps": 5.4, "log_syn_rate": 0.34, "syn_ratio": 0.002, "log_rst_rate": 0.0, "log_icmp_echo_rate": 0.0, "log_udp_rate": 0.0, "log_unique_dst_ports": 0.6931, "log_unique_src_ports": 1.099, "log_pkts_per_flow": 6.3, "unique_dst_ips": 1.0}}'
RESP_B=$(curl -s -f -X POST "${ML_URL}/predict" -H "Content-Type: application/json" -d "${VECTOR_B}")

if python3 - <<EOF
import sys, json

resp = json.loads('''${RESP_B}''')
verdict = resp.get("verdict")
trigger = resp.get("trigger")
print(f"  Verdict: {verdict}, Trigger: {trigger}, Confidence: {resp.get('confidence')}")

if verdict == "ANOMALOUS":
    print(f"  FAIL: Expected verdict not 'ANOMALOUS' (null or 'SUSPICIOUS'), got '{verdict}'", file=sys.stderr)
    sys.exit(1)
EOF
then
    echo "  -> PASS: Heavy download returned non-anomalous verdict"
else
    echo "  -> FAIL: Heavy download vector failed"
    FAILED=$((FAILED + 1))
fi

# 4. Vector c: UDP flood vector
echo "[4/4] Testing Vector C: UDP flood..."
VECTOR_C='{"source_ip": "10.10.0.99", "features": {"log_pps": 7.9, "log_syn_rate": 0.34, "syn_ratio": 0.002, "log_rst_rate": 0.0, "log_icmp_echo_rate": 0.0, "log_udp_rate": 7.9, "log_unique_dst_ports": 0.6931, "log_unique_src_ports": 9.5, "log_pkts_per_flow": 0.69, "unique_dst_ips": 1.0}}'
RESP_C=$(curl -s -f -X POST "${ML_URL}/predict" -H "Content-Type: application/json" -d "${VECTOR_C}")

if python3 - <<EOF
import sys, json

resp = json.loads('''${RESP_C}''')
verdict = resp.get("verdict")
trigger = resp.get("trigger")
desc = resp.get("description", "")
print(f"  Verdict: {verdict}, Trigger: {trigger}, Confidence: {resp.get('confidence')}")
print(f"  Description: {desc}")

if verdict != "ANOMALOUS":
    print(f"  FAIL: Expected verdict 'ANOMALOUS', got '{verdict}'", file=sys.stderr)
    sys.exit(1)
if trigger != "guard":
    print(f"  FAIL: Expected trigger 'guard', got '{trigger}'", file=sys.stderr)
    sys.exit(1)
if "UDP packets/sec" not in desc:
    print(f"  FAIL: Expected description to mention 'UDP packets/sec', got '{desc}'", file=sys.stderr)
    sys.exit(1)
EOF
then
    echo "  -> PASS: UDP flood correctly flagged by guard"
else
    echo "  -> FAIL: UDP flood vector failed"
    FAILED=$((FAILED + 1))
fi

echo "=================================================="
if [ ${FAILED} -eq 0 ]; then
    echo "ALL SMOKE TESTS PASSED (4/4)"
    echo "=================================================="
    exit 0
else
    echo "SMOKE TESTS FAILED (${FAILED} failure(s))"
    echo "=================================================="
    exit 1
fi

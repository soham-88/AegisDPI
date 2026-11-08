#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

NAME=""
MODE="mixed"
DURATION=1800
SEED=42
QUICK=false

usage() {
  local code="${1:-1}"
  cat <<EOF
Usage: $0 --name <dataset_name> [options]

Required:
  --name <name>       Dataset name (outputs to datasets/<name>/)

Options:
  --mode <mode>       mixed|benign (default: mixed)
  --duration <sec>    Duration in seconds (benign mode only, default: 1800)
  --seed <int>        Random seed for client traffic generation (default: 42)
  --quick             Mixed mode smoke test with shortened durations
  -h, --help          Show this help message
EOF
  exit "${code}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      NAME="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --quick)
      QUICK=true
      shift
      ;;
    -h|--help)
      usage 0
      ;;
    *)
      echo "Error: Unknown option: $1" >&2
      usage 1
      ;;
  esac
done

if [ -z "${NAME}" ]; then
  echo "Error: --name <dataset name> is required." >&2
  usage
fi

if [ "${MODE}" != "mixed" ] && [ "${MODE}" != "benign" ]; then
  echo "Error: --mode must be 'mixed' or 'benign' (got: ${MODE})" >&2
  exit 1
fi

OUT_DIR="${REPO_DIR}/datasets/${NAME}"
if [ -d "${OUT_DIR}" ] && [ -n "$(ls -A "${OUT_DIR}" 2>/dev/null)" ]; then
  echo "Error: Output directory '${OUT_DIR}' exists and is not empty." >&2
  exit 1
fi

ENGINE="${AEGIS_ENGINE:-/usr/local/sbin/aegis-dpi-engine}"
PASS_FILE="${REPO_DIR}/run/redis.pass"
PYTHON_VENV="${REPO_DIR}/ml-service/venv/bin/python"

# 1. Safety check: running dpi_engine or aegis-dpi-engine
if pgrep -f "(aegis-dpi-engine|dpi_engine)" >/dev/null 2>&1; then
  echo "Error: a dpi_engine process is already running." >&2
  echo "Live mode installs nftables rules and would clash with a running engine. Stop it first." >&2
  exit 1
fi

# 2. Safety check: lab environment and secondary IPs
if [ ! -e /run/netns/ns_attacker ] && ! ip netns list 2>/dev/null | grep -qw "ns_attacker" && ! sudo -n ip netns list 2>/dev/null | grep -qw "ns_attacker"; then
  echo "Error: Lab environment is not up (namespace 'ns_attacker' missing)." >&2
  echo "Please start the lab environment first: ./scripts/lab.sh up" >&2
  exit 1
fi

for ip in 10.10.0.3 10.10.0.4 10.10.0.5 10.10.0.6; do
  if ! sudo ip netns exec ns_attacker ip -4 addr show dev veth_attacker 2>/dev/null | grep -qw "${ip}"; then
    echo "Error: Secondary IP ${ip} missing on veth_attacker in ns_attacker." >&2
    echo "Please run ./scripts/lab.sh up to configure all required lab IPs." >&2
    exit 1
  fi
done

# 3. Safety check: required tools
for tool in hping3 nmap tcpdump curl openssl redis-server; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Error: Required binary '${tool}' is missing. Please install it." >&2
    exit 1
  fi
done

if [ ! -x "${PYTHON_VENV}" ]; then
  echo "Error: Python venv binary missing or not executable at: ${PYTHON_VENV}" >&2
  echo "Please ensure ml-service/venv is set up." >&2
  exit 1
fi

# 4. Safety check: engine binary, capabilities, and redis.pass
if [ ! -x "${ENGINE}" ]; then
  echo "Error: Engine binary not found or not executable at: ${ENGINE}" >&2
  echo "Please install it first: sudo ./scripts/install_engine.sh" >&2
  exit 1
fi

if ! getcap "${ENGINE}" 2>/dev/null | grep -E "cap_net_admin.*cap_net_raw|cap_net_raw.*cap_net_admin" >/dev/null; then
  echo "Error: Engine binary at ${ENGINE} lacks required capabilities (CAP_NET_RAW and CAP_NET_ADMIN)." >&2
  echo "Please install it with capabilities: sudo ./scripts/install_engine.sh" >&2
  exit 1
fi

if [ ! -f "${PASS_FILE}" ]; then
  echo "Error: Redis password file missing at: ${PASS_FILE}" >&2
  echo "Please run ./scripts/setup.sh first to generate credentials." >&2
  exit 1
fi

REDIS_PASS="$(cat "${PASS_FILE}")"

# Authenticate sudo once and keepalive in background
echo "Authenticating sudo credentials..."
sudo -v
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
SUDO_KEEPALIVE_PID=$!

mkdir -p "${OUT_DIR}"

# Timing parameters
if [ "${QUICK}" = true ]; then
  WARMUP=20
  ATTACK_DUR=10
  GAP=5
  SCAN_FAST_CAP=20
  SCAN_SLOW_CAP=20
  COOLDOWN=10
else
  WARMUP=120
  ATTACK_DUR=30
  GAP=30
  SCAN_FAST_CAP=120
  SCAN_SLOW_CAP=180
  COOLDOWN=60
fi

# Global process handles
ENGINE_PID=""
RECORDER_PID=""
TCPDUMP_PID=""
HTTP_PID=""
OPENSSL_PID=""
CLIENT_BROWSER_PID=""
CLIENT_HEAVY_PID=""
WEB_ROOT=""
CERT_DIR=""
ATTACK_ENTRIES_FILE="$(mktemp /tmp/aegis_attack_entries_XXXXXX.jsonl)"

DATASET_START_TS=""
DATASET_END_TS=""
BENIGN_START_TS=""
BENIGN_END_TS=""
LOG_DROPPED=0
LOG_FAILED=0

redis_cmd() {
  redis-cli -h 127.0.0.2 -p 6379 -a "${REDIS_PASS}" --no-auth-warning "$@"
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  echo ""
  echo "Stopping dataset recording and cleaning up..."

  # Record end timestamps if not already set
  if [ -z "${DATASET_END_TS:-}" ]; then
    DATASET_END_TS=$(python3 -c "import time; print(f'{time.time():.6f}')")
  fi
  if [ -z "${BENIGN_END_TS:-}" ]; then
    BENIGN_END_TS="${DATASET_END_TS}"
  fi

  # 1. Stop attack and benign client processes inside ns_attacker
  echo "Stopping client and attack processes..."
  sudo ip netns pids ns_attacker 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
  kill "${CLIENT_BROWSER_PID:-}" "${CLIENT_HEAVY_PID:-}" 2>/dev/null || true

  # 2. Stop host services
  echo "Stopping host services..."
  kill "${HTTP_PID:-}" "${OPENSSL_PID:-}" 2>/dev/null || true
  sudo pkill -f "python3 -m http.server 8080 --bind 10.10.0.1" 2>/dev/null || true
  sudo pkill -f "openssl s_server -accept 10.10.0.1:8443" 2>/dev/null || true
  if [ -n "${WEB_ROOT:-}" ] && [ -d "${WEB_ROOT}" ]; then
    rm -rf "${WEB_ROOT}"
  fi
  if [ -n "${CERT_DIR:-}" ] && [ -d "${CERT_DIR}" ]; then
    rm -rf "${CERT_DIR}"
  fi

  # 3. Stop tcpdump
  echo "Stopping tcpdump..."
  if [ -n "${TCPDUMP_PID:-}" ]; then
    sudo kill -INT "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
  fi
  sudo pkill -INT -f "tcpdump -i veth_lab -s 1514 -w" 2>/dev/null || true

  # 4. Wait 3 s for engine to drain and reporter to flush
  echo "Waiting 3s for engine and reporter queue flush..."
  sleep 3

  # 5. Stop the recorder (SIGINT)
  echo "Stopping log recorder..."
  if [ -n "${RECORDER_PID:-}" ]; then
    kill -INT "${RECORDER_PID}" 2>/dev/null || true
    wait "${RECORDER_PID}" 2>/dev/null || true
  fi

  # 6. Read dpi:stats log_dropped and log_failed from Redis on 127.0.0.2
  LOG_DROPPED=$(redis_cmd --raw HGET dpi:stats log_dropped 2>/dev/null || echo "0")
  LOG_FAILED=$(redis_cmd --raw HGET dpi:stats log_failed 2>/dev/null || echo "0")
  LOG_DROPPED="${LOG_DROPPED:-0}"
  LOG_FAILED="${LOG_FAILED:-0}"

  # 7. Stop the engine (SIGINT, then SIGTERM after 10 s)
  if [ -n "${ENGINE_PID:-}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
    echo "Stopping engine (PID ${ENGINE_PID})..."
    kill -INT "${ENGINE_PID}" 2>/dev/null || pkill -INT -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" 2>/dev/null || true
    wait "${ENGINE_PID}" 2>/dev/null || true
  else
    pkill -INT -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" 2>/dev/null || true
  fi

  local waited=0
  while pgrep -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" >/dev/null 2>&1; do
    sleep 0.2
    waited=$((waited + 1))
    if [ "${waited}" -ge 50 ]; then
      break
    fi
  done

  if pgrep -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" >/dev/null 2>&1; then
    echo "engine did not exit after SIGINT; sending SIGTERM..."
    if [ -n "${ENGINE_PID:-}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
      kill -TERM "${ENGINE_PID}" 2>/dev/null || pkill -TERM -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" 2>/dev/null || true
      wait "${ENGINE_PID}" 2>/dev/null || true
    else
      pkill -TERM -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" 2>/dev/null || true
    fi

    waited=0
    while pgrep -f "(aegis-dpi-engine|dpi_engine).*--live veth_lab" >/dev/null 2>&1; do
      sleep 0.2
      waited=$((waited + 1))
      if [ "${waited}" -ge 25 ]; then
        break
      fi
    done
  fi

  # 8. Verify no "inet aegis" nft table remains
  local nft_tables
  nft_tables=$(sudo nft list tables 2>/dev/null || true)
  if echo "${nft_tables}" | grep -q "inet aegis"; then
    echo "WARNING: nftables table 'inet aegis' is still present after dpi_engine shutdown!" >&2
  fi

  # 9. Shut down isolated Redis
  if [ -n "${REDIS_PASS:-}" ]; then
    redis-cli -h 127.0.0.2 -p 6379 -a "${REDIS_PASS}" --no-auth-warning shutdown nosave 2>/dev/null || true
  fi

  # Stop sudo keepalive
  kill "${SUDO_KEEPALIVE_PID:-}" 2>/dev/null || true

  # Save schedule and summary if recording was initialized
  if [ -n "${BENIGN_START_TS:-}" ]; then
    save_schedule
    generate_summary
  fi

  rm -f "${ATTACK_ENTRIES_FILE:-}"

  echo "Cleanup complete."
  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

save_schedule() {
  python3 - "${OUT_DIR}/schedule.json" "${NAME}" "${MODE}" "${SEED}" "${DATASET_START_TS}" "${DATASET_END_TS}" "${BENIGN_START_TS}" "${BENIGN_END_TS}" "${ATTACK_ENTRIES_FILE}" <<'PY'
import sys, os, json

out_path = sys.argv[1]
name = sys.argv[2]
mode = sys.argv[3]
seed = int(sys.argv[4])
started_at = float(sys.argv[5])
ended_at = float(sys.argv[6])
b_start = float(sys.argv[7])
b_end = float(sys.argv[8])
attacks_file = sys.argv[9]

entries = [
    {
        "label": "benign_browser",
        "src_ip": "10.10.0.3",
        "start_ts": b_start,
        "end_ts": b_end,
        "tool": "curl/ping",
        "command": "browser traffic loop",
        "kind": "benign"
    },
    {
        "label": "benign_heavy_user",
        "src_ip": "10.10.0.4",
        "start_ts": b_start,
        "end_ts": b_end,
        "tool": "curl",
        "command": "heavy user traffic loop",
        "kind": "benign"
    }
]

if os.path.isfile(attacks_file):
    with open(attacks_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception as e:
                    print(f"Warning: failed parsing attack entry: {e}", file=sys.stderr)

schedule = {
    "name": name,
    "mode": mode,
    "seed": seed,
    "started_at": started_at,
    "ended_at": ended_at,
    "local_ips": ["10.10.0.1"],
    "entries": entries
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(schedule, f, indent=2)
PY
}

generate_summary() {
  python3 - "${OUT_DIR}/schedule.json" "${OUT_DIR}/events.jsonl" "${OUT_DIR}/capture.pcap" "${LOG_DROPPED}" "${LOG_FAILED}" "${OUT_DIR}/summary.json" <<'PY'
import sys, os, json

schedule_path = sys.argv[1]
events_path = sys.argv[2]
pcap_path = sys.argv[3]
log_dropped = int(sys.argv[4])
log_failed = int(sys.argv[5])
out_path = sys.argv[6]

if not os.path.isfile(schedule_path):
    return_code = 1
    sys.exit(0)

with open(schedule_path, "r", encoding="utf-8") as f:
    schedule = json.load(f)

started_at = float(schedule.get("started_at", 0.0))
ended_at = float(schedule.get("ended_at", 0.0))
duration = max(0.0, ended_at - started_at)

entries = schedule.get("entries", [])
events_per_label = {e["label"]: 0 for e in entries}
events_per_src_ip = {}
total_events = 0

if os.path.isfile(events_path):
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            total_events += 1
            src = ev.get("src_ip", "unknown")
            ts = float(ev.get("ts", 0.0))

            events_per_src_ip[src] = events_per_src_ip.get(src, 0) + 1

            for e in entries:
                if e["src_ip"] == src and e["start_ts"] <= ts <= e["end_ts"]:
                    events_per_label[e["label"]] += 1

pcap_size = os.path.getsize(pcap_path) if os.path.isfile(pcap_path) else 0
valid = (log_dropped == 0 and log_failed == 0)

summary = {
    "duration": round(duration, 3),
    "total_events": total_events,
    "events_per_src_ip": events_per_src_ip,
    "events_per_label": events_per_label,
    "log_dropped": log_dropped,
    "log_failed": log_failed,
    "pcap_file_size": pcap_size,
    "valid": valid
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print("")
print("=" * 80)
print(f"Dataset Recording Summary: {schedule.get('name', 'dataset')}")
print("=" * 80)
print(f"Mode              : {schedule.get('mode', 'unknown')}")
print(f"Duration          : {duration:.2f} s")
print(f"Total Events      : {total_events:,}")
pcap_mb = pcap_size / (1024 * 1024)
print(f"PCAP File Size    : {pcap_size:,} bytes ({pcap_mb:.2f} MB)")
print(f"Log Dropped       : {log_dropped}")
print(f"Log Failed        : {log_failed}")
status_str = "VALID (0 dropped, 0 failed)" if valid else "INVALID"
print(f"Validation Status : {status_str}")
print("")
print("Events by Source IP:")
for ip in sorted(events_per_src_ip.keys()):
    print(f"  {ip:<16}: {events_per_src_ip[ip]:,}")
print("")
print("Events by Schedule Label:")
for label in sorted(events_per_label.keys()):
    print(f"  {label:<20}: {events_per_label[label]:,}")
print("=" * 80)

if not valid:
    print("")
    print("WARNING: Dataset validation FAILED! Events were lost or dropped during recording:")
    print(f"  log_dropped: {log_dropped}")
    print(f"  log_failed : {log_failed}")
    print("=" * 80)
PY
}

# 1. Start isolated Redis on 127.0.0.2:6379
echo "Starting isolated Redis on 127.0.0.2:6379..."
redis-server --bind 127.0.0.2 --port 6379 --requirepass "${REDIS_PASS}" --save "" --appendonly no --daemonize yes --dir /tmp >/dev/null 2>&1

redis_ready=0
for _ in $(seq 1 20); do
  if [ "$(redis_cmd ping 2>/dev/null || true)" = "PONG" ]; then
    redis_ready=1
    break
  fi
  sleep 0.1
done

if [ "${redis_ready}" -ne 1 ]; then
  echo "Error: Failed to connect to isolated Redis on 127.0.0.2:6379." >&2
  exit 1
fi

# 2. Start engine live on veth_lab against 127.0.0.2
ENGINE_LOG="${OUT_DIR}/engine.log"
echo "Starting engine in live mode on veth_lab (4 FPs)..."
"${ENGINE}" --live veth_lab --lbs 2 --fps 4 --redis-host 127.0.0.2 --redis-password-file "${PASS_FILE}" > "${ENGINE_LOG}" 2>&1 &
ENGINE_PID=$!

connected=0
for _ in $(seq 1 30); do
  if [ -f "${ENGINE_LOG}" ] && grep -q "\[REDIS\] Connected successfully" "${ENGINE_LOG}"; then
    connected=1
    break
  fi
  if ! kill -0 "${ENGINE_PID}" 2>/dev/null; then
    echo "Error: dpi_engine exited prematurely." >&2
    cat "${ENGINE_LOG}" >&2
    exit 1
  fi
  sleep 0.5
done

if [ "${connected}" -ne 1 ]; then
  echo "Error: Timed out waiting for dpi_engine to connect to Redis (15s)." >&2
  if [ -f "${ENGINE_LOG}" ]; then
    cat "${ENGINE_LOG}" >&2
  fi
  exit 1
fi
echo "dpi_engine connected and listening on veth_lab."

# 3. Start the recorder
EVENTS_JSONL="${OUT_DIR}/events.jsonl"
echo "Starting log recorder..."
"${PYTHON_VENV}" "${SCRIPT_DIR}/record_logs.py" --host 127.0.0.2 --password-file "${PASS_FILE}" --out "${EVENTS_JSONL}" > "${OUT_DIR}/recorder.log" 2>&1 &
RECORDER_PID=$!

# 4. Start tcpdump
CAPTURE_PCAP="${OUT_DIR}/capture.pcap"
echo "Starting tcpdump on veth_lab..."
sudo tcpdump -i veth_lab -s 1514 -w "${CAPTURE_PCAP}" >/dev/null 2>&1 &
TCPDUMP_PID=$!

# 5. Host services bound to 10.10.0.1
echo "Starting host HTTP and HTTPS test servers on 10.10.0.1..."
WEB_ROOT="$(mktemp -d /tmp/aegis_web_XXXXXX)"
python3 - "${WEB_ROOT}" <<'PY'
import sys, os, random
root = sys.argv[1]
random.seed(42)
for i in range(1, 21):
    target_kb = random.randint(2, 50)
    content = f"<!DOCTYPE html><html><head><title>Page {i}</title></head><body><h1>AegisDPI Test Page {i}</h1>"
    padding = "<!-- asset-padding-data --> " * 40
    while len(content.encode("utf-8")) < target_kb * 1024:
        content += padding
    content += "</body></html>"
    with open(os.path.join(root, f"page_{i}.html"), "w", encoding="utf-8") as f:
        f.write(content)

with open(os.path.join(root, "large_file.bin"), "wb") as f:
    chunk = b"\x00" * (1024 * 1024)
    for _ in range(20):
        f.write(chunk)
PY

python3 -m http.server 8080 --bind 10.10.0.1 --directory "${WEB_ROOT}" >/dev/null 2>&1 &
HTTP_PID=$!

CERT_DIR="$(mktemp -d /tmp/aegis_cert_XXXXXX)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/key.pem" \
  -out "${CERT_DIR}/cert.pem" \
  -days 1 -subj "/CN=test.local" >/dev/null 2>&1

openssl s_server -accept 10.10.0.1:8443 -cert "${CERT_DIR}/cert.pem" -key "${CERT_DIR}/key.pem" -www >/dev/null 2>&1 &
OPENSSL_PID=$!

# Allow servers a brief moment to bind
sleep 0.5

# Start recording timeline
DATASET_START_TS=$(python3 -c "import time; print(f'{time.time():.6f}')")
BENIGN_START_TS="${DATASET_START_TS}"

# Start benign clients
echo "Starting benign clients (10.10.0.3: browser, 10.10.0.4: heavy user)..."

# Client 1: 10.10.0.3 "browser"
sudo ip netns exec ns_attacker bash -c "
  RANDOM=$((SEED + 1))
  while true; do
    roll=\$(( RANDOM % 100 ))
    if [ \$roll -lt 50 ]; then
      p=\$(( 1 + RANDOM % 20 ))
      curl -s -m 10 --interface 10.10.0.3 \"http://10.10.0.1:8080/page_\${p}.html\" -o /dev/null || true
    elif [ \$roll -lt 75 ]; then
      burst=\$(( 4 + RANDOM % 5 ))
      for _ in \$(seq 1 \$burst); do
        p=\$(( 1 + RANDOM % 20 ))
        curl -s -m 10 --interface 10.10.0.3 \"http://10.10.0.1:8080/page_\${p}.html\" -o /dev/null &
      done
      wait
    elif [ \$roll -lt 90 ]; then
      curl -sk -m 10 --interface 10.10.0.3 --resolve test.local:8443:10.10.0.1 https://test.local:8443/ -o /dev/null || true
    else
      ping -I 10.10.0.3 -c 3 10.10.0.1 >/dev/null 2>&1 || true
    fi

    sleep_ms=\$(( 500 + (RANDOM * 5500) / 32767 ))
    sleep \$(printf \"%d.%03d\" \$((sleep_ms / 1000)) \$((sleep_ms % 1000)))
  done
" &
CLIENT_BROWSER_PID=$!

# Client 2: 10.10.0.4 "heavy user"
sudo ip netns exec ns_attacker bash -c "
  RANDOM=$((SEED + 2))
  last_download=\$SECONDS
  next_download=\$(( 45 + (RANDOM * 75) / 32767 ))
  while true; do
    if [ \$(( SECONDS - last_download )) -ge \$next_download ]; then
      curl -s -m 30 --interface 10.10.0.4 http://10.10.0.1:8080/large_file.bin -o /dev/null || true
      last_download=\$SECONDS
      next_download=\$(( 45 + (RANDOM * 75) / 32767 ))
    else
      roll=\$(( RANDOM % 100 ))
      if [ \$roll -lt 65 ]; then
        p=\$(( 1 + RANDOM % 20 ))
        curl -s -m 10 --interface 10.10.0.4 \"http://10.10.0.1:8080/page_\${p}.html\" -o /dev/null || true
      elif [ \$roll -lt 90 ]; then
        curl -sk -m 10 --interface 10.10.0.4 --resolve test.local:8443:10.10.0.1 https://test.local:8443/ -o /dev/null || true
      else
        ping -I 10.10.0.4 -c 3 10.10.0.1 >/dev/null 2>&1 || true
      fi
    fi

    sleep_ms=\$(( 1000 + (RANDOM * 7000) / 32767 ))
    sleep \$(printf \"%d.%03d\" \$((sleep_ms / 1000)) \$((sleep_ms % 1000)))
  done
" &
CLIENT_HEAVY_PID=$!

run_attack() {
  local label="$1"
  local src_ip="$2"
  local tool="$3"
  local cmd="$4"
  local timeout_sec="$5"

  echo ""
  echo ">>> [Attack] Starting: ${label} (src: ${src_ip}, cap: ${timeout_sec}s)..."
  local start_ts end_ts
  start_ts=$(python3 -c "import time; print(f'{time.time():.6f}')")

  sudo ip netns exec ns_attacker timeout --signal=INT --kill-after=2s "${timeout_sec}s" ${cmd} >/dev/null 2>&1 || true

  end_ts=$(python3 -c "import time; print(f'{time.time():.6f}')")
  local dur
  dur=$(python3 -c "print(f'{float(${end_ts}) - float(${start_ts}):.2f}')")
  echo ">>> [Attack] Finished: ${label} (actual duration: ${dur}s)"

  python3 -c '
import json, sys
entry = {
    "label": sys.argv[1],
    "src_ip": sys.argv[2],
    "start_ts": float(sys.argv[3]),
    "end_ts": float(sys.argv[4]),
    "tool": sys.argv[5],
    "command": sys.argv[6],
    "kind": "attack"
}
with open(sys.argv[7], "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
' "${label}" "${src_ip}" "${start_ts}" "${end_ts}" "${tool}" "${cmd}" "${ATTACK_ENTRIES_FILE}"
}

if [ "${MODE}" = "benign" ]; then
  echo "Running in benign mode for ${DURATION}s..."
  sleep "${DURATION}"
else
  echo "Mixed mode: Starting benign warmup for ${WARMUP}s..."
  sleep "${WARMUP}"

  # 1. icmp_flood_high
  run_attack "icmp_flood_high" "10.10.0.2" "hping3" \
    "hping3 --icmp -i u200 -I veth_attacker -a 10.10.0.2 10.10.0.1" "${ATTACK_DUR}"
  echo "Benign gap: ${GAP}s..."
  sleep "${GAP}"

  # 2. syn_flood_high
  run_attack "syn_flood_high" "10.10.0.2" "hping3" \
    "hping3 -S -p 8080 -i u200 -I veth_attacker -a 10.10.0.2 10.10.0.1" "${ATTACK_DUR}"
  echo "Benign gap: ${GAP}s..."
  sleep "${GAP}"

  # 3. udp_flood_high
  run_attack "udp_flood_high" "10.10.0.2" "hping3" \
    "hping3 --udp -p 9999 -i u200 -I veth_attacker -a 10.10.0.2 10.10.0.1" "${ATTACK_DUR}"
  echo "Benign gap: ${GAP}s..."
  sleep "${GAP}"

  # 4. port_scan_fast
  run_attack "port_scan_fast" "10.10.0.5" "nmap" \
    "nmap -sS -Pn -T4 -p 1-5000 -S 10.10.0.5 -e veth_attacker 10.10.0.1" "${SCAN_FAST_CAP}"
  echo "Benign gap: ${GAP}s..."
  sleep "${GAP}"

  # 5. syn_flood_low
  run_attack "syn_flood_low" "10.10.0.6" "hping3" \
    "hping3 -S -p 8080 -i u5000 -I veth_attacker -a 10.10.0.6 10.10.0.1" "${ATTACK_DUR}"
  echo "Benign gap: ${GAP}s..."
  sleep "${GAP}"

  # 6. icmp_flood_low
  run_attack "icmp_flood_low" "10.10.0.6" "hping3" \
    "hping3 --icmp -i u10000 -I veth_attacker -a 10.10.0.6 10.10.0.1" "${ATTACK_DUR}"
  echo "Benign gap: ${GAP}s..."
  sleep "${GAP}"

  # 7. port_scan_slow
  run_attack "port_scan_slow" "10.10.0.5" "nmap" \
    "nmap -sS -Pn -T2 -p 1-100 -S 10.10.0.5 -e veth_attacker 10.10.0.1" "${SCAN_SLOW_CAP}"
  echo "Benign cooldown: ${COOLDOWN}s..."
  sleep "${COOLDOWN}"
fi

DATASET_END_TS=$(python3 -c "import time; print(f'{time.time():.6f}')")
BENIGN_END_TS="${DATASET_END_TS}"

# Normal exit triggers cleanup trap
exit 0

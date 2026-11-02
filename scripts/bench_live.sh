#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LABEL="live"
FPS=4
RATES="50000 100000 200000 400000 topspeed"
LIMIT=300000
REPS=26000

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      LABEL="$2"
      shift 2
      ;;
    --fps)
      FPS="$2"
      shift 2
      ;;
    --rates)
      RATES="$2"
      shift 2
      ;;
    --limit)
      LIMIT="$2"
      shift 2
      ;;
    --reps)
      REPS="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--label <name>] [--fps <N>] [--rates \"<list>\"] [--limit <N>] [--reps <N>]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

ENGINE="${REPO_DIR}/engine/build/dpi_engine"
PASS_FILE="${REPO_DIR}/run/redis.pass"

# 1. Safety check: running dpi_engine
if pgrep -f "dpi_engine" >/dev/null 2>&1; then
  echo "Error: a dpi_engine process is already running." >&2
  echo "Live mode installs nftables rules and would clash with a running engine. Stop it first." >&2
  exit 1
fi

# 2. Safety check: lab environment up
if [ ! -e /run/netns/ns_attacker ] && ! ip netns list 2>/dev/null | grep -qw "ns_attacker" && ! sudo -n ip netns list 2>/dev/null | grep -qw "ns_attacker"; then
  echo "Error: Lab environment is not up (namespace 'ns_attacker' missing)." >&2
  echo "Please start the lab environment first: ./scripts/lab.sh up" >&2
  exit 1
fi

# 3. Safety check: binaries exist
if ! command -v tcpreplay >/dev/null 2>&1; then
  echo "Error: Required binary 'tcpreplay' is missing. Please install it." >&2
  exit 1
fi

if ! command -v redis-server >/dev/null 2>&1; then
  echo "Error: Required binary 'redis-server' is missing. Please install it." >&2
  exit 1
fi

# 4. Safety check: engine binary and redis.pass
if [[ ! -x "${ENGINE}" ]]; then
  echo "Error: Engine binary not found or not executable at: ${ENGINE}" >&2
  echo "Please build the engine first (e.g. cmake --build engine/build)" >&2
  exit 1
fi

if [[ ! -f "${PASS_FILE}" ]]; then
  echo "Error: Redis password file missing at: ${PASS_FILE}" >&2
  echo "Please run ./scripts/setup.sh first to generate credentials." >&2
  exit 1
fi

REDIS_PASS="$(cat "${PASS_FILE}")"

# Benchmark PCAP check / generation
SRC_PCAP="${REPO_DIR}/engine/test_dpi.pcap"
if [[ ! -f "${SRC_PCAP}" ]]; then
  echo "Error: Source PCAP file not found at: ${SRC_PCAP}" >&2
  exit 1
fi

PCAP="/tmp/aegis_bench_${REPS}.pcap"
if [[ ! -f "${PCAP}" ]]; then
  echo "Generating benchmark capture at ${PCAP} (${REPS} repetitions)..."
  python3 - "${SRC_PCAP}" "${PCAP}" "${REPS}" <<'PY'
import struct, sys
src, dst, reps_str = sys.argv[1], sys.argv[2], sys.argv[3]
reps = int(reps_str)
d = open(src, 'rb').read()
gh, o, pk = d[:24], 24, []
while o < len(d):
    hdr = d[o:o+16]; il = struct.unpack('<IIII', hdr)[2]
    pk.append((hdr, bytearray(d[o+16:o+16+il]))); o += 16 + il
with open(dst, 'wb') as f:
    f.write(gh); n = 0
    for k in range(reps):
        for hdr, p in pk:
            if len(p) >= 34 and p[12:14] == b'\x08\x00':      # IPv4: vary source address
                p = bytearray(p); p[28] = 1 + (k >> 8) % 250; p[29] = 1 + k % 250
            f.write(hdr); f.write(p); n += 1
print(f"{n} packets written to {dst}")
PY
else
  echo "Using existing benchmark capture at ${PCAP}"
fi

ENGINE_PID=""
TCPREPLAY_LOG="$(mktemp)"

cleanup() {
  local exit_code=$?
  echo ""
  echo "Stopping benchmark and cleaning up..."
  trap - EXIT INT TERM

  # 1. Stop engine gracefully with SIGINT so nftables state is cleaned up
  if [ -n "${ENGINE_PID:-}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
    echo "Stopping dpi_engine (PID ${ENGINE_PID})..."
    sudo pkill -INT -f "engine/build/dpi_engine --live veth_lab" 2>/dev/null || kill -INT "${ENGINE_PID}" 2>/dev/null || true
    wait "${ENGINE_PID}" 2>/dev/null || true
  else
    sudo pkill -INT -f "engine/build/dpi_engine --live veth_lab" 2>/dev/null || true
  fi

  # Wait up to 10 seconds for the dpi_engine process to exit
  local waited=0
  while pgrep -f "engine/build/dpi_engine --live veth_lab" >/dev/null 2>&1; do
    sleep 0.2
    waited=$((waited + 1))
    if [ "${waited}" -ge 50 ]; then
      break
    fi
  done

  # If it is still running, send SIGTERM and wait 5 more seconds
  if pgrep -f "engine/build/dpi_engine --live veth_lab" >/dev/null 2>&1; then
    echo "dpi_engine did not exit after SIGINT; sending SIGTERM..."
    if [ -n "${ENGINE_PID:-}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
      sudo pkill -TERM -f "engine/build/dpi_engine --live veth_lab" 2>/dev/null || kill -TERM "${ENGINE_PID}" 2>/dev/null || true
      wait "${ENGINE_PID}" 2>/dev/null || true
    else
      sudo pkill -TERM -f "engine/build/dpi_engine --live veth_lab" 2>/dev/null || true
    fi

    waited=0
    while pgrep -f "engine/build/dpi_engine --live veth_lab" >/dev/null 2>&1; do
      sleep 0.2
      waited=$((waited + 1))
      if [ "${waited}" -ge 25 ]; then
        break
      fi
    done
  fi

  # Verify with sudo nft list tables that no "inet aegis" table remains
  local nft_tables
  nft_tables=$(sudo nft list tables 2>/dev/null || true)
  if echo "${nft_tables}" | grep -q "inet aegis"; then
    echo "WARNING: nftables table 'inet aegis' is still present after dpi_engine shutdown!" >&2
  fi

  # 2. Shutdown isolated Redis on 127.0.0.2:6379
  if [ -n "${REDIS_PASS:-}" ]; then
    redis-cli -h 127.0.0.2 -p 6379 -a "${REDIS_PASS}" --no-auth-warning shutdown nosave 2>/dev/null || true
  fi

  # 3. Remove temp log
  rm -f "${TCPREPLAY_LOG:-}"

  echo "Cleanup complete."
  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

# Start isolated throwaway Redis on 127.0.0.2:6379
echo "Starting isolated Redis on 127.0.0.2:6379..."
redis-server --bind 127.0.0.2 --port 6379 --requirepass "${REDIS_PASS}" --save "" --appendonly no --daemonize yes --dir /tmp >/dev/null 2>&1

# Verify Redis is up
redis_cmd() {
  redis-cli -h 127.0.0.2 -p 6379 -a "${REDIS_PASS}" --no-auth-warning "$@"
}

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

# Start engine in live mode on veth_lab
ENGINE_LOG="/tmp/aegis_bench_live_engine.log"
rm -f "${ENGINE_LOG}"

echo "Starting dpi_engine in live mode on veth_lab (FPS: ${FPS})..."
sudo -n "${ENGINE}" --live veth_lab --lbs 2 --fps "${FPS}" --redis-host 127.0.0.2 --redis-password-file "${PASS_FILE}" > "${ENGINE_LOG}" 2>&1 &
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

# Helpers to read metrics from isolated Redis
get_stat() {
  local field="$1"
  local val
  val=$(redis_cmd --raw HGET dpi:stats "${field}" 2>/dev/null || true)
  echo "${val:-0}"
}

get_processed_total() {
  local fwd drp unh
  fwd=$(get_stat forwarded)
  drp=$(get_stat dropped)
  unh=$(get_stat unhandled)
  echo $(( ${fwd:-0} + ${drp:-0} + ${unh:-0} ))
}

get_entries_added() {
  local val
  val=$(redis_cmd --raw XINFO STREAM dpi:logs 2>/dev/null | awk '$1=="entries-added"{getline; print $1}' || true)
  echo "${val:-0}"
}

# Metadata collection
DATE_STR="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
DATE_DAY="$(date +"%Y-%m-%d")"
GIT_HASH="$(git -C "${REPO_DIR}" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
NPROC_COUNT="$(nproc 2>/dev/null || echo "unknown")"
CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed -E 's/^model name\s*:\s*//' | tr -s ' ' || echo "unknown")"
KERNEL_VER="$(uname -r)"

CSV_DIR="${REPO_DIR}/bench/results"
mkdir -p "${CSV_DIR}"
CSV_FILE="${CSV_DIR}/${DATE_DAY}_${LABEL}.csv"

# Write metadata header to CSV
{
  echo "# label: ${LABEL}"
  echo "# date: ${DATE_STR}"
  echo "# git_commit: ${GIT_HASH}"
  echo "# nproc: ${NPROC_COUNT}"
  echo "# cpu_model: ${CPU_MODEL}"
  echo "# kernel: ${KERNEL_VER}"
  echo "# fps: ${FPS}"
  echo "# limit: ${LIMIT}"
  echo "# pcap: ${PCAP}"
  echo "rate_target,sent,achieved_pps,processed,pcap_recv_delta,kernel_drops,capture_loss_pct,logs_delivered,logs_dropped,log_delivery_pct"
} > "${CSV_FILE}"

# Print metadata to terminal
echo "================================================================================================================================"
echo "AegisDPI Live Capture Benchmark"
echo "================================================================================================================================"
echo "Label         : ${LABEL}"
echo "Date          : ${DATE_STR}"
echo "Git Commit    : ${GIT_HASH}"
echo "CPUs (nproc)  : ${NPROC_COUNT}"
echo "CPU Model     : ${CPU_MODEL}"
echo "Kernel        : ${KERNEL_VER}"
echo "FPs           : ${FPS}"
echo "Limit         : ${LIMIT}"
echo "PCAP          : ${PCAP}"
echo "CSV Output    : ${CSV_FILE}"
echo "================================================================================================================================"
echo ""

# Print Table Header
printf "%-13s %-9s %-13s %-10s %-13s %-13s %-15s %-15s %-13s %-15s\n" \
  "Rate(target)" "Sent" "Achieved PPS" "Processed" "pcap_recv Δ" "Kernel Drops" "Capture Loss %" "Logs Delivered" "Logs Dropped" "Log Delivery %"
echo "--------------------------------------------------------------------------------------------------------------------------------"

for rate in ${RATES}; do
  # Read counters BEFORE
  proc_before=$(get_processed_total)
  recv_before=$(get_stat pcap_recv)
  drop_before=$(get_stat pcap_drop)
  ifdrop_before=$(get_stat pcap_ifdrop)
  log_drop_before=$(get_stat log_dropped)
  entries_before=$(get_entries_added)

  if [ "${rate}" = "topspeed" ]; then
    rate_flag="--topspeed"
  else
    rate_flag="--pps=${rate}"
  fi

  # Run tcpreplay inside ns_attacker
  sudo ip netns exec ns_attacker tcpreplay -q -i veth_attacker --limit="${LIMIT}" ${rate_flag} "${PCAP}" > "${TCPREPLAY_LOG}" 2>&1

  # Parse tcpreplay actual packets sent and achieved pps
  sent=$(grep -E '^Actual:' "${TCPREPLAY_LOG}" | awk '{print $2}' || true)
  sent="${sent:-0}"

  achieved_pps=$(grep -E '^Rated:' "${TCPREPLAY_LOG}" | grep -oE '[0-9.]+\s*pps' | awk '{print $1}' || true)
  achieved_pps="${achieved_pps:-0}"

  # Settle loop: poll Processed total and entries-added once per second until unchanged for 2 consecutive polls (max 15s)
  consecutive_stable=0
  last_p=$(get_processed_total)
  last_e=$(get_entries_added)
  settled=0

  for _ in $(seq 1 15); do
    sleep 1
    curr_p=$(get_processed_total)
    curr_e=$(get_entries_added)
    if [ "$curr_p" = "$last_p" ] && [ "$curr_e" = "$last_e" ]; then
      consecutive_stable=$((consecutive_stable + 1))
      if [ "$consecutive_stable" -ge 2 ]; then
        settled=1
        break
      fi
    else
      consecutive_stable=0
    fi
    last_p="$curr_p"
    last_e="$curr_e"
  done

  if [ "$settled" -ne 1 ]; then
    echo "WARNING: Metrics did not settle within 15 seconds." >&2
  fi

  # Read counters AFTER
  proc_after=$(get_processed_total)
  recv_after=$(get_stat pcap_recv)
  drop_after=$(get_stat pcap_drop)
  ifdrop_after=$(get_stat pcap_ifdrop)
  log_drop_after=$(get_stat log_dropped)
  entries_after=$(get_entries_added)

  # Compute deltas and percentages
  eval "$(python3 - "${sent}" "${proc_before}" "${proc_after}" "${recv_before}" "${recv_after}" "${drop_before}" "${drop_after}" "${ifdrop_before}" "${ifdrop_after}" "${entries_before}" "${entries_after}" "${log_drop_before}" "${log_drop_after}" <<'PY'
import sys

sent = int(sys.argv[1])
p_before, p_after = int(sys.argv[2]), int(sys.argv[3])
r_before, r_after = int(sys.argv[4]), int(sys.argv[5])
d_before, d_after = int(sys.argv[6]), int(sys.argv[7])
id_before, id_after = int(sys.argv[8]), int(sys.argv[9])
ent_before, ent_after = int(sys.argv[10]), int(sys.argv[11])
ld_before, ld_after = int(sys.argv[12]), int(sys.argv[13])

processed = max(0, p_after - p_before)
pcap_recv_delta = max(0, r_after - r_before)
kernel_drops = max(0, (d_after - d_before) + (id_after - id_before))
loss_pct = max(0.0, (sent - processed) / sent * 100.0) if sent > 0 else 0.0
logs_delivered = max(0, ent_after - ent_before)
logs_dropped = max(0, ld_after - ld_before)
total_logs = logs_delivered + logs_dropped
delivery_pct = (logs_delivered / total_logs * 100.0) if total_logs > 0 else 100.0

print(f"processed={processed}")
print(f"pcap_recv_delta={pcap_recv_delta}")
print(f"kernel_drops={kernel_drops}")
print(f"loss_pct='{loss_pct:.2f}'")
print(f"logs_delivered={logs_delivered}")
print(f"logs_dropped={logs_dropped}")
print(f"delivery_pct='{delivery_pct:.2f}'")
PY
)"

  # Print table row
  printf "%-13s %-9s %-13s %-10s %-13s %-13s %-15s %-15s %-13s %-15s\n" \
    "${rate}" "${sent}" "${achieved_pps}" "${processed}" "${pcap_recv_delta}" "${kernel_drops}" "${loss_pct}%" "${logs_delivered}" "${logs_dropped}" "${delivery_pct}%"

  # Write to CSV
  echo "${rate},${sent},${achieved_pps},${processed},${pcap_recv_delta},${kernel_drops},${loss_pct},${logs_delivered},${logs_dropped},${delivery_pct}" >> "${CSV_FILE}"
done

echo ""
echo "Live capture benchmark completed. Results saved to ${CSV_FILE}"

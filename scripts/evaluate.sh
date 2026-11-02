#!/usr/bin/env bash
# AegisDPI evaluation script — produces the numbers for Chapter 10.
# Put this file in ~/AegisDPI/scripts/ and run from the repo root:
#   ./scripts/evaluate.sh bench          (engine throughput, ~2 min, nothing else needs to run)
#   ./scripts/evaluate.sh flood 5        (5 detection trials, needs services + lab + engine on veth_lab)
#   ./scripts/evaluate.sh normal 300     (false-positive check, needs engine on eth0, browse normally)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT="${REPO}/eval_results.txt"
ATTACKER=10.10.0.2
TARGET=10.10.0.1

REDIS_PW=""
[ -f "${REPO}/middleware/.env" ] && REDIS_PW=$(grep -E '^REDIS_URL=' "${REPO}/middleware/.env" | sed -E 's/.*redis:\/\/:([^@]+)@.*/\1/' || true)
[ -z "${REDIS_PW}" ] && { echo "ERROR: Could not read REDIS_URL from middleware/.env. Run scripts/setup.sh first." >&2; exit 1; }
R() { redis-cli -a "${REDIS_PW}" --no-auth-warning "$@"; }
now() { date +%s.%N; }

bench() {
  local ENGINE="${REPO}/engine/build/dpi_engine"
  local PCAP=/tmp/aegis_bench.pcap
  [ -x "${ENGINE}" ] || { echo "engine binary not found: ${ENGINE}"; exit 1; }
  echo "Generating benchmark capture (test_dpi.pcap replicated with varied source IPs)..."
  python3 - "${REPO}/engine/test_dpi.pcap" "${PCAP}" <<'PY'
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
gh, o, pk = d[:24], 24, []
while o < len(d):
    hdr = d[o:o+16]; il = struct.unpack('<IIII', hdr)[2]
    pk.append((hdr, bytearray(d[o+16:o+16+il]))); o += 16 + il
REPS = 6500
with open(dst, 'wb') as f:
    f.write(gh); n = 0
    for k in range(REPS):
        for hdr, p in pk:
            if len(p) >= 34 and p[12:14] == b'\x08\x00':      # IPv4: vary source address
                p = bytearray(p); p[28] = 1 + (k >> 8) % 250; p[29] = 1 + k % 250
            f.write(hdr); f.write(p); n += 1
print(f"{n} packets written to {dst}")
PY
  echo "=== Replay throughput (2 LB threads, Redis disabled so only the engine is measured) ===" | tee -a "${OUT}"
  printf "%-6s %-12s %-10s %-14s %s\n" "FPs" "Packets" "Seconds" "Packets/sec" "FP split" | tee -a "${OUT}"
  for fps in 1 2 4; do
    for run in 1 2 3; do
      local t0 t1 log
      log=$(mktemp)
      t0=$(now)
      "${ENGINE}" --replay "${PCAP}" --lbs 2 --fps "${fps}" --redis-host 127.0.0.254 >"${log}" 2>&1
      t1=$(now)
      local total split
      total=$(grep -m1 "Total Packets Read" "${log}" | awk -F: '{gsub(/ /,"",$2); print $2}')
      split=$(grep -E "^FP\[[0-9]+\] processed" "${log}" | awk '{print $4}' | paste -sd/)
      python3 -c "import sys; t=float(sys.argv[2])-float(sys.argv[1]); n=int(sys.argv[3]); print(f'%-6s %-12d %-10.3f %-14.0f %s' % (sys.argv[4], n, t, n/t, sys.argv[5]))" "${t0}" "${t1}" "${total:-0}" "${fps}" "${split}" | tee -a "${OUT}"
      rm -f "${log}"
    done
  done
  echo "" >> "${OUT}"
}

unblock() {
  R SREM blocklist:ips "${ATTACKER}" >/dev/null
  R HDEL blocklist:meta "${ATTACKER}" >/dev/null
  R PUBLISH blocklist:updates "DEL IP ${ATTACKER}" >/dev/null
}

flood() {
  local N="${1:-5}"
  R PING >/dev/null || { echo "Redis not reachable — run ./scripts/aegis.sh start"; exit 1; }
  sudo ip netns list | grep -qw ns_attacker || { echo "Lab not up — run ./scripts/lab.sh up"; exit 1; }
  echo "=== Flood detection trials (3000-packet ping flood from ${ATTACKER}) ===" | tee -a "${OUT}"
  printf "%-6s %-9s %-11s %-16s %-15s %s\n" "Trial" "Detected" "Confidence" "Attack->Block(s)" "Post-block loss" "Telegram" | tee -a "${OUT}"
  for i in $(seq 1 "${N}"); do
    unblock; sleep 16          # clears the 10 s ML debounce and the 5 s window
    local before t0 t1="" blocked=0
    before=$(R XLEN ml:verdict_history)
    t0=$(now)
    sudo ip netns exec ns_attacker ping -f -q -c 3000 "${TARGET}" >/dev/null 2>&1
    for _ in $(seq 1 300); do   # poll up to 15 s
      if [ "$(R SISMEMBER blocklist:ips "${ATTACKER}")" = "1" ]; then t1=$(now); blocked=1; break; fi
      sleep 0.05
    done
    sleep 1.5
    local after conf="-" tg="-" lat="-" loss="-"
    after=$(R XLEN ml:verdict_history)
    if [ "${after}" -gt "${before}" ]; then
      local js
      js=$(R --raw XREVRANGE ml:verdict_history + - COUNT 1 | grep -m1 '^{')
      conf=$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(f\"{d['confidence']*100:.1f}%\" if d.get('source_ip')=='${ATTACKER}' else '-')" "${js}")
      tg=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('telegram_alert','-'))" "${js}")
    fi
    [ "${blocked}" = "1" ] && lat=$(python3 -c "import sys; print(f'{float(sys.argv[2])-float(sys.argv[1]):.2f}')" "${t0}" "${t1}")
    if [ "${blocked}" = "1" ]; then
      loss=$(sudo ip netns exec ns_attacker ping -c 10 -i 0.2 -W 1 -q "${TARGET}" 2>/dev/null | grep -oE '[0-9.]+% packet loss' | cut -d' ' -f1)
    fi
    printf "%-6s %-9s %-11s %-16s %-15s %s\n" "${i}" "$([ ${blocked} = 1 ] && echo YES || echo NO)" "${conf}" "${lat}" "${loss}" "${tg}" | tee -a "${OUT}"
  done
  unblock
  echo "" >> "${OUT}"
}

normal() {
  local SECS="${1:-300}"
  R PING >/dev/null || { echo "Redis not reachable"; exit 1; }
  local b a
  b=$(R XLEN ml:verdict_history)
  echo "Counting ML ANOMALOUS verdicts for ${SECS} s. Browse normally (YouTube, websites, downloads) now..."
  sleep "${SECS}"
  a=$(R XLEN ml:verdict_history)
  echo "=== Normal-traffic false-positive check ===" | tee -a "${OUT}"
  echo "Duration: ${SECS} s   New ANOMALOUS verdicts (false positives): $((a-b))" | tee -a "${OUT}"
  echo "Packets captured meanwhile (pcap_recv): $(R HGET dpi:stats pcap_recv 2>/dev/null)" | tee -a "${OUT}"
  echo "" >> "${OUT}"
}

case "${1:-}" in
  bench) bench ;;
  flood) shift; flood "${1:-5}" ;;
  normal) shift; normal "${1:-300}" ;;
  *) echo "Usage: $0 {bench|flood [N]|normal [seconds]}"; exit 1 ;;
esac
echo "Results appended to ${OUT}"
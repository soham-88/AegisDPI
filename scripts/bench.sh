#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LABEL="baseline"
REPS=26000
RUNS=3
FPS_LIST="1 2 4 8"
LBS=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      LABEL="$2"
      shift 2
      ;;
    --reps)
      REPS="$2"
      shift 2
      ;;
    --runs)
      RUNS="$2"
      shift 2
      ;;
    --fps-list)
      FPS_LIST="$2"
      shift 2
      ;;
    --lbs)
      LBS="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--label <name>] [--reps <N>] [--runs <N>] [--fps-list \"<list>\"] [--lbs <N>]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

ENGINE="${REPO_DIR}/engine/build/dpi_engine"
if [[ ! -x "${ENGINE}" ]]; then
  echo "Error: DPI engine binary not found or not executable at: ${ENGINE}" >&2
  echo "Please build the engine first (e.g. cmake --build engine/build)" >&2
  exit 1
fi

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

# Metadata collection
DATE_STR="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
DATE_DAY="$(date +"%Y-%m-%d")"
GIT_HASH="$(git -C "${REPO_DIR}" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
NPROC_COUNT="$(nproc 2>/dev/null || echo "unknown")"
CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed -E 's/^model name\s*:\s*//' | tr -s ' ' || echo "unknown")"
BUILD_TYPE="$(grep -E '^CMAKE_BUILD_TYPE(:[A-Z]+)?=' "${REPO_DIR}/engine/build/CMakeCache.txt" 2>/dev/null | cut -d= -f2 || echo "unknown")"

# Prepare CSV output
CSV_DIR="${REPO_DIR}/bench/results"
mkdir -p "${CSV_DIR}"
CSV_FILE="${CSV_DIR}/${DATE_DAY}_${LABEL}.csv"

# Write metadata and header to CSV
{
  echo "# label: ${LABEL}"
  echo "# date: ${DATE_STR}"
  echo "# git_commit: ${GIT_HASH}"
  echo "# nproc: ${NPROC_COUNT}"
  echo "# cpu_model: ${CPU_MODEL}"
  echo "# build_type: ${BUILD_TYPE}"
  echo "# lbs: ${LBS}"
  echo "# reps: ${REPS}"
  echo "fps,run,packets,wall_s,proc_s,pps,mbps,reporter_drops,fp_split"
} > "${CSV_FILE}"

# Print metadata to terminal
echo "================================================================================"
echo "AegisDPI Benchmark"
echo "================================================================================"
echo "Label         : ${LABEL}"
echo "Date          : ${DATE_STR}"
echo "Git Commit    : ${GIT_HASH}"
echo "CPUs (nproc)  : ${NPROC_COUNT}"
echo "CPU Model     : ${CPU_MODEL}"
echo "Build Type    : ${BUILD_TYPE}"
echo "LBs           : ${LBS}"
echo "Reps          : ${REPS}"
echo "CSV Output    : ${CSV_FILE}"
echo "================================================================================"
echo ""

# Print Table Header
printf "%-5s %-4s %-10s %-9s %-9s %-12s %-10s %-14s %s\n" \
  "FPs" "Run" "Packets" "Wall(s)" "Proc(s)" "PPS" "Mbps" "ReporterDrops" "FP split"
echo "--------------------------------------------------------------------------------"

TMP_LOG="$(mktemp)"
trap 'rm -f "${TMP_LOG:-}"' EXIT

for fps in ${FPS_LIST}; do
  for run in $(seq 1 "${RUNS}"); do
    t0=$(date +%s.%N)
    "${ENGINE}" --replay "${PCAP}" --lbs "${LBS}" --fps "${fps}" --redis-host 127.0.0.254 >"${TMP_LOG}" 2>&1
    t1=$(date +%s.%N)

    wall_s=$(python3 -c "import sys; print(f'{float(sys.argv[2]) - float(sys.argv[1]):.3f}')" "${t0}" "${t1}")
    packets=$(grep -m1 "Total Packets Read" "${TMP_LOG}" | awk -F: '{gsub(/ /,"",$2); print $2}')
    packets="${packets:-0}"

    proc_s=$(grep -m1 "Processing Time (s)" "${TMP_LOG}" | awk -F: '{gsub(/ /,"",$2); print $2}')
    proc_s="${proc_s:-0.000}"

    pps=$(grep -m1 "Throughput (pps)" "${TMP_LOG}" | awk -F: '{gsub(/ /,"",$2); print $2}')
    pps="${pps:-0}"

    mbps=$(grep -m1 "Throughput (Mbps)" "${TMP_LOG}" | awk -F: '{gsub(/ /,"",$2); print $2}')
    mbps="${mbps:-0.00}"

    reporter_drops=$(grep -m1 "Reporter Q Drops" "${TMP_LOG}" | awk -F: '{gsub(/ /,"",$2); print $2}')
    reporter_drops="${reporter_drops:-0}"

    fp_split=$(grep -E '^FP\[[0-9]+\] processed' "${TMP_LOG}" | awk '{print $4}' | paste -sd/ - || true)
    fp_split="${fp_split:-0}"

    # Print row
    printf "%-5s %-4s %-10s %-9s %-9s %-12s %-10s %-14s %s\n" \
      "${fps}" "${run}" "${packets}" "${wall_s}" "${proc_s}" "${pps}" "${mbps}" "${reporter_drops}" "${fp_split}"

    # Append to CSV
    echo "${fps},${run},${packets},${wall_s},${proc_s},${pps},${mbps},${reporter_drops},${fp_split}" >> "${CSV_FILE}"
  done
done

echo ""
# Summary table per FP count
python3 - "${CSV_FILE}" <<'PY'
import sys, statistics

filename = sys.argv[1]
runs_by_fp = {}
with open(filename, 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        row = line.split(',')
        if row[0] == 'fps':
            continue
        fps = int(row[0])
        pps = float(row[5])
        mbps = float(row[6])
        runs_by_fp.setdefault(fps, []).append((pps, mbps))

med_1fp_pps = None
if 1 in runs_by_fp:
    med_1fp_pps = statistics.median([r[0] for r in runs_by_fp[1]])

print("=== Summary (Medians & Speedup) ===")
printf_fmt = "{:<5} {:<14} {:<14} {:<15}"
print(printf_fmt.format("FPs", "Median PPS", "Median Mbps", "Speedup vs 1-FP"))
print("-" * 52)
for fps in sorted(runs_by_fp.keys()):
    pps_vals = [r[0] for r in runs_by_fp[fps]]
    mbps_vals = [r[1] for r in runs_by_fp[fps]]
    med_pps = statistics.median(pps_vals)
    med_mbps = statistics.median(mbps_vals)
    if med_1fp_pps and med_1fp_pps > 0:
        speedup = f"{med_pps / med_1fp_pps:.2f}x"
    else:
        speedup = "1.00x" if fps == 1 else "N/A"
    print(f"{fps:<5} {med_pps:<14.0f} {med_mbps:<14.2f} {speedup:<15}")
print("====================================")
PY

echo ""
echo "Benchmark completed. Results saved to ${CSV_FILE}"


# AegisDPI Labelled Dataset Recorder

This directory contains datasets generated for training and evaluating the Machine Learning Anomaly Detection service.

The recorder orchestrates real live traffic across the lab network namespace topology (`veth_lab` <-> `veth_attacker`), capturing simultaneous ground-truth event logs (`events.jsonl`) from the engine and raw network packets (`capture.pcap`).

---

## 1. Quick Start

### Step 1: Start the Network Lab Topology
Ensure the virtual ethernet topology with secondary IP addresses is active:
```bash
./scripts/lab.sh up
```
This creates:
- Host interface: `veth_lab` (`10.10.0.1/24`)
- Namespace `ns_attacker` with `veth_attacker`:
  - Primary address: `10.10.0.2/24`
  - Secondary addresses: `10.10.0.3/24`, `10.10.0.4/24`, `10.10.0.5/24`, `10.10.0.6/24`

> **Capture Realism & Offloads (TSO/GSO/GRO)**:  
> By default, Linux virtual ethernet pairs enable TCP Segmentation Offload (TSO), Generic Segmentation Offload (GSO), and Generic Receive Offload (GRO). This causes the kernel to coalesce packets into "super-packets" up to 64 KB, distorting packet counts (e.g. a 20 MB transfer appears as hundreds of frames rather than ~14,000) and skewing packet-rate/size features for the ML detector. Following IDS best practice (e.g. Suricata/Snort), `lab.sh up` automatically disables TSO, GSO, and GRO on both `veth_lab` and `veth_attacker` via `ethtool` so the engine observes realistic on-wire packets (<= 1514 bytes).

### Step 2: Record a Dataset

#### Smoke Test (Quick Mode)
Run a quick ~2-minute test to verify tools, clients, and recording pipeline:
```bash
./scripts/dataset/run_dataset.sh --name smoke_test --quick
```

#### Full Mixed-Mode Dataset (Standard Evaluation)
Run the full sequential attack matrix (~12-15 minutes):
```bash
./scripts/dataset/run_dataset.sh --name eval_mixed_v1 --mode mixed --seed 42
```

#### Benign-Only Dataset
Record exclusively benign user traffic for baseline model training:
```bash
./scripts/dataset/run_dataset.sh --name benign_baseline --mode benign --duration 1800 --seed 42
```

---

## 2. Network Layout & Traffic Matrix

| IP Address | Role | Description / Tool |
|---|---|---|
| `10.10.0.1` | **Target Server (Host)** | Victim web services: HTTP (`python3 -m http.server 8080`) & HTTPS (`openssl s_server 8443`) |
| `10.10.0.2` | **Attacker (High Flood)** | High-rate floods (ICMP, SYN, UDP) |
| `10.10.0.3` | **Benign Client ("Browser")** | Realistic web browsing: HTTP page fetches, asset bursts (4-8 requests), HTTPS requests, periodic ICMP pings |
| `10.10.0.4` | **Benign Client ("Heavy User")**| Periodic 20 MB downloads (every 45-120 s), occasional HTTPS, less frequent page loads |
| `10.10.0.5` | **Attacker (Port Scans)** | Fast SYN scan (T4, ports 1-5000) and slow stealth scan (T2, ports 1-100) via `nmap` |
| `10.10.0.6` | **Attacker (Low Flood)** | Low-rate stealth floods (SYN, ICMP) |

### Mixed Mode Attack Schedule
In mixed mode, attacks execute sequentially against `10.10.0.1` while benign clients continue in the background:

1. **Warmup**: 120 s (20 s if `--quick`) benign-only traffic.
2. **Attack 1 (`icmp_flood_high`)**: `10.10.0.2` -> `hping3 --icmp -i u200` (30 s / 10 s quick)
3. *Gap*: 30 s (5 s if `--quick`) benign-only traffic.
4. **Attack 2 (`syn_flood_high`)**: `10.10.0.2` -> `hping3 -S -p 8080 -i u200` (30 s / 10 s quick)
5. *Gap*: 30 s (5 s if `--quick`) benign-only traffic.
6. **Attack 3 (`udp_flood_high`)**: `10.10.0.2` -> `hping3 --udp -p 9999 -i u200` (30 s / 10 s quick)
7. *Gap*: 30 s (5 s if `--quick`) benign-only traffic.
8. **Attack 4 (`port_scan_fast`)**: `10.10.0.5` -> `nmap -sS -Pn -T4 -p 1-5000 -S 10.10.0.5 -e veth_attacker 10.10.0.1` (cap 120 s / 20 s quick)
9. *Gap*: 30 s (5 s if `--quick`) benign-only traffic.
10. **Attack 5 (`syn_flood_low`)**: `10.10.0.6` -> `hping3 -S -p 8080 -i u5000` (30 s / 10 s quick)
11. *Gap*: 30 s (5 s if `--quick`) benign-only traffic.
12. **Attack 6 (`icmp_flood_low`)**: `10.10.0.6` -> `hping3 --icmp -i u10000` (30 s / 10 s quick)
13. *Gap*: 30 s (5 s if `--quick`) benign-only traffic.
14. **Attack 7 (`port_scan_slow`)**: `10.10.0.5` -> `nmap -sS -Pn -T2 -p 1-100 -S 10.10.0.5 -e veth_attacker 10.10.0.1` (cap 180 s / 20 s quick)
15. **Cooldown**: 60 s (10 s if `--quick`) benign-only traffic.

---

## 3. Output File Formats

Outputs are saved under `datasets/<name>/`:

| File | Description | Committed to Git |
|---|---|---|
| `schedule.json` | Ground truth schedule: actual epoch start/end timestamps, commands, tools, and labels | Yes |
| `summary.json` | Run metadata, event counts per label/IP, duration, drop statistics, validation status | Yes |
| `events.jsonl` | Engine telemetry events read from Redis `dpi:logs` stream (one JSON object per line) | No (ignored) |
| `capture.pcap` | Full raw packet capture from `veth_lab` recorded by `tcpdump` | No (ignored) |
| `engine.log` | Standard output and diagnostic logs from `dpi_engine` | No (ignored) |

### `schedule.json` Schema
```json
{
  "name": "eval_mixed_v1",
  "mode": "mixed",
  "seed": 42,
  "started_at": 1730830000.123,
  "ended_at": 1730830750.456,
  "local_ips": ["10.10.0.1"],
  "entries": [
    {
      "label": "benign_browser",
      "src_ip": "10.10.0.3",
      "start_ts": 1730830005.123,
      "end_ts": 1730830745.456,
      "tool": "curl/ping",
      "command": "browser traffic loop",
      "kind": "benign"
    },
    {
      "label": "icmp_flood_high",
      "src_ip": "10.10.0.2",
      "start_ts": 1730830125.100,
      "end_ts": 1730830155.100,
      "tool": "hping3",
      "command": "hping3 --icmp -i u200 -I veth_attacker -a 10.10.0.2 10.10.0.1",
      "kind": "attack"
    }
  ]
}
```

### `events.jsonl` Record Format
Each entry in `events.jsonl` contains the exact fields from `dpi:logs`, supplemented with `"ts"` (epoch seconds) and `"id"` (Redis stream entry ID):
```json
{
  "src_ip": "10.10.0.2",
  "dst_ip": "10.10.0.1",
  "src_port": "0",
  "dst_port": "0",
  "protocol": "ICMP",
  "sni": "",
  "action": "forwarded",
  "reason": "PASS_UNMATCHED",
  "thread_id": "1",
  "tcp_flags": "",
  "icmp_type": "8",
  "l3": "ipv4",
  "id": "1730830125100-0",
  "ts": 1730830125.100
}
```

---

## 4. Replay and Regression Evaluation

The recorded `capture.pcap` contains all byte-level traffic generated across benign clients and attack scripts. To evaluate future engine or ML pipeline optimizations on exact identical network conditions without running live generators:

```bash
# Replay against live interface or engine replay mode
tcpreplay -i veth_lab --topspeed datasets/<name>/capture.pcap
```


## Recording notes

- `benign-train` and `benign-val` were recorded with the old 10,000-event reporter queue. 0.82% and 0.96% of log events were dropped during 20 MB download bursts (verified against `capture.pcap`, which agrees with events + counted drops to within 0.2%). Both datasets are used only by replaying `capture.pcap`, so this log loss does not affect training or threshold selection. Their `summary.json` therefore shows `"valid": false`.
- `mixed-test` was re-recorded after the reporter queue was raised to 131,072 events (`--log-queue-size`) and has zero dropped events.

---

## 5. Offline Evaluation

The offline evaluation tool (`ml-service/evaluate_offline.py`) replays recorded `events.jsonl` against the ML detector model without running live traffic or modifying production code or model weights:

```bash
cd ml-service
venv/bin/python evaluate_offline.py --dataset ../datasets/<name> --label <label> [--local-ips 10.10.0.1,10.255.255.254] [--grace 5]
```

### Pipeline Simulation
- **Window Admission**: Replicates `WindowAdmitter` logic verbatim (filters local-to-local traffic, ignores local-sourced packets, maintains flow table with TTL to only admit remote-initiated flows, filters non-unicast).
- **Evaluator Ticks**: Evaluates every 1.0 s tick (matching `anomaly_evaluator_loop`), prunes events older than 5.0 s, and scores all active IPs with $\ge 3$ events via `AnomalyModel.score()`.
- **Ground Truth Labelling**:
  - `POSITIVE`: Attack entry matching `src_ip` within `[start_ts, end_ts + grace]`.
  - `BENIGN`: Benign entry matching `src_ip` within `[start_ts, end_ts]`.
  - `UNLABELLED`: Scored ticks outside defined windows (reported in header count, excluded from classification metrics).
- **Blocking**: Blocking is **not** simulated (no IP is removed after an `ANOMALOUS` verdict) to measure raw detector behavior across the entire dataset.

### Output Metrics & Reports
The script prints aligned terminal summary tables and exports structured JSON to `eval/results/<YYYY-MM-DD>_<label>_<dataset>.json`:
- **Header**: Dataset name, label, git commit hash, total events, scored ticks, unlabelled ticks, tick interval, local IPs, grace period.
- **Per-Attack Evaluation**: Duration, scored ticks, detection at `ANOMALOUS` (`conf >= 0.85`), time to first `ANOMALOUS`, detection at `SUSPICIOUS` (`conf >= 0.60`), time to first `SUSPICIOUS`, percentage of anomalous ticks, max confidence.
- **Per-Benign Evaluation**: Scored ticks, anomalous/suspicious tick counts, alert episodes at `ANOMALOUS` (consecutive flagged ticks merged into one episode), episodes/hour, max confidence, and feature values of the highest-confidence benign tick.
- **Overall Metrics**: Evaluated at both operating points (`conf >= 0.85` and `conf >= 0.60`) with TP, FP, FN, TN, Precision, Recall, F1-Score, False Positive Rate (FPR), ROC-AUC, and PR-AUC (Average Precision). On benign-only datasets, reports false-positive counts and FPR (single-class metrics marked `n/a`).


# AegisDPI Benchmark Suite

`scripts/bench.sh` provides reproducible, automated replay benchmarking for the AegisDPI multi-threaded C++ engine without requiring Redis or `sudo` privileges.

## Running the Benchmark

From the repository root:

```bash
# Run baseline benchmark with default parameters
./scripts/bench.sh

# Custom parameters
./scripts/bench.sh --label experiment1 --reps 26000 --runs 3 --fps-list "1 2 4 8" --lbs 2
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--label <name>` | `baseline` | Label used for output tagging and CSV naming |
| `--reps <N>` | `26000` | Multiplier used to replicate `engine/test_dpi.pcap` with varied IPv4 source addresses |
| `--runs <N>` | `3` | Number of test runs per Fast Path (FP) thread count |
| `--fps-list "<list>"` | `"1 2 4 8"` | Space-separated list of Fast Path thread counts |
| `--lbs <N>` | `2` | Number of Load Balancer (LB) threads |

The benchmark PCAP is generated once at `/tmp/aegis_bench_<reps>.pcap` and reused across runs.

## Benchmark Execution Mode

Benchmarks run in **replay mode** (`--replay <pcap>`), which is offline and independent of external services:
- **No kernel capture overhead**: Packets are read directly from the synthetic PCAP file.
- **Redis disabled**: The engine is pointed to a dummy host (`--redis-host 127.0.0.254`), making the benchmark completely self-contained and isolated from Redis network latency or queue contention.
- **No root/sudo required**: Runs in user space without requiring network interface or nftables privileges.

## Metrics & Column Descriptions

Results are printed to the terminal and saved to `bench/results/<YYYY-MM-DD>_<label>.csv`.

| Column | Description |
|--------|-------------|
| `FPs` | Number of Fast Path worker threads configured for the run |
| `Run` | Iteration number for the current FP configuration |
| `Packets` | Total number of packets read from the PCAP |
| `Wall(s)` | Total process wall-clock time in seconds (measured externally by the script) |
| `Proc(s)` | Engine internal processing time in seconds (from the first packet read until all FP threads join and drain) |
| `PPS` | Packets per second throughput (`Packets / Proc(s)`) |
| `Mbps` | Data throughput in Megabits per second (`total_bytes * 8 / Proc(s) / 10^6`) |
| `ReporterDrops`| Number of log events dropped due to full reporter queues |
| `FP split` | Distribution of processed packets across FP threads (`FP[0]/FP[1]/...`) |

> **Note on `Proc(s)`**: Process wall-clock time (`Wall(s)`) includes process startup, thread initialization, Redis connection timeouts (failing open), and shutdown teardown. `Proc(s)` starts only when the first packet is read and stops once the pipeline has fully drained. Therefore, **`Proc(s)` (and its derived PPS and Mbps) is the primary metric to compare**.

---

## Live Benchmark

`scripts/bench_live.sh` evaluates live-capture performance, kernel capture drop behavior, and Redis telemetry delivery under load using the network lab namespace.

### Running the Live Benchmark

Prerequisites: The network namespace lab must be active (`./scripts/lab.sh up`).

```bash
# Run live benchmark with default parameters
./scripts/bench_live.sh

# Custom parameters
./scripts/bench_live.sh --label live_4fps --fps 4 --rates "50000 100000 200000 400000 topspeed" --limit 300000
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--label <name>` | `live` | Label used for output tagging and CSV naming |
| `--fps <N>` | `4` | Number of Fast Path worker threads for `dpi_engine` |
| `--rates "<list>"` | `"50000 100000 200000 400000 topspeed"` | Target replay transmission rates in PPS (or `topspeed`) |
| `--limit <N>` | `300000` | Number of packets injected per rate step |
| `--reps <N>` | `26000` | Multiplier for generating the benchmark PCAP file |

### Environment and Architecture

- **What it measures**: End-to-end packet capture throughput, kernel ring-buffer drop rates (`pcap_drop` + `pcap_ifdrop`), capture loss percentage, and real-time log ingestion performance (`dpi:logs` pipeline delivery vs. queue drops) under traffic pressure.
- **Isolated Redis Instance**: Automatically starts a dedicated throwaway Redis instance on `127.0.0.2:6379` using `run/redis.pass`. It never modifies or contacts the primary Redis server running on `127.0.0.1`.
- **WSL2 veth Interface Limitations**: Traffic is generated via `tcpreplay` inside `ns_attacker` (`veth_attacker`) and captured on `veth_lab`. Because packets traverse the WSL2 virtual ethernet interface pair in software, absolute throughput numbers reflect Linux veth stack and hypervisor virtualization constraints rather than bare-metal hardware line-rate capabilities.

### Metrics & Column Descriptions

Results are saved to `bench/results/<YYYY-MM-DD>_<label>.csv`.

| Column | Description |
|--------|-------------|
| `Rate(target)` | Target PPS specified for `tcpreplay` (or `topspeed`) |
| `Sent` | Actual packets transmitted by `tcpreplay` |
| `Achieved PPS` | Actual transmission rate achieved by `tcpreplay` |
| `Processed` | Cumulative packets processed by worker threads (`forwarded` + `dropped` + `unhandled` deltas) |
| `pcap_recv Δ` | Raw delta of packets received by libpcap (`pcap_recv` delta) |
| `Kernel Drops` | Kernel/socket drops (`pcap_drop` + `pcap_ifdrop` deltas) |
| `Capture Loss %` | Percentage of injected packets not processed: `max(0, (Sent - Processed) / Sent * 100)` |
| `Logs Delivered`| Stream entries successfully appended to Redis (`entries-added` delta) |
| `Logs Dropped` | Telemetry events dropped due to queue congestion (`log_dropped` delta) |
| `Log Delivery %`| Ratio of delivered logs to total logs generated: `Delivered / (Delivered + Dropped)` |

> **Note on `Processed` vs. `pcap_recv`**: `Processed` (sum of `forwarded`, `dropped`, and `unhandled` packet deltas) is used instead of `pcap_recv` because `pcap_recv` is sampled periodically once per second by libpcap and can carry over across rate steps.



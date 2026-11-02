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


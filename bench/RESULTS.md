# Engine Performance Results

## 1. Test Environment

- **CPU**: 13th Gen Intel(R) Core(TM) i5-13450HX (16 logical cores)
- **Kernel & OS**: Linux 6.18.33.2-microsoft-standard-WSL2 (WSL2 virtualized)
- **Build Type**: Release
- **Replay Packet Count**: 2,002,000 packets (26,000 repetitions of 77-packet capture with varied IPv4 source IPs)
- **Load Balancer Threads**: 2 LB threads across all replay tests

## 2. Replay Throughput

Median throughput (PPS) and median reporter drops across 3 runs per Fast Path (FP) thread count:

| FPs | Baseline PPS | Baseline Drops | Hysteresis+Batch PPS | Hysteresis Drops | Batching+Poll PPS | Batching Drops |
|---|---|---|---|---|---|---|
| 1 | 53,194 | 0 | 176,403 | 0 | 389,869 | 0 |
| 2 | 71,031 | 0 | 135,936 | 0 | 596,393 | 0 |
| 4 | 253,029 | 0 | 1,061,298 | 470,396 | 831,974 | 0 |
| 8 | 758,172 | 827,574 | 1,108,575 | 1,089,536 | 796,339 | 0 |

Throughput for 4 and 8 FPs dropped in the last step because the previous run silently dropped up to ~65% of log events (1,301,792 drops in run 2 at 8 FPs), whereas the last run logs 100% of events with 0 reporter drops. Across all optimizations, the 4-FP routing split remained identical at 498447/502255/500398/500900, and all 18 unit tests pass.

## 3. Bottlenecks and Optimizations

### (a) Producer-Side Context-Switch Ping-Pong
- **Problem**: When a queue was full, every single pop woke a blocked producer, which pushed one packet, found the queue full again and went back to sleep (~2.2 context switches per packet). Baseline with 1 FP produced 4,355,986 voluntary context switches, 41.98 s system time, and 18.71 s user time (8 FP had 579,926 switches).
- **Fix**: Added watermark hysteresis (`low_watermark_ = max_size_ / 2`, waking producers only when occupancy drops below the watermark) and batch popping (`popBatch` of up to 256 packets per lock).
- **Result**: 1-FP voluntary context switches fell to 769,367 and system time to 6.91 s. Median throughput increased from 53,194 to 176,403 PPS.

### (b) Consumer-Side Wake-Ups
- **Problem**: Consumers drained queues faster than producers filled them, sleeping and waking on every single push. Profiling showed ~48% (2 FP) and ~21% (8 FP) of CPU samples in kernel wake-up paths (`_raw_spin_unlock_irqrestore`, `futex`).
- **Fix**: Added producer-side batching (`pushBatch`: the replay reader hands each LB 128 packets at a time, and LB threads flush per-FP batches), and made the Reporter thread non-blocking (`popBatch` with a 0 ms timeout, sleeping 2 ms when fewer than 512 events are queued) so it is never woken per event.
- **Result**: Voluntary context switches dropped to 13,818 (1 FP, 0.32 s system time), 38,290 (2 FP), and 221,400 (8 FP). Median throughput reached 389,869 PPS (1 FP) and 596,393 PPS (2 FP) with 0 reporter drops.

### (c) Redis Telemetry Ingestion Bottleneck
- **Problem**: Individual synchronous `XADD` commands over TCP limited delivery to 66,832 events (1 FP) and 25,360 events (4 FP) during 2,002,000 packet replays, dropping over 96% of events.
- **Fix**: Reused a persistent redis-plus-plus pipeline to batch `XADD` commands per pop cycle, applied `MAXLEN ~ 200000` stream trimming, and exposed cumulative `log_dropped` and `log_failed` counters in `dpi:stats`.
- **Result**: Delivered 746,800 events (1 FP) and 285,968 events (4 FP) with 0 Redis failures.

## 4. Live Capture Performance

Live capture benchmark on `veth_lab` with 4 FP threads (300,000 packets per target rate):

| Target Rate (PPS) | Sent | Achieved PPS | Processed | Kernel Drops | Capture Loss % | Log Delivery % |
|---|---|---|---|---|---|---|
| 50,000 | 300,000 | 50000.16 | 300,000 | 0 | 0.00% | 100.00% |
| 100,000 | 300,000 | 100000.33 | 299,992 | 0 | 0.00% | 100.00% |
| 200,000 | 300,000 | 200000.66 | 299,984 | 0 | 0.01% | 100.00% |
| 400,000 | 300,000 | 400001.06 | 300,000 | 0 | 0.00% | 75.30% |
| topspeed | 300,000 | 413904.42 | 299,378 | 0 | 0.21% | 73.68% |

The ~414K PPS achieved at topspeed is the maximum transmission rate achieved by `tcpreplay` over virtual ethernet (`veth`) on WSL2, serving as a lower bound for the engine rather than its performance limit.

## 5. Known Limitations & Next Steps

- **Per-Packet Telemetry**: Per-packet logging caps at roughly the Redis ingestion rate (~300K events/s here); planned move to flow-level records.
- **Virtualization Overhead**: Benchmarks ran within a WSL2 virtual machine across virtual ethernet interfaces rather than dedicated bare-metal hardware.
- **Synthetic Capture**: Replay tests used a 77-packet capture repeated with varied IPv4 source addresses.


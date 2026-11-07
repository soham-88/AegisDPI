# ML Detection Evaluation Results

## 1. Summary
- On the held-out set `mixed-test-2` (recorded after v3 was frozen), v3 detects **6 of 7** attack types at the blocking (ANOMALOUS) threshold and **all 7** at >=SUSPICIOUS, with precision 1.000 and FPR 0.000 at ANOMALOUS (v1 and v2 also had no false positives on this set).
- Recall at ANOMALOUS rises from 0.603 (v1) and 0.466 (v2) to 0.772; F1 from 0.753 (v1) to 0.871; ROC-AUC from 0.971 (v1) to 0.996; PR-AUC from 0.919 (v1) to 0.989.
- False blocks of the legitimate heavy downloader fall from 5 episodes (v1) to 1 (v3) on the development set, and from 4 (v1) to 0 (v3) on `benign-val`; the held-out set does not stress this case (see Limitations).
- The only attack not blocked on held-out data is the slow port scan (detected at SUSPICIOUS only).

## 2. Evaluation Protocol
| Dataset | Purpose | Duration | Events | Valid |
|---|---|---|---|---|
| benign-train | Baseline training | 1800.0s | 377,731 | False |
| benign-val | Threshold calibration | 900.0s | 197,186 | False |
| mixed-test | Development set | 561.4s | 668,419 | True |
| mixed-test-2 | Held-out evaluation | 561.0s | 907,479 | True |

- `benign-train` (30 min, normal traffic only) was used to train the base model; `benign-val` (15 min) was used only to calibrate detection thresholds.
- `mixed-test` (development set) was used while designing v2 and v3.
- v3 was frozen and committed (commit 583e313) BEFORE `mixed-test-2` was recorded (commit f63e49a, seed 2026). `mixed-test-2` was never used for any design decision.
- `benign-train` and `benign-val` lost 0.82% and 0.96% of log events during download bursts (reporter queue later enlarged); `mixed-test` and `mixed-test-2` have 0 dropped events.
- Offloads (TSO/GSO/GRO) were disabled on the lab veth pair so the engine sees on-wire packets.

## 3. Models
- **v1**: IsolationForest on 5 volume features, trained on 1,000 synthetic vectors, plus a hand-set "more than 4x baseline" rule and a sigmoid confidence.
- **v2**: IsolationForest (200 trees) on 10 traffic-shape features, trained on `benign-train`; ANOMALOUS = more anomalous than every `benign-val` window, SUSPICIOUS = above 99th percentile of `benign-val`; confidence = percentile vs `benign-val`.
- **v3**: v2 unchanged + per-feature envelope guard on 6 shape features; `limit = max(3 x normal max, normal max + 10)`; margins fixed before evaluating v3; 0 guard hits on `benign-val`.

## 4. Held-Out Results (mixed-test-2)

### Per-Attack Detection & Latency
| Attack | v1 Anom | v1 Susp | v1 Latency | v2 Anom | v2 Susp | v2 Latency | v3 Anom | v3 Susp | v3 Latency |
|---|---|---|---|---|---|---|---|---|---|
| icmp_flood_high | Yes | Yes | 0.9s | Yes | Yes | 0.9s | Yes | Yes | 0.9s |
| syn_flood_high | Yes | Yes | 0.7s | Yes | Yes | 0.7s | Yes | Yes | 0.7s |
| udp_flood_high | Yes | Yes | 0.6s | No | No | - | Yes | Yes | 0.6s |
| port_scan_fast | Yes | Yes | 5.3s | Yes | Yes | 5.3s | Yes | Yes | 5.3s |
| syn_flood_low | Yes | Yes | 2.6s | Yes | Yes | 0.6s | Yes | Yes | 0.6s |
| icmp_flood_low | No | Yes | - | No | Yes | - | Yes | Yes | 1.4s |
| port_scan_slow | No | Yes | - | No | Yes | - | No | Yes | - |

*Latency = seconds from the attacker's first admitted packet to the first ANOMALOUS verdict (1 s evaluation ticks); "-" = not detected at ANOMALOUS.*

### Overall Classification Performance
| Model | Operating Point | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| v1 | ANOMALOUS | 1.000 | 0.603 | 0.753 | 0.000 | 0.971 | 0.919 |
| v1 | >=SUSPICIOUS | 0.704 | 0.841 | 0.766 | 0.085 | 0.971 | 0.919 |
| v2 | ANOMALOUS | 1.000 | 0.466 | 0.635 | 0.000 | 0.994 | 0.980 |
| v2 | >=SUSPICIOUS | 0.974 | 0.797 | 0.877 | 0.005 | 0.994 | 0.980 |
| v3 | ANOMALOUS | 1.000 | 0.772 | 0.871 | 0.000 | 0.996 | 0.989 |
| v3 | >=SUSPICIOUS | 0.978 | 0.953 | 0.965 | 0.005 | 0.996 | 0.989 |

## 5. Development-Set Results (mixed-test)

### Overall Classification Performance
| Model | Operating Point | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| v1 | ANOMALOUS | 0.853 | 0.625 | 0.721 | 0.026 | 0.956 | 0.836 |
| v1 | >=SUSPICIOUS | 0.656 | 0.871 | 0.748 | 0.110 | 0.956 | 0.836 |
| v2 | ANOMALOUS | 0.982 | 0.470 | 0.636 | 0.002 | 0.987 | 0.946 |
| v2 | >=SUSPICIOUS | 0.893 | 0.823 | 0.857 | 0.024 | 0.987 | 0.946 |
| v3 | ANOMALOUS | 0.989 | 0.789 | 0.878 | 0.002 | 0.996 | 0.984 |
| v3 | >=SUSPICIOUS | 0.907 | 0.961 | 0.933 | 0.024 | 0.996 | 0.984 |

### Benign Heavy User False Blocks (ANOMALOUS Episodes)
| Dataset | Model | Scored Ticks | Anomalous Ticks | Anomalous Episodes | Episodes / Hour |
|---|---|---|---|---|---|
| mixed-test | v1 | 443 | 25 | 5 | 32.1 |
| mixed-test | v2 | 443 | 2 | 1 | 6.4 |
| mixed-test | v3 | 443 | 2 | 1 | 6.4 |
| benign-val | v1 | 729 | 18 | 4 | 16.0 |
| benign-val | v2 | 729 | 0 | 0 | 0.0 |
| benign-val | v3 | 729 | 0 | 0 | 0.0 |

*Note: `benign-val` is the threshold set for v2 and v3, so 0 episodes there is by construction for them, but represents unseen data for v1.*

## 6. Diagnosis: Why v2 Failed and v3 Fixed It
`log_udp_rate` and `log_rst_rate` are constant (0) and `unique_dst_ips` is constant (1) in `benign-train`, so IsolationForest cannot split on them and does not extrapolate beyond the training range.
Consequently, v2 missed the UDP flood (median score 0.140 vs threshold 0.186) and the low-rate ICMP flood (0.185 vs 0.186).
v3 keeps the v2 IsolationForest unchanged and adds a per-feature envelope guard across 6 shape features with `limit = max(3 x normal max, normal max + 10)`.
Guard margins were fixed before evaluating v3, producing 0 guard hits on `benign-val` while detecting the UDP and ICMP floods.

## 7. Live End-to-End Demo
Evaluation conducted on 7 Nov 2026 using real engine, ML service, nftables auto-mitigation, and Telegram:
- Legitimate heavy user (3 x 20 MB downloads at roughly 0.7-1.0 GB/s): evaluated with one SUSPICIOUS verdict, was not blocked, and maintained 0% ping loss.
- UDP flood from 10.10.0.2: blocked by guard ("UDP packets/sec 839.6 vs normal max 0.0 (limit 10.0)").
- Low-rate ICMP flood from 10.10.0.6: blocked by guard ("ICMP echo requests/sec 26.4 vs normal max 1.0 (limit 11.0)").
- nftables set contained exactly 10.10.0.2 and 10.10.0.6; attacker ping experienced 100% packet loss; two Telegram alerts dispatched with Trigger: GUARD.

## 8. Limitations
- Slow port scan was detected only at SUSPICIOUS on held-out data (~2 ports/s sits near the 13-port guard limit in a 5 s window; a longer window is future work).
- Held-out heavy-user activity was lighter than in `mixed-test` (6,178 events for `benign_heavy_user` in `mixed-test-2` vs 13,400 in `mixed-test`; `benign_browser` had 6,810 vs 5,966 events), so the held-out set does not stress false blocks.
- All test sets evaluate the same 7 attack types; generalisation to novel attack types is not shown.
- The 1 s evaluation / 5 s window cadence can detect but not prevent a sub-second port scan.
- Evaluation performed on a single lab host on WSL2 veth with two benign client profiles.
- Rule blocks currently do not expire (planned future mitigation: TTL and allowlist).

## 9. How to Reproduce
Raw recordings (`events.jsonl`, `capture.pcap`) are not committed (hundreds of MB); only each dataset's `schedule.json` and `summary.json` are. To reproduce, record datasets with `scripts/dataset/run_dataset.sh` (see `datasets/README.md`); numbers will differ slightly between recordings.

```bash
cd ml-service
L="--local-ips 10.10.0.1,10.255.255.254"
venv/bin/python train_v2.py --train ../datasets/benign-train --val ../datasets/benign-val $L
venv/bin/python train_v3.py --train ../datasets/benign-train --val ../datasets/benign-val $L
venv/bin/python evaluate_offline.py --dataset ../datasets/mixed-test-2 --model v1 --label baseline-isoforest $L
venv/bin/python evaluate_offline.py --dataset ../datasets/mixed-test-2 --model v2 --label v2-isoforest $L
venv/bin/python evaluate_offline.py --dataset ../datasets/mixed-test-2 --model v3 --label v3-hybrid $L
cd ..
python3 eval/compare.py "$(ls eval/results/*_baseline-isoforest_mixed-test-2.json | tail -1)" "$(ls eval/results/*_v3-hybrid_mixed-test-2.json | tail -1)"
```

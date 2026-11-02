# AegisDPI — ML Service Design Document (Python / FastAPI)

## 1. Purpose

Detect volumetric/behavioral anomalies (DDoS-shaped traffic) from aggregated flow data and, when confident, trigger auto-mitigation by publishing a verdict the Node middleware turns into a blocklist entry.

## 2. Why Isolation Forest specifically

- Unsupervised — doesn't require large amounts of pre-labeled attack data, which fits a project without an external labeled dataset.
- Works well on tabular, moderate-dimensional feature vectors (which is what you'll be feeding it — not raw packets).
- Fast to train/score, appropriate for near-real-time scoring on a modest VM.
- **Limitation to state honestly:** it flags statistical outliers, not "attacks" per se — a legitimate sudden traffic spike (e.g. a real viral download) can also be flagged. This is exactly why the report should describe the auto-mitigation trigger as a _heuristic response_, with a human-visible override in the dashboard.

## 3. Critical design point: raw packets ≠ ML input

Isolation Forest cannot consume a raw packet stream. You need a **feature aggregation step**:

```
Redis (dpi:logs stream, raw per-packet/flow events)
        │
        ▼
Feature Aggregator (runs inside the FastAPI service, or a small
separate worker) — groups events into a sliding window per source IP
        │
        ▼
Feature Vector per (source_ip, window)
        │
        ▼
Isolation Forest .predict()
        │
        ▼
Verdict published to Redis (ml:verdicts)
```

## 4. Feature Set (per source IP, per sliding window — e.g. 5-second window)

| Feature              | Why it matters for DDoS detection                       |
| -------------------- | ------------------------------------------------------- |
| `packets_per_second` | Core volumetric signal                                  |
| `unique_dst_ports`   | Port-scan-like or flood-across-ports behavior           |
| `syn_ratio`          | High SYN-without-completion ratio = SYN flood signature |
| `avg_packet_size`    | Floods are often small, uniform packets                 |
| `unique_dst_ips`     | Fan-out behavior (one source hitting many destinations) |
| `bytes_per_second`   | Secondary volumetric signal alongside packet rate       |

## 5. Training / Validation Data Strategy (say this explicitly in your report)

The project doesn't use an external CSV/Kaggle dataset for the **live demo pipeline** — but the ML model still needs data to fit and validate on. Approach:

1. Generate your own labeled traffic with `scapy`: a "normal" traffic set (varied, moderate-rate flows) and several "attack" sets (SYN flood, UDP flood, slow-connection-flood) — all self-generated in your lab topology.
2. Optionally cross-validate against a small slice of a public benchmark (e.g. CIC-DDoS2019) purely to sanity-check the model isn't just overfit to your one synthetic generator — **not** required for the live demo, but strengthens the "how did you validate this" answer in viva.
3. Fit `IsolationForest` (scikit-learn) on the normal-traffic feature vectors (unsupervised — it learns what "normal" looks like); score all traffic including attack sets; report contamination rate, false-positive rate on held-out normal traffic.

## 6. API Surface

```
POST /predict          -> {source_ip, features} -> {is_anomaly, score}
GET  /model/status      -> model version, last trained timestamp, feature schema
POST /model/retrain      -> (admin-only, for demo purposes — retrain on latest window)
```

In production this would run as a background consumer of the Redis stream rather than a request/response API — but exposing `/predict` and `/model/status` also gives you clean, demoable REST endpoints for a viva walkthrough via Swagger UI (`/docs`, which FastAPI generates automatically — genuinely useful to show live).

## 7. Auto-Mitigation Flow

1. Aggregator computes feature vector for `(source_ip, window)`.
2. `IsolationForest.decision_function()` below threshold → anomaly flagged.
3. Verdict `{source_ip, score, reason, timestamp}` published to `ml:verdicts`.
4. Node middleware subscribes, if score below a configured severity threshold: (a) writes `source_ip` into `blocklist:ips` (same mechanism as a manual rule), (b) fires Telegram alert, (c) pushes `threat:flagged` event to dashboard.
5. Dashboard `/ml-insights` page shows the verdict **and the underlying feature values** — this transparency is what turns "black box ML" into something you can actually defend point-by-point in a viva.

## 8. Testing this layer

See `07_TESTING_QA_PLAN.md` Phase 5 — includes exact `scapy` snippets to generate a synthetic SYN flood in your lab topology and verify the full detection → block chain.

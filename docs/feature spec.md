# AegisDPI — Feature Specification & Phased Roadmap

Rule for this whole document: **every feature has a phase, a "definition of working," and a demo.** Nothing gets marked done just because code compiles.

## Phasing Philosophy

Build in this order specifically because each phase de-risks the next:

1. Prove offline correctness first (you already have a head start here from the reference repo).
2. Prove live traffic capture works in your actual dev environment (WSL2) before building anything on top of it — this is the phase most likely to surface environment problems, so it goes early, alone, isolated.
3. Prove real enforcement (kernel actually drops something) before wiring a UI to it — a beautiful dashboard connected to fake enforcement is worse than no dashboard.
4. Add distributed pieces (Redis, Node, React) once the core engine is trustworthy.
5. ML and "copycat-crusher" features come last — they're additive and impressive, but depend on everything else being stable.

## MVP (must work for a passing grade, no exceptions)

| ID  | Feature                                            | Phase | Definition of Working                                                                                                                                                    |
| --- | -------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F1  | Offline pcap replay pipeline (parse, 5-tuple, SNI) | 1     | Reference repo's existing pipeline compiles & runs on your machine, verified against `test_dpi.pcap`                                                                     |
| F2  | Multi-threaded LB/FP architecture                  | 1     | Thread stats in output show packets distributed across ≥2 FP threads, not all on one                                                                                     |
| F3  | Live packet capture (not just file replay)         | 2     | Engine processes packets from a live interface/veth, counters increase in real time                                                                                      |
| F4  | Real enforcement (nftables-set based)              | 2     | A blocked IP's connection genuinely fails from a second lab VM/namespace — verified with `curl`/`ping`, not just log output                                              |
| F5  | Redis IPC (logs + stats + rule sync)               | 3     | `redis-cli XRANGE dpi:logs - +` shows real entries while engine runs; adding a rule via `redis-cli SADD blocklist:ips` gets picked up by engine within its poll interval |
| F6  | Node API + Socket.io live relay                    | 3     | Postman/curl can CRUD rules; a browser console connected via Socket.io receives live events                                                                              |
| F7  | React dashboard: live feed + rule management       | 4     | Adding a rule in the UI results in the corresponding IP failing to connect, end to end                                                                                   |

## Stretch Features (build only after MVP is fully demoable)

| ID  | Feature                                                                                                                                    | Phase | Definition of Working                                                                                                                                             |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------ | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S1  | JA3 fingerprinting _(synopsis "Future Scope" item — build only if time permits; present as ahead-of-roadmap, not a committed deliverable)_ | 5     | Engine logs a JA3 hash per TLS flow; a script using a non-browser TLS stack (e.g. `curl`, `python-requests`) produces a visibly different JA3 than a real browser |
| S2  | ML anomaly detection (Isolation Forest) — _in the submitted synopsis's core scope_                                                         | 5     | Simulated flood (self-generated, lab-only) triggers a verdict published to `ml:verdicts` within a few seconds                                                     |
| S3  | ML auto-mitigation (verdict → auto-block) — _in the submitted synopsis's core scope_                                                       | 5     | Following S2, the flagged source appears in `blocklist:ips` automatically, no human click                                                                         |
| S4  | Threat map (geo of blocked/flagged sources) — _in the submitted synopsis's core scope_                                                     | 6     | Dashboard map renders markers for recent flagged sources using ip-api.com lookups                                                                                 |
| S5  | Threat intel enrichment (VirusTotal/AbuseIPDB) — _in the submitted synopsis's core scope_                                                  | 6     | New unknown IP triggers an API call, result cached in Redis, shown in dashboard                                                                                   |
| S6  | Telegram alerting — _in the submitted synopsis's core scope_                                                                               | 6     | High-severity event produces a real push notification on your phone within seconds                                                                                |
| S7  | TCP Tarpitting _(not mentioned in the submitted synopsis at all — pure bonus, skip without consequence if short on time)_                  | 7     | Against a lab-simulated attacker only: attacker's client visibly hangs/stalls on the connection                                                                   |

## Explicitly Deferred / "If Time Permits" (say this plainly if asked)

- QUIC/HTTP-3 SNI extraction (SNI is encrypted differently in QUIC — meaningfully harder, don't promise it)
- Full signature-based IDS rule language (Suricata-style) — out of scope, said in PRD non-goals
- Horizontal scaling of the C++ engine across multiple hosts

## Per-Feature Acceptance Checklist Template

Use this for every feature before marking it done in your tracker:

- [ ] Code compiles/runs without manual patching
- [ ] Has at least one automated test (unit or integration) — see `07_TESTING_QA_PLAN.md`
- [ ] Has a reproducible manual demo you can run live in front of the panel
- [ ] Failure mode is handled gracefully (doesn't crash the whole engine/service)
- [ ] Relevant Redis keys/API routes documented in `02_TRD.md` section 6.2 if changed

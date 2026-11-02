# AegisDPI — Product Requirements Document (PRD)

**Project:** High-Performance Multi-Threaded Deep Packet Inspection (DPI) Engine
**Type:** B.Tech Final Year Project — Computer Science
**Document owner:** Soham (Final Year Student)
**Status:** Draft v1.0 — prepared before Phase 1 build begins

---

## 1. Problem Statement

Open-source traffic tools such as Wireshark are **passive** — they observe and record network traffic but cannot act on it. There is no accessible, self-built tool for a network administrator to **actively drop or throttle** specific websites, apps, or malicious flows at the network level, in real time, using their own rules.

## 2. Why This Matters (Justification for a Viva Panel)

- Passive monitoring tools answer "what happened." Active DPI answers "what do I do about it, right now."
- Enterprises, ISPs, and campus networks all run some form of active filtering (parental controls, bandwidth shaping, malware/C2 blocking). Building a scaled-down version demonstrates understanding of real production network-security architecture, not just a script.
- The project intentionally spans four disciplines examiners will want to see: **systems programming (C++)**, **distributed backend engineering (Node/Redis)**, **applied ML (anomaly detection)**, and **security engineering (threat modeling, safe defaults)**.

## 2.5 Cross-Reference with the Submitted Synopsis (TYCS Sem-V, "AegisDPI")

This PRD is written to match what was **already officially submitted** to your department (`Research_Project_Synopsis.docx`). Two alignment points matter and should not be forgotten mid-build:

1. **JA3 TLS fingerprinting is listed in the synopsis's "Future Scope" section, not the current Scope.** Build it (per `03_FEATURE_SPEC.md`) only if time permits, and when you demo it, frame it explicitly as _"we got ahead of our own future-scope roadmap"_ — a nice thing to say in a viva, but don't let it eat time the core deliverables need.
2. **TCP Tarpitting is not mentioned anywhere in the submitted synopsis.** It's not a promised deliverable. Treat it strictly as bonus/optional (see `03_FEATURE_SPEC.md` S7) — if you don't get to it, that's not a gap against what you committed to; if you do, present it as an unplanned extra, not something being checked off a list.

Everything else in the synopsis (5-tuple hashing, SNI-based active drop, React+Socket.io dashboard, Isolation Forest anomaly detection, Telegram SecOps bot, VirusTotal/AbuseIPDB enrichment, ip-api.com geolocation, self-captured `.pcap` testing methodology) maps directly to the MVP + stretch features already defined here — no conflicts.

The synopsis's own **Limitations** section already gives you cover for questions about scale and ECH — it explicitly states single-machine testing, dependency on visible SNI, and no native ECH support. Reuse that language if asked; you already committed to it in writing.

## 3. Goals

| #   | Goal                                                                      | Success Criterion                                                                                                      |
| --- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| G1  | Inspect traffic and identify the destination service even when encrypted  | Correctly extracts SNI from TLS ClientHello for ≥95% of HTTPS flows in test pcaps                                      |
| G2  | Actively drop/block matching traffic, not just log it                     | A blocked domain/IP genuinely fails to connect in a live lab demo (verified with a client, not just log output)        |
| G3  | Process traffic fast enough to be credible as "real-time"                 | Sustain ≥5,000 packets/sec on a test VM without dropped/corrupted packets in the pipeline                              |
| G4  | Give an admin a live, usable control surface                              | Dashboard reflects a new blocking rule take effect within 2 seconds, end-to-end                                        |
| G5  | Detect volumetric anomalies (DDoS-shaped traffic) automatically           | Isolation Forest flags a simulated SYN-flood/DDoS pattern with acceptable false-positive rate on held-out test traffic |
| G6  | Be defensible in a viva — every claimed feature must be demonstrable live | Each feature in Section 6 has a corresponding entry in `07_TESTING_QA_PLAN.md` with a reproducible demo                |

## 4. Non-Goals (explicitly out of scope — say this in the synopsis to preempt questions)

- This is **not** a production-grade carrier/ISP-scale DPI system (no DPDK/kernel-bypass, no multi-Gbps target).
- This is **not** a general-purpose IDS/IPS replacement for Snort/Suricata — the rule engine is simpler (IP/CIDR/domain/app-signature match), not a full signature language.
- No claim of decrypting TLS payload content — only metadata visible pre-encryption (SNI) or via fingerprinting (JA3) is used. This project does **not** perform TLS interception/MITM.
- Threat intelligence (VirusTotal/AbuseIPDB) integration is **best-effort enrichment**, not a guarantee of catching zero-days.
- Enforcement demos are run against **self-generated lab traffic**, not arbitrary live internet targets.

## 5. Target User / Persona

**Primary persona:** A network administrator for a small-to-medium network (campus lab, small office) who wants visibility _and_ the ability to act — block a misbehaving app/IP, see it reflected instantly, and get proactively alerted if traffic looks like an attack.

## 6. Feature Summary (detail lives in `03_FEATURE_SPEC.md`)

1. Multi-threaded packet ingestion + 5-tuple hash load balancing (C++)
2. SNI extraction from TLS ClientHello for HTTPS traffic identification
3. Rule-based drop/forward decision (IP, CIDR, domain, app-signature)
4. Redis-backed IPC between engine and backend (logs, stats, live rule sync)
5. Real-time dashboard (React) with live traffic feed, rule management, and a global threat map
6. ML microservice (Isolation Forest) for DDoS/anomaly detection with auto-mitigation trigger
7. JA3 TLS fingerprinting to flag non-browser/bot clients
8. TCP tarpitting for detected malicious sources (lab-scoped)
9. Threat intel enrichment (VirusTotal/AbuseIPDB) for unknown IPs
10. Telegram bot alerting on high-severity events

## 7. System Actors

| Actor              | Interacts with                                                                   |
| ------------------ | -------------------------------------------------------------------------------- |
| Network Admin      | React Dashboard                                                                  |
| C++ DPI Engine     | Live/replayed traffic, Redis                                                     |
| Node.js Middleware | Redis, Dashboard (via Socket.io + REST), Telegram API, VirusTotal/AbuseIPDB      |
| Python ML Service  | Redis (reads aggregated flow features), Node middleware (posts anomaly verdicts) |

## 8. Key Assumptions

- Development happens on WSL2 (Ubuntu) for the C++ engine; live-traffic enforcement demos may require a plain Linux VM if WSL2's kernel lacks required netfilter modules (to be validated Phase 1 — see `07_TESTING_QA_PLAN.md`).
- Demo traffic is either (a) pre-captured `.pcap` replayed at controlled rate via `tcpreplay`, or (b) self-generated lab traffic between two VMs/namespaces — never uncontrolled production/public internet traffic.
- All four services (C++, Node, React, FastAPI) are developed independently and integrated incrementally, per phase.

## 9. Risks

| Risk                                            | Impact                                                | Mitigation                                                                                                     |
| ----------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| WSL2 lacks NFQUEUE kernel support               | Can't do true inline drop in dev environment          | Validate Day 1; fall back to nftables-set enforcement or demo on a Linux VM                                    |
| Manual TLS parsing crashes on malformed packets | Live demo crash in front of panel                     | Bounds-check every offset; fuzz-test parser; catch and skip malformed packets, never crash the process         |
| ML model overfits to one synthetic attack shape | "It only works because you rigged the demo" objection | Use varied attack patterns (SYN flood, UDP flood, slow-loris-like) + one negative/normal-traffic-only test run |
| Scope creep across 4 services in limited time   | Nothing fully finished by deadline                    | Strict MVP-first phase order (see `03_FEATURE_SPEC.md`); stretch features are explicitly optional and labeled  |

## 10. Definition of Done (for the whole project)

The project is demo-ready when: a panel member can (1) watch the dashboard show live traffic, (2) add a block rule through the UI, (3) watch a real client's connection to that domain fail within ~2 seconds, (4) trigger a simulated flood and watch the ML service flag it and auto-block the source, and (5) receive a Telegram alert for that event — all without the presenter touching a terminal.

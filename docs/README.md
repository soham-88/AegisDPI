# AegisDPI Documentation Index

This directory contains technical specifications, design documents, security architecture references, and operation guides for AegisDPI.

> [!NOTE]
> Architecture and security models evolved through optimization and hardening passes. Documents designated as **original design document** reflect early design milestones and predate recent hardening passes; consult the root [README.md](../README.md), [security.md](security.md), and [safe-blocking.md](safe-blocking.md) for the active, implemented architecture.

---

## Index of Documents

- [deployment docker.md](deployment%20docker.md) — Docker Compose deployment and multi-container orchestration guide (original design document; predates later changes; see README for the current architecture).
- [feature spec.md](feature%20spec.md) — Detailed feature specification covering telemetry, packet classification, and rule synchronisation (original design document; predates later changes; see README for the current architecture).
- [frontend design.md](frontend%20design.md) — React dashboard design, state store architecture, and real-time visualization layout (original design document; predates later changes; see README for the current architecture).
- [local dev run.md](local%20dev%20run.md) — Step-by-step local setup, capability installation, service lifecycle, and live lab testing guide.
- [ml service design.md](ml%20service%20design.md) — Initial ML service architecture, sliding-window schemas, and scoring flow (original design document; predates later changes; see README for the current architecture).
- [prd.md](prd.md) — Product Requirements Document detailing core system objectives, capabilities, and personas (original design document; predates later changes; see README for the current architecture).
- [prompts.md](prompts.md) — Engineering prompt trajectory and implementation logs across initial development phases.
- [safe-blocking.md](safe-blocking.md) — Safe blocking architecture: automated TTL escalation ladder (10m $\to$ 1h $\to$ 24h), strike tracking, allowlist validation, and append-only audit trail.
- [security design.md](security%20design.md) — Initial threat model, STRIDE evaluation, and service boundary specifications (original design document; predates later changes; see README for the current architecture).
- [security.md](security.md) — Comprehensive security hardening specification: Linux file capabilities (`CAP_NET_RAW` + `CAP_NET_ADMIN`), in-process `libnftables`, role enforcement, CORS allowlists, CSP, rate limiting, and `TRUST_PROXY` anti-spoofing.
- [testing qa plan.md](testing%20qa%20plan.md) — Initial testing strategy, mock scenarios, and QA phase milestones (original design document; predates later changes; see README for the current architecture).
- [trd.md](trd.md) — Technical Requirements Document detailing engine threading, ring buffers, IPC, and Redis key schemas (original design document; predates later changes; see README for the current architecture).
- [viva prep.md](viva%20prep.md) — Examination defense preparation, presentation notes, and architectural walkthrough scripts (original design document; predates later changes; see README for the current architecture).


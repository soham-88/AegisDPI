# AegisDPI — Agent Prompts (for Antigravity IDE)

How to use this file: put the whole `AegisDPI-docs/` folder at the root of your project (next to `engine/`, `middleware/`, `frontend/`, `ml-service/`). Paste the **Master Context Prompt** into a new Antigravity agent session first, once, then work through the phase prompts in order — one at a time, testing after each (per `07_TESTING_QA_PLAN.md`) before moving to the next. Don't paste multiple phase prompts into one session in a row; that's how scope creep and half-finished features happen.

---

## Master Context Prompt (paste this first, every new session)

```
You are acting as a senior systems engineer helping me build AegisDPI, a
multi-threaded Deep Packet Inspection engine, described fully in the docs
folder at ./AegisDPI-docs/. Before doing anything, read:
- AegisDPI-docs/01_PRD.md
- AegisDPI-docs/02_TRD.md
- AegisDPI-docs/03_FEATURE_SPEC.md

Follow these rules for the whole session:
1. Build incrementally. Only implement what I explicitly ask for in this
   message — do not silently add features from the roadmap ahead of where
   we are.
2. After any change, tell me exactly which terminal commands to run to
   verify it, and what output means success vs failure. Reference
   AegisDPI-docs/07_TESTING_QA_PLAN.md for the expected format.
3. Never break previously working functionality. If a change risks that,
   tell me before making it.
4. Follow the security constraints in AegisDPI-docs/04_SECURITY_DESIGN.md
   at all times — especially: no string-concatenated shell commands built
   from user/network input, no secrets in code, least-privilege by default.
5. If something in my request conflicts with the docs (e.g. I ask for a
   shortcut that would leave a security gap), point it out before doing it,
   don't just silently comply.
6. Keep functions/files reasonably small and commented — this is an
   academic project that will be read and explained line-by-line in a viva.
```

---

## Phase 0 — Environment & Project Scaffold

```
Set up the base project structure for AegisDPI at the repo root, matching
this layout:

AegisDPI/
├── AegisDPI-docs/         (already exists, don't touch)
├── engine/                (C++17, CMake)
├── middleware/             (Node.js/Express)
├── frontend/                (React + Vite + Tailwind)
├── ml-service/              (Python/FastAPI)
├── docker-compose.yml
├── docker-compose.engine.yml
└── .gitignore

For now, just create the directory skeletons, a root .gitignore covering
node_modules, build/, __pycache__, venv/, .env files, and *.pcap test
artifacts, and empty placeholder README.md files in each service folder
pointing back to the relevant doc in AegisDPI-docs/. Don't write any real
code yet — I want to validate my environment (WSL2 kernel module support,
nftables, g++/cmake versions) manually first, per Phase 0 of
AegisDPI-docs/07_TESTING_QA_PLAN.md, before we build anything.
```

_(Run the Phase 0 terminal commands from the testing plan yourself before continuing — this determines whether NFQUEUE is even an option for you.)_

---

## Phase 1 — Offline Engine Core

```
We're starting the C++ engine. I'm bringing in the parsing logic and
multi-threaded LB/FP architecture from a reference implementation
(offline pcap-in, pcap-out). Here's what I need you to do:

1. Set up CMakeLists.txt for a C++17 project using libpcap, targeting
   two build targets: dpi_simple (single-threaded) and dpi_engine
   (multi-threaded), matching the structure in AegisDPI-docs/02_TRD.md
   section 2.
2. I'll paste in the reference pcap_reader, packet_parser, sni_extractor,
   and types files next — review them specifically for missing bounds
   checks on buffer offsets (per AegisDPI-docs/04_SECURITY_DESIGN.md,
   threat T3) and flag every place a read could go past the payload
   length before I compile.
3. Add a GoogleTest setup (via CMake FetchContent, no manual install
   needed) with these initial tests:
   - Five-tuple hashing is deterministic and well-distributed across
     a small bucket count
   - SNI extractor correctly parses a known-good ClientHello byte array
     (I'll provide a real captured example)
   - SNI extractor returns "not found" (not a crash) on a truncated/
     malformed ClientHello
4. Add a background flow-table eviction sweep (TTL-based, default 60s
   idle timeout) to the multi-threaded engine, per TRD section 2.4 —
   don't let the flow map grow unbounded.

After each step, tell me the exact build and test commands to run.
```

---

## Phase 2 — Live Capture + Enforcement

```
Now extend the engine to support live traffic, not just pcap replay,
per AegisDPI-docs/02_TRD.md section 2.2-2.3.

1. Add a --live <iface> CLI mode using pcap_open_live(), alongside the
   existing --replay <file> mode — both should feed the same downstream
   parsing/LB/FP pipeline, just different packet sources.
2. Implement an Enforcer interface with one concrete implementation for
   now: NftablesEnforcer. It should:
   - On startup, create a dedicated nftables table/chain/set for AegisDPI
     if it doesn't exist
   - Expose addBlock(ip_or_cidr) / removeBlock(ip_or_cidr) methods
   - Build nft commands ONLY from input that has passed a strict
     IPv4/CIDR validation regex first — refuse and log anything that
     doesn't match, never pass raw strings through
3. Wire a simple in-memory rule check for now (we'll connect Redis in
   Phase 3) — a hardcoded test IP added via a CLI flag should result in
   that IP actually being added to the nftables set on startup.
4. Tell me the exact commands to set up the two-namespace lab topology
   from AegisDPI-docs/07_TESTING_QA_PLAN.md Phase 2, and how to verify
   enforcement is real (not just logged) using ping.
```

---

## Phase 3 — Redis IPC + Node Middleware

```
Now build the IPC layer and middleware, per AegisDPI-docs/02_TRD.md
section 3, using the exact Redis key/stream contract in TRD section 3.3
— do not invent different key names, keep the C++ and Node sides in sync
with what's documented there.

On the C++ side:
1. Add a Redis client (redis-plus-plus) integration. Fast Path threads
   must NOT block on Redis calls directly — implement a separate Reporter
   thread that drains an internal queue and performs all Redis writes
   (XADD to dpi:logs, counter updates for dpi:stats).
2. On startup, load blocklist:ips / blocklist:domains / blocklist:apps
   from Redis Sets. Subscribe to blocklist:updates and reload/patch the
   in-memory rule set (and call the Enforcer) when it fires.

On the Node side, scaffold middleware/ as an Express + Socket.io app:
3. Implement the REST routes from TRD section 3.2 (rules CRUD, stats
   summary). Rule writes go to the Redis Sets and publish to
   blocklist:updates.
4. Implement a Redis Streams consumer (XREAD BLOCK) on dpi:logs that
   relays new entries over Socket.io on a log:new event, and a stats
   relay on stats:update.
5. Add JWT auth middleware protecting all routes except /api/auth/login,
   per AegisDPI-docs/04_SECURITY_DESIGN.md T2.

Give me curl commands to test the REST API and a way to sanity-check the
Socket.io relay without a frontend yet, per Phase 3 of the testing plan.
```

---

## Phase 4 — React Dashboard

```
Build the frontend per AegisDPI-docs/05_FRONTEND_DESIGN.md exactly —
follow its page list, component list, and the dark "SOC console" visual
direction described there (not a generic admin template).

1. Scaffold with Vite + React + Tailwind. Set up the route structure
   from section 2 of the frontend doc, with auth-guarded routes.
2. Build the Login page wired to /api/auth/login, storing the JWT in
   React state (not localStorage).
3. Build the Dashboard page with a LiveCounterBar component connected
   to Socket.io stats:update events.
4. Build the Traffic page with a virtualized TrafficTable (react-window)
   connected to log:new events, batching UI updates every 200-300ms
   rather than re-rendering per event (per frontend doc section 5).
5. Build the Rules page with a RuleForm (client-side validation matching
   the backend's IP/CIDR regex) and a list of active rules with delete.

After each page, tell me what to click through manually to verify it,
and what the Phase 4 end-to-end test looks like (a UI rule change should
break real connectivity in my lab topology — walk me through confirming
that specifically).
```

---

## Phase 5 — ML Service

```
Build ml-service/ per AegisDPI-docs/06_ML_SERVICE_DESIGN.md.

1. Scaffold a FastAPI app with a feature aggregator that consumes
   dpi:logs from Redis (XREAD) and computes the sliding-window feature
   set from section 4 of the ML doc, keyed per source IP.
2. Add a training script that generates labeled traffic with scapy
   (normal + at least 2 attack shapes: SYN flood, UDP flood) as described
   in section 5, and fits a scikit-learn IsolationForest on the normal
   traffic's feature vectors. Save the model to disk.
3. Add the /predict and /model/status endpoints from section 6.
4. Add the auto-mitigation publish step: when a window scores as
   anomalous, publish a verdict to ml:verdicts with the source IP, score,
   and the feature values that triggered it (needed for the dashboard's
   transparency requirement in the ML doc section 7).
5. On the Node side, subscribe to ml:verdicts and, on a flagged verdict,
   write the source IP into blocklist:ips (same path as a manual rule)
   and log the auto-mitigation action.

Then walk me through the exact scapy flood-test script and the sequence
of terminals/commands from Phase 5 of AegisDPI-docs/07_TESTING_QA_PLAN.md
to verify detection → auto-block end-to-end, plus a negative test with
normal-rate traffic to check for false positives.
```

---

## Phase 6 — JA3, Threat Map, Threat Intel, Telegram

```
Add the remaining stretch features, one at a time, testing each in
isolation before wiring into the full pipeline (per Phase 6 of the
testing plan):

1. JA3: extend the existing ClientHello parser in the C++ engine to
   also collect TLS version, cipher suites, extensions, elliptic curves,
   and EC point formats, and compute the JA3 MD5 hash per TRD section 2.6.
   Log it alongside SNI in dpi:logs.
2. Threat map: on the Node side, add an ip-api.com lookup (with caching
   in Redis to avoid repeat calls) for flagged/blocked source IPs, and
   a /api/threats/recent endpoint. On the frontend, build the ThreatMap
   component per the frontend doc.
3. Threat intel: add AbuseIPDB and VirusTotal lookups (API keys from
   .env, never sent to the frontend) for unknown IPs, cached in Redis,
   surfaced in the dashboard's threats view.
4. Telegram: add a sendTelegramAlert() function triggered on high-
   severity events (ml:verdicts above a configured threshold, or repeated
   manual blocks), posting to the Telegram Bot API.

Test each integration with a standalone curl command first (I'll paste
the exact ones from the testing plan) before wiring it into the full
event chain.
```

---

## Phase 7 — Tarpitting, Load Testing, Fuzzing, Hardening

```
Final hardening pass before the demo.

1. Implement TCP tarpitting in the C++ engine: on a flagged malicious
   source, send a raw TCP packet with window size 0 back to it, scoped
   ONLY to sources within a configured lab CIDR allow-list (refuse and
   log if the target falls outside it) — per
   AegisDPI-docs/04_SECURITY_DESIGN.md threat T8.
2. Set up capability-based privilege (setcap cap_net_raw,cap_net_admin)
   for the engine binary instead of running the whole process as root,
   and update the run instructions accordingly.
3. Write the fuzz-testing script from Phase 7 of the testing plan
   (scapy-generated malformed packets) and run it against the engine —
   fix any crash it finds, don't just note it.
4. Run the tcpreplay load test at --topspeed and report actual
   packets/sec achieved against the NFR target in AegisDPI-docs/02_TRD.md
   section 7.
5. Do a final pass over AegisDPI-docs/04_SECURITY_DESIGN.md's full
   threat table (T1-T8) and confirm each mitigation is actually
   implemented, not just planned — list any gaps honestly.

Then produce the docker-compose.yml and docker-compose.engine.yml exactly
per AegisDPI-docs/08_DEPLOYMENT_DOCKER.md, and tell me the startup order
and commands for a full clean-machine demo run.
```

---

## Debugging Prompt Template (use anytime something breaks)

```
This isn't working as expected. Here's what I ran and what happened:

Command: [paste exact command]
Expected (per AegisDPI-docs/07_TESTING_QA_PLAN.md): [paste expected outcome]
Actual output/error: [paste terminal output]

Before changing code, tell me your hypothesis for the root cause and how
you'd confirm it, then fix it. Don't touch files/logic outside what's
needed to fix this specific issue.
```

# AegisDPI — Technical Requirements & System Design Document (TRD)

## 1. High-Level Architecture

```
                         ┌──────────────────────────┐
   Live NIC / Replayed   │   LAYER 1: C++17 Engine  │
   traffic (.pcap or     │  Reader → LB(hash) → FP  │──── writes stats/logs ───┐
   live capture)  ─────► │  (SNI/JA3 inspect, rule  │                          │
                         │   match, DROP/FWD verdict)│                          ▼
                         └──────────────────────────┘                 ┌─────────────────┐
                                     ▲                                 │  Redis           │
                                     │ polls/subscribes                │  - blocklist:*   │
                                     │ live rule updates                │  - stats stream  │
                                     │                                 │  - logs stream   │
                         ┌──────────────────────────┐                 └────────┬────────┘
                         │ LAYER 2: Node.js/Express  │◄────────────────────────┘
                         │  REST API + Socket.io     │─── HTTP ───► VirusTotal / AbuseIPDB
                         │  writes rule updates back  │─── HTTP ───► Telegram Bot API
                         │  to Redis for engine       │
                         └─────────────┬─────────────┘
                                       │ WebSocket (live) + REST (CRUD)
                                       ▼
                         ┌──────────────────────────┐        ┌──────────────────────────┐
                         │ LAYER 3: React Dashboard │        │ LAYER 4: Python/FastAPI  │
                         │  Live feed, rules, map    │        │  Isolation Forest        │
                         └──────────────────────────┘        │  reads flow features from│
                                                               │  Redis, posts verdicts to│
                                                               │  Node → auto-block       │
                                                               └──────────────────────────┘
```

## 2. Layer 1 — C++ Engine

### 2.1 Process model

- Single process, multiple threads: 1 Reader → N Load Balancers → M Fast Paths → 1 Output/Reporter.
- Thread count configurable via CLI flags (`--lbs`, `--fps`), same pattern as the reference implementation.

### 2.2 Two traffic-source modes (both must exist)

| Mode            | Source API                                                            | Purpose                                                   |
| --------------- | --------------------------------------------------------------------- | --------------------------------------------------------- |
| **Replay mode** | Read `.pcap` file directly (existing reference code)                  | Deterministic, repeatable testing and grading demos       |
| **Live mode**   | `pcap_open_live()` on an interface (or a veth pair in a lab topology) | Satisfies the "real-time" claim on genuinely live traffic |

### 2.3 Enforcement mechanism (the critical addition vs. the reference repo)

Two mechanisms, implemented as a pluggable `Enforcer` interface so you can swap them without touching the parser:

1. **`NftablesEnforcer`** (primary): engine shells out to (or, better, uses `libnftnl`/`libmnl`) to add/remove elements from a pre-created nftables set, e.g. `nft add element inet aegis blocked_ips { 1.2.3.4 }`. The kernel then drops future packets from that IP at the firewall level — this is genuine enforcement, independent of whether the engine sees every subsequent packet.
2. **`NfqueueEnforcer`** (stretch/Phase-2, validate kernel support first): engine registers as an NFQUEUE target via `libnetfilter_queue`; for each packet in queue it returns `NF_ACCEPT` or `NF_DROP`. True per-packet inline control, but heavier to set up and not guaranteed to work under WSL2's default kernel.

**Rule:** all commands sent to `nft`/`iptables` must be built from a strict input contract (validated IPv4/CIDR regex, allow-listed table/chain names — never raw string interpolation of user input).

### 2.4 Core data structures (extend reference repo's `types.h`)

- `FiveTuple` — unchanged.
- `Flow` — add `first_seen`, `last_seen` (for TTL eviction), `ja3_hash`, `blocked_reason`.
- `RuleSet` — becomes **Redis-backed**, not CLI-only: on startup, load from `blocklist:ips`, `blocklist:domains`, `blocklist:apps` (Redis Sets/Hashes); poll or subscribe (`blocklist:updates` Pub/Sub channel) for live changes.
- Flow table eviction: background sweep every N seconds removes flows idle > timeout (default 60s) to bound memory.

### 2.5 IPC to Redis

- Use `redis-plus-plus` (recommended) or `hiredis` C++ client.
- **Never block the Fast Path thread on network I/O.** Fast Path pushes `{event, flow, verdict, timestamp}` into an in-process lock-free queue; a dedicated **Reporter thread** drains it and writes to Redis (`XADD dpi:logs`, `INCR` counters, or `PUBLISH dpi:stats`).

### 2.6 JA3 fingerprinting

- Extend the existing ClientHello parser (already walks cipher suites/extensions for SNI) to also collect: TLS version, cipher suite list, extension list, elliptic curve list, EC point format list.
- JA3 string = `TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats` (comma-joined, dash-separated within each field) → MD5 hash = JA3.
- Compare against a small local list of known-bad/bot JA3 hashes (curated, not exhaustive — say this explicitly in the viva).

### 2.7 TCP Tarpitting

- On detecting a flagged malicious source (from ML verdict or rule match), engine crafts a raw TCP response with `window size = 0` back to that source (using a raw socket, requires `CAP_NET_RAW`).
- **Scope:** only fired against sources within the lab-simulated "attacker" topology, never arbitrary internet hosts, during any demo.

## 3. Layer 2 — Node.js Middleware

### 3.1 Responsibilities

- REST API: CRUD for blocking rules (writes to Redis, which the C++ engine consumes).
- Socket.io: pushes live log/stat events to connected dashboards (subscribe to Redis Pub/Sub / `XREAD BLOCK` on Streams, forward over WebSocket).
- Threat intel: on new unknown IP, call AbuseIPDB/VirusTotal, cache result in Redis (avoid re-querying same IP repeatedly — respect free-tier rate limits).
- Alerting: on high-severity event (ML anomaly or repeated block threshold), POST to Telegram Bot API.

### 3.2 API surface (initial)

```
GET    /api/rules              -> list all active rules
POST   /api/rules               -> add a rule {type: ip|domain|app, value}
DELETE /api/rules/:id            -> remove a rule
GET    /api/stats/summary        -> aggregate counters (forwarded/dropped/apps)
GET    /api/threats/recent       -> recent flagged sources w/ geo + threat-intel data
POST   /api/auth/login           -> issue JWT (admin-only dashboard)
```

All routes except `/auth/login` require a valid JWT (`Authorization: Bearer`).

### 3.3 Redis keys/streams contract (shared with C++ engine — keep this in sync)

| Key                 | Type                    | Written by         | Read by                                              |
| ------------------- | ----------------------- | ------------------ | ---------------------------------------------------- |
| `blocklist:ips`     | Set                     | Node (on rule add) | C++ engine                                           |
| `blocklist:domains` | Set                     | Node               | C++ engine                                           |
| `blocklist:apps`    | Set                     | Node               | C++ engine                                           |
| `blocklist:updates` | Pub/Sub channel         | Node               | C++ engine (live reload)                             |
| `dpi:logs`          | Stream                  | C++ engine         | Node (Socket.io relay), FastAPI (feature extraction) |
| `dpi:stats`         | Pub/Sub / Hash counters | C++ engine         | Node                                                 |
| `ml:verdicts`       | Pub/Sub                 | FastAPI            | Node (triggers auto-block + Telegram)                |

## 4. Layer 3 — React Dashboard

See `05_FRONTEND_DESIGN.md` for full spec. Summary: Vite + React + Tailwind, Socket.io-client, `recharts` for time series, `react-simple-maps`/Leaflet for the threat map, JWT stored in memory (not localStorage) with refresh via httpOnly cookie.

## 5. Layer 4 — Python/FastAPI ML Service

See `06_ML_SERVICE_DESIGN.md` for full spec. Summary: consumes `dpi:logs` stream, aggregates into per-source-IP sliding-window feature vectors, runs Isolation Forest, publishes verdicts to `ml:verdicts`.

## 6. Cross-Cutting Concerns

- **Config management:** one `.env` per service, never committed; a single `config/rules-schema.md` documents the Redis key contract above so all four services stay in sync as you build them independently.
- **Logging:** structured JSON logs from every service (easier to screenshot/demonstrate and easier to grep during debugging).
- **Error isolation:** a crash/exception in SNI/JA3 parsing must never crash the whole engine — catch per-packet, log, continue.

## 7. Non-Functional Requirements

| Requirement                                  | Target                                                             |
| -------------------------------------------- | ------------------------------------------------------------------ |
| Throughput                                   | ≥5,000 pkt/s sustained on test VM (4 vCPU)                         |
| Rule propagation latency (UI → enforced)     | <2s                                                                |
| Dashboard update latency (event → UI)        | <500ms                                                             |
| Engine uptime under malformed-packet fuzzing | No crash over a 10-minute fuzz run                                 |
| Redis auth                                   | `requirepass` set, bound to localhost/internal Docker network only |

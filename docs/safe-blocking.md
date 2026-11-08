# AegisDPI — Safe Blocking Architecture & Policy

## 1. Overview
Safe blocking prevents indefinite lockouts, protects internal and management subnets, tracks repeat offenders through automated TTL escalation, and records every mitigation event in an append-only audit stream.

## 2. Redis Data Structures
All blocking state is coordinated centrally in Redis:

| Key | Type | Description |
|---|---|---|
| `blocklist:ips` | Set | Active blocked IPv4 addresses. Read by C++ engine at startup and live-synced via pub/sub. |
| `blocklist:meta` | Hash | Maps `ip` to JSON metadata: `{ ip, added_at, added_by, source, reason, ttl_s, expires_at, strikes_24h }`. |
| `blocklist:expiry` | Sorted Set | Maps `ip` to `expires_at_ms` (Unix timestamp in milliseconds). Excludes permanent rules. |
| `blocklist:strikes` | Hash | Maps `ip` to JSON array of strike timestamps in ms `[ts1, ts2, ...]`. Pruned on every write to the 24-hour window. |
| `allowlist:entries` | Hash | Maps IP or CIDR `entry` to JSON: `{ entry, note, added_by, added_at }`. |
| `audit:log` | Stream | Append-only security audit log capped at ~10,000 entries via `MAXLEN ~ 10000`. |
| `dpi:logs` | Stream | Packet inspection log stream trimmed periodically to `DPI_LOGS_MAXLEN` (default ~200,000 entries). |
| `blocklist:updates` | Pub/Sub Channel | Published commands (`ADD IP <ip>`, `DEL IP <ip>`) consumed by engine and UI. |

## 3. Block Expiry & Repeat Offender Escalation
### TTL Ladder
- **ML Automated Blocks**: When the ML service enforces a block (`POST /api/rules` with role `ml-service`), the TTL is derived dynamically based on prior strikes within the strike window (`ML_STRIKE_WINDOW_S`, default 86400s = 24h):
  - Strike 1: 600 seconds (10 minutes)
  - Strike 2: 3600 seconds (1 hour)
  - Strike 3+: 86400 seconds (24 hours)
- **Manual Admin Blocks**: Administrators may specify a manual TTL (`ttl_s` between 60s and 2,592,000s / 30 days), or omit/set 0 for permanent blocks.
- **Strike Recording & Escalation**:
  - Every block created—whether initiated manually by an administrator or automatically by the ML service (`ml_auto`)—records a strike timestamp in `blocklist:strikes` for that IP.
  - Any subsequent block (manual or ML) within the 24-hour strike window (`ML_STRIKE_WINDOW_S`) advances the IP to the next tier on the escalation ladder.
- **Rule Extension**:
  - If ML re-blocks an already-blocked IP, expiry is extended to `max(existing, new)` and audited as `extend`.
  - If an admin updates a rule, the new TTL replaces the previous expiry and is audited as `extend`.

### ML Service Cooldowns & Re-blocking Interaction
The ML service cleanly decouples alert dispatch rate-limiting from auto-mitigation enforcement:
- **Telegram Alert Cooldown (`ML_ALERT_COOLDOWN_S`, default 600s)**:
  - Throttles external Telegram alert dispatch to at most once every 10 minutes per source IP to prevent notification spam.
- **Mitigation Debounce Cooldown (`ML_MITIGATION_COOLDOWN_S`, default 10s)**:
  - Throttles HTTP calls to `POST /api/rules` per source IP to at most once every 10 seconds.
  - This prevents flood traffic from bombarding the middleware with redundant block requests while an attack is active.
  - Because active blocks are synced into Redis `blocklist:ips`, the ML service skips already-blocked IPs entirely during scoring.
  - When a temporary block expires, the IP leaves `blocklist:ips`. Because `ML_MITIGATION_COOLDOWN_S` (10s) is far shorter than the 600s block TTL, an attacker returning after expiry is immediately re-blocked on the next evaluation interval, triggering the next strike on the escalation ladder.
  - **Allowlist Conflict Debounce (HTTP 409)**: If the middleware rejects a block because the target IP is allowlisted (`409 Conflict`), the ML service records the attempt in `mitigated_cooldowns` so the 10s debounce applies, preventing continuous 409 rejection logging while logging/publishing verdicts with `mitigated=false`.

### Expiry Sweeper
- The middleware runs a background sweeper every `BLOCK_SWEEP_INTERVAL_MS` (default 5000 ms) using `ZRANGEBYSCORE blocklist:expiry -inf <now>`.
- Expired IPs are atomically removed from `blocklist:ips`, `blocklist:meta`, and `blocklist:expiry`, published to `blocklist:updates DEL IP <ip>`, and audited as action `expire`.
- **Fault Tolerance**: If the middleware is down when a block reaches expiry, the middleware executes a startup sweep on its next initialization, immediately evicting any blocks that expired during downtime.

## 4. Allowlist Protection
- CIDR-aware allowlisting supports individual IPv4 addresses and subnets from `/0` to `/32` (e.g. `10.10.0.1/32`, `192.0.2.0/29`).
- Adding an allowlist entry immediately sweeps active blocks and unblocks any matching IP address.
- Attempts to block an allowlisted address return `409 Conflict` (`{ error: "IP is allowlisted" }`) and log a `block_rejected` event in `audit:log`.

## 5. Role Enforcement & Endpoint Access
Role-based authorization is enforced on all middleware routes via `requireRole`:
- `admin`: Full administrative control across the dashboard, manual rules, allowlist, audit trail, packet capture controls, and reports.
- `ml-service`: Restricted exclusively to `POST /api/rules` for `type: "ip"` and `POST /api/auth/login`. All other routes (`DELETE /api/rules`, `/api/capture/*`, `/api/stats/*`, etc.) return `403 Forbidden`.

## 6. Audit Trail (`audit:log`)
Every policy decision is recorded to Redis stream `audit:log` with fields:
- `ts`: ISO-8601 timestamp
- `actor`: Username or service account
- `role`: `admin`, `ml-service`, or `system`
- `action`: `block`, `extend`, `unblock`, `expire`, `block_rejected`, `allowlist_add`, `allowlist_remove`
- `target`: IP address or CIDR entry
- `source`: `manual`, `ml_auto`, or `system`
- `reason`: Attribution or justification tag
- `ttl_s`: Active TTL in seconds (or empty if permanent)
- `expires_at`: ISO timestamp of expiration
- `result`: Outcome (`blocked`, `extended`, `unblocked`, `expired`, `rejected`, `added`, `removed`)
- `detail`: Context details or rejection diagnostic

The audit trail is viewable live in the console under the Blocklist & Security Audit Trail panel and accessible via `GET /api/audit?limit=200`.


# AegisDPI — Security Architecture & Hardening Controls

This document details the security controls, policies, and default configurations implemented across the AegisDPI middleware, dashboard, and service boundary.

---

## 1. Role-Based Access Control (RBAC)

AegisDPI enforces strict role separation using JSON Web Tokens (JWT) signed with `JWT_SECRET` (HS256).

| Role | Permitted Actions | Prohibited Actions | Default |
|---|---|---|---|
| `admin` | Full management access: read/write firewall rules, manage allowlist, inspect audit logs, capture start/stop, view stats/anomalies/reports, connect to Socket.io real-time feed. | None. | Human operator account authenticated via `/api/auth/login`. |
| `ml-service` | Restricted exclusively to `POST /api/rules` (enforcing automated `ml_auto` blocks) and `/api/auth/login`. | Disallowed from `DELETE /api/rules`, `/api/capture/*`, `/api/audit/*`, `/api/allowlist/*`, and Socket.io WebSocket connections. | Service account for ML anomaly detector daemon. |

- **HTTP Enforcement**: Enforced by the `requireRole('admin')` middleware on sensitive Express endpoints. Unauthorized roles receive `403 Forbidden` (`{ "error": "Forbidden for role <role>" }`).
- **WebSocket Enforcement**: The Socket.io connection handshake verifies the JWT token and enforces `socket.user.role === 'admin'`. Non-admin roles (e.g. `ml-service`) are rejected with `Forbidden for role <role>`.

---

## 2. Input Validation

All inputs crossing network or service boundaries are strictly validated before processing or persisting to Redis:

- **IPv4 Address Validation**: `isValidIPv4()` verifies strict dotted-quad notation (`0.0.0.0` to `255.255.255.255`). Trailing/leading whitespace, non-numeric characters, IPv6 addresses, and octets with leading zeros (e.g. `010.1.1.1`, which some parsers misinterpret as octal) are rejected.
- **CIDR Subnet Validation**: `parseCidr()` validates CIDR prefixes from `/0` to `/32` and normalizes network addresses using bitwise masking.
- **TTL Validation**: `validateManualTtl()` validates manual block durations as integers between 60 seconds (1 minute) and 2,592,000 seconds (30 days), or 0 / omitted for permanent blocks.
- **Default Behavior**: Invalid inputs return `400 Bad Request` with an explicit diagnostic message and do not reach storage or engine subsystems.

---

## 3. Allowlist Protection

To prevent self-lockouts and protect management, monitoring, and gateway infrastructure:

- **Storage**: Stored in Redis hash `allowlist:entries`.
- **CIDR-Aware Matching**: Evaluates IP addresses against single IPs and CIDR ranges (`/0` through `/32`) via `isAllowlisted()`.
- **Enforcement**:
  - Any block attempt against an allowlisted IP (manual or ML) is rejected with `409 Conflict` (`{ "error": "IP is allowlisted" }`) and recorded to `audit:log` with action `block_rejected`.
  - Adding an entry to the allowlist immediately triggers a sweep of active blocks and evicts any currently blocked IP that matches the new entry.
- **Default Seed**: Host lab interface `10.10.0.1/32` is pre-seeded on lab startup.

---

## 4. Persistent Security Audit Log

All state mutations and security-relevant decisions are committed to an append-only Redis stream:

- **Stream Key**: `audit:log` capped at ~10,000 entries using `MAXLEN ~ 10000`.
- **Logged Events**: `block`, `extend`, `unblock`, `expire`, `block_rejected`, `allowlist_add`, `allowlist_remove`.
- **Fields**: `ts` (ISO-8601), `actor`, `role`, `action`, `target`, `source`, `reason`, `ttl_s`, `expires_at`, `result`, `detail`.
- **Default**: Active for all administrative and ML mitigation operations; stream viewable in the console UI and via `GET /api/audit`.

---

## 5. Cross-Origin Resource Sharing (CORS)

Cross-origin access is controlled across both Express HTTP endpoints and Socket.io WebSocket connections:

- **Environment Variable**: `CORS_ORIGINS` (comma-separated list of allowed origins).
- **Default Value**: `http://localhost:5173,http://127.0.0.1:5173,http://localhost:4000,http://127.0.0.1:4000`
- **Origin Handling**:
  - Requests **without** an `Origin` header (e.g. `curl`, CLI tools, internal backend calls from `ml-service`) are permitted.
  - Allowed origins receive appropriate `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true` headers.
  - Disallowed origins receive **no** CORS headers, causing browser clients to reject the response.
  - Distinct rejected origins are logged once to the server console (`[CORS] Rejected disallowed origin: <origin>`) to maintain observability without log flooding.

---

## 6. Socket.io Handshake & Role Restriction

Real-time telemetry and state updates are delivered over Socket.io:

- **Handshake Authentication**: Requires a valid JWT token passed in `socket.handshake.auth.token` or the `Authorization: Bearer <token>` header.
- **Role Requirement**: Requires `decoded.role === 'admin'`.
- **Rejection**: Clients without a token fail with `Authentication error: No token provided`. Clients presenting non-admin tokens (e.g. `ml-service`) fail with `Forbidden for role <role>`.
- **Default**: Only human admin console sessions can establish WebSocket subscriptions. The ML service does not use Socket.io.

---

## 7. HTTP Security Headers & Content Security Policy (CSP)

Implemented in `middleware/middleware/security_headers.js` without third-party dependencies:

### Universal Security Headers (All Responses)
- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
- `X-Frame-Options: DENY`: Prevents embedding the application in frames/iframes to protect against clickjacking.
- `Referrer-Policy: no-referrer`: Omits referrer headers to prevent leaking sensitive query strings or internal paths.
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`: Disables high-risk browser device APIs.
- `Cross-Origin-Opener-Policy: same-origin`: Isolates the browsing context from cross-origin documents.

### Content Security Policy (CSP)
Applied **strictly to static dashboard responses** (omitted from `/api/*` REST routes):

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

- **Origin Rationales**:
  - `https://fonts.googleapis.com`: Loads Google Fonts stylesheets defined in `frontend/index.html`.
  - `https://fonts.gstatic.com`: Downloads web font assets referenced by Google Fonts stylesheets.
  - `style-src 'unsafe-inline'`: Required for dynamic inline styles generated by React components (e.g. SVG gauge bars, progress widths, protocol indicator colors).
  - `script-src 'self'`: Only bundles served by the local host; `'unsafe-eval'` is strictly disallowed.
  - `connect-src 'self' ws: wss:`: Authorizes REST API requests and Socket.io WebSocket connections back to the host.
  - `object-src 'none'`: Disallows legacy Flash/Java plugin execution.
  - `frame-ancestors 'none'`: Modern standard complement to `X-Frame-Options: DENY`.

---

## 8. Rate Limiting

In-memory sliding window rate limiters protect against brute force and resource exhaustion without external dependencies:

| Limiter | Target | Window | Limit / Default | Behavior on Exceeded |
|---|---|---|---|---|
| General API | `/api/*` | 60 seconds (sliding) | 600 req/min (configurable via `API_RATE_LIMIT_PER_MIN`) | HTTP 429 `{ "error": "Too many requests - rate limit exceeded" }` |
| Login Brute-Force | `/api/auth/login` | 60 seconds (sliding) | 5 failed attempts per IP | HTTP 429 `{ "error": "Too many failed attempts - wait 60 seconds" }` |

- **Design**: Implemented as a factory (`createRateLimiter`) accepting a configurable clock function (`now`) to enable deterministic unit testing with fake timers.
- **Client IP Resolution & Anti-Spoofing (`TRUST_PROXY`)**:
  - Implemented via a unified resolver in `middleware/middleware/client_ip.js` shared by both the general API limiter and the login brute-force limiter.
  - **Default (`TRUST_PROXY=false`)**: Resolves client IP strictly from `req.socket.remoteAddress`. Any incoming `X-Forwarded-For` header is completely ignored. This prevents attackers from rotating arbitrary spoofed `X-Forwarded-For` values to bypass rate limits when connecting directly to the middleware without a reverse proxy.
  - **Reverse Proxy Mode (`TRUST_PROXY=true`)**: Enabled only when operating behind a reverse proxy you control (e.g. the Phase 7 TLS proxy). Resolves client IP from the left-most entry of the `X-Forwarded-For` header.
  - **Normalisation**: Automatically normalises IPv6-mapped IPv4 addresses (`::ffff:x.x.x.x` -> `x.x.x.x`) and IPv6 loopback addresses (`::1` -> `127.0.0.1`).

---

## 9. Startup Secret & Configuration Checks

When `server.js` boots, it validates all critical security parameters before binding ports or connecting to Redis:

1. **`JWT_SECRET`**:
   - Must be present.
   - Must be at least 32 characters long.
   - Must not match the default `.env.example` placeholder (`replace_with_a_secure_jwt_secret_key`).
   - *Failure*: Terminates process immediately (`process.exit(1)`).
2. **`REDIS_URL`**:
   - Must be present and valid URL.
   - Must contain a password (e.g. `redis://:password@127.0.0.1:6379`).
   - *Failure*: Terminates process immediately (`process.exit(1)`).
3. **`ADMIN_PASSWORD_HASH`**:
   - Checked at boot.
   - *Failure*: Logs a console warning (`[SECURITY WARNING] ADMIN_PASSWORD_HASH is unset...`), allowing service-only operation if intentionally running headless.

---

## 10. Localhost & Interface Binding

- **Frontend Dev Server (`frontend/vite.config.ts`)**:
  - Bound strictly to loopback: `server.host = '127.0.0.1'` (replaces `host: true` to prevent unintended LAN exposure).
  - Dev server port: `5173`.
- **Middleware API & WebSocket (`middleware/server.js`)**:
  - Default bind host: `127.0.0.1` (`HOST` env var).
  - Port: `4000` (`PORT` env var).
- **Redis Server**:
  - Bound to `127.0.0.1` (or isolated lab virtual network) requiring password authentication (`requirepass`).
- **File Permissions**:
  - Passwords and keys in `run/redis.pass` are stored with mode `600` (readable only by owner).
  - All real `.env` files are excluded from Git commits via `.gitignore`.

---

## 11. Engine Privileges (Capabilities vs Sudo)

The packet processing and filtering engine (`dpi_engine`) operates under the principle of least privilege:

### Comparison: Before vs. After

| Security Aspect | Before (Insecure / Overprivileged) | After (Hardened / Least Privilege) |
|---|---|---|
| **Execution Identity** | Executed as full `root` via passwordless `sudo`. | Executed as regular unprivileged user (`soham`). |
| **Privilege Mechanism** | Sudoers rule: `/etc/sudoers.d/aegis-engine` (`<user> ALL=(root) NOPASSWD: .../dpi_engine`). | Linux File Capabilities: `CAP_NET_RAW` + `CAP_NET_ADMIN` on the installed binary. |
| **Binary Location & Ownership** | `engine/build/dpi_engine` located in user-writable repo directory; owned by unprivileged user. | `/usr/local/sbin/aegis-dpi-engine` installed root-owned (`root:root`, mode `0755`); non-writable by non-root users. |
| **Library Loading (`RUNPATH`)** | Embedded `RUNPATH` pointing to user-writable build directory (`engine/build/_deps/redis-plus-plus-build`), loading shared `libredis++.so.1`. | Statically links `redis++_static`; `RPATH`/`RUNPATH` completely eliminated (`SKIP_BUILD_RPATH TRUE`); all dynamic libraries loaded strictly from `/usr/lib`. |
| **Firewall Enforcement** | Child process shell execution via `std::system("nft ...")`, invoking `/bin/sh`. | In-process C API via `libnftables` (`nft_ctx_new`, `nft_run_cmd_from_buffer`); zero shell or fork/exec invocation. |
| **Startup Verification** | Generic check expecting root. | Live mode verifies `CapEff` bits 12 (`CAP_NET_ADMIN`) and 13 (`CAP_NET_RAW`) in `/proc/self/status`; replay mode requires zero privileges. |
| **Middleware Process Spawning** | Node.js middleware spawned `sudo -n ENGINE_BIN ...`. | Node.js middleware checks `fs.statSync()` (uid 0, non-writable by group/other) and spawns `ENGINE_BIN` directly without sudo. |

### Threats Removed
1. **Arbitrary Code Execution as Root**: Previously, because the binary in `engine/build/dpi_engine` was writable by the standard user and permitted passwordless sudo execution with any arguments, any compromised user process or script could replace the binary or inject malicious code to gain instantaneous root privileges.
2. **Dynamic Library Hijacking (DLL Hijacking / Library Poisoning)**: Because `RUNPATH` pointed to a user-writable directory, an attacker could plant a malicious `libredis++.so.1` in the build folder and have it executed under root context when the engine started.
3. **Shell & Command Injection**: Moving from `std::system("nft ...")` to in-process `libnftables` removed `/bin/sh` from the execution path, eliminating shell injection hazards.
4. **Child Capability Loss**: Because Linux file capabilities are not inherited across fork/exec by unprivileged child processes without ambient capability setup, running `nft` in a child process previously forced the engine to run under full root. In-process `libnftables` executes netlink operations directly within the capability-empowered process.


# AegisDPI — Frontend Design Document

## 1. Stack

- Vite + React 18 + Tailwind CSS
- `socket.io-client` for live data
- `recharts` for time-series/throughput charts
- `react-simple-maps` (or Leaflet.js) for the threat map
- `react-window` for virtualized log tables (essential once you have thousands of log rows — don't render them all into the DOM)
- `zustand` (lightweight) or React Context for global state (live stats, rule list, auth) — avoid pulling in Redux for a project this size

## 2. Information Architecture (pages)

| Route          | Purpose                                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/login`       | Admin auth                                                                                                                                             |
| `/dashboard`   | Overview: live throughput, forwarded/dropped counters, top apps, recent alerts                                                                         |
| `/traffic`     | Live packet/flow feed (virtualized table), filterable by app/IP/verdict                                                                                |
| `/rules`       | CRUD for IP/domain/app block rules; shows which rules are currently active in Redis                                                                    |
| `/threats`     | Threat map + flagged-source list with JA3/threat-intel enrichment                                                                                      |
| `/ml-insights` | Recent anomaly verdicts from the ML service, with the feature values that triggered them (transparency matters for a viva — don't make it a black box) |
| `/logs`        | Historical log search (reads from Redis Streams / persisted store)                                                                                     |

## 3. Visual Direction — "SOC console," not "generic admin template"

The failure mode to avoid: a default Tailwind admin dashboard that looks like every tutorial. This is a security-operations tool — lean into that:

- **Dark base theme** (a real SOC room is dark so screens are legible) — deep charcoal/near-black background, not pure black; one accent color for "safe/forwarded" (a controlled green/teal) and one for "blocked/threat" (a controlled red/amber) — used sparingly, not everywhere.
- **Monospace font for IPs, ports, hashes, JA3 strings** (e.g. `JetBrains Mono` or `IBM Plex Mono`) — signals "this is real technical data," and it's genuinely more legible for this content.
- **Live-feels-live:** new rows in the traffic table should visibly animate in (subtle slide/fade), not just silently appear — this is what makes a demo _read_ as real-time to a panel rather than a static screenshot.
- Avoid heavy card-shadow "SaaS dashboard" aesthetics; prefer flat panels with thin 1px borders — reads more like an ops tool, less like a marketing site.

## 4. Key Components

- `LiveCounterBar` — forwarded/dropped/total, updating via socket events, with a small trend sparkline.
- `TrafficTable` (virtualized) — columns: time, src, dst, app/SNI, verdict, JA3 (if available).
- `RuleForm` — add rule by type (IP/CIDR/domain/app), with client-side validation matching the backend's validation contract (same regex, don't diverge).
- `ThreatMap` — markers sized/colored by severity, tooltip with IP, country/city (from ip-api.com via backend), reason flagged.
- `AnomalyCard` — shows the ML verdict, the underlying feature values (pps, unique ports, SYN ratio) and the auto-mitigation action taken, if any.
- `ConnectionStatusBadge` — visibly shows Socket.io connection state (connected/reconnecting) — small detail, but it proves to a panel the "live" data is actually a live connection, not a timer-based mock.

## 5. Real-Time Data Handling

- Subscribe to distinct Socket.io namespaces/events: `stats:update`, `log:new`, `rule:changed`, `threat:flagged`, `ml:verdict` — don't multiplex everything onto one generic `message` event, it becomes unmanageable fast.
- **Batch UI updates:** if events arrive faster than ~10/sec, buffer and flush to the table every 200–300ms instead of a React re-render per socket message — this is what actually keeps the UI smooth under real load and is worth mentioning in your report as a deliberate performance decision.

## 6. Auth Handling

- JWT held in memory (React state), not `localStorage` (XSS-exfiltration risk) — acceptable for a project this scope; refresh via httpOnly cookie if you want to go further.
- Route guarding: unauthenticated users redirected to `/login`; token attached via `Authorization` header on REST calls and passed during Socket.io handshake (`auth: { token }`).

## 7. What to explicitly avoid

- Don't build a marketing landing page — this is an internal admin tool, go straight to `/login` → `/dashboard`.
- Don't over-invest in animation/3D map effects before the MVP data pipeline (F1–F7 in `03_FEATURE_SPEC.md`) is fully working end-to-end. A good-looking dashboard connected to fake/static data is worse for your grade than a plain one connected to real live data.

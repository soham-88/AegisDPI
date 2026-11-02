# AegisDPI — Security Design Document

This document covers two different things and they must not be confused in your synopsis or viva: (A) the security **features** the engine provides (blocking, tarpitting, threat intel), and (B) the security **of the system itself** (how AegisDPI avoids becoming the vulnerability). Panels often probe (B) specifically because it's the part students skip.

## 1. Ethical & Legal Scoping (state this up front in your synopsis)

- All enforcement demos (blocking, tarpitting, anomaly response) run against **traffic the student controls**: replayed `.pcap` files, or live traffic between VMs/network namespaces the student owns, simulating an "attacker" and a "victim/admin network."
- The project does **not** decrypt TLS payloads. It only reads plaintext metadata that is, by design, sent unencrypted before the TLS handshake completes (SNI) or observable at the network layer (JA3 fingerprint of the handshake itself).
- Threat-intel lookups (VirusTotal/AbuseIPDB) query only IPs observed in the student's own lab traffic — not used to build a surveillance tool against third parties.

## 2. Threat Model — Threats _to_ AegisDPI Itself

| #   | Threat                                                                                              | Attack Vector                                                                                                              | Mitigation                                                                                                                                                                         |
| --- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1  | Command injection into `nft`/`iptables` calls                                                       | Malicious/malformed rule value (e.g. an IP field containing shell metacharacters) submitted via API or crafted packet data | Strict allow-list regex validation for every value before it reaches any shell-out call; prefer `libnftnl`/`libmnl` bindings over shelling out entirely where feasible             |
| T2  | Unauthenticated access to the rule API                                                              | Dashboard/API exposed without auth                                                                                         | JWT-protected routes; Redis bound to localhost/internal Docker network with `requirepass`                                                                                          |
| T3  | Malformed/adversarial packets crash the C++ engine (DoS on the DPI engine itself)                   | Crafted TLS ClientHello with out-of-bounds length fields                                                                   | Bounds-check every offset in the manual parser; wrap per-packet processing in try/catch equivalent (no unguarded pointer arithmetic); fuzz-test the SNI/JA3 parser before the demo |
| T4  | Redis exposed without auth becomes a pivot point (attacker rewrites blocklist / reads all logs)     | Default Redis config, no password, bound to `0.0.0.0`                                                                      | `requirepass`, bind to internal network only, never expose Redis port outside Docker network                                                                                       |
| T5  | Engine running as root for raw-socket access is over-privileged                                     | Full root needed only for `AF_PACKET`/raw socket ops                                                                       | Use Linux capabilities (`setcap cap_net_raw,cap_net_admin+eip ./aegis_engine`) instead of running the whole binary as root                                                         |
| T6  | Flow table / memory exhaustion (unbounded growth = self-inflicted DoS)                              | No eviction of idle flows under sustained traffic                                                                          | TTL-based eviction sweep (see TRD §2.4)                                                                                                                                            |
| T7  | Secrets (Telegram bot token, VirusTotal/AbuseIPDB API keys) committed to git or exposed to frontend | Hardcoded keys, `.env` committed, keys sent to browser                                                                     | All secrets in backend-only `.env`, `.gitignore`'d; frontend never receives raw third-party API keys, only proxies through Node                                                    |
| T8  | Tarpit/enforcement logic accidentally targets a real, unintended host                               | Misconfigured lab network, bug in scoping check                                                                            | Enforcer only acts within a configured CIDR allow-list for the lab topology; hard-fail (log + skip) if the target IP is outside it                                                 |

## 3. Security Features Provided by the Engine (Product-Facing)

- **SNI/domain/IP/app-based blocking** — described fully in TRD.
- **JA3 fingerprinting** — flags non-standard TLS clients (bots, malware C2 frameworks often have distinctive JA3s vs. real browsers). Framed correctly: this is a _heuristic signal_, not a guaranteed malware detector — false positives happen (e.g. unusual-but-legitimate clients), state this limitation explicitly.
- **ML-based volumetric anomaly detection** — heuristic, not signature-based; will not catch a slow, low-and-slow attack designed to stay under its window thresholds. State this as a known limitation.
- **Threat intel enrichment** — best-effort; a "not flagged by VirusTotal" result does not mean an IP is safe, only that it hasn't been reported yet. Say this precisely in the report to avoid overclaiming.

## 4. Secure Development Practices Applied

- Input validation at every trust boundary (API → Redis → C++ engine → shell-out to `nft`).
- Principle of least privilege for every process (capabilities not full root; Redis internal-only; JWT-scoped API access).
- Fail-closed vs fail-open decision, stated explicitly: **if the engine cannot reach Redis to check the current blocklist, does it fail open (forward everything) or fail closed (drop everything)?** Recommendation for this project: **fail open with a loud log/alert**, since fail-closed on a real network would look like the whole project just breaks connectivity — but document this trade-off, don't just default silently.
- Dependency hygiene: pin versions in `package.json`/`requirements.txt`/`CMakeLists.txt`; no wildcard versions for the final submission.

## 5. What NOT to Claim in the Synopsis/Report (avoid overclaiming — this protects you in the viva)

- Don't say "detects all zero-day threats" — say "enriches unknown IPs against known threat-intelligence databases; does not guarantee detection of previously unseen threats."
- Don't say "decrypts HTTPS traffic" — say "identifies destination service via plaintext TLS handshake metadata (SNI), without decrypting payload."
- Don't say "prevents all DDoS attacks" — say "detects volumetric anomalies matching the trained model's feature patterns and can auto-mitigate the specific flagged source."

# AegisDPI — Viva / Presentation Prep

Your stated worry was that your mam will ask "what is actually happening in the project" and it needs to not look like nothing is really working. The single best defense against that is exactly what the Testing plan builds toward: **every claim maps to a live, reproducible action you can trigger on the spot.** This doc is your rehearsal script.

## 1. The 5-Minute Live Demo Script (memorize this sequence)

1. Show the dashboard with live traffic flowing (from `tcpreplay` or your lab topology) — narrate: "this is the Node middleware relaying live events from the C++ engine over Socket.io, sourced from Redis Streams."
2. Add a block rule through the UI for a domain/IP currently generating traffic — narrate: "this write goes to Redis; the C++ engine picks it up on its next poll cycle."
3. Show, from a terminal (namespace `ns_attacker`), that the connection to that host now fails — this is your proof point. Say explicitly: "this is not just a log entry — the underlying connection is actually broken, enforced via an nftables set the engine updates dynamically."
4. Trigger the synthetic flood script — narrate while it runs: "this is generating a self-contained SYN flood inside my lab network namespace, not against any external host."
5. Show the ML verdict appear, the auto-block happen, and (if wired) the Telegram alert land on your phone.
6. Close with the threat map / JA3 fingerprint view as the "and there's more" beat.

## 2. Hard Questions to Expect — and How to Answer Them

**"Isn't this just Wireshark with extra steps?"**
No — Wireshark is passive capture and display only. This engine makes an active drop/forward decision per flow and enforces it at the kernel level via nftables, which you can demonstrate live by breaking a real connection.

**"How is this different from an existing firewall/iptables rule?"**
A firewall rule needs a human to already know the IP/domain to block. This engine _discovers_ the destination in real time from encrypted HTTPS traffic (via SNI) and can _automatically_ decide to block based on behavior (ML anomaly detection), not just a static pre-written rule.

**"You said HTTPS is encrypted — how are you inspecting it?"**
The TLS handshake's ClientHello message includes the destination hostname (SNI) in plaintext by design, before encryption keys are established — that's how the client tells the server which certificate to present. We read that one field; we do not decrypt the actual payload/data after the handshake.

**"What's your dataset for the ML model?"**
We generate our own labeled traffic (normal and several attack shapes) using `scapy` in a controlled lab topology, since the live pipeline doesn't rely on an external dataset. [If you cross-validated against a public benchmark, mention it here as additional validation.]

**"What's your false positive rate?"**
State the actual number you measured in Phase 5 testing (`07_TESTING_QA_PLAN.md`) — never guess this live, know it cold.

**"Does this work on real internet traffic, not just your lab?"**
The detection and parsing logic works on any TLS/TCP traffic. For the demo we deliberately scope enforcement actions (blocking, tarpitting) to a lab topology we control, both for safety/ethics and because that gives a reproducible, verifiable demo rather than relying on unpredictable live internet conditions.

**"Why C++ for the engine and not just Python/Node for everything?"**
Byte-level packet parsing at high packet rates needs to avoid interpreter/GC overhead — C++ gives predictable, low-latency processing per packet, which is why production DPI/networking tools (Snort, Suricata's core, etc.) are written in C/C++ as well.

**"Is your multi-threading actually doing anything, or is it just for show?"**
Show the per-thread stats output from Phase 1 testing — packets distributed across multiple Fast Path threads, not all serialized onto one. That's your evidence.

**"What happens if your engine crashes mid-demo?"**
Point to the fuzz-testing result from Phase 7 — malformed packets are caught and skipped, not allowed to crash the process. If you're honest that it's not bulletproof against everything, say so; overclaiming "it never crashes" invites someone to try to break it live.

**"Could this be misused to spy on people?"**
It reads a routing/destination signal already visible to network operators by design (SNI), not private payload content. Any deployment of a tool like this — same as an enterprise firewall — should be on networks the operator has the right to administer, with users informed per applicable policy. That's a deployment/governance question, not something the tool itself decides.

## 3. Things to Have Physically Ready on Exam Day

- A recorded screen capture of the full demo sequence (Section 1) as a fallback if live networking misbehaves under exam-room conditions.
- The false-positive number and throughput number, written down, not memorized loosely.
- This docs folder itself, open and browsable — a panel is often visibly reassured by seeing a PRD/TRD/security doc exist, even if they don't read every line.

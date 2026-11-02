# AegisDPI — Testing & QA Plan (Phase by Phase)

Rule for the whole project: **you don't move to the next phase until the current phase's tests pass and you can reproduce the demo on demand.** This document tells you, for every phase, what to type, in which terminal, and exactly what output means "this worked."

Recommended terminal layout throughout: use multiple terminal panes/tabs in Antigravity (or `tmux`) — one per running service. Never run everything crammed into one shell; you need to watch multiple logs at once during integration testing.

---

## Phase 0 — Environment Validation (do this before writing any new code)

**Terminal 1:**

```bash
lsb_release -a                       # confirm Ubuntu version under WSL2
g++ --version                        # need C++17 support
cmake --version
sudo apt list --installed | grep libpcap
```

**Expected:** g++ ≥9 (C++17 support), cmake ≥3.10, `libpcap-dev` installed (`sudo apt install libpcap-dev` if not).

**Critical spike test — validate NFQUEUE availability before you design around it:**

```bash
lsmod | grep nfnetlink_queue
sudo modprobe nfnetlink_queue        # try to load it
lsmod | grep nfnetlink_queue         # check again
```

**Outcome A (module loads):** you can plan to use `NfqueueEnforcer` later (TRD §2.3) as a stretch goal.
**Outcome B (fails / "module not found"):** your WSL2 kernel doesn't have it compiled in. **Do not lose time fighting this.** Fall back to the `NftablesEnforcer` (set-based blocking) as your primary/only enforcement mechanism — it's fully sufficient for the project's requirements and doesn't need this module. Note this decision explicitly in your report as a deliberate architecture choice.

**Also test basic nftables availability (this you likely do need):**

```bash
sudo nft list ruleset
sudo nft add table inet aegis_test
sudo nft add set inet aegis_test test_blocklist { type ipv4_addr\; }
sudo nft add element inet aegis_test test_blocklist { 1.2.3.4 }
sudo nft list set inet aegis_test test_blocklist
sudo nft delete table inet aegis_test   # cleanup
```

**Expected:** each command runs without error, and the last `list set` shows `1.2.3.4` in the set. If any of this fails, resolve it now — this is load-bearing for F4 in the feature spec.

---

## Phase 1 — Offline Engine (F1, F2)

**Terminal 1 — build:**

```bash
cd ~/AegisDPI/engine
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

**Expected:** clean build, no warnings ideally (warnings are fine to note but shouldn't be ignored long-term — a professor skimming code sees them).

**Terminal 1 — run against the sample pcap:**

```bash
./dpi_engine ../test_dpi.pcap ../output.pcap --lbs 2 --fps 4
```

**Expected output to check for, specifically:**

- Total packets read == packets in input file (sanity: `capinfos test_dpi.pcap` if you have `tshark`/`capinfos` installed, compare counts).
- Thread stats show non-zero counts across **more than one** FP thread — if everything lands on FP0, your hashing/distribution is broken, fix before proceeding.
- At least a few SNI values correctly extracted and printed (spot-check 2–3 against `tshark -r test_dpi.pcap -Y tls.handshake.extensions_server_name`).

**Unit tests (add these now, don't defer):**

```bash
cd ~/AegisDPI/engine/build
ctest --output-on-failure         # if using GoogleTest via CMake
```

Minimum tests to have by end of Phase 1: 5-tuple hashing determinism, SNI extractor against a known-good ClientHello byte array, SNI extractor against a truncated/malformed input (must return "not found," must not crash).

**Phase 1 exit criteria:** offline pipeline reproducibly runs, thread distribution confirmed, ≥3 unit tests passing, no crash on malformed input.

---

## Phase 2 — Live Capture + Real Enforcement (F3, F4)

Set up a lab topology first — simplest version, two network namespaces:

```bash
sudo ip netns add ns_admin
sudo ip netns add ns_attacker
sudo ip link add veth_admin type veth peer name veth_attacker
sudo ip link set veth_admin netns ns_admin
sudo ip link set veth_attacker netns ns_attacker
sudo ip netns exec ns_admin ip addr add 10.10.0.1/24 dev veth_admin
sudo ip netns exec ns_attacker ip addr add 10.10.0.2/24 dev veth_attacker
sudo ip netns exec ns_admin ip link set veth_admin up
sudo ip netns exec ns_attacker ip link set veth_attacker up
```

**Terminal 2 — sanity check the link works before involving your engine at all:**

```bash
sudo ip netns exec ns_attacker ping -c 3 10.10.0.1
```

**Expected:** 3 successful replies. If this fails, fix networking before touching your C++ code — you'd otherwise be debugging two problems at once.

**Terminal 1 — run engine in live-capture mode on the admin side:**

```bash
sudo ip netns exec ns_admin ./dpi_engine --live --iface veth_admin
```

**Expected:** counters increase in real time as Terminal 2 generates traffic.

**Test real enforcement:**

```bash
# Terminal 3: add a block rule directly via redis-cli (before Node exists yet)
redis-cli SADD blocklist:ips 10.10.0.2

# Terminal 2: retry the ping
sudo ip netns exec ns_attacker ping -c 3 10.10.0.1
```

**Expected:** pings now fail/time out — this is the moment that proves "active blocking," not just logging. Screenshot/record this for your report; it's your strongest single piece of evidence against the "you're just watching traffic like Wireshark" objection.

**Phase 2 exit criteria:** live capture confirmed via counters increasing in real time; a rule added via `redis-cli` demonstrably breaks connectivity for the target within your poll interval.

---

## Phase 3 — Redis + Node Middleware (F5, F6)

**Terminal 1:** keep the C++ engine running from Phase 2.
**Terminal 2 — Redis:**

```bash
redis-server --requirepass <your_redis_password>   # dev only; real secret via .env for anything beyond localhost
redis-cli -a <your_redis_password> monitor          # watch every command hit Redis live — extremely useful while debugging
```

**Terminal 3 — Node:**

```bash
cd ~/AegisDPI/middleware
npm install
npm run dev
```

**Test the REST API:**

```bash
curl -X POST http://localhost:4000/api/rules \
  -H "Content-Type: application/json" \
  -d '{"type":"ip","value":"10.10.0.2"}'

curl http://localhost:4000/api/rules
```

**Expected:** 200/201 responses; the new rule appears both in the API response and in `redis-cli SMEMBERS blocklist:ips`.

**Test Socket.io relay (quick manual check without a frontend yet):**

```bash
npx wscat -c ws://localhost:4000/socket.io/?EIO=4\&transport=websocket
```

Then generate some traffic through the engine in Terminal 1's network and confirm events appear in the `wscat` session.

**Phase 3 exit criteria:** rule CRUD via curl reflects into Redis and gets picked up by the C++ engine within its poll window (verify with the Phase 2 ping test again, but triggered via `curl` this time, not `redis-cli` directly).

---

## Phase 4 — React Dashboard (F7)

**Terminal 4:**

```bash
cd ~/AegisDPI/frontend
npm install
npm run dev
```

**Manual test checklist (browser):**

- [ ] Login works, JWT stored, protected routes redirect when logged out
- [ ] Live traffic table shows new rows without a page refresh while Terminal 1's engine processes traffic
- [ ] Adding a rule through the UI results in the corresponding host failing to connect (repeat the Phase 2 ping test, triggered from the UI this time — this is your full end-to-end demo)
- [ ] Removing a rule restores connectivity

**Phase 4 exit criteria:** the full MVP loop (UI click → Redis → engine enforcement → real connectivity change) works, is repeatable, and takes under ~2 seconds.

---

## Phase 5 — ML Service (S2, S3)

**Terminal 5:**

```bash
cd ~/AegisDPI/ml-service
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Visit `http://localhost:8000/docs` — FastAPI's auto-generated Swagger UI. This alone is a good live-demo artifact for a viva ("here's the interactive API spec, generated automatically").

**Generate a synthetic flood in the lab topology (Terminal 2, from the "attacker" namespace) — never against anything outside your own lab netns:**

```python
# flood_test.py — run with: sudo ip netns exec ns_attacker python3 flood_test.py
from scapy.all import IP, TCP, send
import time
target = "10.10.0.1"
start = time.time()
while time.time() - start < 5:
    send(IP(dst=target)/TCP(dport=80, flags="S"), verbose=0)
```

**Expected chain of events, watch across terminals:**

1. Terminal 1 (engine): packet counters spike.
2. Terminal 3 (Node, or `redis-cli monitor`): `ml:verdicts` receives an anomaly event.
3. `redis-cli SMEMBERS blocklist:ips`: attacker IP appears automatically, without you adding it.
4. Terminal 2: subsequent pings from the attacker namespace fail.
5. (If Phase 6 alerting is wired) your phone gets a Telegram notification.

**Also run a negative test — this matters as much as the positive one:**
Run 5 seconds of _normal-rate_ traffic through the same path and confirm it does **not** get flagged. A model that flags everything isn't detecting anomalies, it's just always triggering — a panel may ask you directly "what's your false positive rate," so know this number.

**Phase 5 exit criteria:** synthetic flood reliably triggers detection + auto-block within a few seconds; normal traffic run does not trigger a false positive; you can state your model's approximate false-positive rate on held-out normal traffic.

---

## Phase 6 — Threat Map, Threat Intel, Telegram (S4, S5, S6)

Test each integration in isolation before wiring it into the full flow:

```bash
# ip-api.com lookup
curl "http://ip-api.com/json/8.8.8.8"

# AbuseIPDB (needs your API key in .env)
curl -G https://api.abuseipdb.com/api/v2/check \
  -d ipAddress=8.8.8.8 -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json"

# Telegram bot — send yourself a test message
curl -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" \
  -d chat_id=$TELEGRAM_CHAT_ID -d text="AegisDPI test alert"
```

**Expected:** each returns a valid JSON response / you receive the Telegram message on your phone, **before** you wire these into the auto-mitigation flow. Debugging a broken API key inside a five-service integration chain is much harder than catching it here.

**Phase 6 exit criteria:** repeat the Phase 5 flood test end-to-end; confirm map marker appears, threat-intel data shown in dashboard, Telegram alert received — all from one trigger.

---

## Phase 7 — Tarpitting, Load Testing, Fuzzing (S7 + hardening)

**Tarpit test (lab-scoped only):**

```bash
sudo ip netns exec ns_attacker curl -v http://10.10.0.1:80
```

**Expected:** connection visibly hangs (window size 0 response) rather than completing or cleanly refusing — capture this with `tcpdump`/Wireshark for your report as evidence of the actual TCP-level mechanism, not just a claim.

**Load test (confirms your throughput NFR from the TRD):**

```bash
sudo apt install tcpreplay
tcpreplay --topspeed -i veth_admin large_test_capture.pcap
```

Watch Terminal 1's engine stats for packets/sec and confirm no dropped/corrupted packets in the pipeline itself (distinct from packets your rules intentionally dropped).

**Fuzz test the parser (confirms your T3 mitigation in the security doc):**

```bash
pip install scapy
python3 -c "
from scapy.all import *
import random
pkts = [IP()/TCP()/Raw(bytes(random.getrandbits(8) for _ in range(random.randint(0,200)))) for _ in range(2000)]
wrpcap('fuzz.pcap', pkts)
"
./dpi_engine fuzz.pcap fuzz_out.pcap
```

**Expected:** engine processes all 2000 malformed packets without crashing (check exit code `$?` == 0 and process didn't segfault). This is one of the more convincing things you can show a professor — that you deliberately tried to break your own parser.

**Phase 7 exit criteria:** tarpit behavior confirmed on the wire; throughput target met; engine survives a fuzz run with zero crashes.

---

## Final Pre-Viva Checklist

- [ ] Every feature in `03_FEATURE_SPEC.md`'s MVP table has a live demo you can run in under 2 minutes
- [ ] You can explain, for every claim, _exactly_ which mechanism makes it true (see `04_SECURITY_DESIGN.md` §5 — "what not to claim")
- [ ] You have screenshots/recordings as a fallback if live demo networking fails on exam day
- [ ] `09_VIVA_PREP.md` questions have been rehearsed out loud at least once

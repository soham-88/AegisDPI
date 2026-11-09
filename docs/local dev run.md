# AegisDPI — Local Run Guide

This guide describes how to run and demonstrate the complete AegisDPI stack locally on Linux (Ubuntu 22.04+, Ubuntu 24.04, or WSL2) using the provided lifecycle scripts and capability-hardened engine.

---

## 1. Services & Architecture Overview

All services run locally on loopback addresses with dedicated roles and security boundaries:

| Service | Execution Mechanism | Default Endpoint / Port | Description |
|---|---|---|---|
| **Redis** | `redis-server` (managed by `aegis.sh`) | `127.0.0.1:6379` | In-memory message bus (`dpi:logs`, `dpi:stats`, `blocklist:*`, `audit:log`). Requires password. |
| **C++ Engine** | `/usr/local/sbin/aegis-dpi-engine` | `veth_lab` / Replay | Multi-threaded capture, classification, and in-process `libnftables` enforcement. |
| **Node.js Middleware** | Node 22 (`server.js`) | `http://127.0.0.1:4000` | REST API, Socket.io real-time streaming, RBAC auth, static frontend host. |
| **ML Anomaly Service** | FastAPI / Python 3.14 (`uvicorn`) | `http://127.0.0.1:8000` | Real-time sliding window anomaly detection (IsolationForest + EnvelopeGuard). |
| **Frontend Console** | Vite production bundle or dev server | `http://127.0.0.1:4000` / `:5173` | Dark-mode SOC dashboard with real-time charts, log inspection, and rule management. |

---

## 2. One-Time Setup

### Step A: Prerequisites & Automated Setup

Run the automated setup script to install dependencies, compile the engine, set up Python and Node.js environments, and generate secure environment files:

```bash
git clone https://github.com/soham-88/AegisDPI.git
cd AegisDPI

# Run automated setup
./scripts/setup.sh
```

`setup.sh` performs the following idempotently:
1. Installs system packages via `apt` (`g++`, `cmake`, `libpcap-dev`, `libhiredis-dev`, `libnftables-dev`, `redis-server`, `python3-venv`, `nodejs`, `npm`, `ethtool`, etc.).
2. Verifies Node.js version ($\ge 18$, Node 22 recommended).
3. Stops and masks any default system-wide `redis-server` service so `aegis.sh` manages isolated Redis instances.
4. Compiles the C++ engine in `Release` mode (`engine/build`) and runs unit tests via `ctest`.
5. Installs middleware and frontend npm dependencies (`npm ci`) and builds the frontend production bundle.
6. Sets up the Python virtual environment in `ml-service/venv` and installs `requirements.txt`.
7. Prompts for admin credentials and generates cryptographically secure, randomized secrets (`JWT_SECRET`, Redis password, service account passwords) in `middleware/.env` and `ml-service/.env`.

### Step B: Install the Hardened Engine Binary (Capabilities)

AegisDPI does **not** run the engine under root or `sudo`. Instead, install the binary to `/usr/local/sbin` with minimal Linux file capabilities (`CAP_NET_RAW` and `CAP_NET_ADMIN`):

```bash
# Builds, verifies no RPATH/RUNPATH, installs root-owned binary, sets capabilities,
# and removes any legacy sudoers entries:
./scripts/install_engine.sh --remove-sudoers
```

This ensures:
- The binary is root-owned (`root:root`, mode `0755`) at `/usr/local/sbin/aegis-dpi-engine` to prevent tampering.
- Only raw packet capture (`CAP_NET_RAW`) and firewall table modification (`CAP_NET_ADMIN`) are granted.
- In-process `libnftables` operates without invoking `/bin/sh` or child shells.
- Zero sudo rules are required in `/etc/sudoers.d/`.

---

## 3. Starting the Stack

Use `scripts/aegis.sh` to manage the background services:

```bash
# 1. Start virtual network lab (creates ns_attacker and veth_lab with disabled offloads)
sudo ./scripts/lab.sh up

# 2. Start core services (Redis, ML Service, and Middleware)
./scripts/aegis.sh start
```

`aegis.sh start` automatically:
- Reads the generated Redis password from `middleware/.env`.
- Spawns Redis on `127.0.0.1:6379` with `requirepass`.
- Starts the ML service daemon on `http://127.0.0.1:8000`.
- Starts the Node middleware on `http://127.0.0.1:4000`.
- Waits for all three ports to respond healthy.

Open your browser at **`http://127.0.0.1:4000`** and log in using the admin credentials chosen during setup.

---

## 4. Starting Traffic Inspection

### Live Network Capture (Interactive Demo)

1. On the dashboard header, click **Start Capture** and select interface `veth_lab`.
2. Alternatively, launch the engine directly from the command line as an unprivileged user:
   ```bash
   PASS=$(grep -E '^REDIS_URL=' middleware/.env | sed -E 's/.*redis:\/\/:([^@]+)@.*/\1/')
   /usr/local/sbin/aegis-dpi-engine --live veth_lab --lbs 2 --fps 4 --redis-host 127.0.0.1 --redis-password "${PASS}"
   ```
3. Generate traffic or attack floods from the attacker network namespace (`ns_attacker`):
   ```bash
   # Normal ping check (0% drop)
   sudo ip netns exec ns_attacker ping -c 3 10.10.0.1

   # ICMP flood attack (triggers ML envelope guard / auto-mitigation)
   sudo ip netns exec ns_attacker hping3 --icmp -i u1000 -I veth_attacker -a 10.10.0.2 10.10.0.1

   # TCP SYN flood attack
   sudo ip netns exec ns_attacker hping3 -S -p 80 --flood 10.10.0.1

   # Or run built-in lab attack test
   ./scripts/lab.sh attack 3000
   ```
4. Observe the dashboard:
   - Packet logs stream into the console in real time.
   - The ML service evaluates traffic in 5-second windows; detected attacks produce `ANOMALOUS` alerts.
   - The auto-mitigation pipeline blocks the attacker's source IP via `libnftables`.
   - Further traffic from the attacker drops immediately at the kernel level (100% loss).

### Offline Replay Mode (Deterministic Benchmark)

To demonstrate the engine without live virtual interfaces:
```bash
engine/build/dpi_engine --replay engine/test_dpi.pcap --lbs 2 --fps 2 --redis-host 127.0.0.254
```
This reads the bundled 77-packet capture and prints detailed throughput, thread dispatch, and classification statistics.

---

## 5. Verification & Service Management

Check service status at any time:
```bash
./scripts/aegis.sh status
```

Inspect live background logs:
```bash
./scripts/aegis.sh logs middleware
./scripts/aegis.sh logs ml
```

Run end-to-end smoke tests against running services:
```bash
# Verify ML service status and scoring vectors
./scripts/ml_smoke.sh

# Verify role enforcement, block expiry, and audit trail
./scripts/phase4_smoke.sh
```

---

## 6. Teardown

To stop all services and remove virtual network interfaces:
```bash
# Stop Redis, Middleware, and ML service
./scripts/aegis.sh stop

# Tear down lab namespaces and veth interfaces
sudo ./scripts/lab.sh down
```

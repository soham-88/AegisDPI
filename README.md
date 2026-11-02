# AegisDPI

AegisDPI is an active, multi-threaded Deep Packet Inspection (DPI) engine and network intrusion response system. It captures live network traffic, extracts protocol metadata (TCP/UDP, TLS SNI), and enforces kernel-level drops via nftables. An anomaly-detection ML pipeline monitors live traffic flows in real time, auto-quarantines attack sources, and visualizes system state across a modern web operations dashboard.

---

## Requirements

- **Operating System**: Linux (Ubuntu 22.04 LTS or WSL2 with Ubuntu).
- **Core Runtime & Tools**:
  - `g++` (C++17 support) and `cmake` (>= 3.10)
  - `libpcap-dev` and `libhiredis-dev`
  - `redis-server` (managed standalone by Aegis)
  - `nftables` and `iproute2`
  - `python3` (>= 3.10) with `python3-venv`
  - `nodejs` (>= 18) and `npm`
  - `openssl`, `zip`, `unzip`

### Why Linux is Required
1. **`libpcap`**: Direct, low-overhead raw packet capture on physical, virtual (`veth`), and bridge network interfaces.
2. **`nftables`**: Kernel-space packet filtering using dynamic named sets (`@blocklist`) for instant, high-throughput flow dropping without per-packet userspace round-trips.
3. **Network Namespaces (`ip netns`)**: Creation of isolated virtual networks and `veth` pairs (`veth_lab` / `veth_attacker`) to run safe, realistic flood and replay attacks without impacting host network connectivity.

---

## Quick Start

1. **Run Setup**:
   ```bash
   ./scripts/setup.sh
   ```
   This verifies dependencies, compiles the C++ DPI engine, builds frontend assets, initializes the Python ML virtual environment, and configures environment credentials.

2. **Start Services**:
   ```bash
   ./scripts/aegis.sh start
   ```
   Launches Redis (port 6379), ML Anomaly Detection Service (port 8000), and Middleware API (port 4000).

3. **Open Dashboard**:
   Navigate to [http://localhost:4000](http://localhost:4000) in your web browser.

4. **Sign In**:
   Log in using the administrator credentials configured during `setup.sh` (default user: `admin`).

---

## Lab Demo

AegisDPI includes an automated network namespace lab topology for realistic attack simulation and validation:

1. **Spin Up Lab Network**:
   ```bash
   ./scripts/lab.sh up
   ```
   Creates network namespace `ns_attacker` (IP: `10.10.0.2/24`) connected via a virtual ethernet pair to host interface `veth_lab` (IP: `10.10.0.1/24`).

2. **Start Engine on Lab Interface**:
   - In the web console, navigate to **Packet Flow Logs** or **Control Center**.
   - Under **Network Interfaces**, select `veth_lab`.
   - Click **Start Capture**. The engine spawns with elevated capture permissions.

3. **Simulate Attack**:
   ```bash
   ./scripts/lab.sh attack
   ```
   Launches a high-rate flood simulation from the attacker namespace toward `10.10.0.1`.

4. **Observe Response**:
   - Packets stream live into the dashboard table.
   - The ML service detects the volumetric anomaly and issues an autonomous verdict.
   - The IP `10.10.0.2` is added to `blocklist:ips`, published to the engine's subscriber thread, and inserted into the `nftables` kernel drop set.
   - Subsequent attacker packets are immediately dropped at the network layer.

---

## Stop & Shutdown

To gracefully stop all background services (Middleware, ML service, Redis) and verify no dangling engine processes or kernel tables remain:

```bash
./scripts/aegis.sh stop
```

Check running status at any time with:
```bash
./scripts/aegis.sh status
```

---

## Reset Demo State

To wipe all accumulated packet logs, ML anomaly verdict histories, and active blocklist entries back to a clean state:

```bash
./scripts/reset-demo.sh
```
Prompts for confirmation (`y/N`), purges Redis streams (`dpi:logs`, `ml:verdict_history`), removes all IPs from `blocklist:ips`, flushes `blocklist:meta`, and clears the kernel `nftables` set.

---

## Troubleshooting

- **Port Already in Use (4000, 8000, or 6379)**:
  Check which processes are listening:
  ```bash
  ss -tulpn | grep -E '4000|8000|6379'
  ```
  Run `./scripts/aegis.sh stop` to terminate managed instances, or kill stray background processes with `pkill -f 'node server.js'` / `pkill -f 'uvicorn main:app'`.

- **Sudoers Permission Error (`sudo rule missing or does not match ENGINE_BIN`)**:
  Live packet capture and kernel rule updates require root elevation. Verify that `/etc/sudoers.d/aegis-engine` exists and specifies the exact path to your compiled binary:
  ```bash
  sudo visudo -cf /etc/sudoers.d/aegis-engine
  ```
  Re-running `./scripts/setup.sh` will automatically generate and validate this file.

- **Login Lockout (60-second Cooldown)**:
  The authentication API enforces brute-force protection. More than 5 failed login attempts within 60 seconds from an IP returns HTTP 429 (`Too many login attempts. Please try again after 60 seconds`). Wait 60 seconds before trying again.

- **WSL2 IP Address Changes**:
  WSL2 assigns dynamic IP addresses to virtual adapters on reboot. If accessing the web interface from the Windows host or an external device, ensure `HOST=127.0.0.1` (or your WSL interface IP) in `middleware/.env` and verify `ML_IGNORE_IPS` in `ml-service/.env`.

---

## Project Layout

- `engine/`: Multi-threaded C++17 DPI capture engine, packet parser, TLS SNI extractor, and nftables enforcer.
- `middleware/`: Node.js Express API server and Socket.io gateway bridging Redis data streams with the web dashboard.
- `frontend/`: React + Vite + Tailwind CSS monitoring and administration web console.
- `ml-service/`: Python FastAPI service running real-time Isolation Forest anomaly detection and Telegram alerts.
- `scripts/`: Operational management scripts (`setup.sh`, `aegis.sh`, `lab.sh`, `reset-demo.sh`, `package.sh`).
- `docs/`: Technical specifications, PRD, TRD, security threat modeling, and testing plans.

---

## Known Limitations

- **Feature Limitations**: The engine does not log packet length, so the ML uses 5 features.
- **Training Baseline**: The model is trained on synthetic normal traffic rather than long-term enterprise captures.
- **Stream Reassembly**: No TCP stream reassembly (a TLS hello split across packets is not reassembled).
- **Initiator Inference**: UDP flow initiator is still inferred from arrival order; TCP uses the SYN flag and ICMP uses the message type.
- **Capture Interfaces**: One capture interface at a time; multi-interface aggregation is not supported.
- **Elevation Method**: The capture button relies on a restricted sudo rule; production would use Linux capabilities and a service account.
- **Session Management**: Sessions use JWTs that are not revoked on sign-out; they expire after 8 h.

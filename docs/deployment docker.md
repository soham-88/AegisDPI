# AegisDPI — Deployment & Docker Compose Design

## 1. Key constraint that shapes this whole document

The C++ engine needs raw-packet/netfilter access (`CAP_NET_RAW`, `CAP_NET_ADMIN`) to do live capture and real enforcement. That's fundamentally different from the other three services, which are normal stateless-ish app containers. Plan for **two deployment tiers**, not one uniform Compose file:

- **Tier A (engine):** runs with host networking / elevated capabilities, either directly on the host or as a privileged container with `--network host --cap-add=NET_ADMIN --cap-add=NET_RAW`.
- **Tier B (everything else):** Redis, Node, FastAPI, React — normal least-privilege Docker Compose services on a private bridge network.

## 2. docker-compose.yml (Tier B — the safe majority of the stack)

```yaml
version: "3.9"

services:
  redis:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD}"]
    networks: [aegis_net]
    volumes:
      - redis_data:/data
    # deliberately NOT exposing ports to host — internal only

  middleware:
    build: ./middleware
    env_file: ./middleware/.env
    depends_on: [redis]
    ports:
      - "4000:4000"
    networks: [aegis_net]

  ml-service:
    build: ./ml-service
    env_file: ./ml-service/.env
    depends_on: [redis]
    ports:
      - "8000:8000"
    networks: [aegis_net]

  frontend:
    build: ./frontend
    depends_on: [middleware]
    ports:
      - "5173:80" # served via nginx after `npm run build`
    networks: [aegis_net]

networks:
  aegis_net:
    driver: bridge

volumes:
  redis_data:
```

## 3. The engine (Tier A) — run separately, documented clearly

For the demo, run the engine directly on the host/WSL2 (or the lab VM), pointed at the same Redis instance via its exposed connection details, OR as its own privileged container:

```yaml
# separate compose file: docker-compose.engine.yml — run explicitly, not by default
engine:
  build: ./engine
  network_mode: host
  cap_add:
    - NET_ADMIN
    - NET_RAW
  environment:
    - REDIS_HOST=127.0.0.1
    - REDIS_PASSWORD=${REDIS_PASSWORD}
  command: ["./dpi_engine", "--live", "--iface", "eth0"]
```

Run with: `docker compose -f docker-compose.engine.yml up`. Keeping it in a **separate** compose file (rather than folding into the main one) makes the privilege boundary visible and intentional — a good thing to point out if a professor asks about your security posture.

## 4. Environment Variables (per service `.env`, never committed)

```
# middleware/.env
REDIS_HOST=redis
REDIS_PASSWORD=changeme
JWT_SECRET=changeme
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
ABUSEIPDB_KEY=
VIRUSTOTAL_KEY=

# ml-service/.env
REDIS_HOST=redis
REDIS_PASSWORD=changeme
MODEL_PATH=./models/isolation_forest.pkl
```

## 5. Startup Order for a Live Demo

1. `docker compose up -d redis`
2. `docker compose up -d middleware ml-service`
3. `docker compose up -d frontend`
4. Start the engine last (Tier A, host/privileged) once everything it reports to is confirmed running — check with `docker compose ps` and a quick `redis-cli -a $REDIS_PASSWORD ping`.

## 6. What to Show If Asked "Is This Actually Production-Ready?"

Be direct rather than defensive: it's a working prototype demonstrating the full architecture and real enforcement mechanics, not a hardened production deployment. Gaps you can name proactively if asked (shows maturity, not weakness): no TLS on the Node API itself yet, no horizontal scaling of the engine, no persistent long-term log storage beyond Redis Streams' retention, no automated CI/CD pipeline. Naming these yourself, unprompted, reads far better than getting caught not having thought about them.

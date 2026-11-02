# AegisDPI — Local (Non-Docker) Run Guide

Use this doc, not `08_DEPLOYMENT_DOCKER.md`, for your upcoming presentation. Docker Compose is for later, once the panel has seen the working system and you're packaging it for a cleaner/portable deployment. Running everything directly via `npm run dev` / `uvicorn` / the compiled engine binary is actually **better for a live presentation** — no container startup delay, and if something needs a quick fix mid-demo you can edit and restart in seconds instead of rebuilding an image.

## 1. What runs where (all on `localhost`, different ports)

| Service            | How it runs                                 | Default port                                              |
| ------------------ | ------------------------------------------- | --------------------------------------------------------- |
| Redis              | `redis-server` (installed directly in WSL2) | 6379                                                      |
| C++ Engine         | compiled binary, run directly               | n/a (talks to Redis + NIC/netns, no HTTP port of its own) |
| Node middleware    | `npm run dev`                               | 4000                                                      |
| FastAPI ML service | `uvicorn main:app --reload`                 | 8000                                                      |
| React frontend     | `npm run dev` (Vite)                        | 5173                                                      |

## 2. One-time local setup

```bash
# Redis
sudo apt install redis-server
sudo systemctl status redis-server   # or run manually: redis-server --requirepass <your_redis_password>

# Node middleware
cd middleware && npm install

# FastAPI ML service
cd ml-service && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# React frontend
cd frontend && npm install
```

Create a **local-only** `.env` in each service (never commit these):

```
# middleware/.env
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=<your_redis_password>
JWT_SECRET=<your_jwt_secret>
FRONTEND_ORIGIN=http://localhost:5173

# ml-service/.env
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=<your_redis_password>

# frontend/.env
VITE_API_URL=http://localhost:4000
```

## 3. Startup sequence for a presentation (one terminal tab per service)

Start in this order — each one depends on the previous being up:

```bash
# Terminal 1
redis-server --requirepass <your_redis_password>

# Terminal 2 (once Redis is confirmed up: redis-cli -a <your_redis_password> ping -> PONG)
cd middleware && npm run dev

# Terminal 3
cd ml-service && source venv/bin/activate && uvicorn main:app --reload --port 8000

# Terminal 4
cd frontend && npm run dev
# open http://localhost:5173

# Terminal 5 (start last — this is the traffic source)
cd engine/build
sudo ./dpi_engine --live --iface <your interface, or your netns veth>
# or, if live capture / your lab netns isn't set up for this particular
# presentation yet: ./dpi_engine --replay ../test_dpi.pcap ../output.pcap
```

If your live-capture/enforcement path (Phase 2+ in `07_TESTING_QA_PLAN.md`) isn't finished yet by presentation day, **replay mode is a completely legitimate thing to show** — say plainly "this is running against a recorded capture for a repeatable demo; live-interface capture is implemented and validated separately, shown here [or: coming in the next milestone]." Don't fake live capture with replay without saying so — a professor asking "is this actually live?" and getting caught overstating it is far worse than being upfront about what's finished.

## 4. CORS reminder (a very common local-run gotcha)

Since frontend (`:5173`) and middleware (`:4000`) are different origins locally, make sure Express has CORS enabled for `http://localhost:5173` specifically (not `*`, since you're also sending a JWT) — and that Socket.io's CORS config matches. This is one of the most common "works when I `curl` it, breaks in the browser" issues — check the browser console's network tab first if the dashboard shows no live data.

## 5. What "done" looks like for the localhost presentation

Same end-to-end loop as the full viva demo in `09_VIVA_PREP.md`, just without Docker in the picture:

1. Dashboard at `http://localhost:5173` shows live/replayed traffic.
2. Adding a rule in the UI updates Redis (`redis-cli -a <your_redis_password> SMEMBERS blocklist:ips`) and the engine enforces it.
3. (If ready) the ML → auto-block → Telegram chain fires from a synthetic flood.

## 6. Moving to Docker afterward

Once the localhost version is fully working and demoed, follow `08_DEPLOYMENT_DOCKER.md` — the only real changes are: services read Redis host as `redis` (the Compose service name) instead of `127.0.0.1`, and the engine still runs outside the main Compose file (host networking / privileged), exactly as documented there. Nothing about your application logic needs to change between local and Dockerized — only the `.env` values pointing at hostnames.

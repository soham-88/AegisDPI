"""
AegisDPI — ML Anomaly Detection Service (FastAPI)
Subscribes to 'dpi:logs' stream in Redis, aggregates flow statistics across 5-second
sliding windows per source IP, scores traffic via IsolationForest, performs auto-mitigation
via Node middleware on ANOMALOUS verdicts, and publishes verdicts to 'ml:verdicts'.
"""

import os
import sys
import time
import json
import uuid
import asyncio
import logging
import ipaddress
import socket
import psutil
from collections import defaultdict, deque, Counter, OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, Any, Optional, Set, Union

import redis.asyncio as aioredis
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from model import AnomalyModel, aggregate_features, FEATURE_NAMES
from features_v2 import FEATURE_NAMES_V2, extract_features_v2
from model_v3 import AnomalyModelV3
from middleware_client import MiddlewareClient
from telegram_client import send_telegram_alert
from window_logic import WindowAdmitter, is_non_unicast

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Load environment configuration
load_dotenv(dotenv_path=os.path.join(BASE_DIR, ".env"))
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [ML-SERVICE] %(message)s")
logger = logging.getLogger("ml-service")
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
BASELINES_PATH = os.path.join(BASE_DIR, "baselines.json")
MODEL_V3_DIR = os.path.join(BASE_DIR, "models", "v3")

ML_MODEL_VERSION = os.getenv("ML_MODEL_VERSION", "v3").strip().lower()
if ML_MODEL_VERSION not in ("v1", "v3"):
    logger.error("Invalid ML_MODEL_VERSION: '%s'. Must be 'v1' or 'v3'.", ML_MODEL_VERSION)
    sys.exit(1)

REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    raise RuntimeError("REDIS_URL is not set. Copy ml-service/.env.example to ml-service/.env and fill it in.")
STATIC_IGNORE_IPS: Set[str] = set(ip.strip() for ip in os.getenv("ML_IGNORE_IPS", "").split(",") if ip.strip())
ML_IGNORE_IPS: Set[str] = set(STATIC_IGNORE_IPS)

def refresh_local_ips() -> bool:
    """
    Query all IPv4 addresses of this host's network interfaces via psutil.net_if_addrs()
    and merge them with ML_IGNORE_IPS. Returns True if the set changed.
    """
    global ML_IGNORE_IPS
    new_local_ips = set(STATIC_IGNORE_IPS)
    try:
        if_addrs = psutil.net_if_addrs()
        for iface_name, addrs in if_addrs.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address:
                    ip = addr.address.strip()
                    if ip:
                        new_local_ips.add(ip)
    except Exception as e:
        logger.warning("Error reading host interface addresses via psutil: %s", e)

    if new_local_ips != ML_IGNORE_IPS:
        ML_IGNORE_IPS = new_local_ips
        window_admitter.set_local_ips(ML_IGNORE_IPS)
        logger.info("ML local IP set updated (%d IPs): %s", len(ML_IGNORE_IPS), sorted(list(ML_IGNORE_IPS)))
        return True
    return False

async def local_ip_refresh_loop():
    """Periodically refresh local host IPs every 30 seconds."""
    while True:
        try:
            await asyncio.sleep(30)
            refresh_local_ips()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Exception in local_ip_refresh_loop: %s", e)

ML_AUTO_MITIGATE = os.getenv("ML_AUTO_MITIGATE", "true").strip().lower() in ("true", "1", "yes")
ML_ALERT_COOLDOWN_S = float(os.getenv("ML_ALERT_COOLDOWN_S", "600"))
ML_MITIGATION_COOLDOWN_S = float(os.getenv("ML_MITIGATION_COOLDOWN_S", "10"))
FLOW_TABLE_TTL_S = float(os.getenv("FLOW_TABLE_TTL_S", "120"))
MAX_FLOW_ENTRIES = int(os.getenv("MAX_FLOW_ENTRIES", "50000"))
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Global instances
if ML_MODEL_VERSION == "v3":
    model = AnomalyModelV3(MODEL_V3_DIR)
else:
    model = AnomalyModel(MODEL_PATH, BASELINES_PATH)
middleware_client = MiddlewareClient()

# In-memory sliding window state: source_ip -> deque of (timestamp, event_dict)
ip_event_windows: Dict[str, deque] = defaultdict(deque)

# Sliding window admission logic & connection tracking flow table:
window_admitter = WindowAdmitter(ML_IGNORE_IPS, FLOW_TABLE_TTL_S, MAX_FLOW_ENTRIES)
flow_table: OrderedDict = window_admitter.flow_table

# Debounce tracking: source_ip -> last verdict timestamp
last_verdict_time: Dict[str, float] = {}

# Mitigation cooldown tracking: source_ip -> last mitigation attempt timestamp
mitigated_cooldowns: Dict[str, float] = {}

# Alert cooldown tracking: source_ip -> last Telegram alert timestamp
last_alert_time: Dict[str, float] = {}

# Set of currently blocked IPs from Redis blocklist:ips
current_blocked_ips: set = set()

# Background task handles
bg_tasks = []


async def log_stream_consumer(redis_client: aioredis.Redis):
    """
    Consumes new entries from the Redis 'dpi:logs' stream using XREAD.
    Maintains a 5-second in-memory sliding window of events per source_ip.
    """
    logger.info("Connecting to Redis 'dpi:logs' stream consumer...")
    last_id = "$"  # Only consume new events published after startup

    # Ensure stream exists to prevent XREAD errors
    try:
        await redis_client.xadd("dpi:logs", {"init": "1"})
    except Exception as e:
        logger.warning("Initializing stream check: %s", e)

    while True:
        try:
            # XREAD BLOCK 1000 COUNT 100 STREAMS dpi:logs last_id
            entries = await redis_client.xread({"dpi:logs": last_id}, count=100, block=1000)
            if entries:
                for stream_name, messages in entries:
                    for msg_id, data in messages:
                        last_id = msg_id
                        # Ignore initialization marker
                        if data.get("init") == "1":
                            continue

                        now = time.time()
                        admitted_ip = window_admitter.admit(data, now)
                        if not admitted_ip:
                            continue

                        # 2. Skip already-blocked IPs from feeding sliding window
                        if admitted_ip in current_blocked_ips:
                            continue

                        # Remaining inbound packets (remote-initiated) feed the window
                        window = ip_event_windows[admitted_ip]
                        window.append((now, data))

                        # Prune events older than 5.0 seconds for this source IP
                        cutoff = now - 5.0
                        while window and window[0][0] < cutoff:
                            window.popleft()

        except asyncio.CancelledError:
            logger.info("Log stream consumer task cancelled.")
            break
        except Exception as e:
            logger.error("Error reading 'dpi:logs' stream: %s", e)
            await asyncio.sleep(1.0)


async def anomaly_evaluator_loop(redis_client: aioredis.Redis):
    """
    Runs periodically every 1.0 second.
    For every source_ip with at least 3 events in its 5-second window:
      1. Aggregates features
      2. Scores via IsolationForest & calibrated sigmoid transform
      3. On ANOMALOUS (confidence >= 0.85): triggers auto-mitigation via middleware (if enabled)
      4. Dispatches Telegram alert with cooldown
      5. Publishes verdict to Redis channel 'ml:verdicts'
      6. Applies 10-second debounce per source_ip
    """
    global current_blocked_ips
    logger.info("Anomaly evaluation loop started (1-second evaluation interval)...")

    while True:
        try:
            await asyncio.sleep(1.0)
            now = time.time()
            cutoff = now - 5.0

            # 1. Expire flow table entries older than FLOW_TABLE_TTL_S (120 s)
            window_admitter.expire_flows(now)

            # 2. Skip already-blocked IPs: query blocklist:ips once per loop
            try:
                blocked_members = await redis_client.smembers("blocklist:ips")
                blocked_ips = set(blocked_members) if blocked_members else set()
            except Exception as e:
                logger.warning("Failed to fetch blocklist:ips: %s", e)
                blocked_ips = set()
            current_blocked_ips = blocked_ips

            active_ips = list(ip_event_windows.keys())
            for src_ip in active_ips:
                # Never evaluate or alert for already-blocked IPs; clear sliding window
                if src_ip in blocked_ips:
                    if src_ip in ip_event_windows:
                        del ip_event_windows[src_ip]
                    continue

                window = ip_event_windows[src_ip]

                # Prune expired events
                while window and window[0][0] < cutoff:
                    window.popleft()

                # Clean up empty deques
                if not window:
                    del ip_event_windows[src_ip]
                    continue

                # Minimum 3 events in 5-second window required for meaningful feature evaluation
                if len(window) < 3:
                    continue

                # Debounce check: max 1 verdict per source_ip every 10 seconds
                last_time = last_verdict_time.get(src_ip, 0.0)
                if now - last_time < 10.0:
                    continue

                # Extract event dictionaries
                events = [item[1] for item in window]

                # Aggregate features
                if ML_MODEL_VERSION == "v3":
                    features = extract_features_v2(events, window_s=5.0)
                else:
                    features = aggregate_features(events, window_seconds=5.0)

                # Score with ML model
                raw_score, confidence, verdict, feature_contributions, description = model.score(features)
                trigger = getattr(model, "last_trigger", None)

                # Only emit if classified as ANOMALOUS or SUSPICIOUS
                if verdict in ("ANOMALOUS", "SUSPICIOUS"):
                    last_verdict_time[src_ip] = now

                    # Determine most frequent destination IP in this window
                    dst_ips = [e.get("dst_ip") for e in events if e.get("dst_ip")]
                    dest_ip = Counter(dst_ips).most_common(1)[0][0] if dst_ips else "0.0.0.0"

                    if ML_MODEL_VERSION == "v3":
                        trig_str = trigger if trigger else "unknown"
                        alert_description = f"ML v3 ({trig_str}): {description}"
                        block_reason = alert_description
                    else:
                        top_feat = feature_contributions[0] if feature_contributions else {}
                        feat_human = top_feat.get("name", "traffic").replace("_", " ")
                        top_val = top_feat.get("value", 0.0)
                        top_base = top_feat.get("baseline", 0.0)
                        conf_pct = round(confidence * 100, 1)
                        block_reason = f"Volumetric flood: {feat_human} {top_val} vs {top_base} ({conf_pct}% confidence)"
                        alert_description = description

                    if verdict == "SUSPICIOUS":
                        logger.info("SUSPICIOUS verdict evaluated (dashboard push suppressed): IP: %s -> %s (conf: %.2f)",
                                    src_ip, dest_ip, confidence)

                    auto_mitigated = False
                    if verdict == "ANOMALOUS":
                        # 5. Safety switch & debounce: check ML_AUTO_MITIGATE and ML_MITIGATION_COOLDOWN_S before calling POST /api/rules
                        if ML_AUTO_MITIGATE:
                            last_mitigated = mitigated_cooldowns.get(src_ip, 0.0)
                            if now - last_mitigated >= ML_MITIGATION_COOLDOWN_S:
                                logger.info("Triggering auto-mitigation block for IP: %s (reason: %s)", src_ip, block_reason)
                                try:
                                    success = await asyncio.to_thread(middleware_client.post_rule, src_ip, block_reason)
                                    auto_mitigated = bool(success)
                                except Exception as ex:
                                    logger.error("Auto-mitigation call failed for %s: %s", src_ip, ex)
                                    auto_mitigated = False
                                # Record timestamp so debounce applies (including on 409 where success is False)
                                mitigated_cooldowns[src_ip] = now
                            else:
                                logger.info(
                                    "Auto-mitigation suppressed for %s (mitigation cooldown active: %.1fs remaining)",
                                    src_ip,
                                    ML_MITIGATION_COOLDOWN_S - (now - last_mitigated),
                                )
                        else:
                            logger.info("Auto-mitigation disabled (ML_AUTO_MITIGATE=false); skipping block rule for %s", src_ip)
                            auto_mitigated = False

                        # 4. Telegram alert cooldown check (ML_ALERT_COOLDOWN_S)
                        last_alert = last_alert_time.get(src_ip, 0.0)
                        if now - last_alert >= ML_ALERT_COOLDOWN_S:
                            telegram_status = await asyncio.to_thread(
                                send_telegram_alert,
                                src_ip,
                                dest_ip,
                                confidence,
                                alert_description,
                                auto_mitigated,
                                trigger=trigger,
                            )
                            if telegram_status == "sent":
                                last_alert_time[src_ip] = now
                        else:
                            telegram_status = "suppressed_cooldown"
                            logger.info(
                                "Telegram alert suppressed for %s (cooldown active: %.1fs remaining)",
                                src_ip,
                                ML_ALERT_COOLDOWN_S - (now - last_alert),
                            )
                    else:
                        telegram_status = "not_applicable"

                    if verdict == "ANOMALOUS":
                        clean_features = [
                            f for f in feature_contributions
                            if isinstance(f, dict) and f.get("name") != "guard" and "contribution_pct" in f
                        ]
                        guard_entries_list = []
                        for f in feature_contributions:
                            if isinstance(f, dict) and f.get("name") == "guard":
                                guard_entries_list = f.get("guard", [])
                                break

                        # Construct exact AnomalyAlert payload matching frontend / Redis contract
                        verdict_payload = {
                            "id": f"anom_{uuid.uuid4().hex[:12]}",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source_ip": src_ip,
                            "dest_ip": dest_ip,
                            "confidence": float(round(confidence, 4)),
                            "verdict": verdict,
                            "auto_mitigated": auto_mitigated,
                            "description": alert_description,
                            "features": clean_features,
                            "telegram_alert": telegram_status,
                            "model_version": ML_MODEL_VERSION,
                            "trigger": trigger,
                            "guard": guard_entries_list,
                        }

                        # Publish verdict to Redis channel 'ml:verdicts'
                        payload_json = json.dumps(verdict_payload)
                        await redis_client.publish("ml:verdicts", payload_json)
                        try:
                            await redis_client.xadd("ml:verdict_history", {"data": payload_json}, maxlen=500, approximate=True)
                        except Exception as ex:
                            logger.warning("Failed to XADD to ml:verdict_history: %s", ex)
                        logger.info("Published verdict to 'ml:verdicts': [%s] IP: %s -> %s (conf: %.2f, mitigated: %s)",
                                    verdict, src_ip, dest_ip, confidence, auto_mitigated)

        except asyncio.CancelledError:
            logger.info("Anomaly evaluator loop cancelled.")
            break
        except Exception as e:
            logger.error("Exception in anomaly evaluator loop: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI Lifespan:
    1. Loads model.joblib and baselines.json on startup (gracefully exits if missing).
    2. Spawns async background stream consumer and evaluation worker.
    3. Handles clean resource shutdown.
    """
    # 1. Verify and load model artifacts
    try:
        model.load()
        if ML_MODEL_VERSION == "v3":
            logger.info("Active ML model: v3 (IsolationForest + envelope guard)")
            logger.info("Successfully loaded v3 model from: %s", MODEL_V3_DIR)
        else:
            logger.info("Active ML model: v1 (volumetric IsolationForest)")
            logger.info("Successfully loaded ML model from: %s", MODEL_PATH)
            logger.info("Loaded feature baselines: %s", model.baselines)
    except FileNotFoundError as e:
        logger.error("Missing model artifact for %s: %s", ML_MODEL_VERSION, e)
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to load ML model (%s): %s", ML_MODEL_VERSION, e)
        sys.exit(1)

    # Refresh host interface IPv4 addresses
    refresh_local_ips()

    # Startup configuration logging
    logger.info(
        "Effective ML config: local_ips=%s, auto_mitigate=%s, alert_cooldown_s=%.1f, mitigation_cooldown_s=%.1f, flow_table_ttl_s=%.1f, max_flow_entries=%d",
        sorted(list(ML_IGNORE_IPS)),
        ML_AUTO_MITIGATE,
        ML_ALERT_COOLDOWN_S,
        ML_MITIGATION_COOLDOWN_S,
        FLOW_TABLE_TTL_S,
        MAX_FLOW_ENTRIES,
    )

    # Authenticate with Node.js middleware
    try:
        middleware_client.login()
    except Exception as e:
        logger.warning("Initial login to middleware failed: %s", e)

    # 2. Start background Redis tasks and local IP refresh loop
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    consumer_task = asyncio.create_task(log_stream_consumer(redis_client))
    evaluator_task = asyncio.create_task(anomaly_evaluator_loop(redis_client))
    ip_refresh_task = asyncio.create_task(local_ip_refresh_loop())
    bg_tasks.extend([consumer_task, evaluator_task, ip_refresh_task])

    yield

    # 3. Shutdown cleanup
    for t in bg_tasks:
        t.cancel()
    await asyncio.gather(*bg_tasks, return_exceptions=True)
    await redis_client.aclose()
    logger.info("ML Service background tasks shut down cleanly.")


app = FastAPI(
    title="AegisDPI ML Anomaly Detection Service",
    description="Real-time volumetric & behavioral anomaly detection using Isolation Forest over Redis streams.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- REST API Models & Endpoints (per docs/ml service design.md Section 6) ---

class PredictRequest(BaseModel):
    source_ip: str = Field(..., example="10.10.0.2")
    features: Dict[str, float] = Field(
        ...,
        example={
            "packets_per_second": 350.0,
            "unique_dst_ports": 1.0,
            "unique_dst_ips": 1.0,
            "dropped_ratio": 0.0,
            "protocol_diversity": 1.0,
        },
    )

class PredictResponse(BaseModel):
    source_ip: str
    is_anomaly: bool
    confidence: float
    verdict: Optional[str]
    description: str
    features: list
    model_version: Optional[str] = None
    trigger: Optional[str] = None
    guard: Optional[list] = None

class ModelStatusResponse(BaseModel):
    model_loaded: bool
    model_version: str = "v1"
    model_type: str
    n_estimators: int
    contamination: Union[float, str]
    training_sample_count: Optional[int]
    trained_at: str
    feature_schema: list[str]
    baselines: Dict[str, float]
    auto_mitigate: bool
    alert_cooldown_s: float
    mitigation_cooldown_s: Optional[float] = None
    num_local_ips: int
    flow_table_size: int
    tracked_source_ips: int


@app.get("/model/status", response_model=ModelStatusResponse, tags=["Model Info"])
def get_model_status():
    """
    Returns model loaded state, model hyperparameters from model artifact,
    training metadata, baselines, and active operational state.
    """
    if not model.is_loaded():
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    if ML_MODEL_VERSION == "v3":
        m = model.base_model.model
        model_type = "IsolationForest + EnvelopeGuard"
        n_estimators = int(m.n_estimators)
        try:
            contamination = float(m.contamination)
        except (ValueError, TypeError):
            contamination = str(m.contamination)
        training_sample_count = model.meta.get("train_vectors_count")
        trained_at = model.meta.get("timestamp", "unknown")
        feature_schema = FEATURE_NAMES_V2
        baselines = {
            k: float(v.get("median", 0.0))
            for k, v in model.base_model.feature_stats.items()
        }
    else:
        try:
            mtime = os.path.getmtime(MODEL_PATH)
            trained_at_file = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except Exception:
            trained_at_file = "unknown"

        m = model.model
        model_type = type(m).__name__
        n_estimators = int(m.n_estimators)
        try:
            contamination = float(m.contamination)
        except (ValueError, TypeError):
            contamination = str(m.contamination)
        training_sample_count = model.meta.get("n_training_samples")
        trained_at = model.meta.get("trained_at", trained_at_file)
        feature_schema = FEATURE_NAMES
        baselines = model.baselines

    return ModelStatusResponse(
        model_loaded=model.is_loaded(),
        model_version=ML_MODEL_VERSION,
        model_type=model_type,
        n_estimators=n_estimators,
        contamination=contamination,
        training_sample_count=training_sample_count,
        trained_at=trained_at,
        feature_schema=feature_schema,
        baselines=baselines,
        auto_mitigate=ML_AUTO_MITIGATE,
        alert_cooldown_s=ML_ALERT_COOLDOWN_S,
        mitigation_cooldown_s=ML_MITIGATION_COOLDOWN_S,
        num_local_ips=len(ML_IGNORE_IPS),
        flow_table_size=len(flow_table),
        tracked_source_ips=len(ip_event_windows),
    )


@app.post("/predict", response_model=PredictResponse, tags=["Manual Scoring Demo"])
def predict_features(req: PredictRequest):
    """
    Runs manual IsolationForest inference and confidence calibration for demonstration.
    Does NOT publish to Redis or trigger auto-mitigation.
    """
    if not model.is_loaded():
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    try:
        raw_score, confidence, verdict, feature_contributions, description = model.score(req.features)
        trigger = getattr(model, "last_trigger", None)
        is_anomaly = bool(verdict == "ANOMALOUS")

        clean_features = [
            f for f in feature_contributions
            if isinstance(f, dict) and f.get("name") != "guard" and "contribution_pct" in f
        ]
        guard_entries = []
        for f in feature_contributions:
            if isinstance(f, dict) and f.get("name") == "guard":
                guard_entries = f.get("guard", [])
                break

        return PredictResponse(
            source_ip=req.source_ip,
            is_anomaly=is_anomaly,
            confidence=float(round(confidence, 4)),
            verdict=verdict,
            description=description,
            features=clean_features,
            model_version=ML_MODEL_VERSION,
            trigger=trigger,
            guard=guard_entries,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

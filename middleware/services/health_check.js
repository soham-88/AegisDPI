function buildHealthPayload({
    redisPingOk = false,
    mlStatusOk = false,
    engineState = 'stopped',
    engineUpdatedAtMs = 0,
    nowMs = Date.now(),
    freshnessWindowMs = 5000
} = {}) {
    const redis = redisPingOk ? 'ok' : 'down';
    const ml = mlStatusOk ? 'online' : 'offline';
    const engine_stats_fresh = Boolean(redisPingOk && engineUpdatedAtMs > 0 && (nowMs - engineUpdatedAtMs < freshnessWindowMs));
    const engine = engineState || 'stopped';

    return {
        redis,
        ml,
        engine,
        engine_stats_fresh
    };
}

async function pingRedis(redisClient, timeoutMs = 1000) {
    if (!redisClient || !redisClient.isOpen) return false;
    try {
        let timer;
        const pingPromise = redisClient.ping();
        const timeoutPromise = new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
        });
        const res = await Promise.race([pingPromise, timeoutPromise]);
        clearTimeout(timer);
        return res === 'PONG';
    } catch {
        return false;
    }
}

async function checkMl(mlUrl, timeoutMs = 1000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(`${mlUrl}/model/status`, { signal: controller.signal });
        clearTimeout(timer);
        return res.ok;
    } catch {
        clearTimeout(timer);
        return false;
    }
}

async function getHealthStatus({ redisClient, mlUrl, engineManager }) {
    const targetMlUrl = mlUrl || process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000';
    const [redisPingOk, mlStatusOk] = await Promise.all([
        pingRedis(redisClient, 1000),
        checkMl(targetMlUrl, 1000)
    ]);

    let engineState = 'stopped';
    let engineUpdatedAtMs = 0;

    if (redisPingOk && redisClient) {
        try {
            const rawUpdatedAt = await redisClient.hGet('dpi:stats', 'updated_at_ms');
            engineUpdatedAtMs = Number(rawUpdatedAt) || 0;
        } catch {
            // ignore
        }
    }

    if (engineManager) {
        try {
            const status = await engineManager.getStatus(redisPingOk ? redisClient : null);
            engineState = status.state || 'stopped';
        } catch {
            engineState = engineManager.child ? 'running' : 'stopped';
        }
    }

    return buildHealthPayload({
        redisPingOk,
        mlStatusOk,
        engineState,
        engineUpdatedAtMs,
        nowMs: Date.now()
    });
}

module.exports = {
    buildHealthPayload,
    pingRedis,
    checkMl,
    getHealthStatus
};


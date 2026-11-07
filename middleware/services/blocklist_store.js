'use strict';

const {
    CONFIG,
    isValidIPv4,
    parseCidr,
    ipInCidr,
    isAllowlisted,
    nextMlTtl,
    computeExpiry,
} = require('./block_policy');

const AUDIT_STREAM = 'audit:log';
const AUDIT_MAXLEN = 10000;

/**
 * Records an entry into the audit:log Redis stream.
 */
async function recordAudit(redisClient, {
    actor = 'system',
    role = 'system',
    action,
    target = '',
    source = '',
    reason = '',
    ttl_s = null,
    expires_at = null,
    result = '',
    detail = '',
}) {
    if (!redisClient) return;
    const ts = new Date().toISOString();
    const payload = {
        ts,
        actor: String(actor || 'system'),
        role: String(role || 'system'),
        action: String(action || 'unknown'),
        target: String(target || ''),
        source: String(source || ''),
        reason: String(reason || ''),
        ttl_s: ttl_s !== null && ttl_s !== undefined ? String(ttl_s) : '',
        expires_at: expires_at ? String(expires_at) : '',
        result: String(result || ''),
        detail: String(detail || ''),
    };

    try {
        await redisClient.xAdd(AUDIT_STREAM, '*', payload, {
            TRIM: { strategy: 'MAXLEN', strategyModifier: '~', threshold: AUDIT_MAXLEN }
        });
        console.log(`[AUDIT] action="${payload.action}" target="${payload.target}" actor="${payload.actor}" role="${payload.role}" result="${payload.result}" at ${ts}`);
    } catch (err) {
        console.error('[AUDIT-ERROR] Failed to record audit log:', err);
    }
}

/**
 * Prunes and retrieves active strike timestamps for an IP within the strike window.
 */
async function getAndPruneStrikes(redisClient, ip, nowMs, windowSeconds) {
    const windowMs = (windowSeconds || CONFIG.ML_STRIKE_WINDOW_S) * 1000;
    let raw;
    try {
        raw = await redisClient.hGet('blocklist:strikes', ip);
    } catch (e) {
        raw = null;
    }

    let timestamps = [];
    if (raw) {
        try {
            timestamps = JSON.parse(raw);
            if (!Array.isArray(timestamps)) timestamps = [];
        } catch (e) {
            timestamps = [];
        }
    }

    const filtered = timestamps.filter(ts => typeof ts === 'number' && (nowMs - ts) < windowMs);
    return filtered;
}

/**
 * Adds or extends an IP block rule.
 * Returns { result: "blocked"|"extended", expires_at, ttl_s }.
 */
async function addBlock({
    redisClient,
    io,
    ip,
    actor = 'admin',
    role = 'admin',
    reason = '',
    ttlSeconds = null,
    source,
}) {
    const nowMs = Date.now();
    const iso = new Date(nowMs).toISOString();
    const ruleSource = source || (role === 'ml-service' ? 'ml_auto' : 'manual');
    const ruleReason = reason || (ruleSource === 'ml_auto' ? 'ML auto-mitigation block' : 'Manual Admin Block');

    // 1. Manage strikes in blocklist:strikes
    const activeStrikes = await getAndPruneStrikes(redisClient, ip, nowMs, CONFIG.ML_STRIKE_WINDOW_S);

    let effectiveTtl = ttlSeconds;
    if (role === 'ml-service' || ruleSource === 'ml_auto') {
        effectiveTtl = nextMlTtl(activeStrikes, nowMs, CONFIG.ML_BLOCK_TTL_LADDER, CONFIG.ML_STRIKE_WINDOW_S);
    }

    // Append this strike timestamp and save back to Redis
    const updatedStrikes = [...activeStrikes, nowMs];
    await redisClient.hSet('blocklist:strikes', ip, JSON.stringify(updatedStrikes));
    const strikes24h = updatedStrikes.length;

    // 2. Check if already blocked
    const alreadyBlocked = await redisClient.sIsMember('blocklist:ips', ip);

    if (alreadyBlocked) {
        let finalExpiresAtMs = null;
        let finalTtlSeconds = null;

        if (role === 'ml-service' || ruleSource === 'ml_auto') {
            // ML extends: max(existing, new)
            const existingScoreStr = await redisClient.zScore('blocklist:expiry', ip);
            if (existingScoreStr === null || existingScoreStr === undefined) {
                // Currently permanent -> remains permanent
                finalExpiresAtMs = null;
                finalTtlSeconds = null;
            } else {
                const existingScore = Number(existingScoreStr);
                const newExpiryMs = computeExpiry(nowMs, effectiveTtl);
                finalExpiresAtMs = Math.max(existingScore, newExpiryMs);
                finalTtlSeconds = Math.max(1, Math.round((finalExpiresAtMs - nowMs) / 1000));
                await redisClient.zAdd('blocklist:expiry', [{ score: finalExpiresAtMs, value: ip }]);
            }
        } else {
            // Admin replaces TTL with requested one
            if (effectiveTtl !== null && effectiveTtl !== undefined) {
                finalExpiresAtMs = computeExpiry(nowMs, effectiveTtl);
                finalTtlSeconds = effectiveTtl;
                await redisClient.zAdd('blocklist:expiry', [{ score: finalExpiresAtMs, value: ip }]);
            } else {
                finalExpiresAtMs = null;
                finalTtlSeconds = null;
                await redisClient.zRem('blocklist:expiry', ip);
            }
        }

        const expiresAtIso = finalExpiresAtMs ? new Date(finalExpiresAtMs).toISOString() : null;

        // Update metadata
        let metaObj = {};
        try {
            const raw = await redisClient.hGet('blocklist:meta', ip);
            if (raw) metaObj = JSON.parse(raw) || {};
        } catch (e) {}

        metaObj = {
            ...metaObj,
            ip,
            added_at: metaObj.added_at || iso,
            added_by: actor,
            source: ruleSource,
            reason: ruleReason,
            ttl_s: finalTtlSeconds,
            expires_at: expiresAtIso,
            strikes_24h: strikes24h,
        };
        await redisClient.hSet('blocklist:meta', ip, JSON.stringify(metaObj));

        // Audit & socket.io emit
        await recordAudit(redisClient, {
            actor,
            role,
            action: 'extend',
            target: ip,
            source: ruleSource,
            reason: ruleReason,
            ttl_s: finalTtlSeconds,
            expires_at: expiresAtIso,
            result: 'extended',
            detail: `TTL updated to ${finalTtlSeconds !== null ? finalTtlSeconds + 's' : 'permanent'}`,
        });

        if (io) {
            io.emit('blocklist:changed', { action: 'extend', ip, source: ruleSource });
        }

        return { result: 'extended', expires_at: expiresAtIso, ttl_s: finalTtlSeconds };
    }

    // 3. New block
    await redisClient.sAdd('blocklist:ips', ip);

    const expiresAtMs = computeExpiry(nowMs, effectiveTtl);
    const expiresAtIso = expiresAtMs ? new Date(expiresAtMs).toISOString() : null;

    if (expiresAtMs !== null) {
        await redisClient.zAdd('blocklist:expiry', [{ score: expiresAtMs, value: ip }]);
    }

    const metaObj = {
        ip,
        added_at: iso,
        added_by: actor,
        source: ruleSource,
        reason: ruleReason,
        ttl_s: effectiveTtl,
        expires_at: expiresAtIso,
        strikes_24h: strikes24h,
    };
    await redisClient.hSet('blocklist:meta', ip, JSON.stringify(metaObj));

    // Live update for C++ engine
    await redisClient.publish('blocklist:updates', `ADD IP ${ip}`);

    // Audit & socket.io emit
    await recordAudit(redisClient, {
        actor,
        role,
        action: 'block',
        target: ip,
        source: ruleSource,
        reason: ruleReason,
        ttl_s: effectiveTtl,
        expires_at: expiresAtIso,
        result: 'blocked',
        detail: `New block enforced (strikes 24h: ${strikes24h})`,
    });

    if (io) {
        io.emit('blocklist:changed', { action: 'block', ip, source: ruleSource });
    }

    return { result: 'blocked', expires_at: expiresAtIso, ttl_s: effectiveTtl };
}

/**
 * Removes an IP from the blocklist (unblock or expire). Idempotent.
 */
async function removeBlock({
    redisClient,
    io,
    ip,
    actor = 'admin',
    role = 'admin',
    action = 'unblock',
    reason = '',
}) {
    await redisClient.sRem('blocklist:ips', ip);
    await redisClient.hDel('blocklist:meta', ip);
    await redisClient.zRem('blocklist:expiry', ip);

    // Live update for C++ engine
    await redisClient.publish('blocklist:updates', `DEL IP ${ip}`);

    const act = action === 'expire' ? 'expire' : 'unblock';
    const res = action === 'expire' ? 'expired' : 'unblocked';
    const defaultReason = action === 'expire' ? 'Block TTL expired' : 'Manual Admin Unblock';
    const effectiveReason = reason || defaultReason;

    await recordAudit(redisClient, {
        actor,
        role,
        action: act,
        target: ip,
        source: role === 'system' ? 'system' : (role === 'ml-service' ? 'ml_auto' : 'manual'),
        reason: effectiveReason,
        result: res,
        detail: `Removed from blocklist (${res})`,
    });

    if (io) {
        io.emit('blocklist:changed', {
            action: act,
            ip,
            source: role === 'system' ? 'system' : (role === 'ml-service' ? 'ml_auto' : 'manual')
        });
    }

    return { success: true, ip, action: act };
}

/**
 * Sweeps expired blocks from blocklist:expiry.
 * Returns the list of expired IPs removed.
 */
async function sweepExpired({ redisClient, io, nowMs }) {
    if (!redisClient) return [];
    const now = typeof nowMs === 'number' ? nowMs : Date.now();
    let expiredIps = [];

    try {
        // Query sorted set for scores <= now
        expiredIps = await redisClient.zRangeByScore('blocklist:expiry', '-inf', now);
        if (!Array.isArray(expiredIps) || expiredIps.length === 0) {
            return [];
        }

        for (const ip of expiredIps) {
            await removeBlock({
                redisClient,
                io,
                ip,
                actor: 'system',
                role: 'system',
                action: 'expire',
                reason: 'Block TTL expired',
            });
        }
    } catch (err) {
        console.error('[SWEEPER-ERROR] Failed during sweepExpired:', err);
    }

    return expiredIps;
}

/**
 * Fetches all allowlist entries.
 */
async function getAllowlist(redisClient) {
    if (!redisClient) return [];
    try {
        const raw = await redisClient.hGetAll('allowlist:entries');
        if (!raw) return [];
        const entries = [];
        for (const [key, jsonStr] of Object.entries(raw)) {
            try {
                const parsed = JSON.parse(jsonStr);
                entries.push(parsed);
            } catch (e) {
                entries.push({ entry: key, note: '', added_by: 'system', added_at: '' });
            }
        }
        return entries;
    } catch (err) {
        console.error('[ALLOWLIST] Error fetching allowlist:', err);
        return [];
    }
}

/**
 * Adds an allowlist entry and unblocks any currently blocked IPs it covers.
 */
async function addAllowlistEntry({ redisClient, io, entry, note = '', actor = 'admin', role = 'admin' }) {
    const trimmed = typeof entry === 'string' ? entry.trim() : '';
    const parsed = parseCidr(trimmed);
    if (!parsed) {
        throw new Error('Invalid IPv4 or CIDR address');
    }

    const iso = new Date().toISOString();
    const entryObj = {
        entry: trimmed,
        note: note || '',
        added_by: actor,
        added_at: iso,
    };

    await redisClient.hSet('allowlist:entries', trimmed, JSON.stringify(entryObj));

    await recordAudit(redisClient, {
        actor,
        role,
        action: 'allowlist_add',
        target: trimmed,
        source: 'manual',
        reason: note || '',
        result: 'added',
        detail: `Allowlist entry created for ${trimmed}`,
    });

    // Immediately remove any currently blocked IPs covered by this allowlist entry
    try {
        const blockedIps = await redisClient.sMembers('blocklist:ips');
        for (const blockedIp of blockedIps) {
            if (ipInCidr(blockedIp, trimmed)) {
                await removeBlock({
                    redisClient,
                    io,
                    ip: blockedIp,
                    actor,
                    role,
                    action: 'unblock',
                    reason: 'allowlisted',
                });
            }
        }
    } catch (err) {
        console.error('[ALLOWLIST] Error unblocking covered IPs:', err);
    }

    return { success: true, entry: entryObj };
}

/**
 * Removes an allowlist entry.
 */
async function removeAllowlistEntry({ redisClient, io, entry, actor = 'admin', role = 'admin' }) {
    const trimmed = typeof entry === 'string' ? entry.trim() : '';
    const exists = await redisClient.hExists('allowlist:entries', trimmed);
    if (!exists) {
        return { success: false, notFound: true };
    }

    await redisClient.hDel('allowlist:entries', trimmed);

    await recordAudit(redisClient, {
        actor,
        role,
        action: 'allowlist_remove',
        target: trimmed,
        source: 'manual',
        result: 'removed',
        detail: `Allowlist entry removed for ${trimmed}`,
    });

    return { success: true, entry: trimmed };
}

/**
 * Retrieves audit log entries from the audit:log stream (newest first).
 */
async function getAudit(redisClient, limit = 200) {
    if (!redisClient) return [];
    const count = Math.min(Math.max(parseInt(limit, 10) || 200, 1), 1000);
    try {
        const entries = await redisClient.xRevRange(AUDIT_STREAM, '+', '-', { COUNT: count });
        return entries.map(e => ({
            id: e.id,
            ts: e.message.ts || '',
            actor: e.message.actor || '',
            role: e.message.role || '',
            action: e.message.action || '',
            target: e.message.target || '',
            source: e.message.source || '',
            reason: e.message.reason || '',
            ttl_s: e.message.ttl_s ? Number(e.message.ttl_s) : null,
            expires_at: e.message.expires_at || null,
            result: e.message.result || '',
            detail: e.message.detail || '',
        }));
    } catch (err) {
        console.error('[AUDIT] Failed to fetch audit stream:', err);
        return [];
    }
}

module.exports = {
    recordAudit,
    addBlock,
    removeBlock,
    sweepExpired,
    getAllowlist,
    addAllowlistEntry,
    removeAllowlistEntry,
    getAudit,
};


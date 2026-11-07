'use strict';

const express = require('express');
const router = express.Router();
const os = require('os');
const { verifyToken, requireRole } = require('../middleware/auth');
const {
    isValidIPv4,
    isAllowlisted,
    validateManualTtl,
} = require('../services/block_policy');
const {
    addBlock,
    removeBlock,
    recordAudit,
    getAllowlist,
} = require('../services/blocklist_store');

router.use(verifyToken);

function isHostLocalIp(targetIp) {
    if (!targetIp || typeof targetIp !== 'string') return false;
    const cleanIp = targetIp.trim();
    if (cleanIp.startsWith('127.') || cleanIp === '::1' || cleanIp === '0.0.0.0') {
        return true;
    }
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
        for (const net of ifaces[name] || []) {
            if (net.address === cleanIp) {
                return true;
            }
        }
    }
    return false;
}

// GET /api/rules (admin only)
router.get('/', requireRole('admin'), async (req, res) => {
    try {
        const ips = await req.redisClient.sMembers('blocklist:ips');
        const domains = await req.redisClient.sMembers('blocklist:domains');
        const apps = await req.redisClient.sMembers('blocklist:apps');
        const metaRaw = await req.redisClient.hGetAll('blocklist:meta');
        const meta = {};
        if (metaRaw) {
            for (const [ip, jsonStr] of Object.entries(metaRaw)) {
                try {
                    meta[ip] = JSON.parse(jsonStr);
                } catch (e) {
                    meta[ip] = null;
                }
            }
        }

        res.json({ ips, domains, apps, meta });
    } catch (err) {
        console.error('[RULES] Error fetching rules:', err);
        res.status(500).json({ error: 'Failed to fetch rules' });
    }
});

// POST /api/rules (admin and ml-service)
router.post('/', requireRole('admin', 'ml-service'), async (req, res) => {
    const role = req.user?.role;
    const actor = req.user?.username || role || 'unknown';
    const { type, value, reason } = req.body || {};

    // Source is strictly derived from role (ignore body.source)
    const source = role === 'ml-service' ? 'ml_auto' : 'manual';

    if (!type || !value || !['ip', 'domain', 'app'].includes(type)) {
        await recordAudit(req.redisClient, {
            actor,
            role,
            action: 'block_rejected',
            target: value || '',
            source,
            reason: reason || '',
            result: 'rejected',
            detail: 'Invalid rule type or value',
        });
        return res.status(400).json({ error: 'Invalid rule type or value' });
    }

    // ml-service is restricted strictly to type 'ip'
    if (role === 'ml-service' && type !== 'ip') {
        await recordAudit(req.redisClient, {
            actor,
            role,
            action: 'block_rejected',
            target: value,
            source,
            reason: reason || '',
            result: 'rejected',
            detail: 'ml-service may only manage IP rules',
        });
        return res.status(400).json({ error: 'ml-service may only manage IP rules' });
    }

    // IP validation and safe blocking checks
    if (type === 'ip') {
        const ip = String(value).trim();

        if (!isValidIPv4(ip)) {
            await recordAudit(req.redisClient, {
                actor,
                role,
                action: 'block_rejected',
                target: ip,
                source,
                reason: reason || '',
                result: 'rejected',
                detail: 'Invalid IPv4 address format',
            });
            return res.status(400).json({ error: 'Invalid IPv4 address' });
        }

        if (isHostLocalIp(ip)) {
            await recordAudit(req.redisClient, {
                actor,
                role,
                action: 'block_rejected',
                target: ip,
                source,
                reason: reason || '',
                result: 'rejected',
                detail: 'Refusing to block a local address of this host',
            });
            return res.status(400).json({ error: 'Refusing to block a local address of this host' });
        }

        const allowlistEntries = await getAllowlist(req.redisClient);
        if (isAllowlisted(ip, allowlistEntries)) {
            await recordAudit(req.redisClient, {
                actor,
                role,
                action: 'block_rejected',
                target: ip,
                source,
                reason: reason || '',
                result: 'rejected',
                detail: 'IP is allowlisted',
            });
            return res.status(409).json({ error: 'IP is allowlisted' });
        }

        let manualTtl = null;
        if (role === 'admin') {
            try {
                manualTtl = validateManualTtl(req.body?.ttl_s);
            } catch (err) {
                return res.status(400).json({ error: err.message });
            }
        }

        const io = req.io || req.app?.get('io');
        const blockResult = await addBlock({
            redisClient: req.redisClient,
            io,
            ip,
            actor,
            role,
            reason,
            ttlSeconds: manualTtl,
            source,
        });

        return res.status(201).json({
            success: true,
            ip,
            ttl_s: blockResult.ttl_s,
            expires_at: blockResult.expires_at,
            result: blockResult.result,
        });
    }

    // Domain & App rules (admin only)
    if (role !== 'admin') {
        return res.status(403).json({ error: `Forbidden for role ${role}` });
    }

    const key = `blocklist:${type}s`;
    await req.redisClient.sAdd(key, value);

    // Live reload update for C++ engine
    await req.redisClient.publish('blocklist:updates', `ADD ${type.toUpperCase()} ${value}`);

    await recordAudit(req.redisClient, {
        actor,
        role,
        action: 'block',
        target: value,
        source: 'manual',
        reason: reason || 'Manual Admin Block',
        result: 'blocked',
        detail: `Added to ${key}`,
    });

    const io = req.io || req.app?.get('io');
    if (io) {
        io.emit('blocklist:changed', { action: 'add', ip: value, source: 'manual' });
    }

    return res.status(201).json({ success: true, message: `Added ${value} to ${key}` });
});

// DELETE /api/rules (admin only)
router.delete('/', requireRole('admin'), async (req, res) => {
    const role = req.user?.role || 'admin';
    const actor = req.user?.username || role;
    const { type, value, reason } = req.body || {};

    if (!type || !value || !['ip', 'domain', 'app'].includes(type)) {
        return res.status(400).json({ error: 'Invalid rule type or value' });
    }

    if (type === 'ip') {
        const ip = String(value).trim();
        const io = req.io || req.app?.get('io');
        await removeBlock({
            redisClient: req.redisClient,
            io,
            ip,
            actor,
            role,
            action: 'unblock',
            reason: reason || 'Manual Admin Unblock',
        });
        return res.json({ success: true, message: `Removed ${ip} from blocklist:ips` });
    }

    const key = `blocklist:${type}s`;
    await req.redisClient.sRem(key, value);

    // Live reload update for C++ engine
    await req.redisClient.publish('blocklist:updates', `DEL ${type.toUpperCase()} ${value}`);

    await recordAudit(req.redisClient, {
        actor,
        role,
        action: 'unblock',
        target: value,
        source: 'manual',
        reason: reason || 'Manual Admin Unblock',
        result: 'unblocked',
        detail: `Removed from ${key}`,
    });

    const ioDel = req.io || req.app?.get('io');
    if (ioDel) {
        ioDel.emit('blocklist:changed', { action: 'remove', ip: value, source: 'manual' });
    }

    return res.json({ success: true, message: `Removed ${value} from ${key}` });
});

module.exports = router;

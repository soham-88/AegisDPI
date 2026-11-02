const express = require('express');
const router = express.Router();
const os = require('os');
const auth = require('../middleware/auth');

router.use(auth);

function isHostLocalIp(targetIp) {
    if (!targetIp || typeof targetIp !== 'string') return false;
    const cleanIp = targetIp.trim();
    if (cleanIp.startsWith('127.') || cleanIp === '::1' || cleanIp === '0.0.0.0') {
        return true;
    }
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
        for (const net of ifaces[name]) {
            if (net.address === cleanIp) {
                return true;
            }
        }
    }
    return false;
}

// GET /api/rules
router.get('/', async (req, res) => {
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
});

// POST /api/rules
router.post('/', async (req, res) => {
    const user = req.user?.username || req.user?.role || 'admin';
    const iso = new Date().toISOString();
    const { type, value, reason, source } = req.body;
    if (!type || !value || !['ip', 'domain', 'app'].includes(type)) {
        console.log(`[AUDIT] Rejected block rule ${value || 'unknown'} from "${user}": Invalid rule type or value at ${iso}`);
        return res.status(400).json({ error: 'Invalid rule type or value' });
    }
    
    if (type === 'ip' && isHostLocalIp(value)) {
        console.log(`[AUDIT] Rejected block rule ${value} from "${user}": Refusing to block a local address of this host at ${iso}`);
        return res.status(400).json({ error: 'Refusing to block a local address of this host' });
    }
    
    const key = `blocklist:${type}s`;
    await req.redisClient.sAdd(key, value);
    
    const ruleSource = source || 'manual';
    const ruleReason = reason || (ruleSource === 'ml_auto' ? 'ML auto-mitigation block' : 'Manual Admin Block');
    if (type === 'ip') {
        const metaObj = {
            ip: value,
            added_at: iso,
            added_by: user,
            source: ruleSource,
            reason: ruleReason,
        };
        await req.redisClient.hSet('blocklist:meta', value, JSON.stringify(metaObj));
        console.log(`[AUDIT] User "${user}" added block rule ${value} (source ${ruleSource}) at ${iso}`);
    } else {
        console.log(`[AUDIT] User "${user}" added block rule ${value} (source ${ruleSource}) at ${iso}`);
    }
    
    // Publish update so C++ engine live-reloads
    await req.redisClient.publish('blocklist:updates', `ADD ${type.toUpperCase()} ${value}`);

    // Emit live blocklist change event over Socket.io
    const io = req.io || req.app?.get('io');
    if (io) {
        io.emit('blocklist:changed', {
            action: 'add',
            ip: value,
            source: ruleSource
        });
    }

    res.status(201).json({ success: true, message: `Added ${value} to ${key}` });
});

// DELETE /api/rules
router.delete('/', async (req, res) => {
    const user = req.user?.username || req.user?.role || 'admin';
    const iso = new Date().toISOString();
    const { type, value } = req.body;
    if (!type || !value || !['ip', 'domain', 'app'].includes(type)) {
        return res.status(400).json({ error: 'Invalid rule type or value' });
    }
    
    const key = `blocklist:${type}s`;
    await req.redisClient.sRem(key, value);
    
    if (type === 'ip') {
        await req.redisClient.hDel('blocklist:meta', value);
    }
    console.log(`[AUDIT] User "${user}" removed block rule ${value} at ${iso}`);
    
    // Publish update so C++ engine live-reloads
    await req.redisClient.publish('blocklist:updates', `DEL ${type.toUpperCase()} ${value}`);

    // Emit live blocklist change event over Socket.io
    const ioDel = req.io || req.app?.get('io');
    if (ioDel) {
        ioDel.emit('blocklist:changed', {
            action: 'remove',
            ip: value,
            source: 'manual'
        });
    }

    res.json({ success: true, message: `Removed ${value} from ${key}` });
});

module.exports = router;

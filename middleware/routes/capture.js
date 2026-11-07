const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const engineManager = require('../services/engine_manager');

router.use(auth);
router.use(auth.requireRole('admin'));

// GET /api/capture/interfaces
router.get('/interfaces', (req, res) => {
    try {
        const interfaces = engineManager.listInterfaces();
        res.json(interfaces);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve network interfaces' });
    }
});

// GET /api/capture/status
router.get('/status', async (req, res) => {
    try {
        const status = await engineManager.getStatus(req.redisClient);
        res.json(status);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch engine status' });
    }
});

// POST /api/capture/start
router.post('/start', async (req, res) => {
    if (process.env.ENGINE_CONTROL_ENABLED !== 'true') {
        return res.status(403).json({ error: 'capture control disabled' });
    }

    const bodyKeys = Object.keys(req.body || {});
    if (bodyKeys.length !== 1 || !req.body.interface || typeof req.body.interface !== 'string') {
        return res.status(400).json({ error: 'Body must only contain an "interface" string field' });
    }

    const iface = req.body.interface;
    const user = req.user?.username || req.user?.id || 'admin';
    console.log(`[AUDIT] User "${user}" requested engine start on interface "${iface}" at ${new Date().toISOString()}`);

    try {
        const status = await engineManager.start(iface, req.redisClient);
        res.json(status);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// POST /api/capture/stop
router.post('/stop', async (req, res) => {
    if (process.env.ENGINE_CONTROL_ENABLED !== 'true') {
        return res.status(403).json({ error: 'capture control disabled' });
    }

    const user = req.user?.username || req.user?.id || 'admin';
    console.log(`[AUDIT] User "${user}" requested engine stop at ${new Date().toISOString()}`);

    try {
        const status = await engineManager.stop(req.redisClient);
        res.json(status);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;

const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.use(auth);
router.use(auth.requireRole('admin'));

// GET /api/logs?limit=200 (default 200, max 500)
router.get('/', async (req, res) => {
    try {
        let limit = parseInt(req.query.limit || '200', 10);
        if (isNaN(limit) || limit < 1) limit = 200;
        if (limit > 500) limit = 500;

        const raw = await req.redisClient.xRevRange('dpi:logs', '+', '-', { COUNT: limit * 2 });
        const logs = [];

        for (const entry of raw) {
            if (entry.message && (entry.message.init === '1' || entry.message.init === 1)) {
                continue;
            }
            logs.push({
                ...entry.message,
                stream_id: entry.id
            });
            if (logs.length >= limit) {
                break;
            }
        }

        res.json(logs);
    } catch (err) {
        console.error('Failed to fetch from dpi:logs:', err);
        res.status(500).json({ error: 'Failed to fetch packet logs' });
    }
});

module.exports = router;

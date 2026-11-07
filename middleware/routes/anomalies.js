const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.use(auth);
router.use(auth.requireRole('admin'));

// GET /api/anomalies?limit=100
router.get('/', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit || '100', 10);
        const entries = await req.redisClient.xRevRange('ml:verdict_history', '+', '-', { COUNT: limit });
        const anomalies = entries.map(entry => {
            try {
                if (entry.message && entry.message.data) {
                    return JSON.parse(entry.message.data);
                }
                return entry.message;
            } catch {
                return null;
            }
        }).filter(Boolean);

        res.json(anomalies);
    } catch (err) {
        console.error('Failed to fetch from ml:verdict_history:', err);
        res.status(500).json({ error: 'Failed to fetch anomaly history' });
    }
});

module.exports = router;

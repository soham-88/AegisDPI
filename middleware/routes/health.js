const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const engineManager = require('../services/engine_manager');
const { getHealthStatus, buildHealthPayload } = require('../services/health_check');

router.use(auth);
router.use(auth.requireRole('admin'));

router.get('/', async (req, res) => {
    try {
        const health = await getHealthStatus({
            redisClient: req.redisClient,
            mlUrl: process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000',
            engineManager
        });
        res.json(health);
    } catch (err) {
        res.json(buildHealthPayload({
            redisPingOk: false,
            mlStatusOk: false,
            engineState: 'stopped',
            engineUpdatedAtMs: 0
        }));
    }
});

module.exports = router;


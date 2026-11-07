const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.use(auth);
router.use(auth.requireRole('admin'));

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000';

// GET /api/ml/status
router.get('/status', async (req, res) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    try {
        const response = await fetch(`${ML_SERVICE_URL}/model/status`, {
            signal: controller.signal
        });
        clearTimeout(timeout);

        if (!response.ok) {
            return res.json({ online: false });
        }

        const data = await response.json();
        res.json({
            online: true,
            ...data
        });
    } catch (err) {
        clearTimeout(timeout);
        res.json({ online: false });
    }
});

module.exports = router;

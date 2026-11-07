'use strict';

const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { getAudit } = require('../services/blocklist_store');

router.use(verifyToken);
router.use(requireRole('admin'));

// GET /api/audit?limit=200 (max 1000)
router.get('/', async (req, res) => {
    try {
        let limit = parseInt(req.query.limit || '200', 10);
        if (isNaN(limit) || limit < 1) limit = 200;
        if (limit > 1000) limit = 1000;

        const audit = await getAudit(req.redisClient, limit);
        res.json({ success: true, audit });
    } catch (err) {
        console.error('[AUDIT] GET error:', err);
        res.status(500).json({ error: 'Failed to fetch audit log' });
    }
});

module.exports = router;


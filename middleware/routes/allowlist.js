'use strict';

const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { parseCidr } = require('../services/block_policy');
const {
    getAllowlist,
    addAllowlistEntry,
    removeAllowlistEntry,
} = require('../services/blocklist_store');

router.use(verifyToken);
router.use(requireRole('admin'));

// GET /api/allowlist
router.get('/', async (req, res) => {
    try {
        const entries = await getAllowlist(req.redisClient);
        res.json({ success: true, entries });
    } catch (err) {
        console.error('[ALLOWLIST] GET error:', err);
        res.status(500).json({ error: 'Failed to fetch allowlist' });
    }
});

// POST /api/allowlist
router.post('/', async (req, res) => {
    const actor = req.user?.username || 'admin';
    const role = req.user?.role || 'admin';
    const { entry, note } = req.body || {};

    if (!entry || typeof entry !== 'string') {
        return res.status(400).json({ error: 'Entry is required (IPv4 or CIDR)' });
    }

    const trimmed = entry.trim();
    if (!parseCidr(trimmed)) {
        return res.status(400).json({ error: 'Invalid IPv4 or CIDR address' });
    }

    try {
        const io = req.io || req.app?.get('io');
        const result = await addAllowlistEntry({
            redisClient: req.redisClient,
            io,
            entry: trimmed,
            note: note || '',
            actor,
            role,
        });
        res.status(201).json({ success: true, entry: result.entry });
    } catch (err) {
        console.error('[ALLOWLIST] POST error:', err);
        res.status(400).json({ error: err.message || 'Failed to add allowlist entry' });
    }
});

// DELETE /api/allowlist
router.delete('/', async (req, res) => {
    const actor = req.user?.username || 'admin';
    const role = req.user?.role || 'admin';
    const entry = req.body?.entry || req.query?.entry;

    if (!entry || typeof entry !== 'string') {
        return res.status(400).json({ error: 'Entry is required (IPv4 or CIDR)' });
    }

    const trimmed = entry.trim();
    if (!parseCidr(trimmed)) {
        return res.status(400).json({ error: 'Invalid IPv4 or CIDR address' });
    }

    try {
        const io = req.io || req.app?.get('io');
        const result = await removeAllowlistEntry({
            redisClient: req.redisClient,
            io,
            entry: trimmed,
            actor,
            role,
        });

        if (result.notFound) {
            return res.status(404).json({ error: 'Allowlist entry not found' });
        }

        res.json({ success: true, message: `Removed allowlist entry ${trimmed}` });
    } catch (err) {
        console.error('[ALLOWLIST] DELETE error:', err);
        res.status(500).json({ error: 'Failed to remove allowlist entry' });
    }
});

module.exports = router;


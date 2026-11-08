const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getClientIp } = require('../middleware/client_ip');

// In-memory rate limiting: ip -> Array of failed attempt timestamps (ms)
const failedAttempts = new Map();

function cleanAndCountFailed(ip) {
    const now = Date.now();
    const attempts = (failedAttempts.get(ip) || []).filter(t => now - t < 60000);
    failedAttempts.set(ip, attempts);
    return attempts.length;
}

function recordFailedAttempt(ip) {
    const now = Date.now();
    const attempts = (failedAttempts.get(ip) || []).filter(t => now - t < 60000);
    attempts.push(now);
    failedAttempts.set(ip, attempts);
}

function clearFailedAttempts(ip) {
    failedAttempts.delete(ip);
}

router.post('/login', (req, res) => {
    const clientIp = getClientIp(req);
    const iso = new Date().toISOString();

    // Check rate limit: max 5 failed attempts per IP per minute -> 429
    if (cleanAndCountFailed(clientIp) >= 5) {
        return res.status(429).json({ error: 'Too many failed attempts - wait 60 seconds' });
    }

    const { username, password } = req.body || {};
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        recordFailedAttempt(clientIp);
        console.log(`[AUDIT] Login failed for "${username || 'unknown'}" from ${clientIp} at ${iso}`);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
    const mlUsername = process.env.ML_SERVICE_USERNAME || 'ml-service';
    const mlPasswordHash = process.env.ML_SERVICE_PASSWORD_HASH;

    let authenticated = false;
    let matchedUser = '';
    let matchedRole = '';

    if (username === adminUsername && adminPasswordHash && bcrypt.compareSync(password, adminPasswordHash)) {
        authenticated = true;
        matchedUser = adminUsername;
        matchedRole = 'admin';
    } else if (username === mlUsername && mlPasswordHash && bcrypt.compareSync(password, mlPasswordHash)) {
        authenticated = true;
        matchedUser = mlUsername;
        matchedRole = 'ml-service';
    }

    if (authenticated) {
        clearFailedAttempts(clientIp);
        console.log(`[AUDIT] Login succeeded for "${matchedUser}" from ${clientIp} at ${iso}`);
        const token = jwt.sign(
            { username: matchedUser, role: matchedRole },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );
        return res.json({ token, username: matchedUser, role: matchedRole });
    } else {
        recordFailedAttempt(clientIp);
        console.log(`[AUDIT] Login failed for "${username}" from ${clientIp} at ${iso}`);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
});

router.post('/logout', (req, res) => {
    let user = 'unknown';
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            user = decoded.username || 'unknown';
        } catch (e) {
            const decoded = jwt.decode(token);
            if (decoded && decoded.username) user = decoded.username;
        }
    }
    if (user === 'unknown' && req.body && req.body.username) {
        user = req.body.username;
    }
    const iso = new Date().toISOString();
    console.log(`[AUDIT] Logout for "${user}" at ${iso}`);
    return res.json({ success: true, message: 'Logged out' });
});

module.exports = router;

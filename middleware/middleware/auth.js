'use strict';

const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
    const header = req.header('Authorization');
    if (!header) {
        return res.status(401).json({ error: 'Session expired or invalid token' });
    }

    const token = header.replace(/^Bearer\s+/i, '').trim();
    if (!token) {
        return res.status(401).json({ error: 'Session expired or invalid token' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (ex) {
        return res.status(401).json({ error: 'Session expired or invalid token' });
    }
}

function requireRole(...roles) {
    return (req, res, next) => {
        const userRole = req.user?.role;
        if (!userRole || !roles.includes(userRole)) {
            console.warn(`[AUTH] Access denied: user "${req.user?.username || 'unknown'}" (role "${userRole || 'none'}") attempted to access ${req.method} ${req.originalUrl || req.url}`);
            return res.status(403).json({ error: `Forbidden for role ${userRole || 'unknown'}` });
        }
        next();
    };
}

verifyToken.verifyToken = verifyToken;
verifyToken.requireRole = requireRole;

module.exports = verifyToken;

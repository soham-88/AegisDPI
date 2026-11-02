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

module.exports = verifyToken;

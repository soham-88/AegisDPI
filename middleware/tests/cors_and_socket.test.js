'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

test('CORS: allowlist delegate behavior', () => {
    const allowed = ['http://localhost:5173', 'http://127.0.0.1:5173'];
    const rejectedOrigins = new Set();
    const warnings = [];

    const corsDelegate = (origin, cb) => {
        if (!origin || allowed.includes(origin)) {
            return cb(null, true);
        }
        if (!rejectedOrigins.has(origin)) {
            rejectedOrigins.add(origin);
            warnings.push(`[CORS] Rejected disallowed origin: ${origin}`);
        }
        return cb(null, false);
    };

    // 1. No origin (curl, ML service)
    corsDelegate(undefined, (err, allow) => {
        assert.equal(err, null);
        assert.equal(allow, true);
    });

    // 2. Allowed origin
    corsDelegate('http://localhost:5173', (err, allow) => {
        assert.equal(err, null);
        assert.equal(allow, true);
    });

    // 3. Disallowed origin
    corsDelegate('https://malicious.example.com', (err, allow) => {
        assert.equal(err, null);
        assert.equal(allow, false);
    });
    assert.equal(warnings.length, 1);

    // 4. Disallowed origin again (logged only once)
    corsDelegate('https://malicious.example.com', (err, allow) => {
        assert.equal(err, null);
        assert.equal(allow, false);
    });
    assert.equal(warnings.length, 1);
});

test('Socket.io authentication middleware: admin role requirement', () => {
    const secret = 'super_secret_test_key_at_least_32_characters_long';

    const verifySocket = (socket, next) => {
        const token = socket.handshake.auth?.token;
        if (!token) {
            return next(new Error('Authentication error: No token provided'));
        }
        try {
            const decoded = jwt.verify(token, secret);
            socket.user = decoded;
            if (decoded.role !== 'admin') {
                return next(new Error(`Forbidden for role ${decoded.role || 'unknown'}`));
            }
            next();
        } catch (err) {
            return next(new Error('Authentication error: Session expired or invalid token'));
        }
    };

    // 1. Admin token -> succeeds
    const adminToken = jwt.sign({ username: 'admin', role: 'admin' }, secret);
    const adminSocket = { handshake: { auth: { token: adminToken } } };
    let adminErr;
    verifySocket(adminSocket, (err) => { adminErr = err; });
    assert.equal(adminErr, undefined);
    assert.equal(adminSocket.user.role, 'admin');

    // 2. ml-service token -> rejected with "Forbidden for role ml-service"
    const mlToken = jwt.sign({ username: 'ml-service', role: 'ml-service' }, secret);
    const mlSocket = { handshake: { auth: { token: mlToken } } };
    let mlErr = null;
    verifySocket(mlSocket, (err) => { mlErr = err; });
    assert.ok(mlErr instanceof Error);
    assert.equal(mlErr.message, 'Forbidden for role ml-service');

    // 3. No token -> rejected with no token error
    const noTokenSocket = { handshake: { auth: {} } };
    let noTokenErr = null;
    verifySocket(noTokenSocket, (err) => { noTokenErr = err; });
    assert.ok(noTokenErr instanceof Error);
    assert.equal(noTokenErr.message, 'Authentication error: No token provided');
});

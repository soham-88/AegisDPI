'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getClientIp, normalizeIp } = require('../middleware/client_ip');

test('client_ip: X-Forwarded-For is ignored by default (uses socket.remoteAddress)', () => {
    const originalEnv = process.env.TRUST_PROXY;
    delete process.env.TRUST_PROXY;

    try {
        const req = {
            headers: {
                'x-forwarded-for': '198.51.100.42, 10.0.0.1',
            },
            socket: {
                remoteAddress: '203.0.113.99',
            },
        };

        const ip = getClientIp(req);
        assert.equal(ip, '203.0.113.99', 'Should ignore spoofed X-Forwarded-For and use socket.remoteAddress');
    } finally {
        if (originalEnv !== undefined) {
            process.env.TRUST_PROXY = originalEnv;
        }
    }
});

test('client_ip: X-Forwarded-For is ignored when TRUST_PROXY=false', () => {
    const originalEnv = process.env.TRUST_PROXY;
    process.env.TRUST_PROXY = 'false';

    try {
        const req = {
            headers: {
                'x-forwarded-for': '1.2.3.4, 5.6.7.8',
            },
            socket: {
                remoteAddress: '10.10.0.2',
            },
        };

        const ip = getClientIp(req);
        assert.equal(ip, '10.10.0.2');
    } finally {
        if (originalEnv !== undefined) {
            process.env.TRUST_PROXY = originalEnv;
        } else {
            delete process.env.TRUST_PROXY;
        }
    }
});

test('client_ip: X-Forwarded-For left-most entry is used when TRUST_PROXY=true', () => {
    const originalEnv = process.env.TRUST_PROXY;
    process.env.TRUST_PROXY = 'true';

    try {
        const req = {
            headers: {
                'x-forwarded-for': '198.51.100.55, 10.0.0.1, 10.0.0.2',
            },
            socket: {
                remoteAddress: '127.0.0.1',
            },
        };

        const ip = getClientIp(req);
        assert.equal(ip, '198.51.100.55', 'Should take left-most XFF entry');

        // Test with options override
        const reqWithSpaces = {
            headers: {
                'x-forwarded-for': '   203.0.113.77  , 10.0.0.1',
            },
            socket: {
                remoteAddress: '127.0.0.1',
            },
        };
        assert.equal(getClientIp(reqWithSpaces, { trustProxy: true }), '203.0.113.77');
    } finally {
        if (originalEnv !== undefined) {
            process.env.TRUST_PROXY = originalEnv;
        } else {
            delete process.env.TRUST_PROXY;
        }
    }
});

test('client_ip: IPv6-mapped IPv4 and ::1 normalisation', () => {
    // 1. ::ffff: prefix stripped on remoteAddress
    const reqV4Mapped = {
        headers: {},
        socket: {
            remoteAddress: '::ffff:192.168.1.10',
        },
    };
    assert.equal(getClientIp(reqV4Mapped), '192.168.1.10');

    // 2. ::1 converted to 127.0.0.1
    const reqLoopback = {
        headers: {},
        socket: {
            remoteAddress: '::1',
        },
    };
    assert.equal(getClientIp(reqLoopback), '127.0.0.1');

    // 3. ::ffff: prefix stripped from XFF when TRUST_PROXY=true
    const reqXffV4Mapped = {
        headers: {
            'x-forwarded-for': '::ffff:10.20.30.40, 10.0.0.1',
        },
        socket: {
            remoteAddress: '127.0.0.1',
        },
    };
    assert.equal(getClientIp(reqXffV4Mapped, { trustProxy: true }), '10.20.30.40');

    // 4. ::1 in XFF converted to 127.0.0.1 when TRUST_PROXY=true
    const reqXffLoopback = {
        headers: {
            'x-forwarded-for': '::1, 10.0.0.1',
        },
        socket: {
            remoteAddress: '127.0.0.1',
        },
    };
    assert.equal(getClientIp(reqXffLoopback, { trustProxy: true }), '127.0.0.1');

    // 5. normalizeIp direct unit checks
    assert.equal(normalizeIp('::ffff:172.16.0.5'), '172.16.0.5');
    assert.equal(normalizeIp('::1'), '127.0.0.1');
    assert.equal(normalizeIp('10.0.0.1'), '10.0.0.1');
    assert.equal(normalizeIp(null), '127.0.0.1');
    assert.equal(normalizeIp(undefined), '127.0.0.1');
});


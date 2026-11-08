'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRateLimiter } = require('../middleware/rate_limit');

function createMockReqRes(ip) {
    const req = {
        headers: {},
        socket: { remoteAddress: ip },
        ip,
    };
    const res = {
        statusCode: 200,
        status(code) {
            this.statusCode = code;
            return this;
        },
        payload: null,
        json(data) {
            this.payload = data;
            return this;
        },
    };
    return { req, res };
}

test('rate_limit: allows requests up to the configured limit', () => {
    let currentTime = 100000;
    const limiter = createRateLimiter({
        windowMs: 60000,
        max: 3,
        now: () => currentTime,
    });

    for (let i = 1; i <= 3; i++) {
        const { req, res } = createMockReqRes('192.168.1.100');
        let nextCalled = false;
        limiter(req, res, () => {
            nextCalled = true;
        });

        assert.equal(nextCalled, true, `Request #${i} should be allowed`);
        assert.equal(res.statusCode, 200);
        assert.equal(res.payload, null);
    }
});

test('rate_limit: blocks the request exceeding the limit with 429 JSON {error}', () => {
    let currentTime = 100000;
    const limiter = createRateLimiter({
        windowMs: 60000,
        max: 3,
        now: () => currentTime,
    });

    // Send 3 requests up to the limit
    for (let i = 0; i < 3; i++) {
        const { req, res } = createMockReqRes('192.168.1.100');
        limiter(req, res, () => {});
    }

    // 4th request at same timestamp should be blocked
    const { req, res } = createMockReqRes('192.168.1.100');
    let nextCalled = false;
    limiter(req, res, () => {
        nextCalled = true;
    });

    assert.equal(nextCalled, false, 'Exceeded request should not call next()');
    assert.equal(res.statusCode, 429);
    assert.deepEqual(res.payload, { error: 'Too many requests - rate limit exceeded' });
});

test('rate_limit: recovers after the sliding window expires', () => {
    let currentTime = 100000;
    const limiter = createRateLimiter({
        windowMs: 60000,
        max: 2,
        now: () => currentTime,
    });

    // 2 allowed requests at t = 100000
    for (let i = 0; i < 2; i++) {
        const { req, res } = createMockReqRes('10.10.0.5');
        limiter(req, res, () => {});
    }

    // 3rd request at t = 100000 is blocked
    const blocked = createMockReqRes('10.10.0.5');
    let nextBlocked = false;
    limiter(blocked.req, blocked.res, () => { nextBlocked = true; });
    assert.equal(nextBlocked, false);
    assert.equal(blocked.res.statusCode, 429);

    // Advance clock past the 60s sliding window
    currentTime += 60001;

    // Next request should now be allowed
    const recovered = createMockReqRes('10.10.0.5');
    let nextRecovered = false;
    limiter(recovered.req, recovered.res, () => { nextRecovered = true; });
    assert.equal(nextRecovered, true, 'Request after window expiration should be allowed');
    assert.equal(recovered.res.statusCode, 200);
});

test('rate_limit: separate client IPs are tracked independently', () => {
    let currentTime = 100000;
    const limiter = createRateLimiter({
        windowMs: 60000,
        max: 2,
        now: () => currentTime,
    });

    // Exhaust limit for IP A
    for (let i = 0; i < 2; i++) {
        const { req, res } = createMockReqRes('10.0.0.1');
        limiter(req, res, () => {});
    }

    // IP A is blocked on 3rd request
    const ipABlocked = createMockReqRes('10.0.0.1');
    let ipANext = false;
    limiter(ipABlocked.req, ipABlocked.res, () => { ipANext = true; });
    assert.equal(ipANext, false);
    assert.equal(ipABlocked.res.statusCode, 429);

    // IP B should be allowed despite IP A being blocked
    const ipBAllowed = createMockReqRes('10.0.0.2');
    let ipBNext = false;
    limiter(ipBAllowed.req, ipBAllowed.res, () => { ipBNext = true; });
    assert.equal(ipBNext, true, 'IP B should not be affected by IP A rate limit');
    assert.equal(ipBAllowed.res.statusCode, 200);
});


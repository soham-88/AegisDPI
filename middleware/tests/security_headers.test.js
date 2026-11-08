'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const securityHeaders = require('../middleware/security_headers');
const { CSP_DIRECTIVE } = securityHeaders;

function createMockReqRes(path) {
    const headers = {};
    const req = { path };
    const res = {
        setHeader(name, val) {
            headers[name.toLowerCase()] = val;
        },
        getHeader(name) {
            return headers[name.toLowerCase()];
        },
        headers,
    };
    return { req, res };
}

test('security_headers: sets base security headers on all responses', () => {
    const { req, res } = createMockReqRes('/api/stats');
    let nextCalled = false;
    securityHeaders(req, res, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(res.getHeader('x-content-type-options'), 'nosniff');
    assert.equal(res.getHeader('x-frame-options'), 'DENY');
    assert.equal(res.getHeader('referrer-policy'), 'no-referrer');
    assert.equal(res.getHeader('permissions-policy'), 'camera=(), microphone=(), geolocation=()');
    assert.equal(res.getHeader('cross-origin-opener-policy'), 'same-origin');
});

test('security_headers: omits Content-Security-Policy on /api responses', () => {
    const { req, res } = createMockReqRes('/api/rules');
    securityHeaders(req, res, () => {});

    assert.equal(res.getHeader('content-security-policy'), undefined);
});

test('security_headers: includes Content-Security-Policy on static dashboard responses', () => {
    const paths = ['/', '/index.html', '/assets/index.js', '/dashboard', '/rules'];

    for (const p of paths) {
        const { req, res } = createMockReqRes(p);
        securityHeaders(req, res, () => {});

        assert.equal(res.getHeader('content-security-policy'), CSP_DIRECTIVE, `CSP should be present on ${p}`);
        assert.match(res.getHeader('content-security-policy'), /connect-src 'self' ws: wss:/);
        assert.match(res.getHeader('content-security-policy'), /style-src 'self' https:\/\/fonts\.googleapis\.com 'unsafe-inline'/);
        assert.match(res.getHeader('content-security-policy'), /font-src 'self' https:\/\/fonts\.gstatic\.com/);
        assert.doesNotMatch(res.getHeader('content-security-policy'), /'unsafe-eval'/);
    }
});


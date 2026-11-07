'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
    isValidIPv4,
    parseCidr,
    ipInCidr,
    isAllowlisted,
    nextMlTtl,
    validateManualTtl,
    computeExpiry,
} = require('../services/block_policy');

test('isValidIPv4: valid addresses', () => {
    assert.equal(isValidIPv4('192.168.1.1'), true);
    assert.equal(isValidIPv4('10.10.0.1'), true);
    assert.equal(isValidIPv4('0.0.0.0'), true);
    assert.equal(isValidIPv4('255.255.255.255'), true);
    assert.equal(isValidIPv4('192.0.2.10'), true);
});

test('isValidIPv4: invalid addresses (leading zeros, out of range, non-IPs)', () => {
    assert.equal(isValidIPv4('010.1.1.1'), false);
    assert.equal(isValidIPv4('192.168.01.1'), false);
    assert.equal(isValidIPv4('999.1.1.1'), false);
    assert.equal(isValidIPv4('256.0.0.1'), false);
    assert.equal(isValidIPv4('192.168.1'), false);
    assert.equal(isValidIPv4('192.168.1.1.1'), false);
    assert.equal(isValidIPv4(''), false);
    assert.equal(isValidIPv4(null), false);
    assert.equal(isValidIPv4(undefined), false);
    assert.equal(isValidIPv4('192.168.1.1a'), false);
    assert.equal(isValidIPv4('abc.def.ghi.jkl'), false);
    assert.equal(isValidIPv4('::1'), false);
    assert.equal(isValidIPv4('fe80::1'), false);
});

test('parseCidr and ipInCidr: single IP /32 and /0 edges', () => {
    // Single IP
    assert.equal(ipInCidr('192.0.2.1', '192.0.2.1'), true);
    assert.equal(ipInCidr('192.0.2.2', '192.0.2.1'), false);
    assert.equal(ipInCidr('192.0.2.1', '192.0.2.1/32'), true);
    assert.equal(ipInCidr('192.0.2.2', '192.0.2.1/32'), false);

    // /0 matches all IPv4
    assert.equal(ipInCidr('10.10.0.1', '0.0.0.0/0'), true);
    assert.equal(ipInCidr('192.0.2.10', '0.0.0.0/0'), true);

    // /29 subnet (e.g. 192.0.2.0 - 192.0.2.7)
    assert.equal(ipInCidr('192.0.2.0', '192.0.2.0/29'), true);
    assert.equal(ipInCidr('192.0.2.5', '192.0.2.0/29'), true);
    assert.equal(ipInCidr('192.0.2.7', '192.0.2.0/29'), true);
    assert.equal(ipInCidr('192.0.2.8', '192.0.2.0/29'), false);
    assert.equal(ipInCidr('192.0.2.10', '192.0.2.0/29'), false);

    // /24 subnet
    assert.equal(ipInCidr('10.10.0.50', '10.10.0.0/24'), true);
    assert.equal(ipInCidr('10.10.1.50', '10.10.0.0/24'), false);

    // Invalid CIDR
    assert.equal(parseCidr('192.0.2.0/33'), null);
    assert.equal(parseCidr('192.0.2.0/-1'), null);
    assert.equal(parseCidr('010.0.0.0/24'), null);
    assert.equal(parseCidr('invalid'), null);
    assert.equal(ipInCidr('192.0.2.1', 'invalid/cidr'), false);
    assert.equal(ipInCidr('invalid-ip', '192.0.2.0/24'), false);
});

test('isAllowlisted: checks against array and object keys', () => {
    const list = ['10.10.0.1/32', '192.0.2.0/29'];
    assert.equal(isAllowlisted('10.10.0.1', list), true);
    assert.equal(isAllowlisted('192.0.2.5', list), true);
    assert.equal(isAllowlisted('192.0.2.10', list), false);
    assert.equal(isAllowlisted('172.16.0.1', list), false);

    const objEntries = {
        '192.0.2.0/29': { note: 'test' }
    };
    assert.equal(isAllowlisted('192.0.2.5', objEntries), true);
    assert.equal(isAllowlisted('192.0.2.20', objEntries), false);
});

test('nextMlTtl: escalation ladder and strike window', () => {
    const ladder = [600, 3600, 86400];
    const windowS = 86400; // 24h
    const now = 1000000000;

    // 0 strikes -> 600
    assert.equal(nextMlTtl([], now, ladder, windowS), 600);

    // 1 strike in window -> 3600
    assert.equal(nextMlTtl([now - 1000], now, ladder, windowS), 3600);

    // 2 strikes in window -> 86400
    assert.equal(nextMlTtl([now - 2000, now - 1000], now, ladder, windowS), 86400);

    // 5 strikes in window -> 86400 (capped at last entry)
    const fiveStrikes = [now - 5000, now - 4000, now - 3000, now - 2000, now - 1000];
    assert.equal(nextMlTtl(fiveStrikes, now, ladder, windowS), 86400);

    // Strikes older than window ignored
    const windowMs = windowS * 1000;
    const oldStrikes = [
        now - windowMs - 10000, // expired strike (>24h ago)
        now - 1000              // active strike
    ];
    // Only 1 active strike -> should give ladder[1] = 3600
    assert.equal(nextMlTtl(oldStrikes, now, ladder, windowS), 3600);

    // All strikes expired -> 600
    const allOld = [now - windowMs - 5000, now - windowMs - 2000];
    assert.equal(nextMlTtl(allOld, now, ladder, windowS), 600);
});

test('validateManualTtl: permanent and valid ranges', () => {
    assert.equal(validateManualTtl(null), null);
    assert.equal(validateManualTtl(undefined), null);
    assert.equal(validateManualTtl(0), null);
    assert.equal(validateManualTtl('0'), null);
    assert.equal(validateManualTtl(''), null);

    // Valid bounds
    assert.equal(validateManualTtl(60), 60);
    assert.equal(validateManualTtl(3600), 3600);
    assert.equal(validateManualTtl(86400), 86400);
    assert.equal(validateManualTtl(2592000), 2592000); // 30 days
    assert.equal(validateManualTtl('600'), 600);
});

test('validateManualTtl: invalid inputs throw clear errors', () => {
    assert.throws(() => validateManualTtl(59), /out of range/i);
    assert.throws(() => validateManualTtl(2592001), /out of range/i);
    assert.throws(() => validateManualTtl(-10), /out of range/i);
    assert.throws(() => validateManualTtl('abc'), /integer/i);
    assert.throws(() => validateManualTtl(60.5), /integer/i);
});

test('computeExpiry: calculations', () => {
    const now = 1700000000000;
    assert.equal(computeExpiry(now, null), null);
    assert.equal(computeExpiry(now, undefined), null);
    assert.equal(computeExpiry(now, 60), now + 60000);
    assert.equal(computeExpiry(now, 3600), now + 3600000);
});


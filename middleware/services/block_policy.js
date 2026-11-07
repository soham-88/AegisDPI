'use strict';

const net = require('node:net');

const DEFAULT_LADDER = [600, 3600, 86400];
const DEFAULT_STRIKE_WINDOW_S = 86400; // 24 hours
const DEFAULT_SWEEP_INTERVAL_MS = 5000;

function parseLadder(envVal) {
    if (!envVal || typeof envVal !== 'string') return DEFAULT_LADDER;
    const parts = envVal.split(',').map(s => parseInt(s.trim(), 10)).filter(n => Number.isInteger(n) && n > 0);
    return parts.length > 0 ? parts : DEFAULT_LADDER;
}

const CONFIG = {
    get ML_BLOCK_TTL_LADDER() {
        return parseLadder(process.env.ML_BLOCK_TTL_LADDER);
    },
    get ML_STRIKE_WINDOW_S() {
        const val = parseInt(process.env.ML_STRIKE_WINDOW_S, 10);
        return Number.isInteger(val) && val > 0 ? val : DEFAULT_STRIKE_WINDOW_S;
    },
    get BLOCK_SWEEP_INTERVAL_MS() {
        const val = parseInt(process.env.BLOCK_SWEEP_INTERVAL_MS, 10);
        return Number.isInteger(val) && val > 0 ? val : DEFAULT_SWEEP_INTERVAL_MS;
    }
};

/**
 * Validates strict IPv4 dotted-quad format (e.g. "192.168.1.1").
 * Rejects leading zeros (like "010.1.1.1"), non-numbers, out-of-range octets.
 */
function isValidIPv4(str) {
    if (typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (!net.isIPv4(trimmed)) return false;
    const parts = trimmed.split('.');
    if (parts.length !== 4) return false;
    for (const p of parts) {
        if (!/^\d+$/.test(p)) return false;
        if (p.length > 1 && p.startsWith('0')) return false;
        const n = parseInt(p, 10);
        if (n < 0 || n > 255) return false;
    }
    return true;
}

/**
 * Converts a valid IPv4 dotted-quad string to an unsigned 32-bit integer.
 */
function ipToInt(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Parses an IPv4 CIDR string (e.g. "192.0.2.0/29") or single IP ("192.0.2.5").
 * Single IP is treated as /32. Mask must be between 0 and 32.
 * Returns { prefix, mask, maskInt, networkInt } or null if invalid.
 */
function parseCidr(str) {
    if (typeof str !== 'string') return null;
    const trimmed = str.trim();
    let prefix;
    let mask;
    if (trimmed.includes('/')) {
        const parts = trimmed.split('/');
        if (parts.length !== 2) return null;
        prefix = parts[0].trim();
        const maskStr = parts[1].trim();
        if (!/^\d+$/.test(maskStr)) return null;
        mask = parseInt(maskStr, 10);
        if (mask < 0 || mask > 32) return null;
    } else {
        prefix = trimmed;
        mask = 32;
    }

    if (!isValidIPv4(prefix)) return null;

    const maskInt = mask === 0 ? 0 : ((0xFFFFFFFF << (32 - mask)) >>> 0);
    const networkInt = (ipToInt(prefix) & maskInt) >>> 0;
    return { prefix, mask, maskInt, networkInt };
}

/**
 * Checks whether an IPv4 address falls within a CIDR or matches a single IP.
 */
function ipInCidr(ip, cidr) {
    if (!isValidIPv4(ip)) return false;
    const parsed = parseCidr(cidr);
    if (!parsed) return false;
    return ((ipToInt(ip) & parsed.maskInt) >>> 0) === parsed.networkInt;
}

/**
 * Checks whether an IPv4 address is covered by any entry in an allowlist.
 * entries can be an array or iterable of IP / CIDR strings.
 */
function isAllowlisted(ip, entries) {
    if (!isValidIPv4(ip) || !entries) return false;
    const list = Array.isArray(entries) ? entries : Object.keys(entries);
    for (const entry of list) {
        const cidrStr = typeof entry === 'string' ? entry : entry?.entry;
        if (cidrStr && ipInCidr(ip, cidrStr)) {
            return true;
        }
    }
    return false;
}

/**
 * Calculates the next TTL for an ML automated block.
 * Counts strikes in strikeTimestampsMs strictly within windowSeconds of nowMs.
 * Returns the ladder entry for that count (capped at the last entry).
 */
function nextMlTtl(strikeTimestampsMs, nowMs, ladderSeconds, windowSeconds) {
    const ladder = Array.isArray(ladderSeconds) && ladderSeconds.length > 0 ? ladderSeconds : CONFIG.ML_BLOCK_TTL_LADDER;
    const windowSec = Number.isInteger(windowSeconds) && windowSeconds > 0 ? windowSeconds : CONFIG.ML_STRIKE_WINDOW_S;
    const windowMs = windowSec * 1000;
    const now = typeof nowMs === 'number' ? nowMs : Date.now();

    const strikes = Array.isArray(strikeTimestampsMs) ? strikeTimestampsMs : [];
    // Count prior strikes within the window
    let count = 0;
    for (const ts of strikes) {
        if (typeof ts === 'number' && ts < now && (now - ts) < windowMs) {
            count++;
        }
    }

    const index = Math.min(count, ladder.length - 1);
    return ladder[index];
}

/**
 * Validates manual TTL for admin block rules.
 * null/undefined/0/"" => permanent (returns null).
 * Otherwise must be an integer between 60 and 2592000 (30 days).
 * Throws an Error with clear explanation on invalid input.
 */
function validateManualTtl(ttl) {
    if (ttl === null || ttl === undefined || ttl === 0 || ttl === '0' || ttl === '') {
        return null;
    }
    const n = Number(ttl);
    if (!Number.isInteger(n)) {
        throw new Error('Invalid TTL: must be an integer number of seconds, or 0/null for permanent');
    }
    if (n < 60 || n > 2592000) {
        throw new Error(`Invalid TTL: ${n} seconds is out of range. Must be between 60 seconds (1 minute) and 2592000 seconds (30 days)`);
    }
    return n;
}

/**
 * Computes expiry timestamp in milliseconds, or null if permanent.
 */
function computeExpiry(nowMs, ttlSeconds) {
    if (ttlSeconds === null || ttlSeconds === undefined) return null;
    return nowMs + (ttlSeconds * 1000);
}

module.exports = {
    CONFIG,
    isValidIPv4,
    ipToInt,
    parseCidr,
    ipInCidr,
    isAllowlisted,
    nextMlTtl,
    validateManualTtl,
    computeExpiry,
};


'use strict';

/**
 * Normalizes an IP string:
 * - Strips IPv6-mapped IPv4 prefix (::ffff:x.x.x.x -> x.x.x.x)
 * - Converts IPv6 loopback ::1 -> 127.0.0.1
 * - Trims whitespace
 *
 * @param {string|null|undefined} ip
 * @returns {string} Normalized IP address
 */
function normalizeIp(ip) {
    if (!ip || typeof ip !== 'string') {
        return '127.0.0.1';
    }
    let trimmed = ip.trim();
    if (trimmed.startsWith('::ffff:')) {
        trimmed = trimmed.substring(7);
    }
    if (trimmed === '::1') {
        return '127.0.0.1';
    }
    return trimmed;
}

/**
 * Extracts normalized client IPv4 address from an incoming HTTP request.
 *
 * Security rationale:
 * When direct-to-client (no trusted reverse proxy in front), an attacker can supply
 * arbitrary X-Forwarded-For headers to rotate IP addresses and bypass rate limits.
 * Therefore, by default (TRUST_PROXY=false), client IP resolution uses ONLY the real
 * socket remoteAddress. Only when TRUST_PROXY is explicitly enabled (e.g. behind
 * an authenticating TLS reverse proxy), the left-most entry of X-Forwarded-For is trusted.
 *
 * @param {Object} req - HTTP / Express request object
 * @param {Object|boolean} [options] - Options object or boolean override for trustProxy
 * @param {boolean} [options.trustProxy] - Override for TRUST_PROXY env flag
 * @returns {string} Normalized IPv4 address
 */
function getClientIp(req, options = {}) {
    const trustProxy = typeof options === 'boolean'
        ? options
        : (options.trustProxy ?? (process.env.TRUST_PROXY?.toLowerCase() === 'true'));

    if (trustProxy && req?.headers?.['x-forwarded-for']) {
        const xff = req.headers['x-forwarded-for'];
        const leftMost = Array.isArray(xff) ? xff[0] : (typeof xff === 'string' ? xff.split(',')[0] : '');
        if (leftMost && leftMost.trim()) {
            return normalizeIp(leftMost);
        }
    }

    const remote = req?.socket?.remoteAddress || req?.ip || '127.0.0.1';
    return normalizeIp(remote);
}

module.exports = {
    getClientIp,
    normalizeIp,
};


'use strict';

/**
 * Content-Security-Policy for static dashboard responses.
 *
 * Directive rationale:
 * - default-src 'self': Restrict fallbacks to same origin.
 * - script-src 'self': Scripts served strictly from local bundle (no 'unsafe-eval').
 * - style-src 'self' https://fonts.googleapis.com 'unsafe-inline':
 *     - https://fonts.googleapis.com is required by frontend/index.html Google Fonts link.
 *     - 'unsafe-inline' is required by React inline styles (e.g. style={{ width, opacity, backgroundColor }}).
 * - font-src 'self' https://fonts.gstatic.com data::
 *     - https://fonts.gstatic.com serves the web font files referenced by Google Fonts stylesheets.
 *     - data: allows embedded font URIs.
 * - img-src 'self' data:: Favicons and data URIs.
 * - connect-src 'self' ws: wss:: Same-origin REST API calls and Socket.io WebSocket connections.
 * - object-src 'none': Disallow plugin embeds (Flash, Java).
 * - base-uri 'self': Prevent DOM injection of malicious <base> URLs.
 * - frame-ancestors 'none': Prevent framing/clickjacking (matches X-Frame-Options: DENY).
 */
const CSP_DIRECTIVE = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data:",
    "connect-src 'self' ws: wss:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
].join('; ');

/**
 * Express middleware setting standard security headers on all responses,
 * and Content-Security-Policy on static dashboard responses only (not /api).
 */
function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

    // Apply Content-Security-Policy ONLY on static dashboard responses (not /api)
    if (!req.path.startsWith('/api')) {
        res.setHeader('Content-Security-Policy', CSP_DIRECTIVE);
    }

    next();
}

module.exports = securityHeaders;
module.exports.CSP_DIRECTIVE = CSP_DIRECTIVE;


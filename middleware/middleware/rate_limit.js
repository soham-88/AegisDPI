'use strict';

const { getClientIp } = require('./client_ip');

/**
 * Creates an in-memory sliding window rate limiter middleware.
 *
 * @param {Object} [options]
 * @param {number} [options.windowMs=60000] - Sliding window duration in milliseconds (default 60s)
 * @param {number} [options.max] - Max requests allowed per window (default from env API_RATE_LIMIT_PER_MIN or 600)
 * @param {Function} [options.now] - Clock function returning current timestamp in ms (default () => Date.now())
 * @param {Function} [options.keyGenerator] - Function extracting client key/IP from request
 * @param {string} [options.message] - Error message returned on 429
 * @returns {Function} Express middleware function
 */
function createRateLimiter(options = {}) {
    const windowMs = options.windowMs ?? 60000;
    const envLimit = process.env.API_RATE_LIMIT_PER_MIN ? parseInt(process.env.API_RATE_LIMIT_PER_MIN, 10) : NaN;
    const max = options.max ?? (!isNaN(envLimit) && envLimit > 0 ? envLimit : 600);
    const now = options.now ?? (() => Date.now());
    const keyGenerator = options.keyGenerator ?? getClientIp;
    const message = options.message ?? 'Too many requests - rate limit exceeded';

    // Map: clientKey -> Array of timestamps in ms (sorted ascending)
    const store = new Map();

    const limiter = (req, res, next) => {
        const key = keyGenerator(req);
        const currentTime = now();
        const cutoff = currentTime - windowMs;

        let timestamps = store.get(key);
        if (!timestamps) {
            timestamps = [];
            store.set(key, timestamps);
        }

        // Prune expired timestamps outside the sliding window
        while (timestamps.length > 0 && timestamps[0] <= cutoff) {
            timestamps.shift();
        }

        if (timestamps.length >= max) {
            return res.status(429).json({ error: message });
        }

        timestamps.push(currentTime);
        next();
    };

    limiter.reset = () => store.clear();
    limiter.store = store;

    return limiter;
}

module.exports = {
    createRateLimiter,
    getClientIp,
};


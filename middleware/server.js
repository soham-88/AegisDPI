const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { createClient } = require('redis');
const jwt = require('jsonwebtoken');

// Startup secret checks
const JWT_PLACEHOLDER = 'replace_with_a_secure_jwt_secret_key';
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32 || process.env.JWT_SECRET === JWT_PLACEHOLDER) {
    console.error('[FATAL] Insecure or missing JWT_SECRET: must be at least 32 characters and not match the default placeholder.');
    process.exit(1);
}

let redisHasPassword = false;
try {
    if (process.env.REDIS_URL) {
        const parsedRedisUrl = new URL(process.env.REDIS_URL);
        redisHasPassword = Boolean(parsedRedisUrl.password);
    }
} catch (_) {
    redisHasPassword = false;
}

if (!redisHasPassword) {
    console.error('[FATAL] Insecure or missing REDIS_URL: must be provided and contain password authentication (redis://[:password]@host:port).');
    process.exit(1);
}

if (!process.env.ADMIN_PASSWORD_HASH) {
    console.warn('[SECURITY WARNING] ADMIN_PASSWORD_HASH is unset; admin login via password will be unavailable.');
}

const trustProxy = process.env.TRUST_PROXY?.toLowerCase() === 'true';
console.log(`[SECURITY] Client IP resolution: X-Forwarded-For is ${trustProxy ? 'TRUSTED (TRUST_PROXY=true)' : 'IGNORED (direct connection, TRUST_PROXY=false)'}`);

const securityHeaders = require('./middleware/security_headers');
const { createRateLimiter } = require('./middleware/rate_limit');

// CORS configuration (Express and Socket.io)
const DEFAULT_CORS_ORIGINS = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:4000',
    'http://127.0.0.1:4000',
];
const allowedCorsOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : DEFAULT_CORS_ORIGINS;

const rejectedCorsOrigins = new Set();

const corsOriginDelegate = (origin, callback) => {
    // Requests without an Origin header (curl, ML service) must keep working
    if (!origin) {
        return callback(null, true);
    }
    if (allowedCorsOrigins.includes(origin)) {
        return callback(null, true);
    }
    // Disallowed origins get no CORS headers; log one line per distinct rejected origin
    if (!rejectedCorsOrigins.has(origin)) {
        rejectedCorsOrigins.add(origin);
        console.warn(`[CORS] Rejected disallowed origin: ${origin}`);
    }
    return callback(null, false);
};

const corsOptions = {
    origin: corsOriginDelegate,
    credentials: true,
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: corsOriginDelegate,
        credentials: true,
    }
});

app.use(securityHeaders);
app.use(cors(corsOptions));
app.use(express.json());

// General API rate limiter (sliding 60 s window, default 600 req/min)
app.use('/api', createRateLimiter());

// Socket.io JWT handshake authentication & admin role check
io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, '')?.trim();
    if (!token) {
        return next(new Error('Authentication error: No token provided'));
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = decoded;
        if (decoded.role !== 'admin') {
            return next(new Error(`Forbidden for role ${decoded.role || 'unknown'}`));
        }
        next();
    } catch (err) {
        return next(new Error('Authentication error: Session expired or invalid token'));
    }
});

io.on('connection', (socket) => {
    console.log(`[SOCKET] Client connected: ${socket.id} (user: ${socket.user?.username || 'anonymous'})`);
    
    socket.on('disconnect', (reason) => {
        console.log(`[SOCKET] Client disconnected: ${socket.id}, Reason: ${reason}`);
    });
});

// Redis Client
const redisClient = createClient({
    url: process.env.REDIS_URL,
    socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 2000)
    }
});
redisClient.on('error', err => console.error('[Redis Client Error]', err));

// Make redisClient and io available to routes
app.set('io', io);
app.use((req, res, next) => {
    req.redisClient = redisClient;
    req.io = io;
    next();
});

// Import routes
const authRoutes = require('./routes/auth');
const rulesRoutes = require('./routes/rules');
const statsRoutes = require('./routes/stats');
const anomaliesRoutes = require('./routes/anomalies');
const mlRoutes = require('./routes/ml');
const logsRoutes = require('./routes/logs');
const captureRoutes = require('./routes/capture');
const reportRoutes = require('./routes/report');
const allowlistRoutes = require('./routes/allowlist');
const auditRoutes = require('./routes/audit');
const healthRoutes = require('./routes/health');
const engineManager = require('./services/engine_manager');
const { sweepExpired } = require('./services/blocklist_store');
const { CONFIG } = require('./services/block_policy');

app.use('/api/auth', authRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/allowlist', allowlistRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/health', healthRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/threads', statsRoutes);
app.use('/api/anomalies', anomaliesRoutes);
app.use('/api/ml', mlRoutes);
app.use('/api/logs', logsRoutes);
app.use('/api/capture', captureRoutes);
app.use('/api/report', reportRoutes);

// Static frontend serving and SPA fallback
const distPath = path.resolve(__dirname, '../frontend/dist');
app.use(express.static(distPath));

app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/socket.io')) {
        return next();
    }
    res.sendFile(path.join(distPath, 'index.html'));
});

const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || '127.0.0.1';

async function start() {
    try {
        await redisClient.connect();
        console.log('[REDIS] Connected');

        // Startup sweep: remove any blocks that expired while middleware was down
        try {
            const initialExpired = await sweepExpired({ redisClient, io });
            console.log(`[SWEEPER] Startup sweep completed: ${initialExpired.length} expired block(s) removed`);
        } catch (sweepErr) {
            console.error('[SWEEPER] Startup sweep error:', sweepErr);
        }

        // Periodic sweeper for expired block rules
        setInterval(async () => {
            try {
                await sweepExpired({ redisClient, io });
            } catch (err) {
                console.error('[SWEEPER] Periodic sweep error:', err);
            }
        }, CONFIG.BLOCK_SWEEP_INTERVAL_MS);

        // Periodically trim dpi:logs stream every 30s (approximate trim to DPI_LOGS_MAXLEN entries, default: 200,000)
        const DPI_LOGS_MAXLEN = parseInt(process.env.DPI_LOGS_MAXLEN, 10) || 200000;
        setInterval(async () => {
            try {
                await redisClient.xTrim('dpi:logs', 'MAXLEN', DPI_LOGS_MAXLEN, { strategyModifier: '~' });
            } catch (err) {
                console.error('[Redis Trim Error] Failed to trim dpi:logs:', err);
            }
        }, 30000);
        
        // Start Redis Consumer for Socket.io relay
        const { startRedisConsumer } = require('./services/redis_consumer');
        startRedisConsumer(io, process.env.REDIS_URL);
        
        server.listen(PORT, HOST, () => {
            console.log(`[SERVER] Running on http://${HOST}:${PORT}`);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
    }
}

start();

// Shutdown hook: call engineManager.stop() and wait up to 5s for engine to exit
const gracefulShutdown = async (signal) => {
    console.log(`[SERVER] Received ${signal}, exiting...`);
    const timeout = setTimeout(() => {
        console.warn('[SERVER] Shutdown timed out after 5s, forcing exit');
        process.exit(0);
    }, 5000);
    timeout.unref();

    try {
        console.log('[SERVER] Stopping managed engine if running...');
        await Promise.race([
            engineManager.stop(),
            new Promise((resolve) => setTimeout(resolve, 5000))
        ]);
    } catch (err) {
        console.error('[SERVER] Error stopping engine on shutdown:', err);
    }
    process.exit(0);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

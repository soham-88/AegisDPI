const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { createClient } = require('redis');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

app.use(cors());
app.use(express.json());

// Socket.io JWT handshake authentication
io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, '')?.trim();
    if (!token) {
        return next(new Error('Authentication error: No token provided'));
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = decoded;
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
const redisClient = createClient({ url: process.env.REDIS_URL });
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
const engineManager = require('./services/engine_manager');

app.use('/api/auth', authRoutes);
app.use('/api/rules', rulesRoutes);
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

        // Periodically trim dpi:logs stream every 30s (approximate trim to 20,000 entries)
        setInterval(async () => {
            try {
                await redisClient.xTrim('dpi:logs', 'MAXLEN', 20000, { strategyModifier: '~' });
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

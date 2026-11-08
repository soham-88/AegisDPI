const { createClient, commandOptions } = require('redis');

async function startRedisConsumer(io, redisUrl) {
    const redisClient = createClient({
        url: redisUrl,
        socket: {
            reconnectStrategy: (retries) => Math.min(retries * 50, 2000)
        }
    });
    redisClient.on('error', err => console.error('[Redis Consumer Client Error]', err));
    await redisClient.connect();

    const subClient = createClient({
        url: redisUrl,
        socket: {
            reconnectStrategy: (retries) => Math.min(retries * 50, 2000)
        }
    });
    subClient.on('error', err => console.error('[Redis Sub Client Error]', err));
    await subClient.connect();

    // 1. Subscribe to stats updates
    await subClient.subscribe('dpi:stats:updated', () => {
        io.emit('stats:update', { message: 'New stats available' });
    });

    // Subscribe to ML verdicts and forward to frontend via Socket.io
    await subClient.subscribe('ml:verdicts', (message) => {
        try {
            const verdict = JSON.parse(message);
            io.emit('anomaly:new', verdict);
        } catch (e) {
            console.error('[Redis Consumer] Failed to parse ml:verdicts message:', e);
        }
    });

    // 2. Consume logs stream with batched relay (at most every 250ms, max 200 entries, keep newest)
    let lastId = '$'; // Start consuming new messages only
    let logBuffer = [];
    let skippedCounter = 0;

    function flushBatch() {
        if (logBuffer.length === 0) return;

        let batch = [];
        let skipped = skippedCounter;
        if (logBuffer.length > 200) {
            skipped += (logBuffer.length - 200);
            batch = logBuffer.slice(-200);
        } else {
            batch = logBuffer;
        }

        logBuffer = [];
        skippedCounter = 0;

        io.emit('log:batch', { logs: batch, batch, skipped });
    }

    setInterval(flushBatch, 250);

    // Create the stream if it doesn't exist to avoid NOAUTH/NOGROUP errors in XREAD
    try {
        await redisClient.xAdd('dpi:logs', '*', { init: '1' });
    } catch(e) {}

    async function consumeLogs() {
        while (true) {
            try {
                // XREAD BLOCK 0 STREAMS dpi:logs lastId
                const response = await redisClient.xRead(
                    commandOptions({ isolated: true }),
                    [
                        { key: 'dpi:logs', id: lastId }
                    ],
                    { BLOCK: 0, COUNT: 200 }
                );

                if (response && response.length > 0) {
                    const stream = response[0];
                    const messages = stream.messages;
                    
                    for (const msg of messages) {
                        lastId = msg.id;
                        // Omit the initialization message
                        if (!msg.message.init) {
                            logBuffer.push({ ...msg.message, stream_id: msg.id });
                        }
                    }

                    // Protect memory from unbounded growth during massive floods
                    if (logBuffer.length > 5000) {
                        skippedCounter += (logBuffer.length - 1000);
                        logBuffer = logBuffer.slice(-1000);
                    }
                }
            } catch (err) {
                console.error('[Redis Consumer] Error reading stream:', err);
                await new Promise(res => setTimeout(res, 1000));
            }
        }
    }

    // Run in background
    consumeLogs();
}

module.exports = { startRedisConsumer };

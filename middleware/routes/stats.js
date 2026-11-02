const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.use(auth);

// Helper to construct threads array from Redis hash
function buildThreadsList(stats) {
    const threads = [];
    
    // 2 Load Balancers (LB[0], LB[1])
    for (let i = 0; i < 2; i++) {
        const dispatched = parseInt(stats[`lb_${i}_dispatched`] || '0', 10);
        threads.push({
            thread_id: i,
            name: `LB[${i}]`,
            role: 'LB',
            packets_processed: dispatched,
            forwarded: 0,
            dropped: 0,
            unhandled: 0,
            pps_history: []
        });
    }

    // 4 Fast Path workers (FP[0] .. FP[3])
    for (let i = 0; i < 4; i++) {
        const processed = parseInt(stats[`fp_${i}_processed`] || '0', 10);
        const forwarded = parseInt(stats[`fp_${i}_forwarded`] || '0', 10);
        const dropped = parseInt(stats[`fp_${i}_dropped`] || '0', 10);
        const unhandled = parseInt(stats[`fp_${i}_unhandled`] || '0', 10);
        threads.push({
            thread_id: i,
            name: `FP[${i}]`,
            role: 'FAST_PATH',
            packets_processed: processed,
            forwarded,
            dropped,
            unhandled,
            pps_history: []
        });
    }

    return threads;
}

// GET /api/stats/summary
router.get('/summary', async (req, res) => {
    try {
        const stats = await req.redisClient.hGetAll('dpi:stats');
        const threads = buildThreadsList(stats);

        // Reconcile top-level counts directly with FP worker sums
        const fpThreads = threads.filter(t => t.role === 'FAST_PATH');
        const sumFwd = fpThreads.reduce((sum, t) => sum + t.forwarded, 0);
        const sumDrp = fpThreads.reduce((sum, t) => sum + t.dropped, 0);
        const sumUnh = fpThreads.reduce((sum, t) => sum + t.unhandled, 0);

        const hasActiveFP = fpThreads.some(t => t.packets_processed > 0);
        const forwarded = hasActiveFP ? sumFwd : parseInt(stats.forwarded || '0', 10);
        const dropped = hasActiveFP ? sumDrp : parseInt(stats.dropped || '0', 10);
        const unhandled = hasActiveFP ? sumUnh : parseInt(stats.unhandled || '0', 10);

        res.json({
            forwarded,
            dropped,
            unhandled,
            interface: stats.interface || 'offline',
            engine_pid: parseInt(stats.engine_pid || '0', 10),
            started_at: parseInt(stats.started_at || '0', 10),
            bytes_total: parseInt(stats.bytes_total || '0', 10),
            pcap_recv: parseInt(stats.pcap_recv || '0', 10),
            pcap_drop: parseInt(stats.pcap_drop || '0', 10),
            pcap_ifdrop: parseInt(stats.pcap_ifdrop || '0', 10),
            updated_at_ms: parseInt(stats.updated_at_ms || '0', 10),
            proto_tls: parseInt(stats.proto_tls || '0', 10),
            proto_http: parseInt(stats.proto_http || '0', 10),
            proto_tcp_ctrl: parseInt(stats.proto_tcp_ctrl || '0', 10),
            proto_tcp_other: parseInt(stats.proto_tcp_other || '0', 10),
            tls_sni_seen: parseInt(stats.tls_sni_seen || '0', 10),
            threads
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// GET /api/stats/threads
router.get('/threads', async (req, res) => {
    try {
        const stats = await req.redisClient.hGetAll('dpi:stats');
        const threads = buildThreadsList(stats);
        res.json(threads);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch thread stats' });
    }
});

// GET / (alias if mounted directly at /api/threads)
router.get('/', async (req, res) => {
    try {
        const stats = await req.redisClient.hGetAll('dpi:stats');
        const threads = buildThreadsList(stats);
        res.json(threads);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch thread stats' });
    }
});

module.exports = router;

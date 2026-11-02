const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.use(auth);

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000';

// GET /api/report
router.get('/', async (req, res) => {
    try {
        // Read everything from ONE snapshot
        const mlPromise = (async () => {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 2000);
            try {
                const response = await fetch(`${ML_SERVICE_URL}/model/status`, {
                    signal: controller.signal
                });
                clearTimeout(timeout);
                if (response.ok) {
                    const data = await response.json();
                    return { online: true, ...data };
                }
                return { online: false };
            } catch (err) {
                clearTimeout(timeout);
                return { online: false };
            }
        })();

        const [stats, blocklistIps, rawVerdictHistory, mlStatus] = await Promise.all([
            req.redisClient.hGetAll('dpi:stats'),
            req.redisClient.sMembers('blocklist:ips'),
            req.redisClient.xRevRange('ml:verdict_history', '+', '-'),
            mlPromise
        ]);

        const generated_at = new Date().toISOString();

        // Engine metadata
        const started_at = parseInt(stats.started_at || '0', 10);
        const updated_at_ms = parseInt(stats.updated_at_ms || '0', 10);
        const now = Date.now();
        const isRunning = updated_at_ms > 0 && (now - updated_at_ms < 5000);
        const state = isRunning ? 'running' : 'stopped';

        const started_at_sec = started_at > 1e11 ? Math.floor(started_at / 1000) : started_at;
        const updated_at_sec = Math.floor(updated_at_ms / 1000);
        const session_seconds = (started_at_sec > 0 && updated_at_sec >= started_at_sec)
            ? (updated_at_sec - started_at_sec)
            : 0;

        const engine = {
            interface: stats.interface || 'offline',
            engine_pid: parseInt(stats.engine_pid || '0', 10),
            started_at,
            last_update: updated_at_ms,
            state,
            session_seconds
        };

        // Traffic totals
        const forwarded = parseInt(stats.forwarded || '0', 10);
        const dropped = parseInt(stats.dropped || '0', 10);
        const unhandled = parseInt(stats.unhandled || '0', 10);
        const total_inspected = forwarded + dropped + unhandled;
        const bytes_total = parseInt(stats.bytes_total || '0', 10);
        const pcap_recv = parseInt(stats.pcap_recv || '0', 10);
        const pcap_drop = parseInt(stats.pcap_drop || '0', 10);
        const pcap_ifdrop = parseInt(stats.pcap_ifdrop || '0', 10);

        const avg_pps = session_seconds > 0 ? Math.round(total_inspected / session_seconds) : 0;
        const avg_mbps = session_seconds > 0 ? +(((bytes_total * 8) / session_seconds) / 1e6).toFixed(2) : 0;

        const traffic = {
            total_inspected,
            forwarded,
            dropped,
            unhandled,
            bytes_total,
            pcap_recv,
            pcap_drop,
            pcap_ifdrop,
            avg_pps,
            avg_mbps
        };

        // Protocol mix
        const proto_tls = parseInt(stats.proto_tls || '0', 10);
        const proto_http = parseInt(stats.proto_http || '0', 10);
        const proto_tcp_ctrl = parseInt(stats.proto_tcp_ctrl || '0', 10);
        const proto_tcp_other = parseInt(stats.proto_tcp_other || '0', 10);
        const tls_sni_seen = parseInt(stats.tls_sni_seen || '0', 10);

        const calcPct = (cnt) => total_inspected > 0 ? +((cnt / total_inspected) * 100).toFixed(1) : 0;

        const protocol_mix = {
            classes: [
                { name: 'TLS records', count: proto_tls, percentage: calcPct(proto_tls) },
                { name: 'HTTP', count: proto_http, percentage: calcPct(proto_http) },
                { name: 'TCP control (no payload)', count: proto_tcp_ctrl, percentage: calcPct(proto_tcp_ctrl) },
                { name: 'TCP other payload', count: proto_tcp_other, percentage: calcPct(proto_tcp_other) },
                { name: 'Non-TCP', count: unhandled, percentage: calcPct(unhandled) },
                { name: 'Dropped', count: dropped, percentage: calcPct(dropped) }
            ],
            tls_sni_seen
        };

        // Threads
        const lbs = [];
        for (let i = 0; ; i++) {
            const key = `lb_${i}_dispatched`;
            if (!(key in stats)) {
                if (i < 2 && Object.keys(stats).length === 0) {
                    lbs.push({ thread_id: i, name: `LB[${i}]`, dispatched: 0 });
                    continue;
                }
                break;
            }
            lbs.push({
                thread_id: i,
                name: `LB[${i}]`,
                dispatched: parseInt(stats[key] || '0', 10)
            });
        }

        const fps = [];
        for (let i = 0; ; i++) {
            const key = `fp_${i}_processed`;
            if (!(key in stats)) {
                if (i < 4 && Object.keys(stats).length === 0) {
                    fps.push({
                        thread_id: i,
                        name: `FP[${i}]`,
                        processed: 0,
                        forwarded: 0,
                        dropped: 0,
                        unhandled: 0
                    });
                    continue;
                }
                break;
            }
            fps.push({
                thread_id: i,
                name: `FP[${i}]`,
                processed: parseInt(stats[key] || '0', 10),
                forwarded: parseInt(stats[`fp_${i}_forwarded`] || '0', 10),
                dropped: parseInt(stats[`fp_${i}_dropped`] || '0', 10),
                unhandled: parseInt(stats[`fp_${i}_unhandled`] || '0', 10)
            });
        }

        const lb_total = lbs.reduce((sum, t) => sum + t.dispatched, 0);
        const fp_total = fps.reduce((sum, t) => sum + t.processed, 0);

        const threads = {
            lbs,
            fps,
            lb_total,
            fp_total
        };

        // Consistency checks
        const sum_lb_dispatched = lb_total;
        const sum_fp_processed = fp_total;
        const sum_fp_forwarded = fps.reduce((sum, t) => sum + t.forwarded, 0);
        const sum_fp_dropped = fps.reduce((sum, t) => sum + t.dropped, 0);
        const sum_fp_unhandled = fps.reduce((sum, t) => sum + t.unhandled, 0);
        const sum_forwarded_dropped_unhandled = forwarded + dropped + unhandled;
        const sum_tcp_protos = proto_tls + proto_http + proto_tcp_ctrl + proto_tcp_other;

        const checks = [
            {
                name: 'sum(lb_i_dispatched) == sum(fp_i_processed)',
                left: sum_lb_dispatched,
                right: sum_fp_processed,
                pass: sum_lb_dispatched === sum_fp_processed
            },
            {
                name: 'sum(fp_i_processed) == forwarded + dropped + unhandled',
                left: sum_fp_processed,
                right: sum_forwarded_dropped_unhandled,
                pass: sum_fp_processed === sum_forwarded_dropped_unhandled
            },
            {
                name: 'sum(fp_i_forwarded) == forwarded',
                left: sum_fp_forwarded,
                right: forwarded,
                pass: sum_fp_forwarded === forwarded
            },
            {
                name: 'sum(fp_i_dropped) == dropped',
                left: sum_fp_dropped,
                right: dropped,
                pass: sum_fp_dropped === dropped
            },
            {
                name: 'sum(fp_i_unhandled) == unhandled',
                left: sum_fp_unhandled,
                right: unhandled,
                pass: sum_fp_unhandled === unhandled
            },
            {
                name: 'proto_tls + proto_http + proto_tcp_ctrl + proto_tcp_other == forwarded',
                left: sum_tcp_protos,
                right: forwarded,
                pass: sum_tcp_protos === forwarded
            },
            {
                name: 'Kernel delivered (pcap_recv) vs engine inspected',
                left: pcap_recv,
                right: total_inspected,
                diff: pcap_recv - total_inspected,
                is_info: true,
                pass: null,
                note: 'pcap counters are sampled separately; small differences while running are expected'
            }
        ];

        // Blocklist
        const blocklist = (blocklistIps || []).sort();

        // Anomalies
        const started_at_ms = started_at_sec > 0 ? started_at_sec * 1000 : 0;
        const allParsedAnomalies = (rawVerdictHistory || []).map(entry => {
            let payload = null;
            try {
                if (entry.message && entry.message.data) {
                    payload = JSON.parse(entry.message.data);
                } else if (entry.message) {
                    payload = typeof entry.message === 'string' ? JSON.parse(entry.message) : entry.message;
                }
            } catch (e) {}
            if (!payload) return null;

            let timeMs = 0;
            if (payload.timestamp) {
                timeMs = new Date(payload.timestamp).getTime();
            }
            if ((!timeMs || isNaN(timeMs)) && entry.id) {
                timeMs = parseInt(entry.id.split('-')[0], 10) || 0;
            }

            let top_feature = '-';
            if (Array.isArray(payload.features) && payload.features.length > 0) {
                const sorted = [...payload.features].sort((a, b) =>
                    (b.deviation || b.contribution || 0) - (a.deviation || a.contribution || 0)
                );
                top_feature = sorted[0].name || '-';
            }

            return {
                id: payload.id || entry.id,
                time: payload.timestamp || (timeMs > 0 ? new Date(timeMs).toISOString() : '-'),
                timeMs,
                src: payload.source_ip || payload.src_ip || '-',
                dst: payload.dest_ip || payload.dest_ip || '-',
                verdict: payload.verdict || 'ANOMALOUS',
                confidence: typeof payload.confidence === 'number' ? payload.confidence : 0,
                mitigated: Boolean(payload.auto_mitigated ?? payload.mitigated),
                top_feature,
                telegram_alert: payload.telegram_alert || null
            };
        }).filter(Boolean);

        const thisSessionAnomalies = started_at_ms > 0
            ? allParsedAnomalies.filter(a => a.timeMs >= started_at_ms)
            : [];

        const anomalies = {
            this_session_count: thisSessionAnomalies.length,
            total_history_count: allParsedAnomalies.length,
            list: thisSessionAnomalies.slice(0, 50).map(({ time, src, dst, verdict, confidence, mitigated, top_feature, telegram_alert }) => ({
                time,
                src,
                dst,
                verdict,
                confidence,
                mitigated,
                top_feature,
                telegram_alert: telegram_alert || null
            }))
        };

        // ML info
        const ml = {
            model_type: mlStatus.model_type || (mlStatus.online ? 'IsolationForest' : 'N/A'),
            feature_count: Array.isArray(mlStatus.feature_schema) ? mlStatus.feature_schema.length : (mlStatus.online ? 5 : 0),
            auto_mitigate: Boolean(mlStatus.auto_mitigate),
            threshold: 0.85,
            online: Boolean(mlStatus.online)
        };

        res.json({
            generated_at,
            engine,
            traffic,
            protocol_mix,
            threads,
            checks,
            blocklist,
            anomalies,
            ml
        });
    } catch (err) {
        console.error('[Report Route Error]', err);
        res.status(500).json({ error: 'Failed to generate session report' });
    }
});

module.exports = router;

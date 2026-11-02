const os = require('os');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class EngineManager {
    constructor() {
        this.child = null;
        this.pid = null;
        this.iface = null;
        this.startedAt = null;
        this.lastExitCode = null;
        this.lastError = null;
        this.lastExitAtMs = 0;
        this.state = 'stopped'; // 'stopped' | 'starting' | 'running' | 'stopping' | 'external'
        this._starting = false;
        this.logBuffer = []; // Max 200 lines
    }

    listInterfaces() {
        const ifaces = os.networkInterfaces();
        const list = [];
        for (const [name, addrs] of Object.entries(ifaces)) {
            if (!addrs) continue;
            for (const addr of addrs) {
                if (addr.family === 'IPv4' && !addr.internal) {
                    list.push({ name, ip: addr.address });
                }
            }
        }
        return list;
    }

    _appendLog(chunk) {
        const lines = chunk.toString().split('\n');
        for (const line of lines) {
            if (line.trim()) {
                this.logBuffer.push(line);
                if (this.logBuffer.length > 200) {
                    this.logBuffer.shift();
                }
            }
        }
    }

    async getStatus(redisClient) {
        const isControlEnabled = process.env.ENGINE_CONTROL_ENABLED === 'true';
        let isRedisFresh = false;
        let isExternalEngine = false;
        let redisIface = null;
        let redisEnginePid = null;

        if (redisClient) {
            try {
                const updatedAt = Number(await redisClient.hGet('dpi:stats', 'updated_at_ms')) || 0;
                isRedisFresh = (Date.now() - updatedAt) < 5000;
                isExternalEngine = isRedisFresh && (updatedAt > this.lastExitAtMs);
                redisIface = await redisClient.hGet('dpi:stats', 'interface');
                if (isRedisFresh) {
                    const rawPid = await redisClient.hGet('dpi:stats', 'engine_pid');
                    if (rawPid !== null && rawPid !== undefined && rawPid !== '') {
                        const parsedPid = Number(rawPid);
                        redisEnginePid = !isNaN(parsedPid) ? parsedPid : null;
                    }
                }
            } catch {
                // Ignore redis read errors
            }
        }

        let currentState = this.state;
        if (this.child) {
            if (this.state === 'stopping') {
                currentState = 'stopping';
            } else if (isRedisFresh) {
                this.state = 'running';
                currentState = 'running';
            } else {
                currentState = 'starting';
            }
        } else {
            if (isExternalEngine) {
                currentState = 'external';
            } else {
                this.state = 'stopped';
                currentState = 'stopped';
            }
        }

        return {
            state: currentState,
            iface: this.child ? this.iface : (currentState === 'external' ? redisIface : null),
            pid: this.pid,
            engine_pid: redisEnginePid,
            started_at: this.startedAt,
            last_exit_code: this.lastExitCode,
            last_error: this.lastError,
            control_enabled: isControlEnabled,
            logs: this.logBuffer.slice(-20)
        };
    }

    async start(iface, redisClient) {
        if (this._starting) {
            throw new Error('start already in progress');
        }
        this._starting = true;

        try {
            if (process.env.ENGINE_CONTROL_ENABLED !== 'true') {
                throw new Error('capture control disabled');
            }

            const engineBin = process.env.ENGINE_BIN;
            if (!engineBin || !engineBin.trim()) {
                throw new Error('ENGINE_BIN is not set');
            }

            // Validate interface regex and existence in listInterfaces()
            if (!/^[A-Za-z0-9_.-]{1,15}$/.test(iface)) {
                throw new Error(`Invalid interface name format: ${iface}`);
            }
            const available = this.listInterfaces();
            if (!available.some(i => i.name === iface)) {
                throw new Error(`Interface ${iface} not found among available network interfaces`);
            }

            // Refuse if managed or external engine is already running
            if (this.child) {
                throw new Error('A managed engine process is already running');
            }
            if (redisClient) {
                const updatedAt = Number(await redisClient.hGet('dpi:stats', 'updated_at_ms')) || 0;
                if ((Date.now() - updatedAt < 5000) && (updatedAt > this.lastExitAtMs)) {
                    throw new Error('An external engine is currently running on the system');
                }
            }

            const extraArgsStr = process.env.ENGINE_EXTRA_ARGS || '--lbs 2 --fps 4 --redis-host 127.0.0.1';
            const extraArgs = extraArgsStr.trim().split(/\s+/).filter(Boolean);

            this.logBuffer = [];
            this.state = 'starting';
            this.iface = iface;
            this.startedAt = Date.now();
            this.lastExitCode = null;
            this.lastError = null;

                        // Hand the Redis password to the engine via a private file:
            // sudo strips env vars, and CLI args are visible in `ps`.
            let redisPassword = '';
            try {
                redisPassword = decodeURIComponent(new URL(process.env.REDIS_URL || '').password || '');
            } catch (_) { /* malformed REDIS_URL -> engine connects without auth */ }
            const pwFile = path.join(__dirname, '..', '..', 'run', 'redis.pass');
            fs.mkdirSync(path.dirname(pwFile), { recursive: true });
            fs.writeFileSync(pwFile, redisPassword + '\n', { mode: 0o600 });
            fs.chmodSync(pwFile, 0o600);

            const args = ['-n', engineBin, '--live', iface, '--redis-password-file', pwFile, ...extraArgs];
            const child = spawn('sudo', args, { shell: false });
            this.child = child;
            this.pid = child.pid;

            child.stdout.on('data', (d) => this._appendLog(d));
            child.stderr.on('data', (d) => {
                this._appendLog(d);
                const str = d.toString().toLowerCase();
                if (
                    str.includes('interactive authentication is required') ||
                    str.includes('a password is required') ||
                    str.includes('a terminal is required') ||
                    str.includes('not allowed to execute')
                ) {
                    this.lastError = 'sudo rule missing or does not match ENGINE_BIN - re-create /etc/sudoers.d/aegis-engine for the path in ENGINE_BIN';
                }
            });

            child.on('error', (err) => {
                this.lastExitAtMs = Date.now();
                this.lastError = `Failed to spawn engine: ${err.message}`;
                this.state = 'stopped';
                this.child = null;
                this.pid = null;
            });

            child.on('exit', (code, signal) => {
                this.lastExitAtMs = Date.now();
                this.lastExitCode = code !== null ? code : signal;
                // If the state was 'stopping' (user asked for it), do NOT set last_error
                if (this.state !== 'stopping' && code !== 0 && code !== null && !this.lastError) {
                    this.lastError = `Engine exited unexpectedly with code ${code}`;
                }
                this.state = 'stopped';
                this.child = null;
                this.pid = null;
            });

            return await this.getStatus(redisClient);
        } finally {
            this._starting = false;
        }
    }

    async stop(redisClient) {
        if (process.env.ENGINE_CONTROL_ENABLED !== 'true') {
            throw new Error('capture control disabled');
        }

        if (!this.child) {
            return await this.getStatus(redisClient);
        }

        this.state = 'stopping';
        const child = this.child;

        return new Promise((resolve) => {
            let termTimer = null;

            const onExit = () => {
                if (termTimer) clearTimeout(termTimer);
                this.state = 'stopped';
                this.child = null;
                this.pid = null;
                this.getStatus(redisClient).then(resolve);
            };

            child.once('exit', onExit);

            // 1. Send SIGINT for clean nftables teardown
            try {
                child.kill('SIGINT');
            } catch (err) {
                this.lastError = `Error sending SIGINT: ${err.message}`;
            }

            // 2. Escalate to SIGTERM after 8s if still alive (never SIGKILL)
            termTimer = setTimeout(() => {
                if (this.child) {
                    try {
                        this.child.kill('SIGTERM');
                    } catch {}
                }
            }, 8000);
        });
    }
}

const engineManager = new EngineManager();
module.exports = engineManager;

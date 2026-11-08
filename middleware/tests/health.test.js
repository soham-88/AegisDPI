const test = require('node:test');
const assert = require('node:assert/strict');
const { buildHealthPayload } = require('../services/health_check');

test('buildHealthPayload: all healthy returns ok, online, and fresh stats', () => {
    const now = 1700000000000;
    const payload = buildHealthPayload({
        redisPingOk: true,
        mlStatusOk: true,
        engineState: 'running',
        engineUpdatedAtMs: now - 1000,
        nowMs: now,
        freshnessWindowMs: 5000
    });

    assert.deepEqual(payload, {
        redis: 'ok',
        ml: 'online',
        engine: 'running',
        engine_stats_fresh: true
    });
});

test('buildHealthPayload: redis down marks redis down and stats not fresh', () => {
    const now = 1700000000000;
    const payload = buildHealthPayload({
        redisPingOk: false,
        mlStatusOk: true,
        engineState: 'running',
        engineUpdatedAtMs: now - 1000,
        nowMs: now
    });

    assert.deepEqual(payload, {
        redis: 'down',
        ml: 'online',
        engine: 'running',
        engine_stats_fresh: false
    });
});

test('buildHealthPayload: ml offline marks ml offline', () => {
    const now = 1700000000000;
    const payload = buildHealthPayload({
        redisPingOk: true,
        mlStatusOk: false,
        engineState: 'external',
        engineUpdatedAtMs: now - 2000,
        nowMs: now
    });

    assert.deepEqual(payload, {
        redis: 'ok',
        ml: 'offline',
        engine: 'external',
        engine_stats_fresh: true
    });
});

test('buildHealthPayload: stale engine stats marked as not fresh', () => {
    const now = 1700000000000;
    const payload = buildHealthPayload({
        redisPingOk: true,
        mlStatusOk: true,
        engineState: 'stopped',
        engineUpdatedAtMs: now - 8000,
        nowMs: now,
        freshnessWindowMs: 5000
    });

    assert.deepEqual(payload, {
        redis: 'ok',
        ml: 'online',
        engine: 'stopped',
        engine_stats_fresh: false
    });
});

test('buildHealthPayload: default parameters handle missing inputs safely', () => {
    const payload = buildHealthPayload();

    assert.deepEqual(payload, {
        redis: 'down',
        ml: 'offline',
        engine: 'stopped',
        engine_stats_fresh: false
    });
});


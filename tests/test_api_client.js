'use strict';

const assert = require('assert');
const path = require('path');
const api = require(path.join(__dirname, '..', 'api.js'));

function testResolveBaseUrl() {
  delete global.VERITAS_API_BASE;
  assert.strictEqual(api.resolveBaseUrl(), 'http://localhost:8000');
  assert.strictEqual(api.resolveBaseUrl('http://127.0.0.1:8000/'), 'http://127.0.0.1:8000');
  global.VERITAS_API_BASE = 'http://127.0.0.1:8001';
  assert.strictEqual(api.resolveBaseUrl(), 'http://127.0.0.1:8001');
  delete global.VERITAS_API_BASE;
}

function testNoSecretsOnClient() {
  const serialized = JSON.stringify(api);
  assert.doesNotMatch(serialized, /API_KEY|VERITAS_API_KEY|AEGIS_API_KEY|Bearer /);
  assert.strictEqual(typeof api.inspectCode, 'function');
  assert.strictEqual(typeof api.filterThreat, 'undefined');
}

function testMapInspectCode() {
  const mapped = api.mapInspectCode({
    analysis_id: 'abc123',
    analyzed_at: '2026-11-12T00:00:00+00:00',
    language: 'python',
    trust_score: 88.5,
    verification_status: 'SECURE',
    confidence_index: 91.2,
    threat_breakdown: {
      injection_risk: 0,
      obfuscation_risk: 12.5,
      entropy_risk: 40,
      syntax_risk: 0
    },
    syntax_errors: [],
    anomaly_flags: [],
    analysis_logs: ['Trust engine verdict: SECURE at 88.50/100.']
  });
  assert.strictEqual(mapped.source, 'backend');
  assert.strictEqual(mapped.endpoint, '/api/v1/inspect-code');
  assert.strictEqual(mapped.score, 88.5);
  assert.strictEqual(mapped.status, 'safe');
  assert.strictEqual(mapped.statusText, 'SECURE');
  assert.strictEqual(mapped.confidencePercent, 91.2);
  assert.strictEqual(mapped.signals[0][0], 'Injection risk');
  assert.strictEqual(mapped.signals[0][1], 0);
}

function testMapFilterThreat() {
  const mapped = api.mapFilterThreat({
    analysis_id: 'def456',
    action: 'BLOCK',
    threat_level_index: 92,
    confidence_index: 88,
    summary: 'Threat policy blocked the payload before execution or delivery.',
    threat_breakdown: {
      file_integrity: 10,
      url_phishing: 80,
      code_injection: 0,
      process_anomaly: 0
    },
    policy_reasons: ['URL or network payload matched a hard-block signature'],
    forensic_logs: [{ message: 'javascript scheme blocked' }]
  });
  assert.strictEqual(mapped.source, 'backend');
  assert.strictEqual(mapped.status, 'danger');
  assert.strictEqual(mapped.statusText, 'BLOCK');
  assert.strictEqual(mapped.score, 8);
  assert.ok(mapped.caption.includes('blocked'));
}

function testInvalidApiResponse() {
  assert.throws(() => api.mapInspectCode({ trust_score: 10 }), /missing/);
  assert.throws(() => api.mapInspectCode({ trust_score: 10, verification_status: 'UNKNOWN' }), /unknown/);
  assert.throws(() => api.mapFilterThreat({ action: 'ALLOW' }), /missing/);
}

function testErrorClassification() {
  const auth = api.classifyHttpError(401, 'nope');
  assert.strictEqual(auth.code, 'auth');
  assert.doesNotMatch(auth.message, /nope/);
  const limited = api.classifyHttpError(429, 'slow down');
  assert.strictEqual(limited.code, 'rate_limited');
  const large = api.classifyHttpError(413, 'uploaded file exceeds the 25 MB evidence limit.');
  assert.strictEqual(large.code, 'too_large');
  const invalid = api.classifyHttpError(422, 'source_code cannot be empty');
  assert.strictEqual(invalid.code, 'invalid_input');
}

function testErrorAndIdleAreNotBackendVerdicts() {
  const failed = api.errorResult(api.ApiError('unavailable', 'The analysis API is unavailable.', 0));
  assert.strictEqual(failed.source, 'error');
  assert.strictEqual(failed.backendError, true);
  assert.strictEqual(failed.score, 0);
  assert.strictEqual(failed.statusText, 'BACKEND UNAVAILABLE');
  const idle = api.idleResult();
  assert.strictEqual(idle.source, 'idle');
  assert.notStrictEqual(idle.source, 'backend');
}

function testHealthSuccessShape() {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ status: 'ok', service: 'veritas-inspector-analysis-core' })
  });
  return api.health().then((payload) => {
    assert.strictEqual(payload.status, 'ok');
    global.fetch = originalFetch;
  }).catch((error) => {
    global.fetch = originalFetch;
    throw error;
  });
}

function testOfflineHealth() {
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('ECONNREFUSED'); };
  return api.health().then(() => {
    global.fetch = originalFetch;
    throw new Error('expected unavailable');
  }).catch((error) => {
    global.fetch = originalFetch;
    if (error.message === 'expected unavailable') throw error;
    assert.strictEqual(error.code, 'unavailable');
  });
}

function testAuthFailureOnInspect() {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    text: async () => JSON.stringify({ detail: 'invalid or missing API key' })
  });
  return api.inspectCode('def add(a, b):\n    return a + b\n').then(() => {
    global.fetch = originalFetch;
    throw new Error('expected auth failure');
  }).catch((error) => {
    global.fetch = originalFetch;
    if (error.message === 'expected auth failure') throw error;
    assert.strictEqual(error.code, 'auth');
    assert.doesNotMatch(error.message, /invalid or missing API key/);
  });
}

function testRateLimitOnInspect() {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: false,
    status: 429,
    statusText: 'Too Many Requests',
    text: async () => JSON.stringify({ detail: 'rate limit exceeded' })
  });
  return api.inspectCode('print(1)\n').then(() => {
    global.fetch = originalFetch;
    throw new Error('expected rate limit');
  }).catch((error) => {
    global.fetch = originalFetch;
    if (error.message === 'expected rate limit') throw error;
    assert.strictEqual(error.code, 'rate_limited');
  });
}

function testTooLargeRejectedLocally() {
  const fakeFile = { name: 'huge.bin', size: 26 * 1024 * 1024 };
  return api.filterThreatFile(fakeFile).then(() => {
    throw new Error('expected too_large');
  }).catch((error) => {
    if (error.message === 'expected too_large') throw error;
    assert.strictEqual(error.code, 'too_large');
  });
}

async function main() {
  testResolveBaseUrl();
  testNoSecretsOnClient();
  testMapInspectCode();
  testMapFilterThreat();
  testInvalidApiResponse();
  testErrorClassification();
  testErrorAndIdleAreNotBackendVerdicts();
  await testHealthSuccessShape();
  await testOfflineHealth();
  await testAuthFailureOnInspect();
  await testRateLimitOnInspect();
  await testTooLargeRejectedLocally();
  console.log('api.js client tests passed');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

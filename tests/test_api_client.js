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
  assert.strictEqual(mapped.isVerdict, true);
  assert.strictEqual(mapped.endpoint, '/api/v1/inspect-code');
  assert.strictEqual(mapped.score, 88.5);
  assert.strictEqual(mapped.status, 'safe');
  assert.strictEqual(mapped.statusText, 'SECURE');
  assert.strictEqual(mapped.confidencePercent, 91.2);
  assert.strictEqual(mapped.signals[0][0], 'Injection risk');
  assert.strictEqual(mapped.signals[0][1], 0);
  assert.strictEqual(mapped.signals[0][2], 'safe');
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
  assert.strictEqual(mapped.signals[0][0], 'File integrity risk');
  assert.strictEqual(mapped.signals[0][2], 'safe');
  assert.strictEqual(mapped.signals[1][0], 'URL phishing risk');
  assert.strictEqual(mapped.signals[1][2], 'danger');
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
  assert.strictEqual(failed.isVerdict, false);
  assert.strictEqual(failed.score, null);
  assert.strictEqual(failed.displayScore, '—');
  assert.strictEqual(failed.statusText, 'BACKEND UNAVAILABLE');
  const idle = api.idleResult();
  assert.strictEqual(idle.source, 'idle');
  assert.strictEqual(idle.isVerdict, false);
  assert.strictEqual(idle.score, null);
  assert.notStrictEqual(idle.source, 'backend');
}

function withPageLocation(location, fn) {
  const previousWindow = global.window;
  global.window = { location: location };
  try {
    return fn();
  } finally {
    if (previousWindow === undefined) delete global.window;
    else global.window = previousWindow;
  }
}

function testProductionPageNeverUsesLocalhost() {
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '' }, () => {
    delete global.VERITAS_API_BASE;
    assert.strictEqual(api.resolveBaseUrl(), '');
    assert.strictEqual(api.resolveBaseUrl('http://localhost:8000'), '');
    // P0 hardening: an arbitrary https host is NOT silently trusted.
    // It requires explicit user consent (covered in testUntrustedBaseRequiresExplicitConsent).
    assert.strictEqual(api.resolveBaseUrl('https://veritas-api.example.com'), '');
  });
}

function testMixedContentRejected() {
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '' }, () => {
    assert.strictEqual(api.isSafeApiBase('http://example.com:8000'), false);
    assert.strictEqual(api.isSafeApiBase('https://api.example.com'), true);
  });
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

function testToneForRiskThresholds() {
  assert.strictEqual(api.toneForRisk(null), 'review');
  assert.strictEqual(api.toneForRisk(undefined), 'review');
  assert.strictEqual(api.toneForRisk(0), 'safe');
  assert.strictEqual(api.toneForRisk(39.99), 'safe');
  assert.strictEqual(api.toneForRisk(40), 'review');
  assert.strictEqual(api.toneForRisk(74.99), 'review');
  assert.strictEqual(api.toneForRisk(75), 'danger');
  assert.strictEqual(api.toneForRisk(100), 'danger');
}

function testHighRiskSignalsUseDangerTone() {
  const mapped = api.mapInspectCode({
    analysis_id: 'high-risk',
    analyzed_at: '2026-11-12T00:00:00+00:00',
    language: 'python',
    trust_score: 12,
    verification_status: 'MALICIOUS',
    confidence_index: 88,
    threat_breakdown: {
      injection_risk: 91,
      obfuscation_risk: 40,
      entropy_risk: 22,
      syntax_risk: 8
    },
    syntax_errors: [],
    anomaly_flags: [],
    analysis_logs: ['Trust engine verdict: MALICIOUS at 12.00/100.']
  });
  assert.strictEqual(mapped.status, 'danger');
  assert.strictEqual(mapped.signals[0][2], 'danger');
  assert.strictEqual(mapped.signals[1][2], 'review');
  assert.strictEqual(mapped.signals[2][2], 'safe');
  assert.strictEqual(mapped.signals[3][2], 'safe');
}

function testIsConfigured() {
  delete global.VERITAS_API_BASE;
  assert.strictEqual(api.isConfigured(), true);
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '' }, () => {
    delete global.VERITAS_API_BASE;
    assert.strictEqual(api.isConfigured(), false);
    // P0 hardening: untrusted hosts are not configured without consent.
    assert.strictEqual(api.isConfigured('https://veritas-api.example.com'), false);
    assert.strictEqual(api.isConfigured('http://localhost:8000'), false);
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

// ---------------------------------------------------------------------------
// P0: API destination policy — untrusted hosts need explicit user consent
// ---------------------------------------------------------------------------

function withMetaTags(meta, fn) {
  const previousDocument = global.document;
  global.document = {
    querySelector(selector) {
      const match = /meta\[name="([^"]+)"\]/.exec(selector);
      const name = match ? match[1] : '';
      if (!(name in meta)) return null;
      return {
        getAttribute(attribute) {
          return attribute === 'content' ? meta[name] : null;
        }
      };
    }
  };
  try {
    return fn();
  } finally {
    if (previousDocument === undefined) delete global.document;
    else global.document = previousDocument;
  }
}

function testUntrustedBaseRequiresExplicitConsent() {
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '?apiBase=https://attacker.example' }, () => {
    delete global.VERITAS_API_BASE;
    // Consent denied (or no dialog available) -> the override is ignored.
    global.window.confirm = () => false;
    assert.strictEqual(api.resolveBaseUrl(), '');
    assert.strictEqual(api.isConfigured(), false);
    // The same override is honored only after explicit user consent.
    api.resetDestinationConsent();
    global.window.confirm = (message) => {
      assert.match(message, /attacker\.example/);
      return true;
    };
    assert.strictEqual(api.resolveBaseUrl(), 'https://attacker.example');
    const description = api.describeDestination();
    assert.strictEqual(description.base, 'https://attacker.example');
    assert.strictEqual(description.source, 'query');
    assert.strictEqual(description.trusted, false);
    assert.strictEqual(description.consented, true);
  });
  api.resetDestinationConsent();
}

function testConsentDeniedFallsBackToConfiguredProductionHost() {
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '?apiBase=https://attacker.example' }, () => {
    delete global.VERITAS_API_BASE;
    global.window.confirm = () => false;
    withMetaTags({ 'veritas-api-base-production': 'https://veritas-api.example.com' }, () => {
      // The deployment-configured production host is trusted without prompting.
      assert.strictEqual(api.isTrustedHost('veritas-api.example.com'), true);
      assert.strictEqual(api.isTrustedHost('attacker.example'), false);
      assert.strictEqual(api.resolveBaseUrl(), 'https://veritas-api.example.com');
    });
  });
  api.resetDestinationConsent();
}

function testLocalStorageOverrideGatedByConsent() {
  api.resetDestinationConsent();
  const previousStorage = global.localStorage;
  global.localStorage = {
    getItem: (name) => (name === 'veritas.apiBaseUrl' ? 'https://stored-attacker.example' : null)
  };
  try {
    withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '' }, () => {
      delete global.VERITAS_API_BASE;
      global.window.confirm = () => false;
      assert.strictEqual(api.resolveBaseUrl(), '');
      api.resetDestinationConsent();
      global.window.confirm = () => true;
      assert.strictEqual(api.resolveBaseUrl(), 'https://stored-attacker.example');
    });
  } finally {
    if (previousStorage === undefined) delete global.localStorage;
    else global.localStorage = previousStorage;
    api.resetDestinationConsent();
  }
}

function testSafeBaseRejectsCredentialAndQueryShapes() {
  assert.strictEqual(api.isSafeApiBase('https://user:pass@example.com'), false);
  assert.strictEqual(api.isSafeApiBase('https://example.com/steal?x=1'), false);
  assert.strictEqual(api.isSafeApiBase('https://example.com#frag'), false);
  assert.strictEqual(api.isSafeApiBase('https://example.com'), true);
  assert.strictEqual(api.isSafeApiBase('https://example.com/api'), true);
}

function testDescribeDestinationNeverPrompts() {
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '?apiBase=https://attacker.example' }, () => {
    delete global.VERITAS_API_BASE;
    let prompts = 0;
    global.window.confirm = () => {
      prompts += 1;
      return false;
    };
    const description = api.describeDestination();
    assert.strictEqual(prompts, 0, 'describeDestination must never open a consent dialog');
    assert.strictEqual(description.base, '');
    assert.strictEqual(description.source, 'none');
    // Consent is requested exactly when a request would use the destination.
    assert.strictEqual(api.resolveBaseUrl(), '');
    assert.strictEqual(prompts, 1);
  });
  api.resetDestinationConsent();
}

function testLoopbackDevelopmentBaseNeedsNoConsent() {
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '?apiBase=http://127.0.0.1:8000' }, () => {
    delete global.VERITAS_API_BASE;
    global.window.confirm = () => {
      throw new Error('loopback destinations must never prompt');
    };
    // Mixed content is still rejected on https pages...
    assert.strictEqual(api.resolveBaseUrl(), '');
  });
  withPageLocation({ protocol: 'http:', hostname: 'localhost', search: '?apiBase=http://127.0.0.1:8000' }, () => {
    delete global.VERITAS_API_BASE;
    global.window.confirm = () => {
      throw new Error('loopback destinations must never prompt');
    };
    // ...but local development keeps working without any dialog.
    assert.strictEqual(api.resolveBaseUrl(), 'http://127.0.0.1:8000');
  });
  api.resetDestinationConsent();
}

function testAssessmentTaxonomy() {
  // Backend-provided assessment wins when valid.
  let mapped = api.mapInspectCode({ trust_score: 95, verification_status: 'SECURE', assessment: 'Heuristic Warning' });
  assert.strictEqual(mapped.assessment, 'Heuristic Warning');
  // Fallbacks keep the taxonomy consistent with older backends.
  mapped = api.mapInspectCode({ trust_score: 10, verification_status: 'MALICIOUS', threat_breakdown: {} });
  assert.strictEqual(mapped.assessment, 'Confirmed Detection');
  mapped = api.mapInspectCode({ trust_score: 80, verification_status: 'SECURE', anomaly_flags: ['loop_dense'], threat_breakdown: {} });
  assert.strictEqual(mapped.assessment, 'Heuristic Warning');
  mapped = api.mapInspectCode({ trust_score: 99, verification_status: 'SECURE', threat_breakdown: {} });
  assert.strictEqual(mapped.assessment, 'No Threat Detected');
  assert.strictEqual(api.errorResult({ code: 'failed', message: 'boom' }).assessment, 'Analysis Error');
  assert.strictEqual(api.idleResult().assessment, null);
}

function testFilterAssessmentTaxonomy() {
  const filterBase = { threat_level_index: 3, confidence_index: 90, summary: 'ok', threat_breakdown: {}, forensic_logs: [] };
  let mapped = api.mapFilterThreat({ ...filterBase, action: 'ALLOW', threat_breakdown: { url_phishing: 5 } });
  assert.strictEqual(mapped.assessment, 'No Threat Detected');
  mapped = api.mapFilterThreat({ ...filterBase, action: 'ALLOW', threat_breakdown: { url_phishing: 30 } });
  assert.strictEqual(mapped.assessment, 'Heuristic Warning');
  mapped = api.mapFilterThreat({ ...filterBase, action: 'BLOCK', threat_breakdown: { url_phishing: 95 } });
  assert.strictEqual(mapped.assessment, 'Confirmed Detection');
  // A failed component dominates the label even when the policy action is BLOCK.
  mapped = api.mapFilterThreat({
    ...filterBase,
    action: 'BLOCK',
    threat_breakdown: { error: 100 },
    components: { url_filter: { error: 'url analysis failed' } }
  });
  assert.strictEqual(mapped.assessment, 'Analysis Error');
}

function testUnsafeBaseCharactersRejected() {
  // Control chars, bidi overrides, and raw backslashes must never reach a
  // consent dialog or be honored as a destination.
  const hostile = [
    'https://evil.example/\u202Egnp.exe',
    'https://evil.example/\nTrusted host',
    'https://evil.example\t.com',
    'https://evil.com\\@veritas-api.example.com'
  ];
  hostile.forEach((value) => {
    assert.strictEqual(api.isSafeApiBase(value), false, value);
  });
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '' }, () => {
    delete global.VERITAS_API_BASE;
    let prompts = 0;
    global.window.confirm = () => { prompts += 1; return false; };
    hostile.forEach((value) => {
      assert.strictEqual(api.resolveBaseUrl(value), '');
    });
    assert.strictEqual(prompts, 0, 'hostile bases must be skipped without a dialog');
  });
  api.resetDestinationConsent();
}

function testConsentDialogShowsNormalizedDestination() {
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '' }, () => {
    delete global.VERITAS_API_BASE;
    let shown = '';
    let prompts = 0;
    global.window.confirm = (message) => { prompts += 1; shown = message; return true; };
    // Case/path variants of one destination share one normalized consent.
    assert.strictEqual(api.resolveBaseUrl('HTTPS://Attacker.Example'), 'https://attacker.example');
    assert.ok(shown.indexOf('https://attacker.example') >= 0, 'dialog must show the normalized destination');
    assert.strictEqual(api.resolveBaseUrl('https://attacker.example/'), 'https://attacker.example');
    assert.strictEqual(api.resolveBaseUrl('https://attacker.example'), 'https://attacker.example');
    assert.strictEqual(prompts, 1, 'normalized variants must reuse the cached consent');
  });
  api.resetDestinationConsent();
}

function testIsConfiguredNeverPrompts() {
  api.resetDestinationConsent();
  withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '?apiBase=https://attacker.example' }, () => {
    delete global.VERITAS_API_BASE;
    let prompts = 0;
    global.window.confirm = () => { prompts += 1; return true; };
    assert.strictEqual(api.isConfigured(), false, 'unconsented destination is not configured yet');
    assert.strictEqual(prompts, 0, 'isConfigured must never open a consent dialog');
    // Consent happens where evidence would be sent...
    assert.strictEqual(api.resolveBaseUrl(), 'https://attacker.example');
    assert.strictEqual(prompts, 1);
    // ...after which the destination is configured without further prompts.
    assert.strictEqual(api.isConfigured(), true);
    assert.strictEqual(prompts, 1);
  });
  api.resetDestinationConsent();
}

function testLoopbackAndHostFormsTrusted() {
  withMetaTags({ 'veritas-api-base-production': 'https://veritas-api.example.com' }, () => {
    assert.strictEqual(api.isTrustedHost('veritas-api.example.com.'), true, 'trailing dot is DNS-equivalent');
    assert.strictEqual(api.isTrustedHost('127.0.0.2'), true, 'all of 127.0.0.0/8 is loopback');
    assert.strictEqual(api.isTrustedHost('::ffff:127.0.0.1'), true, 'v4-mapped loopback unwraps');
    assert.strictEqual(api.isTrustedHost('[::ffff:127.0.0.1]'), true);
    assert.strictEqual(api.isTrustedHost('evil.veritas-api.example.com'), false);
  });
}

async function testFetchNeverFollowsRedirects() {
  const previous = global.fetch;
  let recorded = null;
  global.fetch = async (url, options) => {
    recorded = { url: String(url), options: options || {} };
    return { ok: true, status: 200, text: async () => '{"status":"ok","service":"t"}' };
  };
  try {
    await api.health();
    assert.strictEqual(recorded.options.redirect, 'error', 'evidence requests must never follow redirects');
  } finally {
    if (previous === undefined) delete global.fetch;
    else global.fetch = previous;
  }
}

async function testHealthNeverPromptsForConsent() {
  api.resetDestinationConsent();
  const previous = global.fetch;
  const urls = [];
  global.fetch = async (url) => {
    urls.push(String(url));
    return { ok: true, status: 200, text: async () => '{"status":"ok","service":"t"}' };
  };
  try {
    // On a production page: the unconsented override is ignored and health
    // fails as unconfigured — without ever opening the consent dialog.
    await withPageLocation({ protocol: 'https:', hostname: 'mohamdmamdoh83-coder.github.io', search: '?apiBase=https://attacker.example' }, async () => {
      delete global.VERITAS_API_BASE;
      let prompts = 0;
      global.window.confirm = () => { prompts += 1; return true; };
      await api.health().then(
        () => { throw new Error('health must fail unconfigured'); },
        (error) => {
          assert.strictEqual(error.code, 'unconfigured');
          assert.strictEqual(prompts, 0, 'health probes must never open the consent dialog');
          assert.strictEqual(urls.length, 0);
        }
      );
    });
    // On a dev page: health silently falls back to the local default.
    await withPageLocation({ protocol: 'http:', hostname: 'localhost', search: '?apiBase=https://attacker.example' }, async () => {
      delete global.VERITAS_API_BASE;
      let prompts = 0;
      global.window.confirm = () => { prompts += 1; return true; };
      await api.health();
      assert.strictEqual(prompts, 0, 'health probes must never open the consent dialog');
      assert.deepStrictEqual(urls, ['http://localhost:8000/health']);
    });
  } finally {
    if (previous === undefined) delete global.fetch;
    else global.fetch = previous;
    api.resetDestinationConsent();
  }
}

async function main() {
  testResolveBaseUrl();
  testNoSecretsOnClient();
  testMapInspectCode();
  testMapFilterThreat();
  testInvalidApiResponse();
  testErrorClassification();
  testErrorAndIdleAreNotBackendVerdicts();
  testProductionPageNeverUsesLocalhost();
  testMixedContentRejected();
  await testHealthSuccessShape();
  await testOfflineHealth();
  await testAuthFailureOnInspect();
  await testRateLimitOnInspect();
  testToneForRiskThresholds();
  testHighRiskSignalsUseDangerTone();
  testIsConfigured();
  await testTooLargeRejectedLocally();
  testUntrustedBaseRequiresExplicitConsent();
  testConsentDeniedFallsBackToConfiguredProductionHost();
  testLocalStorageOverrideGatedByConsent();
  testSafeBaseRejectsCredentialAndQueryShapes();
  testDescribeDestinationNeverPrompts();
  testLoopbackDevelopmentBaseNeedsNoConsent();
  testAssessmentTaxonomy();
  testFilterAssessmentTaxonomy();
  testUnsafeBaseCharactersRejected();
  testConsentDialogShowsNormalizedDestination();
  testIsConfiguredNeverPrompts();
  testLoopbackAndHostFormsTrusted();
  await testFetchNeverFollowsRedirects();
  await testHealthNeverPromptsForConsent();
  console.log('api.js client tests passed');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

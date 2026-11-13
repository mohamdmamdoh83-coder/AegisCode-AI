/**
 * Veritas Inspector frontend API client.
 *
 * Documented backend contracts (backend_core.py + threat_filter_core.py):
 *
 * GET /health
 *   200  {"status":"ok","service":"veritas-inspector-analysis-core"}
 *   Auth-exempt. Network failure => backend unavailable.
 *
 * POST /api/v1/inspect-code
 *   JSON {"source_code"| "code": string, "language": "auto"|"python"|"javascript", "filename"?: string}
 *   200  {analysis_id, analyzed_at, language, trust_score, verification_status,
 *         confidence_index, threat_breakdown, metrics, anomaly_flags, syntax_errors, analysis_logs}
 *   verification_status: SECURE | REVIEW_REQUIRED | MALICIOUS
 *   400 empty/oversized source; 401 missing API key; 413 body too large;
 *   422 unsupported language / missing source_code; 429 rate limit; 500 safe failure.
 *
 * POST /api/v1/filter-threat
 *   JSON {"payload_type":"url"|"file"|"code"|"auto", "url"?, "source_code"?, "file_content_base64"?, ...}
 *   or multipart file field "file" / "upload", or raw application/octet-stream.
 *   200  {analysis_id, analyzed_at, action, threat_level_index, confidence_index,
 *         summary, threat_breakdown, components, forensic_logs, policy_reasons}
 *   action: ALLOW | QUARANTINE | BLOCK
 *   400 invalid base64; 401; 413 over 25 MB; 422 empty/invalid payload; 429; 500.
 *
 * This module never stores, sends, or logs API keys. A 401 is reported as
 * "authentication required" so the operator can set a key on the server, not
 * in browser JavaScript.
 */
(function (global) {
  'use strict';

  var DEFAULT_BASE_URL = 'http://localhost:8000';
  var PAGES_ORIGIN = 'https://mohamdmamdoh83-coder.github.io';
  var MAX_FILE_BYTES = 25 * 1024 * 1024;
  var MAX_SOURCE_CHARS = 200000;
  var MAX_URL_CHARS = 8192;

  function ApiError(code, message, status) {
    var error = new Error(message);
    error.name = 'ApiError';
    error.code = code;
    error.status = status || 0;
    return error;
  }

  function trimSlash(value) {
    return String(value || '').replace(/\/+$/, '');
  }

  function readMetaBase(name) {
    if (typeof document === 'undefined') return '';
    var meta = document.querySelector('meta[name="' + (name || 'veritas-api-base') + '"]');
    return meta && meta.getAttribute('content') ? meta.getAttribute('content').trim() : '';
  }

  function pageLocation() {
    if (typeof window === 'undefined' || !window.location) return null;
    return window.location;
  }

  function isLoopbackHost(hostname) {
    var host = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0';
  }

  function isPublicHttpsPage() {
    var location = pageLocation();
    if (!location) return false;
    return location.protocol === 'https:' && !isLoopbackHost(location.hostname);
  }

  function parseAbsoluteUrl(value) {
    try {
      return new URL(String(value || '').trim());
    } catch (error) {
      return null;
    }
  }

  function isSafeApiBase(value) {
    var parsed = parseAbsoluteUrl(value);
    if (!parsed) return false;
    // A base URL must be a plain origin (optionally with a path prefix).
    // Embedded credentials, query strings, and fragments are never valid API
    // destinations and are common phishing shapes.
    if (parsed.username || parsed.password) return false;
    if (parsed.search || parsed.hash) return false;
    if (isPublicHttpsPage()) {
      return parsed.protocol === 'https:' && !isLoopbackHost(parsed.hostname);
    }
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  }

  function readQueryBase() {
    if (typeof window === 'undefined' || !window.location) return '';
    try {
      return new URLSearchParams(window.location.search).get('apiBase') || '';
    } catch (error) {
      return '';
    }
  }

  function readStoredBase() {
    try {
      if (typeof localStorage === 'undefined') return '';
      return localStorage.getItem('veritas.apiBaseUrl') || '';
    } catch (error) {
      return '';
    }
  }

  // ------------------------------------------------------------------
  // API destination policy (P0 hardening)
  //
  // A candidate base URL is only honored when:
  //   1. it passes isSafeApiBase (protocol/shape checks), and
  //   2. its host is TRUSTED — loopback for local development, or the host
  //      explicitly configured for this deployment via the
  //      veritas-api-base-production meta tag — or the user explicitly
  //      consented to that exact destination via a confirmation dialog.
  //
  // Untrusted ?apiBase= / localStorage / window overrides can therefore never
  // silently redirect files or source code to a third party. When no user
  // interaction is possible (non-browser hosts, disabled dialogs) consent is
  // denied and the override is ignored (fail closed).
  // ------------------------------------------------------------------

  var destinationConsent = {};

  function confirmDestination(base) {
    var confirmer = null;
    if (typeof window !== 'undefined' && window && typeof window.confirm === 'function') {
      confirmer = function (message) { return window.confirm(message); };
    } else if (typeof globalThis !== 'undefined' && typeof globalThis.confirm === 'function') {
      confirmer = function (message) { return globalThis.confirm(message); };
    }
    if (!confirmer) return false;
    var message = 'Send inspection evidence (files, source code, URLs) to ' + base +
      '? Only approve if you trust this analysis API — everything you scan is sent there.';
    try {
      return Boolean(confirmer(message));
    } catch (error) {
      return false;
    }
  }

  function configuredProductionHost() {
    var raw = readMetaBase('veritas-api-base-production');
    var parsed = raw ? parseAbsoluteUrl(raw) : null;
    return parsed ? parsed.hostname.toLowerCase() : '';
  }

  function isTrustedHost(hostname) {
    var host = String(hostname || '').toLowerCase();
    if (!host) return false;
    if (isLoopbackHost(host)) return true;
    var productionHost = configuredProductionHost();
    return Boolean(productionHost) && host === productionHost;
  }

  function destinationAllowed(base, mayPrompt) {
    var parsed = parseAbsoluteUrl(base);
    if (!parsed) return false;
    if (!isSafeApiBase(base)) return false;
    if (isTrustedHost(parsed.hostname)) return true;
    var key = trimSlash(String(base).trim());
    if (Object.prototype.hasOwnProperty.call(destinationConsent, key)) return destinationConsent[key];
    if (!mayPrompt) return false;
    var granted = confirmDestination(key);
    destinationConsent[key] = granted;
    return granted;
  }

  function resetDestinationConsent() {
    destinationConsent = {};
  }

  function evaluateCandidate(candidate, source, mayPrompt) {
    if (candidate == null) return null;
    var trimmed = trimSlash(String(candidate).trim());
    if (!trimmed) return null;
    if (!destinationAllowed(trimmed, mayPrompt)) return null;
    return { base: trimmed, source: source };
  }

  function resolveDestination(explicit, mayPrompt) {
    var candidates = [
      [explicit, 'explicit'],
      [global.VERITAS_API_BASE, 'window'],
      [readQueryBase(), 'query'],
      [readMetaBase('veritas-api-base-production'), 'meta-production'],
      [readMetaBase('veritas-api-base'), 'meta-dev'],
      [readStoredBase(), 'storage']
    ];
    for (var i = 0; i < candidates.length; i += 1) {
      var resolved = evaluateCandidate(candidates[i][0], candidates[i][1], mayPrompt);
      if (resolved) return resolved;
    }
    if (isPublicHttpsPage()) return { base: '', source: 'none' };
    return { base: DEFAULT_BASE_URL, source: 'default' };
  }

  function resolveBaseUrl(explicit) {
    return resolveDestination(explicit, true).base;
  }

  /** Non-prompting description of the selected API destination (transparency). */
  function describeDestination(explicit) {
    var resolved = resolveDestination(explicit, false);
    var parsed = resolved.base ? parseAbsoluteUrl(resolved.base) : null;
    var host = parsed ? parsed.hostname : '';
    var consented = false;
    if (parsed && !isTrustedHost(host)) {
      var key = trimSlash(resolved.base);
      consented = destinationConsent[key] === true;
    }
    return {
      base: resolved.base,
      source: resolved.source,
      host: host,
      trusted: Boolean(parsed) && isTrustedHost(host),
      consented: consented
    };
  }

  function classifyHttpError(status, detail) {
    var message = typeof detail === 'string' && detail ? detail : 'Request failed';
    if (status === 401) return ApiError('auth', 'Authentication required. The dashboard does not store API keys.', status);
    if (status === 413) return ApiError('too_large', message, status);
    if (status === 429) return ApiError('rate_limited', 'Rate limit exceeded. Wait and retry.', status);
    if (status === 400 || status === 415 || status === 422) return ApiError('invalid_input', message, status);
    if (status >= 500) return ApiError('failed', message, status);
    return ApiError('failed', message, status);
  }

  function extractDetail(payload) {
    if (payload == null) return '';
    if (typeof payload === 'string') return payload;
    if (typeof payload.detail === 'string') return payload.detail;
    if (Array.isArray(payload.detail)) {
      return payload.detail.map(function (item) {
        return item && item.msg ? item.msg : JSON.stringify(item);
      }).join('; ');
    }
    if (payload.detail != null) return String(payload.detail);
    return '';
  }

  function parseJsonSafe(text) {
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch (error) {
      return null;
    }
  }

  async function request(path, options) {
    var baseUrl = resolveBaseUrl(options && options.baseUrl);
    if (!baseUrl) {
      throw ApiError(
        'unconfigured',
        'No HTTPS analysis API is configured for this dashboard.',
        0
      );
    }
    var url = baseUrl + path;
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = null;
    var fetchOptions = {
      method: (options && options.method) || 'GET',
      headers: Object.assign({}, options && options.headers),
      signal: controller ? controller.signal : undefined
    };
    if (options && options.body !== undefined) fetchOptions.body = options.body;
    if (options && options.timeoutMs && controller) {
      timer = setTimeout(function () { controller.abort(); }, options.timeoutMs);
    }

    var response;
    try {
      response = await fetch(url, fetchOptions);
    } catch (error) {
      if (timer) clearTimeout(timer);
      var aborted = error && (error.name === 'AbortError' || error.code === 'ABORT_ERR');
      throw ApiError(
        'unavailable',
        aborted ? 'The analysis API timed out.' : 'The analysis API is unavailable.',
        0
      );
    }
    if (timer) clearTimeout(timer);

    var text = await response.text();
    var payload = parseJsonSafe(text);
    if (!response.ok) {
      throw classifyHttpError(response.status, extractDetail(payload) || text || response.statusText);
    }
    if (payload == null) {
      throw ApiError('invalid_response', 'The analysis API returned a non-JSON response.', response.status);
    }
    return payload;
  }

  function requireObject(payload, label) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw ApiError('invalid_response', 'Invalid ' + label + ' payload from the analysis API.', 200);
    }
    return payload;
  }

  function numberOrNull(value) {
    var n = Number(value);
    return Number.isFinite(n) ? n : null;
  }

  function clip(value) {
    var n = numberOrNull(value);
    if (n == null) return null;
    if (n < 0) return 0;
    if (n > 100) return 100;
    return Math.round(n * 100) / 100;
  }

  function confidenceLabel(index) {
    if (index == null) return 'Unknown';
    if (index >= 94) return 'Very high';
    if (index >= 82) return 'High';
    if (index >= 60) return 'Moderate';
    return 'Low';
  }

  function toneForRisk(risk) {
    if (risk == null) return 'review';
    if (risk >= 75) return 'danger';
    if (risk >= 40) return 'review';
    return 'safe';
  }

  function signal(label, risk, icon) {
    var value = clip(risk);
    if (value == null) value = 0;
    return [label, value, toneForRisk(value), icon];
  }

  var ASSESSMENTS = ['Confirmed Detection', 'Suspicious Behavior', 'Heuristic Warning', 'No Threat Detected', 'Analysis Error'];

  function normalizeAssessment(value) {
    return typeof value === 'string' && ASSESSMENTS.indexOf(value) >= 0 ? value : null;
  }

  // Fallback taxonomy for older backends that omit the assessment field.
  function assessmentFromInspection(body, statusRaw) {
    if (statusRaw === 'MALICIOUS') return 'Confirmed Detection';
    if (statusRaw === 'REVIEW_REQUIRED') return 'Suspicious Behavior';
    var flags = (Array.isArray(body.anomaly_flags) && body.anomaly_flags.length > 0) ||
      (Array.isArray(body.syntax_errors) && body.syntax_errors.length > 0);
    return flags ? 'Heuristic Warning' : 'No Threat Detected';
  }

  function assessmentFromFilter(body, action) {
    var breakdown = body.threat_breakdown && typeof body.threat_breakdown === 'object' ? body.threat_breakdown : {};
    var components = body.components && typeof body.components === 'object' ? body.components : {};
    var componentError = Boolean(breakdown.error) || Object.keys(components).some(function (key) {
      var report = components[key];
      return report && typeof report === 'object' && !Array.isArray(report) && report.error;
    });
    if (componentError) return 'Analysis Error';
    if (action === 'BLOCK') return 'Confirmed Detection';
    if (action === 'QUARANTINE') return 'Suspicious Behavior';
    var highest = 0;
    Object.keys(breakdown).forEach(function (key) {
      if (key === 'error') return;
      var value = Number(breakdown[key]) || 0;
      if (value > highest) highest = value;
    });
    return highest >= 20 ? 'Heuristic Warning' : 'No Threat Detected';
  }

  function mapInspectCode(payload) {
    var body = requireObject(payload, 'inspect-code');
    var statusRaw = String(body.verification_status || '');
    var trust = clip(body.trust_score);
    var confidence = clip(body.confidence_index);
    if (trust == null || !statusRaw) {
      throw ApiError('invalid_response', 'inspect-code response missing trust_score or verification_status.', 200);
    }
    var uiStatus = statusRaw === 'MALICIOUS' ? 'danger' : statusRaw === 'REVIEW_REQUIRED' ? 'review' : statusRaw === 'SECURE' ? 'safe' : null;
    if (!uiStatus) {
      throw ApiError('invalid_response', 'inspect-code returned an unknown verification_status.', 200);
    }
    var breakdown = body.threat_breakdown && typeof body.threat_breakdown === 'object' ? body.threat_breakdown : {};
    var logs = Array.isArray(body.analysis_logs) ? body.analysis_logs : [];
    var caption = logs.length ? String(logs[logs.length - 1]) : ('Backend verdict ' + statusRaw);
    return {
      score: trust,
      status: uiStatus,
      statusText: statusRaw,
      caption: caption,
      confidence: confidenceLabel(confidence),
      confidencePercent: confidence == null ? 0 : confidence,
      signals: [
        signal('Injection risk', breakdown.injection_risk, 'fa-user-shield'),
        signal('Obfuscation risk', breakdown.obfuscation_risk, 'fa-wand-magic-sparkles'),
        signal('Entropy risk', breakdown.entropy_risk, 'fa-wave-square'),
        signal('Syntax risk', breakdown.syntax_risk, 'fa-code')
      ],
      metrics: {
        language: body.language,
        analysisId: body.analysis_id,
        analyzedAt: body.analyzed_at,
        verificationStatus: statusRaw,
        threatBreakdown: breakdown,
        injectionIndex: clip(breakdown.injection_risk) || 0,
        obfuscationIndex: clip(breakdown.obfuscation_risk) || 0,
        entropyIndex: clip(breakdown.entropy_risk) || 0,
        syntaxErrors: Array.isArray(body.syntax_errors) ? body.syntax_errors : [],
        anomalyFlags: Array.isArray(body.anomaly_flags) ? body.anomaly_flags : []
      },
      analysisLogs: logs,
      evidenceFingerprint: 'inspect:' + (body.analysis_id || ''),
      source: 'backend',
      isVerdict: true,
      endpoint: '/api/v1/inspect-code',
      assessment: normalizeAssessment(body.assessment) || assessmentFromInspection(body, statusRaw),
      raw: body
    };
  }

  function mapFilterThreat(payload) {
    var body = requireObject(payload, 'filter-threat');
    var action = String(body.action || '');
    var threat = clip(body.threat_level_index);
    var confidence = clip(body.confidence_index);
    if (threat == null || !action) {
      throw ApiError('invalid_response', 'filter-threat response missing action or threat_level_index.', 200);
    }
    var uiStatus = action === 'BLOCK' ? 'danger' : action === 'QUARANTINE' ? 'review' : action === 'ALLOW' ? 'safe' : null;
    if (!uiStatus) {
      throw ApiError('invalid_response', 'filter-threat returned an unknown action.', 200);
    }
    var breakdown = body.threat_breakdown && typeof body.threat_breakdown === 'object' ? body.threat_breakdown : {};
    var trust = clip(100 - threat);
    return {
      score: trust == null ? 0 : trust,
      status: uiStatus,
      statusText: action,
      caption: body.summary ? String(body.summary) : ('Backend action ' + action),
      confidence: confidenceLabel(confidence),
      confidencePercent: confidence == null ? 0 : confidence,
      signals: [
        signal('File integrity risk', breakdown.file_integrity, 'fa-file-shield'),
        signal('URL phishing risk', breakdown.url_phishing, 'fa-link'),
        signal('Code injection risk', breakdown.code_injection, 'fa-user-shield'),
        signal('Process anomaly risk', breakdown.process_anomaly, 'fa-wave-square')
      ],
      metrics: {
        analysisId: body.analysis_id,
        analyzedAt: body.analyzed_at,
        action: action,
        threatLevelIndex: threat,
        risk: threat,
        threatBreakdown: breakdown,
        policyReasons: Array.isArray(body.policy_reasons) ? body.policy_reasons : [],
        components: body.components || {}
      },
      analysisLogs: Array.isArray(body.forensic_logs)
        ? body.forensic_logs.map(function (entry) { return entry && entry.message ? String(entry.message) : ''; }).filter(Boolean)
        : [],
      evidenceFingerprint: 'filter:' + (body.analysis_id || ''),
      source: 'backend',
      isVerdict: true,
      endpoint: '/api/v1/filter-threat',
      assessment: normalizeAssessment(body.assessment) || assessmentFromFilter(body, action),
      raw: body
    };
  }

  function errorResult(error) {
    var code = error && error.code ? error.code : 'failed';
    var message = error && error.message ? error.message : 'The analysis API request failed.';
    var statusText = {
      unavailable: 'BACKEND UNAVAILABLE',
      unconfigured: 'API NOT CONFIGURED',
      auth: 'AUTHENTICATION REQUIRED',
      rate_limited: 'RATE LIMITED',
      invalid_input: 'INVALID INPUT',
      too_large: 'FILE TOO LARGE',
      invalid_response: 'INVALID API RESPONSE',
      failed: 'REQUEST FAILED'
    }[code] || 'REQUEST FAILED';
    return {
      score: null,
      displayScore: '—',
      status: 'danger',
      statusText: statusText,
      caption: message,
      confidence: 'None',
      confidencePercent: 0,
      signals: [
        ['Injection risk', 0, 'review', 'fa-user-shield'],
        ['Obfuscation risk', 0, 'review', 'fa-wand-magic-sparkles'],
        ['Entropy risk', 0, 'review', 'fa-wave-square'],
        ['Syntax risk', 0, 'review', 'fa-code']
      ],
      metrics: { backendError: true, errorCode: code, httpStatus: error && error.status ? error.status : 0 },
      analysisLogs: [message],
      evidenceFingerprint: 'error:' + code,
      source: 'error',
      isVerdict: false,
      backendError: true,
      assessment: 'Analysis Error'
    };
  }

  function idleResult(caption) {
    return {
      score: null,
      displayScore: '—',
      status: 'review',
      statusText: 'AWAITING INSPECTION',
      caption: caption || 'No backend verdict yet. Run a deep scan against the analysis API.',
      confidence: 'None',
      confidencePercent: 0,
      signals: [
        ['Injection risk', 0, 'safe', 'fa-user-shield'],
        ['Obfuscation risk', 0, 'safe', 'fa-wand-magic-sparkles'],
        ['Entropy risk', 0, 'safe', 'fa-wave-square'],
        ['Syntax risk', 0, 'safe', 'fa-code']
      ],
      metrics: { idle: true },
      analysisLogs: [],
      evidenceFingerprint: 'idle',
      source: 'idle',
      isVerdict: false,
      assessment: null
    };
  }

  async function health(baseUrl) {
    var payload = await request('/health', { method: 'GET', baseUrl: baseUrl, timeoutMs: 4000 });
    if (!payload || payload.status !== 'ok') {
      throw ApiError('invalid_response', 'Health endpoint did not return status ok.', 200);
    }
    return payload;
  }

  async function inspectCode(sourceCode, options) {
    var source = sourceCode == null ? '' : String(sourceCode);
    if (!source.trim()) throw ApiError('invalid_input', 'source_code cannot be empty.', 0);
    if (source.length > MAX_SOURCE_CHARS) {
      throw ApiError('too_large', 'source_code exceeds the 200,000-character limit.', 0);
    }
    var payload = await request('/api/v1/inspect-code', {
      method: 'POST',
      baseUrl: options && options.baseUrl,
      timeoutMs: (options && options.timeoutMs) || 20000,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        source_code: source,
        language: (options && options.language) || 'auto',
        filename: options && options.filename ? options.filename : undefined
      })
    });
    return mapInspectCode(payload);
  }

  async function filterThreatUrl(url, options) {
    var value = url == null ? '' : String(url).trim();
    if (!value) throw ApiError('invalid_input', 'url must be a non-empty string.', 0);
    if (value.length > MAX_URL_CHARS) throw ApiError('too_large', 'url exceeds the 8,192-character limit.', 0);
    var payload = await request('/api/v1/filter-threat', {
      method: 'POST',
      baseUrl: options && options.baseUrl,
      timeoutMs: (options && options.timeoutMs) || 20000,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        payload_type: 'url',
        url: value,
        network_payload: options && options.networkPayload ? options.networkPayload : undefined
      })
    });
    return mapFilterThreat(payload);
  }

  async function filterThreatFile(file, options) {
    if (!file) throw ApiError('invalid_input', 'A file is required.', 0);
    if (file.size > MAX_FILE_BYTES) {
      throw ApiError('too_large', 'uploaded file exceeds the 25 MB evidence limit.', 0);
    }
    var form = new FormData();
    form.append('file', file, file.name || 'upload.bin');
    form.append('payload_type', 'file');
    var payload = await request('/api/v1/filter-threat', {
      method: 'POST',
      baseUrl: options && options.baseUrl,
      timeoutMs: (options && options.timeoutMs) || 30000,
      body: form
    });
    return mapFilterThreat(payload);
  }

  var VeritasAPI = {
    DEFAULT_BASE_URL: DEFAULT_BASE_URL,
    PAGES_ORIGIN: PAGES_ORIGIN,
    MAX_FILE_BYTES: MAX_FILE_BYTES,
    MAX_SOURCE_CHARS: MAX_SOURCE_CHARS,
    ApiError: ApiError,
    isPublicHttpsPage: isPublicHttpsPage,
    isSafeApiBase: isSafeApiBase,
    isTrustedHost: isTrustedHost,
    resolveBaseUrl: resolveBaseUrl,
    describeDestination: describeDestination,
    resetDestinationConsent: resetDestinationConsent,
    isConfigured: function isConfigured(explicit) {
      return Boolean(resolveBaseUrl(explicit));
    },
    toneForRisk: toneForRisk,
    classifyHttpError: classifyHttpError,
    mapInspectCode: mapInspectCode,
    mapFilterThreat: mapFilterThreat,
    errorResult: errorResult,
    idleResult: idleResult,
    health: health,
    inspectCode: inspectCode,
    filterThreatUrl: filterThreatUrl,
    filterThreatFile: filterThreatFile
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeritasAPI;
  }
  global.VeritasAPI = VeritasAPI;
})(typeof globalThis !== 'undefined' ? globalThis : this);

(() => {
  'use strict';

  const $ = (selector, scope = document) => scope.querySelector(selector);
  const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

  const state = {
    mode: 'media',
    scanning: false,
    file: null,
    demoMedia: false,
    codeFile: null,
    fileAnalysis: null,
    liveAnalysisTimer: null,
    fileAnalysisToken: 0,
    lastEvidenceFingerprint: '',
    alertSoundEnabled: true,
    activeAlertFingerprint: '',
    dismissedAlertFingerprint: '',
    lastAlertSeverity: '',
    lastAlertSource: '',
    lastAlertRisk: 0,
    audioContext: null,
    scanTimer: null,
    scanProgress: 0,
    healthTimer: null,
    inspectToken: 0,
    connection: 'connecting',
    lastResult: null,
    previewObjectUrl: null
  };

  const api = () => {
    if (!globalThis.VeritasAPI) {
      throw new Error('VeritasAPI client failed to load');
    }
    return globalThis.VeritasAPI;
  };

  const codeSamples = {
    code: `const observer = new MutationObserver((records) => {
  records.forEach(({ target }) => {
    if (target.dataset.aiInjected === 'true') {
      console.warn('Unexpected DOM mutation detected');
    }
  });
});
observer.observe(document.body, { subtree: true, attributes: true });`,
    url: `https://account-verification.example.com/session/continue

// Resolve target and inspect redirect chain
const destination = new URL(window.location.href);
const next = destination.searchParams.get('next');
if (next && !next.startsWith('https://trusted.example')) {
  window.location.assign(atob(next));
}`
  };

  const textSamples = {
    phishing: {
      url: 'https://account-verification.example.com/session/continue',
      body: 'Your account has been selected for an exclusive security upgrade. Confirm your identity within 30 minutes to avoid a temporary lock. Use the secure link below to continue.'
    },
    'clean-text': {
      url: '',
      body: 'The quarterly report outlines a measured increase in regional adoption, supported by transparent methodology and interviews with three independent researchers.'
    }
  };

  function init() {
    bindNavigation();
    bindTabs();
    bindMediaInput();
    bindEditorTools();
    bindScanControls();
    bindAlertControls();
    bindDeviceControls();
    bindSamples();
    updateCounters();
    setActiveNav('overview');
    applyResult(api().idleResult(), { silent: true });
    startHealthPolling();
  }

  function bindNavigation() {
    $$('.nav-link, .mobile-nav a').forEach((link) => {
      link.addEventListener('click', (event) => {
        const target = link.dataset.navTarget;
        if (target === 'dom-analysis') {
          event.preventDefault();
          setMode('code');
          scrollTo('scanner');
        } else if (target) {
          event.preventDefault();
          scrollTo(target);
        }
        closeMobileNav();
        if (target) setActiveNav(target);
      });
    });

    $$('[data-scroll-to]').forEach((button) => {
      button.addEventListener('click', () => scrollTo(button.dataset.scrollTo));
    });

    $('#mobileMenuButton')?.addEventListener('click', () => {
      const nav = $('#mobileNav');
      const open = nav.classList.toggle('open');
      nav.setAttribute('aria-hidden', String(!open));
      $('#mobileMenuButton').setAttribute('aria-expanded', String(open));
      $('#mobileMenuButton i').className = open ? 'fa-solid fa-xmark' : 'fa-solid fa-bars';
    });

    const observed = ['overview', 'scanner', 'device-guardian', 'settings']
      .map((id) => document.getElementById(id))
      .filter(Boolean);
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver((entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible) setActiveNav(visible.target.id);
      }, { rootMargin: '-25% 0px -62% 0px', threshold: [0, .2, .5] });
      observed.forEach((element) => observer.observe(element));
    }
  }

  function closeMobileNav() {
    const nav = $('#mobileNav');
    if (!nav) return;
    nav.classList.remove('open');
    nav.setAttribute('aria-hidden', 'true');
    $('#mobileMenuButton')?.setAttribute('aria-expanded', 'false');
    const icon = $('#mobileMenuButton i');
    if (icon) icon.className = 'fa-solid fa-bars';
  }

  function scrollTo(id) {
    const target = document.getElementById(id);
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: id === 'results' ? 'center' : 'start' });
  }

  function setActiveNav(target) {
    $$('.nav-link, .mobile-nav a').forEach((link) => {
      link.classList.toggle('active', link.dataset.navTarget === target);
    });
  }

  function bindTabs() {
    $$('.mode-tab').forEach((tab) => {
      tab.addEventListener('click', () => setMode(tab.dataset.mode));
    });
  }

  function setMode(mode) {
    if (!['media', 'code', 'text'].includes(mode)) return;
    state.mode = mode;
    $$('.mode-tab').forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
    });
    $$('.mode-panel').forEach((panel) => {
      const active = panel.dataset.panel === mode;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });
    if (!state.scanning) {
      updateCounters();
    }
  }

  function bindMediaInput() {
    const dropZone = $('#dropZone');
    const fileInput = $('#fileInput');
    const browse = $('#browseButton');

    browse?.addEventListener('click', (event) => {
      event.stopPropagation();
      fileInput?.click();
    });
    dropZone?.addEventListener('click', (event) => {
      if (event.target.closest('button')) return;
      fileInput?.click();
    });
    dropZone?.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        fileInput?.click();
      }
    });
    fileInput?.addEventListener('change', (event) => handleFile(event.target.files?.[0]));

    ['dragenter', 'dragover'].forEach((eventName) => {
      dropZone?.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.add('dragover');
      });
    });
    ['dragleave', 'drop'].forEach((eventName) => {
      dropZone?.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.remove('dragover');
      });
    });
    dropZone?.addEventListener('drop', (event) => handleFile(event.dataTransfer?.files?.[0]));
    $('#removeFile')?.addEventListener('click', clearMedia);
  }

  function handleFile(file) {
    if (!file) return;
    if (file.size > 25 * 1024 * 1024) {
      showToast('That file is larger than the 25 MB evidence limit.', 'fa-circle-exclamation');
      return;
    }

    const extension = file.name.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || '';
    const codeFile = file.type.startsWith('text/') || /\.(py|js|jsx|ts|tsx|json|html|css|sh|bash|ps1|txt)$/.test(extension);
    if (codeFile && !file.type.startsWith('image/') && !file.type.startsWith('video/')) {
      state.codeFile = file;
      state.file = null;
      state.fileAnalysis = null;
      replacePreviewObjectUrl(null);
      file.text().then((source) => {
        setMode('code');
        const input = $('#codeInput');
        if (input) input.value = source;
        updateCounters();
        showToast(`Source file loaded: ${file.name}`, 'fa-code');
        scrollTo('scanner');
      }).catch(() => {
        showToast('The source file could not be read safely.', 'fa-circle-exclamation');
      });
      return;
    }

    if (!file.type.startsWith('image/') && !file.type.startsWith('video/')) {
      showToast('Unsupported file type. Add media or a Python/JavaScript source file.', 'fa-circle-exclamation');
      return;
    }
    state.file = file;
    state.codeFile = null;
    state.fileAnalysis = null;
    state.fileAnalysisToken += 1;
    state.demoMedia = false;
    renderMediaPreview(file);
    showToast('Evidence loaded. Run a deep scan to send it to the analysis API.', 'fa-circle-check');
  }

  function replacePreviewObjectUrl(next) {
    const previous = state.previewObjectUrl;
    state.previewObjectUrl = next || null;
    if (previous && previous !== state.previewObjectUrl) {
      URL.revokeObjectURL(previous);
    }
  }

  function renderMediaPreview(file) {
    const dropZone = $('#dropZone');
    const preview = $('#mediaPreview');
    const thumb = $('#previewThumb');
    if (!preview || !thumb) return;
    dropZone.hidden = true;
    preview.hidden = false;
    thumb.replaceChildren();
    const objectUrl = URL.createObjectURL(file);
    replacePreviewObjectUrl(objectUrl);

    if (file.type.startsWith('image/')) {
      const image = document.createElement('img');
      image.alt = 'Selected evidence preview';
      image.src = objectUrl;
      thumb.appendChild(image);
    } else {
      const video = document.createElement('video');
      video.muted = true;
      video.autoplay = true;
      video.loop = true;
      video.playsInline = true;
      video.src = objectUrl;
      thumb.appendChild(video);
    }
    $('#previewName').textContent = file.name;
    $('#previewMeta').textContent = `${file.type.startsWith('video/') ? 'Video' : 'Image'} · ${formatBytes(file.size)}`;
  }

  function renderDemoMedia(kind = 'image') {
    const dropZone = $('#dropZone');
    const preview = $('#mediaPreview');
    const thumb = $('#previewThumb');
    if (!preview || !thumb) return;
    state.file = null;
    state.codeFile = null;
    state.fileAnalysis = null;
    state.fileAnalysisToken += 1;
    state.demoMedia = true;
    dropZone.hidden = true;
    preview.hidden = false;
    thumb.replaceChildren();
    replacePreviewObjectUrl(null);
    const icon = document.createElement('i');
    icon.className = kind === 'video' ? 'fa-solid fa-film' : 'fa-solid fa-user-astronaut';
    thumb.appendChild(icon);
    thumb.style.background = kind === 'video'
      ? 'linear-gradient(145deg, #232250, #162f45 48%, #7a55ac)'
      : 'radial-gradient(circle at 52% 35%, #f2b99a 0 12%, transparent 13%), radial-gradient(circle at 51% 55%, #7b5aff 0 18%, transparent 19%), linear-gradient(145deg, #163943, #203056 53%, #8d5b9e)';
    $('#previewName').textContent = kind === 'video' ? 'synthetic-motion-frame.mp4' : 'synthetic-portrait-sample.png';
    $('#previewMeta').textContent = kind === 'video' ? 'Video frame · visual preset' : 'Image · visual preset';
    applyResult(api().idleResult('Visual preset only. The analysis API did not inspect this sample. Upload a real file for a backend verdict.'), { silent: true });
    showToast('Visual preset loaded. It is not a backend inspection result.', 'fa-wand-magic-sparkles');
  }

  function clearMedia() {
    state.file = null;
    state.codeFile = null;
    state.fileAnalysis = null;
    state.fileAnalysisToken += 1;
    state.demoMedia = false;
    const input = $('#fileInput');
    if (input) input.value = '';
    const preview = $('#mediaPreview');
    const dropZone = $('#dropZone');
    const thumb = $('#previewThumb');
    if (thumb) thumb.replaceChildren();
    replacePreviewObjectUrl(null);
    if (preview) preview.hidden = true;
    if (dropZone) dropZone.hidden = false;
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 KB';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / (1024 ** index)).toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
  }

  function bindEditorTools() {
    $('#codeInput')?.addEventListener('input', () => {
      updateCounters();
    });
    $('#textInput')?.addEventListener('input', () => {
      updateCounters();
    });
    $('#clearTextButton')?.addEventListener('click', () => {
      const textInput = $('#textInput');
      const urlInput = $('#textUrlInput');
      if (textInput) textInput.value = '';
      if (urlInput) urlInput.value = '';
      updateCounters();
      showToast('Evidence text cleared. URL scan is disabled until a URL is supplied.', 'fa-eraser');
    });
    $('#pasteButton')?.addEventListener('click', async () => {
      try {
        const value = await navigator.clipboard.readText();
        if (!value) throw new Error('empty');
        $('#textInput').value = value;
        updateCounters();
        showToast('Clipboard evidence pasted.', 'fa-paste');
      } catch (error) {
        showToast('Clipboard access is unavailable. Paste directly into the evidence field.', 'fa-keyboard');
      }
    });
  }

  function updateCounters() {
    const code = $('#codeInput')?.value || '';
    const text = $('#textInput')?.value || '';
    if ($('#codeCount')) $('#codeCount').textContent = `${code.length.toLocaleString()} characters`;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    if ($('#wordCount')) $('#wordCount').textContent = `${words.toLocaleString()} words`;
  }

  function clamp(value, min = 0, max = 100) {
    return Math.min(max, Math.max(min, Number(value) || 0));
  }

  function appendEvidenceEntry(time, markClass, icon, message, value) {
    const logList = $('#logList');
    if (!logList) return;
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `<time>${time}</time><span class="log-mark ${markClass}"><i class="fa-solid ${icon}"></i></span><span>${escapeHtml(message)}</span><b>${escapeHtml(value)}</b>`;
    logList.prepend(entry);
    while (logList.children.length > 4) logList.lastElementChild.remove();
  }

  function setBackendStatus(connection, title, detail) {
    state.connection = connection;
    const destination = api().describeDestination ? api().describeDestination() : null;
    const destinationLabel = destination && destination.base
      ? `Analysis API destination: ${destination.base}${destination.trusted ? '' : ' (user-approved)'}`
      : 'Analysis API destination: not configured';
    const shell = $('#backendStatus');
    if (shell) {
      shell.setAttribute('data-connection', connection);
      shell.setAttribute('title', destinationLabel);
    }
    if ($('#backendStatusTitle')) $('#backendStatusTitle').textContent = title;
    if ($('#backendStatusDetail')) $('#backendStatusDetail').textContent = detail;
    const hero = $('#heroApiStatus');
    if (hero) {
      hero.setAttribute('data-connection', connection);
      hero.setAttribute('title', destinationLabel);
    }
    if ($('#heroApiStatusTitle')) $('#heroApiStatusTitle').textContent = title;
    if ($('#heroApiStatusDetail')) $('#heroApiStatusDetail').textContent = detail;
  }

  function startHealthPolling() {
    if (state.healthTimer) {
      window.clearInterval(state.healthTimer);
      state.healthTimer = null;
    }
    if (!api().isConfigured()) {
      setBackendStatus('unavailable', 'API NOT CONFIGURED', 'NO HTTPS BACKEND');
      return;
    }
    pollBackendHealth();
    state.healthTimer = window.setInterval(pollBackendHealth, 15000);
  }

  async function pollBackendHealth() {
    if (!api().isConfigured()) {
      if (state.healthTimer) {
        window.clearInterval(state.healthTimer);
        state.healthTimer = null;
      }
      setBackendStatus('unavailable', 'API NOT CONFIGURED', 'NO HTTPS BACKEND');
      return;
    }
    if (state.connection === 'connecting') {
      setBackendStatus('connecting', 'CONNECTING', 'CHECKING API');
    }
    try {
      const payload = await api().health();
      const service = payload.service ? String(payload.service) : 'API CONNECTED';
      const destination = api().describeDestination();
      const hostSuffix = destination && destination.host ? ` · API ${destination.host}` : '';
      setBackendStatus('connected', 'API CONNECTED', service.replace(/-/g, ' ').toUpperCase() + hostSuffix);
    } catch (error) {
      applyConnectionError(error, false);
    }
  }

  function applyConnectionError(error, updateResults) {
    const code = error && error.code ? error.code : 'unavailable';
    const mapped = {
      unavailable: ['unavailable', 'BACKEND UNAVAILABLE', 'NO API VERDICT'],
      unconfigured: ['unavailable', 'API NOT CONFIGURED', 'NO HTTPS BACKEND'],
      auth: ['auth', 'AUTH REQUIRED', 'API KEY NOT IN BROWSER'],
      rate_limited: ['rate_limited', 'RATE LIMITED', 'TRY AGAIN'],
      failed: ['failed', 'REQUEST FAILED', 'SEE VERDICT STREAM'],
      invalid_input: ['failed', 'INVALID INPUT', 'CHECK EVIDENCE'],
      too_large: ['failed', 'FILE TOO LARGE', '25 MB LIMIT'],
      invalid_response: ['failed', 'INVALID API RESPONSE', 'NOT A BACKEND VERDICT']
    }[code] || ['failed', 'REQUEST FAILED', 'SEE VERDICT STREAM'];
    setBackendStatus(mapped[0], mapped[1], mapped[2]);
    if (updateResults) applyResult(api().errorResult(error), { silent: true });
  }

  function extractUrls(text) {
    const matches = String(text || '').match(/https?:\/\/[^\s"'<>]+/gi) || [];
    return matches.map((item) => item.replace(/[.,;)\]]+$/g, ''));
  }

  function isUrlOnlyPayload(text) {
    const trimmed = String(text || '').trim();
    if (!trimmed) return false;
    const lines = trimmed.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith('//'));
    if (lines.length !== 1) return false;
    return /^(https?:\/\/|\/\/)/i.test(lines[0].trim());
  }

  async function inspectCurrentEvidence() {
    const client = api();
    if (state.mode === 'media') {
      if (state.demoMedia && !state.file) {
        throw client.ApiError('invalid_input', 'Visual presets are not sent to the analysis API. Upload a real file.', 0);
      }
      if (!state.file) {
        throw client.ApiError('invalid_input', 'Add a media or source file before scanning.', 0);
      }
      if (state.file.size > client.MAX_FILE_BYTES) {
        throw client.ApiError('too_large', 'uploaded file exceeds the 25 MB evidence limit.', 0);
      }
      return client.filterThreatFile(state.file);
    }

    if (state.mode === 'code') {
      const source = $('#codeInput')?.value || '';
      if (!source.trim()) {
        throw client.ApiError('invalid_input', 'Paste source code or a URL before scanning.', 0);
      }
      if (isUrlOnlyPayload(source)) {
        return client.filterThreatUrl(extractUrls(source)[0] || source.trim());
      }
      const filename = state.codeFile?.name || undefined;
      return client.inspectCode(source, { filename });
    }

    const text = $('#textInput')?.value || '';
    const url = readInspectionUrl();
    if (!url) {
      throw client.ApiError(
        'invalid_input',
        'The analysis API does not inspect free-form text for authorship. Provide a URL to run /api/v1/filter-threat.',
        0
      );
    }
    return client.filterThreatUrl(url, { networkPayload: text });
  }

  function readInspectionUrl() {
    const field = String($('#textUrlInput')?.value || '').trim();
    if (field) return field;
    const urls = extractUrls($('#textInput')?.value || '');
    return urls[0] || '';
  }

  function bindScanControls() {
    $('#scanButton')?.addEventListener('click', runScan);
    $('#exportButton')?.addEventListener('click', exportReport);
  }

  async function runScan() {
    if (state.scanning) return;
    if (state.mode === 'media' && !state.file && !state.demoMedia) {
      showToast('Add a media file or choose a signal preset to begin.', 'fa-cloud-arrow-up');
      $('#dropZone')?.focus();
      return;
    }
    if (state.mode === 'media' && state.demoMedia && !state.file) {
      const error = api().ApiError('invalid_input', 'Visual presets are not sent to the analysis API. Upload a real file.', 0);
      applyResult(api().errorResult(error), { silent: true });
      showToast(error.message, 'fa-circle-exclamation');
      return;
    }

    const token = ++state.inspectToken;
    state.scanning = true;
    document.body.classList.add('scanning');
    const button = $('#scanButton');
    const label = button?.querySelector('span');
    if (button) button.classList.add('is-scanning');
    if (label) label.textContent = 'Inspecting';
    const status = $('#resultStatus');
    if (status) status.className = 'result-status review';
    if ($('#resultStatusText')) $('#resultStatusText').textContent = 'ANALYZING · BACKEND';

    try {
      const result = await inspectCurrentEvidence();
      if (token !== state.inspectToken) return;
      applyResult(result, { sourceType: state.mode });
      appendLog(result);
      if (Array.isArray(result.analysisLogs)) {
        result.analysisLogs.slice(-3).forEach((message) => {
          appendEvidenceEntry(new Date().toLocaleTimeString([], { hour12: false }), 'info', 'fa-terminal', message, result.statusText);
        });
      }
      showToast('Backend verdict received.', result.status === 'danger' ? 'fa-triangle-exclamation' : 'fa-shield-halved');
    } catch (error) {
      if (token !== state.inspectToken) return;
      applyConnectionError(error, false);
      const result = api().errorResult(error);
      applyResult(result, { silent: true });
      appendLog(result);
      showToast(result.caption, 'fa-circle-exclamation');
    } finally {
      if (token === state.inspectToken) {
        state.scanning = false;
        document.body.classList.remove('scanning');
        if (button) button.classList.remove('is-scanning');
        if (label) label.textContent = 'Run deep scan';
      }
    }
  }

  function applyResult(result, options = {}) {
    if (!result) return;
    if (!Array.isArray(result.signals) || result.signals.length < 4) return;
    state.lastResult = result;
    const isVerdict = result.source === 'backend' && result.score != null && Number.isFinite(Number(result.score));
    const source = result.source === 'backend' || result.source === 'error' || result.source === 'idle' ? result.source : 'idle';
    const gauge = $('#scoreGauge');
    if (gauge) {
      gauge.style.setProperty('--score', isVerdict ? result.score : 0);
      gauge.setAttribute('data-verdict', isVerdict ? 'backend' : source === 'error' ? 'error' : 'none');
    }
    if ($('#scoreValue')) $('#scoreValue').textContent = isVerdict ? Number(result.score).toFixed(1) : '—';
    if ($('#scoreUnit')) $('#scoreUnit').hidden = !isVerdict;
    if ($('#scoreKind')) $('#scoreKind').textContent = isVerdict ? 'TRUST SCORE' : 'NO VERDICT';
    if ($('#scoreCaption')) $('#scoreCaption').textContent = result.caption;
    const captionIcon = $('.score-caption i');
    if (captionIcon) {
      if (!isVerdict) {
        captionIcon.className = source === 'error' ? 'fa-solid fa-plug-circle-xmark' : 'fa-solid fa-circle-pause';
        captionIcon.style.color = source === 'error' ? 'var(--danger)' : 'var(--muted-light)';
      } else {
        captionIcon.className = result.status === 'danger' ? 'fa-solid fa-triangle-exclamation' : result.status === 'review' ? 'fa-solid fa-circle-exclamation' : 'fa-solid fa-circle-check';
        captionIcon.style.color = result.status === 'danger' ? 'var(--danger)' : result.status === 'review' ? 'var(--amber)' : 'var(--lime)';
      }
    }
    const status = $('#resultStatus');
    if (status) {
      status.setAttribute('data-source', source);
      status.className = isVerdict ? `result-status ${result.status}` : `result-status ${source}`;
    }
    const results = $('#results');
    if (results) results.setAttribute('data-source', source);
    if ($('#resultStatusText')) $('#resultStatusText').textContent = result.statusText;
    if ($('#confidenceValue')) $('#confidenceValue').textContent = isVerdict ? result.confidence : 'None';
    if ($('#confidencePercent')) $('#confidencePercent').textContent = isVerdict ? `${result.confidencePercent}%` : 'n/a';
    if ($('#confidenceTrack')) $('#confidenceTrack').style.width = isVerdict ? `${result.confidencePercent}%` : '0%';

    const rows = $$('.signal-row', $('#signalList'));
    rows.forEach((row, index) => {
      const signal = result.signals[index];
      if (!signal) return;
      const [label, value, tone, icon] = signal;
      const labelText = $('.signal-label span:not(.signal-icon)', row);
      const valueText = $('.signal-label b', row);
      const iconWrap = $('.signal-icon', row);
      const meter = $('.meter span', row);
      if (labelText) labelText.textContent = label;
      if (valueText) valueText.textContent = `${value}%`;
      if (iconWrap) {
        iconWrap.className = `signal-icon ${tone}`;
        iconWrap.innerHTML = `<i class="fa-solid ${icon}"></i>`;
      }
      if (meter) {
        meter.classList.toggle('review-meter', tone === 'review');
        meter.classList.toggle('danger-meter', tone === 'danger');
        meter.style.width = `${value}%`;
      }
    });
    if (options.silent) clearActiveThreatAlert();
    else evaluateThreatAlert(result, options.sourceType);
  }

  function appendLog(result) {
    const logList = $('#logList');
    if (!logList) return;
    const now = new Date();
    const time = now.toLocaleTimeString([], { hour12: false });
    const icon = result.status === 'danger' ? 'fa-triangle-exclamation' : result.status === 'review' ? 'fa-eye' : 'fa-check';
    const mark = result.status === 'danger' ? 'info' : result.status === 'review' ? 'violet' : 'success';
    const first = document.createElement('div');
    first.className = 'log-entry';
    const scoreLabel = result.source === 'backend' && result.score != null
      ? `${Number(result.score).toFixed(1)}%`
      : (result.source === 'error' ? 'NO VERDICT' : 'IDLE');
    first.innerHTML = `<time>${time}</time><span class="log-mark ${mark}"><i class="fa-solid ${icon}"></i></span><span>${escapeHtml(result.caption)}</span><b>${escapeHtml(scoreLabel)}</b>`;
    logList.prepend(first);
    while (logList.children.length > 4) logList.lastElementChild.remove();
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#039;', '"': '&quot;' }[character]));
  }

  function bindAlertControls() {
    $('#dismissThreatAlert')?.addEventListener('click', dismissThreatAlert);
    $('#reviewThreatAlert')?.addEventListener('click', () => {
      scrollTo('results');
      showToast('Evidence stream focused below.', 'fa-arrow-down');
    });
    $('#alertSoundToggle')?.addEventListener('click', () => {
      state.alertSoundEnabled = !state.alertSoundEnabled;
      updateAlertSoundControl();
      if (state.alertSoundEnabled) playAlertTone('review');
    });
    updateAlertSoundControl();
  }

  function updateAlertSoundControl() {
    const button = $('#alertSoundToggle');
    const label = $('#alertSoundLabel');
    if (!button) return;
    button.classList.toggle('muted', !state.alertSoundEnabled);
    button.setAttribute('aria-pressed', String(state.alertSoundEnabled));
    button.setAttribute('aria-label', state.alertSoundEnabled ? 'Mute threat alert sound' : 'Unmute threat alert sound');
    if (label) label.textContent = state.alertSoundEnabled ? 'SOUND ON' : 'MUTED';
  }

  function threatAlertPayload(result, sourceType) {
    if (!result || !result.evidenceFingerprint || result.source !== 'backend') return null;
    const metrics = result.metrics || {};
    const injection = Number(metrics.injectionIndex ?? metrics.threatBreakdown?.injectionRisk ?? 0);
    const obfuscation = Number(metrics.obfuscationIndex ?? metrics.threatBreakdown?.obfuscationRisk ?? 0);
    const contentRisk = Number(metrics.risk ?? metrics.threatRisk ?? (100 - Number(result.score || 100)));
    const critical = result.status === 'danger' || injection >= 48 || contentRisk >= 62;
    const review = result.status === 'review' || injection >= 28 || obfuscation >= 65 || contentRisk >= 30;
    if (!critical && !review) return null;

    const source = sourceType || (metrics.fileName ? 'media' : metrics.language ? 'code' : 'text');
    const severity = critical ? 'critical' : 'review';
    let title = 'Suspicious signal detected';
    if (source === 'code' && critical) title = 'Malicious code pattern detected';
    else if (source === 'media' && critical) title = 'File integrity warning';
    else if (source === 'text' && critical) title = 'Phishing intent detected';
    else if (source === 'code') title = 'Code anomaly requires review';
    else if (source === 'media') title = 'Suspicious file characteristics require review';
    else if (source === 'text') title = 'URL phishing signal requires review';

    const sourceLabel = source === 'code' ? 'DOM / CODE ANALYSIS' : source === 'media' ? 'FILE INSPECTION' : 'TEXT SHIELD';
    const message = critical
      ? (source === 'media' ? 'File integrity or entropy signals crossed the protection threshold. This is an integrity warning, not a media-authenticity verdict.' : source === 'code' ? 'Execution, decoder, redirect, or data-sink behavior crossed the active protection threshold.' : 'URL or network payload signals crossed the active protection threshold.')
      : 'The inspection engine found a measurable anomaly. Evidence is held for analyst review.';
    const evidence = source === 'code'
      ? `C ${Number(metrics.cyclomaticComplexity || 1).toFixed(1)} · H ${Number(metrics.entropyIndex || 0).toFixed(1)} · injection ${injection.toFixed(1)}`
      : source === 'media'
        ? `${metrics.signature || 'unknown file'} · H ${Number(metrics.byteEntropy || 0).toFixed(1)} · ${metrics.sha256 ? metrics.sha256.slice(0, 12) : 'digest pending'}…`
        : `url ${metrics.threatBreakdown?.url_phishing ?? 0} · file integrity ${metrics.threatBreakdown?.file_integrity ?? 0}`;
    const risk = clamp(Math.max(contentRisk, injection, 100 - Number(result.score || 100)));
    return {
      fingerprint: result.evidenceFingerprint,
      severity,
      source,
      sourceLabel,
      title,
      message,
      evidence,
      risk,
      score: Number(result.score || 0),
      icon: critical ? 'fa-triangle-exclamation' : 'fa-eye'
    };
  }

  function evaluateThreatAlert(result, sourceType) {
    const payload = threatAlertPayload(result, sourceType);
    if (!payload) {
      clearActiveThreatAlert();
      return;
    }
    if (state.dismissedAlertFingerprint === payload.fingerprint) return;

    const materialChange = state.activeAlertFingerprint !== payload.fingerprint
      || state.lastAlertSeverity !== payload.severity
      || state.lastAlertSource !== payload.source
      || Math.abs(payload.risk - state.lastAlertRisk) >= 8;
    state.activeAlertFingerprint = payload.fingerprint;
    state.lastAlertSeverity = payload.severity;
    state.lastAlertSource = payload.source;
    state.lastAlertRisk = payload.risk;
    renderActiveThreatAlert(payload);
    if (materialChange) {
      createThreatNotification(payload);
      playAlertTone(payload.severity);
    }
  }

  function renderActiveThreatAlert(payload) {
    const shell = $('#threatAlertShell');
    const banner = $('#threatAlertBanner');
    if (!shell || !banner) return;
    shell.hidden = false;
    banner.className = `threat-alert-banner ${payload.severity}`;
    $('#alertSeverity').textContent = payload.severity === 'critical' ? 'CRITICAL SIGNAL' : 'REVIEW REQUIRED';
    $('#alertTitle').textContent = payload.title;
    $('#alertMessage').textContent = payload.message;
    $('#alertEvidence').textContent = `${payload.sourceLabel} · ${payload.evidence}`;
    $('#alertScore').textContent = `RISK ${payload.risk.toFixed(1)}`;
  }

  function createThreatNotification(payload) {
    const stack = $('#threatNotificationStack');
    if (!stack) return;
    const notification = document.createElement('article');
    notification.className = `threat-notification ${payload.severity === 'review' ? 'review' : ''}`;
    notification.setAttribute('role', 'status');
    notification.innerHTML = `<span class="notification-icon"><i class="fa-solid ${payload.icon}"></i></span><span class="notification-copy"><b>${escapeHtml(payload.title)}</b><span>${escapeHtml(payload.message)}</span><small>${escapeHtml(payload.sourceLabel)} · RISK ${payload.risk.toFixed(1)}</small><span class="notification-sound" aria-hidden="true"><i></i><i></i><i></i></span></span><button class="notification-close" type="button" aria-label="Dismiss threat notification"><i class="fa-solid fa-xmark"></i></button>`;
    notification.querySelector('.notification-close')?.addEventListener('click', () => closeThreatNotification(notification));
    stack.prepend(notification);
    while (stack.children.length > 3) stack.lastElementChild.remove();
    window.setTimeout(() => closeThreatNotification(notification), 7200);
  }

  function closeThreatNotification(notification) {
    if (!notification || notification.classList.contains('is-closing')) return;
    notification.classList.add('is-closing');
    window.setTimeout(() => notification.remove(), 260);
  }

  function clearActiveThreatAlert() {
    const shell = $('#threatAlertShell');
    if (shell) shell.hidden = true;
    state.activeAlertFingerprint = '';
    state.dismissedAlertFingerprint = '';
    state.lastAlertSeverity = '';
    state.lastAlertSource = '';
    state.lastAlertRisk = 0;
  }

  function dismissThreatAlert() {
    const shell = $('#threatAlertShell');
    if (!shell) return;
    state.dismissedAlertFingerprint = state.activeAlertFingerprint;
    shell.hidden = true;
    showToast('Threat alert dismissed. Run a deep scan to refresh verdicts.', 'fa-shield-halved');
  }

  function playAlertTone(severity = 'critical') {
    if (!state.alertSoundEnabled) return;
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    try {
      state.audioContext ||= new AudioContextClass();
      const context = state.audioContext;
      const now = context.currentTime;
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = severity === 'critical' ? 'sawtooth' : 'triangle';
      oscillator.frequency.setValueAtTime(severity === 'critical' ? 620 : 440, now);
      oscillator.frequency.exponentialRampToValueAtTime(severity === 'critical' ? 330 : 290, now + .18);
      gain.gain.setValueAtTime(.0001, now);
      gain.gain.exponentialRampToValueAtTime(.045, now + .015);
      gain.gain.exponentialRampToValueAtTime(.0001, now + .22);
      oscillator.connect(gain).connect(context.destination);
      oscillator.start(now);
      oscillator.stop(now + .24);
      if (context.state === 'suspended') context.resume().catch(() => {});
    } catch (error) {
      // Audio is an enhancement; the visual waveform and banner remain active.
    }
  }

  function bindDeviceControls() {
    $('#refreshDevices')?.addEventListener('click', () => {
      const button = $('#refreshDevices');
      button.classList.add('is-refreshing');
      window.setTimeout(() => {
        button.classList.remove('is-refreshing');
        showToast('Demo perimeter refreshed. Device Guardian is layout only.', 'fa-circle-nodes');
      }, 780);
    });
    $('#manageDevices')?.addEventListener('click', () => {
      showToast('Device Guardian is demonstration layout only.', 'fa-mobile-screen-button');
    });
    $('#protectionToggle')?.addEventListener('click', (event) => {
      const toggle = event.currentTarget;
      const active = toggle.classList.toggle('active');
      toggle.setAttribute('aria-pressed', String(active));
      showToast(active ? 'Demo protection toggle on.' : 'Demo protection toggle off.', active ? 'fa-shield-halved' : 'fa-pause');
    });
  }

  function bindSamples() {
    $$('[data-sample]').forEach((button) => {
      button.addEventListener('click', () => {
        const sample = button.dataset.sample;
        if (sample === 'media') renderDemoMedia('image');
        if (sample === 'media-video') renderDemoMedia('video');
        if (sample === 'code' || sample === 'url') {
          setMode('code');
          $('#codeInput').value = codeSamples[sample];
          updateCounters();
          showToast('Code evidence preset loaded. Run a deep scan for a backend verdict.', 'fa-code');
        }
        if (sample === 'phishing' || sample === 'clean-text') {
          setMode('text');
          const preset = textSamples[sample];
          const textInput = $('#textInput');
          const urlInput = $('#textUrlInput');
          if (textInput) textInput.value = preset.body;
          if (urlInput) urlInput.value = preset.url;
          updateCounters();
          showToast(
            preset.url
              ? 'Text and URL loaded. Scan runs /api/v1/filter-threat on the URL, not authorship.'
              : 'Text loaded without a URL. URL scan is disabled until a URL is supplied.',
            'fa-message'
          );
        }
      });
    });
  }

  function exportReport() {
    const result = state.lastResult || api().idleResult();
    const origin = result.source === 'backend'
      ? `Backend ${result.endpoint || ''}`.trim()
      : result.source === 'error'
        ? 'No backend verdict (request failed)'
        : 'No backend verdict yet';
    const report = [
      'VERITAS//INSPECTOR — EVIDENCE REPORT',
      '--------------------------------------',
      `Generated: ${new Date().toISOString()}`,
      `Inspection mode: ${state.mode.toUpperCase()}`,
      `API destination: ${api().describeDestination().base || 'not configured'}`,
      `Result origin: ${origin}`,
      `Trust score: ${result.source === 'backend' && result.score != null ? `${Number(result.score).toFixed(1)} / 100` : 'n/a (no backend verdict)'}`,
      `Verdict: ${result.statusText}`,
      `Confidence: ${result.confidence} (${result.confidencePercent}%)`,
      result.metrics?.analysisId ? `Analysis id: ${result.metrics.analysisId}` : '',
      '',
      'Signal breakdown:',
      ...result.signals.map(([label, value]) => `- ${label}: ${value}%`),
      '',
      origin
    ].filter((line, index, lines) => line !== '' || (index > 0 && lines[index - 1] !== '')).join('\n');
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `veritas-report-${Date.now()}.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 500);
    showToast('Evidence report exported locally.', 'fa-file-export');
  }

  function showToast(message, icon = 'fa-shield-halved') {
    const container = $('#toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    window.setTimeout(() => {
      toast.classList.add('hide');
      window.setTimeout(() => toast.remove(), 320);
    }, 3200);
  }

  document.addEventListener('DOMContentLoaded', init);
})();

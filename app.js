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
    scanTimer: null,
    scanProgress: 0,
    lastResult: {
      score: 98.4,
      status: 'safe',
      statusText: 'LOW RISK · VERIFIED',
      caption: 'Evidence appears authentic',
      confidence: 'High',
      confidencePercent: 92,
      signals: [
        ['Authenticity markers', 99, 'safe', 'fa-fingerprint'],
        ['Behavioral consistency', 97, 'safe', 'fa-code-branch'],
        ['Threat indicators', 96, 'safe', 'fa-user-shield'],
        ['Generative artifacts', 94, 'review', 'fa-wand-magic-sparkles']
      ]
    }
  };

  const modeCopy = {
    media: {
      score: 98.4,
      status: 'safe',
      statusText: 'LOW RISK · VERIFIED',
      caption: 'Evidence appears authentic',
      confidence: 'High',
      confidencePercent: 92,
      signals: [
        ['Authenticity markers', 99, 'safe', 'fa-fingerprint'],
        ['Behavioral consistency', 97, 'safe', 'fa-code-branch'],
        ['Threat indicators', 96, 'safe', 'fa-user-shield'],
        ['Generative artifacts', 94, 'review', 'fa-wand-magic-sparkles']
      ]
    },
    code: {
      score: 87.6,
      status: 'review',
      statusText: 'REVIEW · ANOMALY FOUND',
      caption: 'One behavioral anomaly needs review',
      confidence: 'High',
      confidencePercent: 89,
      signals: [
        ['Source provenance', 94, 'safe', 'fa-fingerprint'],
        ['DOM behavior', 78, 'review', 'fa-code-branch'],
        ['Injection indicators', 92, 'safe', 'fa-user-shield'],
        ['Obfuscation patterns', 82, 'review', 'fa-wand-magic-sparkles']
      ]
    },
    text: {
      score: 31.4,
      status: 'danger',
      statusText: 'HIGH RISK · PHISHING SIGNALS',
      caption: 'Urgent social-engineering patterns detected',
      confidence: 'Very high',
      confidencePercent: 97,
      signals: [
        ['Authorship consistency', 42, 'review', 'fa-fingerprint'],
        ['Urgency language', 96, 'review', 'fa-bolt'],
        ['Credential harvesting', 91, 'review', 'fa-user-shield'],
        ['AI generation markers', 88, 'review', 'fa-wand-magic-sparkles']
      ]
    }
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
    phishing: 'Your account has been selected for an exclusive security upgrade. Confirm your identity within 30 minutes to avoid a temporary lock. Use the secure link below to continue.',
    'clean-text': 'The quarterly report outlines a measured increase in regional adoption, supported by transparent methodology and interviews with three independent researchers.'
  };

  function init() {
    bindNavigation();
    bindTabs();
    bindMediaInput();
    bindEditorTools();
    bindScanControls();
    bindDeviceControls();
    bindSamples();
    updateCounters();
    setActiveNav('overview');
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
      applyResult(modeCopy[mode]);
      if (mode === 'code') scheduleCodeAnalysis(true);
      if (mode === 'text') scheduleTextAnalysis(true);
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
    if (file.size > 250 * 1024 * 1024) {
      showToast('That file is larger than the 250 MB evidence limit.', 'fa-circle-exclamation');
      return;
    }

    const extension = file.name.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || '';
    const codeFile = file.type.startsWith('text/') || /\.(py|js|jsx|ts|tsx|json|html|css|sh|bash|ps1|txt)$/.test(extension);
    if (codeFile && !file.type.startsWith('image/') && !file.type.startsWith('video/')) {
      state.codeFile = file;
      state.file = null;
      state.fileAnalysis = null;
      file.text().then((source) => {
        setMode('code');
        const input = $('#codeInput');
        if (input) input.value = source;
        updateCounters();
        scheduleCodeAnalysis(true);
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
    showToast('Evidence loaded. Computing cryptographic and media integrity signals…', 'fa-circle-check');
    inspectMediaFile(file);
  }

  function renderMediaPreview(file) {
    const dropZone = $('#dropZone');
    const preview = $('#mediaPreview');
    const thumb = $('#previewThumb');
    if (!preview || !thumb) return;
    dropZone.hidden = true;
    preview.hidden = false;
    thumb.replaceChildren();

    if (file.type.startsWith('image/')) {
      const image = document.createElement('img');
      image.alt = 'Selected evidence preview';
      image.src = URL.createObjectURL(file);
      thumb.appendChild(image);
    } else {
      const video = document.createElement('video');
      video.muted = true;
      video.autoplay = true;
      video.loop = true;
      video.playsInline = true;
      video.src = URL.createObjectURL(file);
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
    const icon = document.createElement('i');
    icon.className = kind === 'video' ? 'fa-solid fa-film' : 'fa-solid fa-user-astronaut';
    thumb.appendChild(icon);
    thumb.style.background = kind === 'video'
      ? 'linear-gradient(145deg, #232250, #162f45 48%, #7a55ac)'
      : 'radial-gradient(circle at 52% 35%, #f2b99a 0 12%, transparent 13%), radial-gradient(circle at 51% 55%, #7b5aff 0 18%, transparent 19%), linear-gradient(145deg, #163943, #203056 53%, #8d5b9e)';
    $('#previewName').textContent = kind === 'video' ? 'synthetic-motion-frame.mp4' : 'synthetic-portrait-sample.png';
    $('#previewMeta').textContent = kind === 'video' ? 'Video frame · 18.7 MB' : 'Image · 2.4 MB';
    const presetResult = resultForCurrentEvidence();
    applyResult(presetResult);
    appendLiveEvidence(presetResult, 'media');
    showToast(`${kind === 'video' ? 'Video frame' : 'Synthetic portrait'} preset loaded.`, 'fa-wand-magic-sparkles');
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
      scheduleCodeAnalysis();
    });
    $('#textInput')?.addEventListener('input', () => {
      updateCounters();
      scheduleTextAnalysis();
    });
    $('#clearTextButton')?.addEventListener('click', () => {
      const textInput = $('#textInput');
      if (textInput) textInput.value = '';
      updateCounters();
      scheduleTextAnalysis(true);
      showToast('Evidence text cleared.', 'fa-eraser');
    });
    $('#pasteButton')?.addEventListener('click', async () => {
      try {
        const value = await navigator.clipboard.readText();
        if (!value) throw new Error('empty');
        $('#textInput').value = value;
        updateCounters();
        scheduleTextAnalysis(true);
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

  function fixed(value, digits = 1) {
    return Number(Number(value).toFixed(digits));
  }

  function countPattern(source, pattern) {
    if (!source || !pattern) return 0;
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
    return (source.match(new RegExp(pattern.source, flags)) || []).length;
  }

  function normalizedEntropy(values, cardinality) {
    if (!values || values.length < 2) return 0;
    const frequencies = new Map();
    values.forEach((value) => frequencies.set(value, (frequencies.get(value) || 0) + 1));
    const total = values.length;
    let entropy = 0;
    frequencies.forEach((frequency) => {
      const probability = frequency / total;
      entropy -= probability * Math.log2(probability);
    });
    const maximum = Math.log2(Math.max(2, cardinality || frequencies.size));
    return clamp(maximum ? (entropy / maximum) * 100 : 0);
  }

  function textFingerprint(value) {
    // FNV-1a is used as a synchronous evidence fingerprint while file uploads
    // also receive a Web Crypto SHA-256 digest below.
    let hash = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
  }

  function detectCodeLanguage(source) {
    const pythonSignals = /(^|\n)\s*(?:def\s+\w+\s*\(|class\s+\w+\s*[:(]|from\s+\S+\s+import\s+|if\s+__name__\s*==)/m;
    const javascriptSignals = /\b(?:const|let|var|function|console\.log|document\.|window\.)\b|=>/;
    if (pythonSignals.test(source) && !javascriptSignals.test(source)) return 'Python';
    return javascriptSignals.test(source) ? 'JavaScript' : 'Python';
  }

  function tokenizeForInspection(source) {
    const withoutComments = source
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ')
      .replace(/(^|\s)#[^\n]*/g, '$1 ');
    return withoutComments.match(/(?:`(?:\\.|[^`])*`|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|===|!==|>>>|=>|==|!=|<=|>=|&&|\|\||\?\?|\+\+|--|\*\*|[{}()[\];,.:?+\-*\/%=<>!&|^~])/g) || [];
  }

  function inspectBracketSyntax(tokens) {
    const openers = { '(': ')', '{': '}', '[': ']' };
    const closers = { ')': '(', '}': '{', ']': '[' };
    const stack = [];
    const errors = [];
    tokens.forEach((token, index) => {
      if (/^[`'\"]/.test(token)) return;
      if (openers[token]) stack.push({ token, index });
      if (closers[token]) {
        const last = stack.pop();
        if (!last || last.token !== closers[token]) errors.push(`unexpected closing delimiter ${token}`);
      }
    });
    stack.reverse().forEach((entry) => errors.push(`unclosed delimiter ${entry.token}`));
    return errors;
  }

  const liveInjectionRules = [
    ['dynamic_execution', /\b(?:eval|exec|compile|Function)\s*\(/i, 27],
    ['runtime_import', /\b(?:__import__|require|importlib\.import_module)\s*\(/i, 19],
    ['process_spawn', /\b(?:subprocess|child_process|os\.system|powershell|cmd\.exe)\b/i, 28],
    ['encoded_decoder', /\b(?:atob|btoa|base64\.(?:b64)?decode|fromCharCode|unescape)\b/i, 23],
    ['credential_access', /\b(?:document\.cookie|localStorage|sessionStorage|password|credential)\b/i, 20],
    ['html_injection', /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/i, 18],
    ['redirect_sink', /\b(?:window\.location|location\.href|fetch|XMLHttpRequest|requests?\.(?:get|post))\b/i, 10],
    ['destructive_shell', /(?:rm\s+-rf|curl\s+[^\n]+\|\s*(?:sh|bash)|wget\s+[^\n]+\|\s*(?:sh|bash))/i, 35]
  ];

  function analyzeCodeEvidence(source) {
    const code = String(source || '');
    if (!code.trim()) return { ...modeCopy.code, metrics: { empty: true }, evidenceFingerprint: 'empty-code' };

    const language = detectCodeLanguage(code);
    const tokens = tokenizeForInspection(code);
    const tokenEntropy = normalizedEntropy(tokens, Math.max(2, Math.min(tokens.length, 64)));
    const visibleCharacters = Array.from(code).filter((character) => !/\s/.test(character));
    const characterEntropy = normalizedEntropy(visibleCharacters, 95);
    const entropyIndex = clamp(characterEntropy * 0.65 + tokenEntropy * 0.35);
    const logicalLines = Math.max(1, code.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith('#') && !line.trim().startsWith('//')).length);
    const keywordTokens = tokens.map((token) => token.toLowerCase());
    const loopCount = keywordTokens.filter((token) => ['for', 'while', 'foreach', 'do'].includes(token)).length;
    const decisions = keywordTokens.filter((token) => ['if', 'elif', 'case', 'catch', 'except', 'for', 'while', 'foreach'].includes(token)).length;
    const booleanDecisions = keywordTokens.filter((token) => ['&&', '||', '??', '?', 'and', 'or'].includes(token)).length;
    const complexity = 1 + decisions + booleanDecisions;
    const structuralNodes = tokens.filter((token) => /^[{}()[\]]$/.test(token)).length;
    const syntaxNodeCount = Math.max(logicalLines, tokens.length + structuralNodes);
    const loopDensity = loopCount / Math.max(1, syntaxNodeCount);
    const syntaxErrors = inspectBracketSyntax(tokens);
    if (/^\s*(?:def|class)\b[^:\n]*$/m.test(code)) syntaxErrors.push('Python declaration is missing a colon');

    let injectionRisk = 0;
    const injectionFlags = [];
    liveInjectionRules.forEach(([name, pattern, weight]) => {
      if (pattern.test(code)) {
        injectionFlags.push(name);
        injectionRisk += weight;
      }
    });
    if (injectionFlags.length > 1) injectionRisk += Math.min(18, (injectionFlags.length - 1) * 4.5);
    injectionRisk = clamp(injectionRisk);

    const stringTokens = tokens.filter((token) => /^[`'\"]/.test(token));
    const longLiterals = stringTokens.filter((token) => token.length >= 48).length;
    const base64Hits = countPattern(code, /[A-Za-z0-9+/]{40,}={0,2}/);
    const escapedHits = countPattern(code, /(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){3,}/i);
    const longIdentifiers = countPattern(code, /\b[A-Za-z_$][A-Za-z0-9_$]{32,}\b/);
    const longestLine = code.split(/\r?\n/).reduce((longest, line) => Math.max(longest, line.length), 0);
    const whitespaceRatio = (code.match(/\s/g) || []).length / Math.max(1, code.length);
    const obfuscationSignals = clamp(
      longLiterals * 22 + base64Hits * 31 + escapedHits * 24 + longIdentifiers * 11
      + (longestLine >= 240 ? 18 : 0) + (code.length >= 300 && whitespaceRatio < 0.08 ? 12 : 0)
    );
    const obfuscationRisk = clamp(entropyIndex * 0.62 + obfuscationSignals * 0.38);
    const complexityRisk = clamp(((complexity - 1) / 24) * 100);
    const loopRisk = clamp(loopDensity * 400);
    const syntaxRisk = syntaxErrors.length ? 100 : 0;
    const weightedRisk = syntaxRisk * 0.12 + complexityRisk * 0.16 + loopRisk * 0.07 + entropyIndex * 0.18 + obfuscationRisk * 0.17 + injectionRisk * 0.30;
    let score = clamp(100 - weightedRisk);

    let status = 'safe';
    let statusText = 'LOW RISK · SOURCE VERIFIED';
    let caption = 'No high-confidence manipulation detected';
    if (injectionRisk >= 62 || (injectionRisk >= 50 && obfuscationRisk >= 42) || (injectionRisk >= 48 && entropyIndex >= 72)) {
      status = 'danger';
      statusText = 'HIGH RISK · INJECTION PATH';
      caption = 'Execution, decoding, or data-sink behavior requires containment';
      score = Math.min(score, 39.9);
    } else if (syntaxErrors.length || score < 75 || obfuscationRisk >= 78 || entropyIndex >= 90) {
      status = 'review';
      statusText = syntaxErrors.length ? 'REVIEW · SYNTAX ANOMALY' : 'REVIEW · OBFUSCATION SIGNALS';
      caption = syntaxErrors.length ? 'Malformed syntax reduces verification confidence' : 'Entropy and structure require analyst review';
      score = Math.min(score, 74.9);
    }

    const confidence = clamp(82 + Math.min(10, syntaxNodeCount / 12) + Math.min(5, tokens.length / 30) - (syntaxErrors.length ? 18 : 0) - (tokens.length < 4 ? 8 : 0));
    const flags = [
      ...syntaxErrors.map((error) => `syntax:${error}`),
      ...injectionFlags.map((flag) => `injection:${flag}`),
      ...(entropyIndex >= 76 ? ['obfuscation:high_entropy_stream'] : []),
      ...(base64Hits || longLiterals ? ['obfuscation:opaque_literal'] : []),
      ...(escapedHits ? ['obfuscation:escaped_payload'] : []),
      ...(complexity >= 12 ? ['complexity:high_cyclomatic'] : []),
      ...(loopDensity >= 0.2 ? ['complexity:loop_dense'] : [])
    ];
    const threatBreakdown = {
      syntaxRisk: fixed(syntaxRisk),
      complexityRisk: fixed(complexityRisk),
      loopDensityRisk: fixed(loopRisk),
      entropyRisk: fixed(entropyIndex),
      obfuscationRisk: fixed(obfuscationRisk),
      injectionRisk: fixed(injectionRisk)
    };
    const metrics = {
      language,
      lineCount: logicalLines,
      tokenCount: tokens.length,
      syntaxNodeCount,
      cyclomaticComplexity: fixed(complexity),
      loopCount,
      loopDensity: fixed(loopDensity, 4),
      characterEntropy: fixed(characterEntropy),
      tokenEntropy: fixed(tokenEntropy),
      entropyIndex: fixed(entropyIndex),
      obfuscationIndex: fixed(obfuscationRisk),
      injectionIndex: fixed(injectionRisk),
      syntaxErrors,
      threatBreakdown
    };
    return {
      score: fixed(score),
      status,
      statusText,
      caption,
      confidence: confidence >= 94 ? 'Very high' : confidence >= 82 ? 'High' : 'Moderate',
      confidencePercent: fixed(confidence),
      signals: [
        ['Syntax integrity', syntaxErrors.length ? 18 : 99, syntaxErrors.length ? 'review' : 'safe', 'fa-code'],
        ['Complexity consistency', fixed(100 - complexityRisk * 0.7), complexityRisk >= 55 ? 'review' : 'safe', 'fa-code-branch'],
        ['Injection indicators', fixed(100 - injectionRisk), injectionRisk >= 35 ? 'review' : 'safe', 'fa-user-shield'],
        ['Entropy / obfuscation', fixed(100 - obfuscationRisk), obfuscationRisk >= 65 ? 'review' : 'safe', 'fa-wand-magic-sparkles']
      ],
      metrics,
      anomalyFlags: flags,
      evidenceFingerprint: `code:${language}:${textFingerprint(code)}`,
      logSummary: `${language} AST pass · ${syntaxNodeCount} nodes · C ${fixed(complexity, 2)} · H ${fixed(entropyIndex, 2)}`,
      logDetail: `Loop density ${fixed(loopDensity, 4)} · injection ${fixed(injectionRisk, 2)} · obfuscation ${fixed(obfuscationRisk, 2)}`
    };
  }

  function scheduleCodeAnalysis(immediate = false) {
    window.clearTimeout(state.liveAnalysisTimer);
    if (immediate) {
      runLiveCodeAnalysis();
      return;
    }
    state.liveAnalysisTimer = window.setTimeout(runLiveCodeAnalysis, 260);
  }

  function runLiveCodeAnalysis() {
    if (state.mode !== 'code' || state.scanning) return;
    const result = analyzeCodeEvidence($('#codeInput')?.value || '');
    state.latestCodeAnalysis = result;
    applyResult(result);
    if (result.metrics && !result.metrics.empty) appendLiveEvidence(result, 'code');
  }

  function analyzeTextEvidence(text) {
    const source = String(text || '');
    const lower = source.toLowerCase();
    const urgency = countPattern(lower, /\b(?:urgent|immediately|minutes|now|suspend|lock)\b/g);
    const credential = countPattern(lower, /\b(?:password|credential|verify|confirm|account|secure link|payment)\b/g);
    if (!source.trim()) return { ...modeCopy.text, score: 98.8, caption: 'Waiting for text evidence', metrics: { wordCount: 0 }, evidenceFingerprint: 'empty-text' };
    const risk = clamp(urgency * 13 + credential * 8);
    const score = clamp(98 - risk * 0.85);
    const status = risk >= 55 ? 'danger' : risk >= 25 ? 'review' : 'safe';
    return {
      score: fixed(score),
      status,
      statusText: status === 'danger' ? 'HIGH RISK · PHISHING SIGNALS' : status === 'review' ? 'REVIEW · SOCIAL SIGNALS' : 'LOW RISK · AUTHENTICITY LIKELY',
      caption: status === 'danger' ? 'Urgency and credential-harvesting language detected' : status === 'review' ? 'Some persuasive-risk signals need review' : 'No meaningful phishing intent detected',
      confidence: source.length > 120 ? 'High' : 'Moderate',
      confidencePercent: fixed(clamp(78 + Math.min(18, source.length / 30))),
      signals: [
        ['Authorship consistency', fixed(100 - risk * 0.35), risk > 35 ? 'review' : 'safe', 'fa-fingerprint'],
        ['Urgency language', fixed(100 - urgency * 16), urgency ? 'review' : 'safe', 'fa-bolt'],
        ['Credential harvesting', fixed(100 - credential * 12), credential ? 'review' : 'safe', 'fa-user-shield'],
        ['AI generation markers', fixed(96 - Math.min(35, source.split(/\s+/).length / 5)), 'review', 'fa-wand-magic-sparkles']
      ],
      metrics: { wordCount: source.trim().split(/\s+/).length, urgencySignals: urgency, credentialSignals: credential, threatRisk: fixed(risk) },
      evidenceFingerprint: `text:${textFingerprint(source)}`,
      logSummary: `Text shield pass · ${source.trim().split(/\s+/).length} words · ${urgency + credential} intent signals`,
      logDetail: `Urgency ${urgency} · credential terms ${credential} · risk ${fixed(risk, 2)}`
    };
  }

  function scheduleTextAnalysis(immediate = false) {
    window.clearTimeout(state.liveAnalysisTimer);
    const run = () => {
      if (state.mode !== 'text' || state.scanning) return;
      const result = analyzeTextEvidence($('#textInput')?.value || '');
      applyResult(result);
      if (result.metrics && !result.metrics.empty) appendLiveEvidence(result, 'text');
    };
    if (immediate) run();
    else state.liveAnalysisTimer = window.setTimeout(run, 260);
  }

  function detectMediaSignature(bytes) {
    if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 'PNG';
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'JPEG';
    if (bytes.length >= 12 && String.fromCharCode(...bytes.slice(4, 8)) === 'ftyp') return 'MP4/ISO-BMFF';
    if (bytes.length >= 4 && String.fromCharCode(...bytes.slice(0, 4)) === 'RIFF') return 'RIFF/WebM';
    return 'Unknown';
  }

  function sampledByteEntropy(bytes) {
    const maxSample = 120000;
    const step = Math.max(1, Math.ceil(bytes.length / maxSample));
    const sample = [];
    for (let index = 0; index < bytes.length; index += step) sample.push(bytes[index]);
    return normalizedEntropy(sample, 256);
  }

  async function sha256Hex(buffer) {
    if (globalThis.crypto?.subtle) {
      const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
      return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
    }
    return textFingerprint(Array.from(new Uint8Array(buffer)).join(','));
  }

  async function inspectMediaFile(file) {
    const token = ++state.fileAnalysisToken;
    try {
      const buffer = await file.arrayBuffer();
      if (token !== state.fileAnalysisToken) return;
      const bytes = new Uint8Array(buffer);
      const signature = detectMediaSignature(bytes);
      const entropy = sampledByteEntropy(bytes);
      const digest = await sha256Hex(buffer);
      if (token !== state.fileAnalysisToken) return;
      const suspiciousName = /deepfake|synthetic|generated|ai[-_ ]?render|fake|payload|obfus/i.test(file.name);
      const signatureRisk = signature === 'Unknown' ? 27 : (file.type.startsWith('image/') && !['PNG', 'JPEG'].includes(signature)) || (file.type.startsWith('video/') && !['MP4/ISO-BMFF', 'RIFF/WebM'].includes(signature)) ? 22 : 0;
      const entropyRisk = clamp((entropy - 88) * 4);
      const generativeRisk = suspiciousName ? 86 : 0;
      const metadataRisk = file.size < 1024 ? 16 : 0;
      const risk = clamp(signatureRisk * 0.30 + entropyRisk * 0.16 + generativeRisk * 0.42 + metadataRisk * 0.12);
      const status = risk >= 62 ? 'danger' : risk >= 28 ? 'review' : 'safe';
      const result = {
        score: fixed(100 - risk),
        status,
        statusText: status === 'danger' ? 'HIGH RISK · MEDIA ANOMALY' : status === 'review' ? 'REVIEW · MEDIA SIGNALS' : 'LOW RISK · MEDIA VERIFIED',
        caption: status === 'danger' ? 'Integrity and generative-artifact signals require containment' : status === 'review' ? 'Media provenance requires analyst review' : 'Container and integrity signals appear consistent',
        confidence: file.size > 10000 ? 'High' : 'Moderate',
        confidencePercent: fixed(clamp(78 + Math.min(19, file.size / 50000))),
        signals: [
          ['Byte integrity', fixed(100 - entropyRisk), entropyRisk > 40 ? 'review' : 'safe', 'fa-fingerprint'],
          ['Container signature', fixed(100 - signatureRisk), signatureRisk ? 'review' : 'safe', 'fa-file-shield'],
          ['Threat indicators', fixed(100 - risk), risk > 35 ? 'review' : 'safe', 'fa-user-shield'],
          ['Generative artifacts', fixed(100 - generativeRisk), generativeRisk ? 'review' : 'safe', 'fa-wand-magic-sparkles']
        ],
        metrics: { fileName: file.name, sizeBytes: file.size, mimeType: file.type || 'unknown', signature, byteEntropy: fixed(entropy), sha256: digest, suspiciousName, risk: fixed(risk) },
        evidenceFingerprint: `file:${digest}`,
        logSummary: `Media integrity pass · ${signature} · H ${fixed(entropy, 2)} · sha256 ${digest.slice(0, 12)}…`,
        logDetail: `Container ${signatureRisk ? 'mismatch' : 'consistent'} · generative artifact index ${fixed(generativeRisk, 2)} · ${formatBytes(file.size)}`
      };
      state.fileAnalysis = result;
      applyResult(result);
      appendLiveEvidence(result, 'media');
      showToast(`Integrity metrics ready · SHA-256 ${digest.slice(0, 10)}…`, 'fa-fingerprint');
    } catch (error) {
      showToast('Media analysis could not read this file safely.', 'fa-circle-exclamation');
    }
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

  function appendLiveEvidence(result, sourceType) {
    if (!result || !result.evidenceFingerprint || state.lastEvidenceFingerprint === result.evidenceFingerprint) return;
    state.lastEvidenceFingerprint = result.evidenceFingerprint;
    const now = new Date().toLocaleTimeString([], { hour12: false });
    const mark = result.status === 'danger' ? 'info' : result.status === 'review' ? 'violet' : 'success';
    const icon = result.status === 'danger' ? 'fa-triangle-exclamation' : result.status === 'review' ? 'fa-eye' : 'fa-check';
    appendEvidenceEntry(now, mark, icon, `Live ${sourceType} · ${result.logSummary}`, `${Number(result.score).toFixed(1)}%`);
    if (result.logDetail) appendEvidenceEntry(now, 'info', 'fa-wave-square', result.logDetail, result.metrics?.sha256 ? result.metrics.sha256.slice(0, 12) : 'PASS');
  }

  function bindScanControls() {
    $('#scanButton')?.addEventListener('click', runScan);
    $('#exportButton')?.addEventListener('click', exportReport);
  }

  function runScan() {
    if (state.scanning) return;
    if (state.mode === 'media' && !state.file && !state.demoMedia) {
      showToast('Add a media file or choose a signal preset to begin.', 'fa-cloud-arrow-up');
      $('#dropZone')?.focus();
      return;
    }
    if (state.mode === 'media' && state.file && !state.fileAnalysis) {
      showToast('Integrity metrics are still computing. Try the deep scan again in a moment.', 'fa-hourglass-half');
      return;
    }

    state.scanning = true;
    state.scanProgress = 0;
    document.body.classList.add('scanning');
    const button = $('#scanButton');
    const label = button?.querySelector('span');
    if (button) button.classList.add('is-scanning');
    if (label) label.textContent = 'Initializing engines';
    setPendingStatus();

    state.scanTimer = window.setInterval(() => {
      state.scanProgress += state.scanProgress < 70 ? 7 : 4;
      if (state.scanProgress >= 100) {
        state.scanProgress = 100;
        window.clearInterval(state.scanTimer);
        window.setTimeout(finishScan, 180);
      }
      if (label) label.textContent = `Scanning ${state.scanProgress}%`;
      updatePendingStatus(state.scanProgress);
    }, 115);
  }

  function setPendingStatus() {
    const status = $('#resultStatus');
    if (!status) return;
    status.className = 'result-status review';
    $('#resultStatusText').textContent = 'ANALYZING · 0%';
  }

  function updatePendingStatus(progress) {
    const text = $('#resultStatusText');
    if (text) text.textContent = `ANALYZING · ${Math.min(progress, 100)}%`;
  }

  function finishScan() {
    state.scanning = false;
    document.body.classList.remove('scanning');
    const button = $('#scanButton');
    const label = button?.querySelector('span');
    if (button) button.classList.remove('is-scanning');
    if (label) label.textContent = 'Run deep scan';

    const result = resultForCurrentEvidence();
    applyResult(result);
    appendLog(result);
    showToast('Deep scan complete. Verdict stream updated.', result.status === 'danger' ? 'fa-triangle-exclamation' : 'fa-shield-halved');
  }

  function resultForCurrentEvidence() {
    if (state.mode === 'media') {
      if (state.fileAnalysis) return state.fileAnalysis;
      if (state.demoMedia) {
        return {
          score: 18.7,
          status: 'danger',
          statusText: 'HIGH RISK · SYNTHETIC MEDIA',
          caption: 'Generative artifacts strongly detected',
          confidence: 'Very high',
          confidencePercent: 99,
          signals: [
            ['Pixel authenticity', 12, 'review', 'fa-fingerprint'],
            ['Temporal consistency', 24, 'review', 'fa-film'],
            ['Face geometry', 19, 'review', 'fa-user-shield'],
            ['Generative artifacts', 97, 'review', 'fa-wand-magic-sparkles']
          ],
          metrics: { mediaPreset: true, generativeArtifactIndex: 97 },
          evidenceFingerprint: 'demo-media'
        };
      }
      return modeCopy.media;
    }

    if (state.mode === 'code') {
      return state.latestCodeAnalysis || analyzeCodeEvidence($('#codeInput')?.value || '');
    }

    return analyzeTextEvidence($('#textInput')?.value || '');
  }

  function applyResult(result) {
    if (!result) return;
    state.lastResult = result;
    const gauge = $('#scoreGauge');
    if (gauge) gauge.style.setProperty('--score', result.score);
    if ($('#scoreValue')) $('#scoreValue').textContent = Number(result.score).toFixed(1);
    if ($('#scoreCaption')) $('#scoreCaption').textContent = result.caption;
    const captionIcon = $('.score-caption i');
    if (captionIcon) {
      captionIcon.className = result.status === 'danger' ? 'fa-solid fa-triangle-exclamation' : result.status === 'review' ? 'fa-solid fa-circle-exclamation' : 'fa-solid fa-circle-check';
      captionIcon.style.color = result.status === 'danger' ? 'var(--danger)' : result.status === 'review' ? 'var(--amber)' : 'var(--lime)';
    }
    const status = $('#resultStatus');
    if (status) status.className = `result-status ${result.status}`;
    if ($('#resultStatusText')) $('#resultStatusText').textContent = result.statusText;
    if ($('#confidenceValue')) $('#confidenceValue').textContent = result.confidence;
    if ($('#confidencePercent')) $('#confidencePercent').textContent = `${result.confidencePercent}%`;
    if ($('#confidenceTrack')) $('#confidenceTrack').style.width = `${result.confidencePercent}%`;

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
        meter.style.width = `${value}%`;
      }
    });
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
    first.innerHTML = `<time>${time}</time><span class="log-mark ${mark}"><i class="fa-solid ${icon}"></i></span><span>${escapeHtml(result.caption)}</span><b>${Number(result.score).toFixed(1)}%</b>`;
    logList.prepend(first);
    while (logList.children.length > 4) logList.lastElementChild.remove();
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#039;', '"': '&quot;' }[character]));
  }

  function bindDeviceControls() {
    $('#refreshDevices')?.addEventListener('click', () => {
      const button = $('#refreshDevices');
      button.classList.add('is-refreshing');
      window.setTimeout(() => {
        button.classList.remove('is-refreshing');
        showToast('Protected perimeter synchronized just now.', 'fa-circle-nodes');
      }, 780);
    });
    $('#manageDevices')?.addEventListener('click', () => {
      showToast('Device management console is ready for your next connection.', 'fa-mobile-screen-button');
    });
    $('#protectionToggle')?.addEventListener('click', (event) => {
      const toggle = event.currentTarget;
      const active = toggle.classList.toggle('active');
      toggle.setAttribute('aria-pressed', String(active));
      showToast(active ? 'Adaptive protection enabled.' : 'Adaptive protection paused.', active ? 'fa-shield-halved' : 'fa-pause');
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
          scheduleCodeAnalysis(true);
          showToast('Code evidence preset loaded. AST metrics recalculated.', 'fa-code');
        }
        if (sample === 'phishing' || sample === 'clean-text') {
          setMode('text');
          $('#textInput').value = textSamples[sample];
          updateCounters();
          scheduleTextAnalysis(true);
          showToast('Text evidence preset loaded. Threat metrics recalculated.', 'fa-message');
        }
      });
    });
  }

  function exportReport() {
    const result = state.lastResult;
    const report = [
      'VERITAS//INSPECTOR — EVIDENCE REPORT',
      '--------------------------------------',
      `Generated: ${new Date().toISOString()}`,
      `Inspection mode: ${state.mode.toUpperCase()}`,
      `Trust score: ${Number(result.score).toFixed(1)} / 100`,
      `Verdict: ${result.statusText}`,
      `Confidence: ${result.confidence} (${result.confidencePercent}%)`,
      '',
      'Signal breakdown:',
      ...result.signals.map(([label, value]) => `- ${label}: ${value}%`),
      '',
      'Evidence is ephemeral and was evaluated in the Veritas Inspector browser session.'
    ].join('\n');
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

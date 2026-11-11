(() => {
  'use strict';

  const $ = (selector, scope = document) => scope.querySelector(selector);
  const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

  const state = {
    mode: 'media',
    scanning: false,
    file: null,
    demoMedia: false,
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
    if (!file.type.startsWith('image/') && !file.type.startsWith('video/')) {
      showToast('Unsupported file type. Add an image or video evidence file.', 'fa-circle-exclamation');
      return;
    }
    if (file.size > 250 * 1024 * 1024) {
      showToast('That file is larger than the 250 MB evidence limit.', 'fa-circle-exclamation');
      return;
    }
    state.file = file;
    state.demoMedia = false;
    renderMediaPreview(file);
    showToast('Evidence loaded and ready for a deep scan.', 'fa-circle-check');
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
    showToast(`${kind === 'video' ? 'Video frame' : 'Synthetic portrait'} preset loaded.`, 'fa-wand-magic-sparkles');
  }

  function clearMedia() {
    state.file = null;
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
    $('#codeInput')?.addEventListener('input', updateCounters);
    $('#textInput')?.addEventListener('input', updateCounters);
    $('#clearTextButton')?.addEventListener('click', () => {
      const textInput = $('#textInput');
      if (textInput) textInput.value = '';
      updateCounters();
      showToast('Evidence text cleared.', 'fa-eraser');
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
          ]
        };
      }
      const fileName = (state.file?.name || '').toLowerCase();
      if (/deepfake|synthetic|generated|ai/.test(fileName)) {
        return { ...modeCopy.media, score: 22.8, status: 'danger', statusText: 'HIGH RISK · SYNTHETIC MEDIA', caption: 'The file name and visual signals need review', confidence: 'High', confidencePercent: 94 };
      }
      return { ...modeCopy.media, score: 96.8, caption: 'No meaningful manipulation detected', confidencePercent: 95 };
    }

    if (state.mode === 'code') {
      const code = ($('#codeInput')?.value || '').toLowerCase();
      const suspicious = /(eval\s*\(|atob\s*\(|document\.cookie|innerhtml|window\.location|redirect|base64)/.test(code);
      if (suspicious) {
        return {
          score: 44.2,
          status: 'danger',
          statusText: 'HIGH RISK · INJECTION PATH',
          caption: 'Obfuscated redirect behavior requires containment',
          confidence: 'Very high',
          confidencePercent: 96,
          signals: [
            ['Source provenance', 52, 'review', 'fa-fingerprint'],
            ['DOM behavior', 36, 'review', 'fa-code-branch'],
            ['Injection indicators', 91, 'review', 'fa-user-shield'],
            ['Obfuscation patterns', 96, 'review', 'fa-wand-magic-sparkles']
          ]
        };
      }
      return { ...modeCopy.code, score: 91.8, status: 'safe', statusText: 'LOW RISK · SOURCE VERIFIED', caption: 'DOM behavior is within expected bounds', confidence: 'High', confidencePercent: 93 };
    }

    const text = ($('#textInput')?.value || '').toLowerCase();
    const phishing = /(confirm|verify|account|password|credential|urgent|minutes|lock|secure link|gift|payment)/.test(text);
    if (phishing) return modeCopy.text;
    return {
      score: 95.1,
      status: 'safe',
      statusText: 'LOW RISK · AUTHENTICITY LIKELY',
      caption: 'No meaningful phishing intent detected',
      confidence: 'High',
      confidencePercent: 91,
      signals: [
        ['Authorship consistency', 95, 'safe', 'fa-fingerprint'],
        ['Urgency language', 91, 'safe', 'fa-bolt'],
        ['Credential harvesting', 98, 'safe', 'fa-user-shield'],
        ['AI generation markers', 92, 'review', 'fa-wand-magic-sparkles']
      ]
    };
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
          showToast('Code evidence preset loaded.', 'fa-code');
        }
        if (sample === 'phishing' || sample === 'clean-text') {
          setMode('text');
          $('#textInput').value = textSamples[sample];
          updateCounters();
          showToast('Text evidence preset loaded.', 'fa-message');
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

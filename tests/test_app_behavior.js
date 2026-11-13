'use strict';

/**
 * Behavioral tests for app.js: object-URL preview lifecycle and health polling.
 *
 * These tests load the real app.js into a minimal browser harness
 * (tests/frontend_harness.js), drive it through its own event handlers, and
 * assert observable side effects — object URL creation/revocation, window
 * timers, health requests, and DOM state. No source-code string matching.
 *
 * Every scenario flushes pending async work while the harness still owns the
 * globals, then restores them, so tests cannot leak into each other.
 */

const assert = require('assert');
const {
  createHarness,
  fakeFile,
  settle,
  PAGES_LOCATION,
  LOCAL_LOCATION
} = require('./frontend_harness');

const IMAGE_A = () => fakeFile({ name: 'evidence-a.png', type: 'image/png', size: 2048 });
const IMAGE_B = () => fakeFile({ name: 'evidence-b.jpg', type: 'image/jpeg', size: 4096 });
const CODE_FILE = () => fakeFile({
  name: 'source.js',
  type: 'text/javascript',
  size: 64,
  text: async () => 'const x = 1;'
});

function withModeDom(h) {
  const tabs = ['media', 'code', 'text'].map((mode) => h.el({ dataset: { mode } }));
  const panels = ['media', 'code', 'text'].map((panel) => h.el({ dataset: { panel } }));
  // Mirror the initial markup in index.html: media tab/panel start active,
  // the code and text panels start hidden.
  tabs[0].classList.add('active');
  panels[1].hidden = true;
  panels[2].hidden = true;
  h.setAll('.mode-tab', tabs);
  h.setAll('.mode-panel', panels);
  return { tabs, panels };
}

function withSampleDom(h, samples = ['media', 'media-video', 'code', 'url', 'phishing', 'clean-text']) {
  const buttons = samples.map((sample) => h.el({ dataset: { sample } }));
  h.setAll('[data-sample]', buttons);
  return buttons;
}

function selectFile(h, file) {
  h.get('#fileInput').dispatch('change', { target: { files: [file] } });
}

function previewImage(h) {
  const thumb = h.get('#previewThumb');
  assert.strictEqual(thumb.children.length, 1, 'preview thumb should hold one child');
  return thumb.children[0];
}

async function cleanup(h) {
  await settle(); // let in-flight app work finish while the harness owns the globals
  h.restore();
}

// ---------------------------------------------------------------------------
// Task B — object URL lifecycle
// ---------------------------------------------------------------------------

async function testPreviewUrlCreatedAndKeptAlive() {
  const h = createHarness();
  try {
    withModeDom(h);
    h.boot();
    const file = IMAGE_A();
    selectFile(h, file);

    assert.strictEqual(h.createdUrls.length, 1, 'one object URL is created for the preview');
    assert.strictEqual(h.createdUrls[0].object, file, 'the object URL wraps the selected file');
    const image = previewImage(h);
    assert.strictEqual(image.tagName, 'IMG');
    assert.strictEqual(image.src, h.createdUrls[0].url, 'the visible preview uses the created URL');
    assert.deepStrictEqual(h.revokedUrls, [], 'a freshly created preview URL is not revoked');
    assert.strictEqual(h.get('#mediaPreview').hidden, false);
    assert.strictEqual(h.get('#dropZone').hidden, true);
    assert.strictEqual(h.get('#previewName').textContent, 'evidence-a.png');
    assert.match(h.get('#previewMeta').textContent, /^Image/);
  } finally {
    await cleanup(h);
  }
}

async function testReplacingPreviewRevokesPreviousUrl() {
  const h = createHarness();
  try {
    withModeDom(h);
    h.boot();
    selectFile(h, IMAGE_A());
    selectFile(h, IMAGE_B());

    assert.strictEqual(h.createdUrls.length, 2);
    const [urlA, urlB] = h.createdUrls.map((entry) => entry.url);
    assert.deepStrictEqual(h.revokedUrls, [urlA], 'replacing the preview revokes the previous URL only');
    assert.strictEqual(previewImage(h).src, urlB, 'the new preview uses the new URL');
    assert.ok(!h.revokedUrls.includes(urlB), 'the currently displayed URL stays alive');
  } finally {
    await cleanup(h);
  }
}

async function testRemovingPreviewRevokesUrl() {
  const h = createHarness();
  try {
    withModeDom(h);
    h.boot();
    selectFile(h, IMAGE_A());
    const url = h.createdUrls[0].url;

    h.get('#removeFile').dispatch('click');

    assert.deepStrictEqual(h.revokedUrls, [url], 'removing the file revokes its preview URL');
    assert.strictEqual(h.get('#mediaPreview').hidden, true);
    assert.strictEqual(h.get('#dropZone').hidden, false);
    assert.strictEqual(h.get('#previewThumb').children.length, 0);
    assert.strictEqual(h.get('#fileInput').value, '', 'the file input is reset');
  } finally {
    await cleanup(h);
  }
}

async function testCodeFileSwitchRevokesMediaPreviewUrl() {
  const h = createHarness();
  try {
    const { panels } = withModeDom(h);
    h.boot();
    selectFile(h, IMAGE_A());
    const url = h.createdUrls[0].url;

    selectFile(h, CODE_FILE());

    assert.deepStrictEqual(h.revokedUrls, [url], 'loading a source file revokes the media preview URL');
    await settle();
    assert.strictEqual(h.get('#codeInput').value, 'const x = 1;', 'the source is loaded into the code editor');
    assert.strictEqual(panels[1].hidden, false, 'the code panel becomes active');
    assert.strictEqual(panels[0].hidden, true, 'the media panel is hidden');
    assert.strictEqual(h.get('#codeCount').textContent, '12 characters');
  } finally {
    await cleanup(h);
  }
}

async function testDisplayedPreviewUrlNotRevokedPrematurely() {
  const h = createHarness();
  try {
    const { tabs } = withModeDom(h);
    h.boot();
    selectFile(h, IMAGE_A());
    const url = h.createdUrls[0].url;

    // Interact with unrelated UI while the preview is on screen.
    tabs[2].dispatch('click');
    tabs[1].dispatch('click');
    tabs[0].dispatch('click');
    h.get('#protectionToggle').dispatch('click');
    h.get('#refreshDevices').dispatch('click');

    assert.deepStrictEqual(h.revokedUrls, [], 'the displayed preview URL survives unrelated UI actions');
    assert.strictEqual(previewImage(h).src, url);
  } finally {
    await cleanup(h);
  }
}

async function testDemoPresetClearsLivePreviewUrl() {
  const h = createHarness();
  try {
    withModeDom(h);
    withSampleDom(h, ['media']);
    h.boot();
    selectFile(h, IMAGE_A());
    const url = h.createdUrls[0].url;

    h.doc.querySelectorAll('[data-sample]')[0].dispatch('click');

    assert.deepStrictEqual(h.revokedUrls, [url], 'a demo preset clears and revokes the live preview URL');
    assert.strictEqual(previewImage(h).tagName, 'I', 'the thumb falls back to a preset icon');
    assert.strictEqual(h.createdUrls.length, 1, 'the demo preset creates no object URL');
  } finally {
    await cleanup(h);
  }
}

// ---------------------------------------------------------------------------
// Task C — health polling
// ---------------------------------------------------------------------------

async function testUnconfiguredApiSendsNoHealthRequestAndNoTimer() {
  const h = createHarness({ location: PAGES_LOCATION });
  try {
    h.boot();
    await settle();
    assert.strictEqual(h.fetchCalls.length, 0, 'no health request is sent without a configured API');
    assert.strictEqual(h.win.intervals.size, 0, 'no recurring timer is left running');
    assert.strictEqual(h.win.timeouts.size, 0);
    assert.strictEqual(h.get('#backendStatusTitle').textContent, 'API NOT CONFIGURED');
    assert.strictEqual(h.get('#backendStatusDetail').textContent, 'NO HTTPS BACKEND');
  } finally {
    await cleanup(h);
  }
}

async function testConfiguredApiPollsImmediatelyAndSchedulesInterval() {
  const h = createHarness({ location: LOCAL_LOCATION });
  try {
    h.boot();
    const timers = [...h.win.intervals.entries()];
    assert.strictEqual(timers.length, 1, 'exactly one recurring timer is scheduled');
    assert.strictEqual(timers[0][1].ms, 15000, 'the health interval is the 15-second poll');
    await settle();
    assert.strictEqual(h.fetchCalls.length, 1, 'an initial health check runs immediately');
    assert.strictEqual(h.fetchCalls[0].url, 'http://localhost:8000/health');
    assert.strictEqual(h.get('#backendStatusTitle').textContent, 'API CONNECTED');
  } finally {
    await cleanup(h);
  }
}

async function testIntervalTickIssuesNewHealthRequest() {
  const h = createHarness({ location: LOCAL_LOCATION });
  try {
    h.boot();
    await settle();
    const timer = [...h.win.intervals.values()][0];
    await timer.fn();
    assert.strictEqual(h.fetchCalls.length, 2, 'each interval tick issues a new health request');
    assert.strictEqual(h.fetchCalls[1].url, 'http://localhost:8000/health');
  } finally {
    await cleanup(h);
  }
}

async function testConfigurationLossStopsPolling() {
  const h = createHarness({ location: LOCAL_LOCATION });
  try {
    h.boot();
    await settle();
    assert.strictEqual(h.win.intervals.size, 1);

    h.win.location = PAGES_LOCATION; // the configured API is no longer available
    const timer = [...h.win.intervals.values()][0];
    await timer.fn(); // the scheduled poll notices the configuration is gone

    assert.strictEqual(h.win.intervals.size, 0, 'polling stops when configuration disappears');
    assert.strictEqual(h.fetchCalls.length, 1, 'no health request is attempted without configuration');
    assert.strictEqual(h.get('#backendStatusTitle').textContent, 'API NOT CONFIGURED');
  } finally {
    await cleanup(h);
  }
}

async function testRepeatedInitializationKeepsSingleInterval() {
  const h = createHarness({ location: LOCAL_LOCATION });
  try {
    h.boot();
    const firstIds = [...h.win.intervals.keys()];
    assert.strictEqual(firstIds.length, 1);

    h.boot(); // initialization runs again

    const secondIds = [...h.win.intervals.keys()];
    assert.strictEqual(h.win.intervals.size, 1, 'no duplicate intervals accumulate');
    assert.strictEqual(secondIds.length, 1);
    assert.ok(!h.win.intervals.has(firstIds[0]), 'the earlier interval was cleared');
    await settle();
    assert.strictEqual(h.fetchCalls.length, 2, 'each initialization performs its own health check');
  } finally {
    await cleanup(h);
  }
}

// ---------------------------------------------------------------------------
// Task D — DOM-stub smoke flows (not a real browser run)
// ---------------------------------------------------------------------------

async function testSmokeInitialPageLoad() {
  const h = createHarness({ location: PAGES_LOCATION });
  try {
    const { tabs, panels } = withModeDom(h);
    withSampleDom(h);
    h.boot();
    await settle();
    assert.strictEqual(tabs[0].classList.contains('active'), true, 'media mode is the default');
    assert.strictEqual(panels[0].hidden, false);
    assert.strictEqual(panels[1].hidden, true);
    assert.strictEqual(panels[2].hidden, true);
    assert.strictEqual(h.get('#scoreValue').textContent, '—');
    assert.strictEqual(h.get('#resultStatusText').textContent, 'AWAITING INSPECTION');
    assert.strictEqual(h.get('#backendStatusTitle').textContent, 'API NOT CONFIGURED');
    assert.strictEqual(h.get('#codeCount').textContent, '0 characters');
  } finally {
    await cleanup(h);
  }
}

async function testSmokeModeSwitching() {
  const h = createHarness();
  try {
    const { tabs, panels } = withModeDom(h);
    h.boot();
    tabs[1].dispatch('click');
    assert.strictEqual(panels[1].hidden, false);
    assert.strictEqual(panels[0].hidden, true);
    assert.strictEqual(tabs[1].classList.contains('active'), true);
    assert.strictEqual(tabs[0].classList.contains('active'), false);
    tabs[2].dispatch('click');
    assert.strictEqual(panels[2].hidden, false);
    assert.strictEqual(panels[1].hidden, true);
    assert.strictEqual(tabs[2].getAttribute('aria-selected'), 'true');
  } finally {
    await cleanup(h);
  }
}

async function testSmokePhishingPreset() {
  const h = createHarness();
  try {
    const { panels } = withModeDom(h);
    const buttons = withSampleDom(h, ['phishing', 'clean-text']);
    h.boot();
    buttons[0].dispatch('click');
    assert.strictEqual(panels[2].hidden, false, 'the text panel becomes active');
    assert.match(h.get('#textInput').value, /security upgrade/);
    assert.strictEqual(
      h.get('#textUrlInput').value,
      'https://account-verification.example.com/session/continue'
    );
    assert.match(h.get('#wordCount').textContent, /\d+ words$/);
  } finally {
    await cleanup(h);
  }
}

async function testSmokeClearTextAndUrl() {
  const h = createHarness();
  try {
    withModeDom(h);
    const buttons = withSampleDom(h, ['phishing']);
    h.boot();
    buttons[0].dispatch('click');
    h.get('#clearTextButton').dispatch('click');
    assert.strictEqual(h.get('#textInput').value, '');
    assert.strictEqual(h.get('#textUrlInput').value, '');
    assert.strictEqual(h.get('#wordCount').textContent, '0 words');
  } finally {
    await cleanup(h);
  }
}

async function testSmokeMediaSelectAndRemove() {
  const h = createHarness();
  try {
    withModeDom(h);
    h.boot();
    selectFile(h, IMAGE_A());
    assert.strictEqual(h.get('#mediaPreview').hidden, false);
    assert.strictEqual(h.createdUrls.length, 1);
    h.get('#removeFile').dispatch('click');
    assert.strictEqual(h.get('#mediaPreview').hidden, true);
    assert.deepStrictEqual(h.revokedUrls, [h.createdUrls[0].url]);
  } finally {
    await cleanup(h);
  }
}

// ---------------------------------------------------------------------------
// Harness isolation — API globals are restored after cleanup
// ---------------------------------------------------------------------------

const VeritasAPIReal = require('../api.js');

function globalDescriptor(name) {
  return Object.getOwnPropertyDescriptor(global, name);
}

function hasGlobal(name) {
  return Object.prototype.hasOwnProperty.call(global, name);
}

function restoreGlobal(name, descriptor) {
  if (descriptor) Object.defineProperty(global, name, descriptor);
  else delete global[name];
}

async function testHarnessRestoresApiGlobalsWhenBaseOriginallyDefined() {
  const apiBaseBefore = globalDescriptor('VERITAS_API_BASE');
  const veritasBefore = globalDescriptor('VeritasAPI');
  try {
    // Non-trivial descriptors (enumerable: false) so an exact restoration is
    // distinguishable from a plain property assignment.
    Object.defineProperty(global, 'VERITAS_API_BASE', {
      value: 'http://sentinel.example:9000',
      writable: true,
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(global, 'VeritasAPI', {
      value: { sentinel: 'pre-harness' },
      writable: true,
      enumerable: false,
      configurable: true
    });
    const apiBaseDuring = globalDescriptor('VERITAS_API_BASE');
    const veritasDuring = globalDescriptor('VeritasAPI');

    const h = createHarness({ location: LOCAL_LOCATION });
    h.boot();
    assert.strictEqual(hasGlobal('VERITAS_API_BASE'), false, 'the harness clears VERITAS_API_BASE');
    assert.strictEqual(global.VeritasAPI, VeritasAPIReal, 'the harness binds the real API client');
    await cleanup(h);

    assert.deepStrictEqual(globalDescriptor('VERITAS_API_BASE'), apiBaseDuring,
      'VERITAS_API_BASE descriptor is restored exactly');
    assert.strictEqual(global.VERITAS_API_BASE, 'http://sentinel.example:9000');
    assert.deepStrictEqual(globalDescriptor('VeritasAPI'), veritasDuring,
      'VeritasAPI descriptor is restored exactly');
    assert.strictEqual(global.VeritasAPI.sentinel, 'pre-harness');
  } finally {
    restoreGlobal('VeritasAPI', veritasBefore);
    restoreGlobal('VERITAS_API_BASE', apiBaseBefore);
  }
}

async function testHarnessRestoresApiGlobalsWhenBaseOriginallyAbsent() {
  const apiBaseBefore = globalDescriptor('VERITAS_API_BASE');
  const veritasBefore = globalDescriptor('VeritasAPI');
  try {
    delete global.VERITAS_API_BASE;
    const veritasDuring = globalDescriptor('VeritasAPI');

    const h = createHarness({ location: PAGES_LOCATION });
    h.boot();
    assert.strictEqual(hasGlobal('VERITAS_API_BASE'), false);
    assert.strictEqual(global.VeritasAPI, VeritasAPIReal, 'the harness binds the real API client');
    await cleanup(h);

    assert.strictEqual(hasGlobal('VERITAS_API_BASE'), false,
      'VERITAS_API_BASE stays absent after cleanup');
    assert.deepStrictEqual(globalDescriptor('VeritasAPI'), veritasDuring,
      'VeritasAPI descriptor is restored exactly');
  } finally {
    restoreGlobal('VeritasAPI', veritasBefore);
    restoreGlobal('VERITAS_API_BASE', apiBaseBefore);
  }
}

async function testHarnessRestoreRunsWhenTestThrows() {
  const apiBaseBefore = globalDescriptor('VERITAS_API_BASE');
  const veritasBefore = globalDescriptor('VeritasAPI');
  try {
    Object.defineProperty(global, 'VERITAS_API_BASE', {
      value: 'http://sentinel.example:9000',
      writable: true,
      enumerable: false,
      configurable: true
    });
    const apiBaseDuring = globalDescriptor('VERITAS_API_BASE');

    const h = createHarness({ location: LOCAL_LOCATION });
    h.boot();
    let caught = null;
    try {
      try {
        throw new Error('simulated test failure');
      } finally {
        await cleanup(h); // the suite's standard pattern: finally cleanup during unwind
      }
    } catch (error) {
      caught = error;
    }

    assert.strictEqual(caught && caught.message, 'simulated test failure');
    assert.strictEqual(hasGlobal('VERITAS_API_BASE'), true);
    assert.deepStrictEqual(globalDescriptor('VERITAS_API_BASE'), apiBaseDuring,
      'VERITAS_API_BASE descriptor is restored exactly despite the thrown error');
    assert.strictEqual(global.VERITAS_API_BASE, 'http://sentinel.example:9000');
  } finally {
    restoreGlobal('VeritasAPI', veritasBefore);
    restoreGlobal('VERITAS_API_BASE', apiBaseBefore);
  }
}

// ---------------------------------------------------------------------------

const tests = [
  ['preview: creating a file preview builds an object URL and keeps it alive', testPreviewUrlCreatedAndKeptAlive],
  ['preview: replacing a preview revokes only the previous URL', testReplacingPreviewRevokesPreviousUrl],
  ['preview: removing the selected file revokes its preview URL', testRemovingPreviewRevokesUrl],
  ['preview: switching to a code file revokes the media preview URL', testCodeFileSwitchRevokesMediaPreviewUrl],
  ['preview: the displayed preview URL is not revoked prematurely', testDisplayedPreviewUrlNotRevokedPrematurely],
  ['preview: loading a demo preset revokes the live preview URL', testDemoPresetClearsLivePreviewUrl],
  ['health: unconfigured API sends no request and leaves no timer', testUnconfiguredApiSendsNoHealthRequestAndNoTimer],
  ['health: configured API checks immediately and schedules 15s interval', testConfiguredApiPollsImmediatelyAndSchedulesInterval],
  ['health: interval ticks issue new health requests', testIntervalTickIssuesNewHealthRequest],
  ['health: losing the configuration stops polling', testConfigurationLossStopsPolling],
  ['health: repeated initialization keeps a single interval', testRepeatedInitializationKeepsSingleInterval],
  ['smoke: initial page load settles the idle dashboard', testSmokeInitialPageLoad],
  ['smoke: inspection modes switch', testSmokeModeSwitching],
  ['smoke: phishing preset loads', testSmokePhishingPreset],
  ['smoke: clear button empties text and URL fields', testSmokeClearTextAndUrl],
  ['smoke: media preview select and remove', testSmokeMediaSelectAndRemove],
  ['harness: API globals restored after cleanup (VERITAS_API_BASE originally defined)', testHarnessRestoresApiGlobalsWhenBaseOriginallyDefined],
  ['harness: API globals restored after cleanup (VERITAS_API_BASE originally absent)', testHarnessRestoresApiGlobalsWhenBaseOriginallyAbsent],
  ['harness: globals restored when a test throws (finally cleanup)', testHarnessRestoreRunsWhenTestThrows]
];

async function main() {
  for (const [name, fn] of tests) {
    await fn();
    console.log('ok - ' + name);
  }
  console.log('app.js behavior tests passed');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

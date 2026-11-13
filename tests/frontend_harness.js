'use strict';

/**
 * Minimal browser harness for behavioral tests of app.js in Node.
 *
 * No external dependencies: it fakes only the surface app.js and api.js
 * actually touch — a small DOM with real event dispatch, window interval /
 * timeout registries, URL object-URL spies, and a recording fetch stub.
 * Tests load the real app.js and drive it through its own event handlers,
 * then assert observable side effects (object URLs, timers, requests, DOM).
 */

const path = require('path');

const APP_PATH = path.join(__dirname, '..', 'app.js');
const API_PATH = path.join(__dirname, '..', 'api.js');

// Requiring api.js registers global.VeritasAPI exactly as the browser script does.
const VeritasAPI = require(API_PATH);

class StubElement {
  constructor(tagName = 'div', key = null) {
    this.tagName = String(tagName).toUpperCase();
    this.key = key;
    this.attributes = {};
    this.dataset = {};
    this.children = [];
    this.parent = null;
    this.listeners = new Map();
    this.hidden = false;
    this.value = '';
    this.textContent = '';
    this.innerHTML = '';
    this.className = '';
    const classes = new Set();
    this.classList = {
      add: (...names) => { names.forEach((name) => classes.add(name)); },
      remove: (...names) => { names.forEach((name) => classes.delete(name)); },
      toggle: (name, force) => {
        const want = force === undefined ? !classes.has(name) : Boolean(force);
        if (want) classes.add(name);
        else classes.delete(name);
        return want;
      },
      contains: (name) => classes.has(name)
    };
    this.style = {
      setProperty: (name, value) => { this.style[name] = value; },
      removeProperty: (name) => { delete this.style[name]; }
    };
    this._scoped = new Map();
    this._groups = new Map();
  }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }

  removeEventListener(type, handler) {
    const list = this.listeners.get(type) || [];
    const index = list.indexOf(handler);
    if (index >= 0) list.splice(index, 1);
  }

  /** Dispatch a DOM-like event to this element's listeners. */
  dispatch(type, overrides = {}) {
    const event = {
      type,
      target: this,
      currentTarget: this,
      preventDefault() {},
      stopPropagation() {},
      ...overrides
    };
    for (const handler of [...(this.listeners.get(type) || [])]) handler(event);
    return event;
  }

  click() { this.dispatch('click'); }

  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
  }
  removeAttribute(name) { delete this.attributes[name]; }

  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  prepend(child) { child.parent = this; this.children.unshift(child); return child; }
  replaceChildren(...nodes) {
    this.children.forEach((child) => { child.parent = null; });
    this.children = [];
    nodes.forEach((node) => this.appendChild(node));
  }
  remove() {
    if (!this.parent) return;
    const index = this.parent.children.indexOf(this);
    if (index >= 0) this.parent.children.splice(index, 1);
    this.parent = null;
  }
  get lastElementChild() {
    return this.children.length ? this.children[this.children.length - 1] : null;
  }

  querySelector(selector) {
    if (!this._scoped.has(selector)) this._scoped.set(selector, new StubElement('span', selector));
    return this._scoped.get(selector);
  }
  querySelectorAll(selector) { return this._groups.get(selector) || []; }
  focus() {}
  scrollIntoView() {}
  closest() { return null; }
}

class FakeDocument {
  constructor() {
    this.body = new StubElement('body');
    this._elements = new Map();
    this._groups = new Map();
    this.listeners = new Map();
  }

  _stub(selector) {
    if (!this._elements.has(selector)) this._elements.set(selector, new StubElement('div', selector));
    return this._elements.get(selector);
  }

  querySelector(selector) { return this._stub(selector); }
  querySelectorAll(selector) { return this._groups.get(selector) || []; }
  getElementById(id) { return this._stub('#' + id); }
  createElement(tagName) { return new StubElement(tagName); }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }

  dispatch(type, overrides = {}) {
    const event = {
      type,
      target: this,
      currentTarget: this,
      preventDefault() {},
      stopPropagation() {},
      ...overrides
    };
    for (const handler of [...(this.listeners.get(type) || [])]) handler(event);
    return event;
  }
}

function createFakeWindow(location) {
  let seq = 0;
  const intervals = new Map();
  const timeouts = new Map();
  return {
    location,
    intervals,
    timeouts,
    setInterval(fn, ms) { seq += 1; intervals.set(seq, { fn, ms }); return seq; },
    clearInterval(id) { intervals.delete(id); },
    setTimeout(fn, ms) { seq += 1; timeouts.set(seq, { fn, ms }); return seq; },
    clearTimeout(id) { timeouts.delete(id); }
  };
}

const PAGES_LOCATION = {
  protocol: 'https:',
  hostname: 'mohamdmamdoh83-coder.github.io',
  search: ''
};
const LOCAL_LOCATION = { protocol: 'http:', hostname: 'localhost', search: '' };

const HEALTH_PAYLOAD = { status: 'ok', service: 'veritas-analysis-api' };

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'stub',
    text: async () => JSON.stringify(payload)
  };
}

/**
 * Build a fresh browser environment, load the real app.js into it, and expose
 * handles for tests. Call `restore()` when the scenario is done.
 */
function createHarness(options = {}) {
  const doc = new FakeDocument();
  const win = createFakeWindow(options.location || PAGES_LOCATION);
  const createdUrls = [];
  const revokedUrls = [];
  const fetchCalls = [];
  let urlSeq = 0;

  const original = {
    document: global.document,
    window: global.window,
    navigatorDescriptor: Object.getOwnPropertyDescriptor(global, 'navigator'),
    fetch: global.fetch,
    veritasApiDescriptor: Object.getOwnPropertyDescriptor(global, 'VeritasAPI'),
    apiBaseDescriptor: Object.getOwnPropertyDescriptor(global, 'VERITAS_API_BASE'),
    hadCreate: Object.prototype.hasOwnProperty.call(URL, 'createObjectURL'),
    createObjectURL: URL.createObjectURL,
    hadRevoke: Object.prototype.hasOwnProperty.call(URL, 'revokeObjectURL'),
    revokeObjectURL: URL.revokeObjectURL
  };

  URL.createObjectURL = (object) => {
    urlSeq += 1;
    const url = 'blob:mock-' + urlSeq;
    createdUrls.push({ url, object });
    return url;
  };
  URL.revokeObjectURL = (url) => { revokedUrls.push(url); };

  global.document = doc;
  global.window = win;
  // Node 22 exposes global.navigator as a getter-only property.
  Object.defineProperty(global, 'navigator', {
    value: { clipboard: { readText: async () => '' } },
    configurable: true,
    writable: true
  });
  global.fetch = async (url, init) => {
    fetchCalls.push({ url: String(url), init });
    const responder = options.fetch || (() => jsonResponse(HEALTH_PAYLOAD));
    return responder(String(url), init);
  };
  global.VeritasAPI = VeritasAPI;
  delete global.VERITAS_API_BASE;

  function restore() {
    global.document = original.document;
    global.window = original.window;
    if (original.navigatorDescriptor) Object.defineProperty(global, 'navigator', original.navigatorDescriptor);
    else delete global.navigator;
    global.fetch = original.fetch;
    if (original.veritasApiDescriptor) Object.defineProperty(global, 'VeritasAPI', original.veritasApiDescriptor);
    else delete global.VeritasAPI;
    if (original.apiBaseDescriptor) Object.defineProperty(global, 'VERITAS_API_BASE', original.apiBaseDescriptor);
    else delete global.VERITAS_API_BASE;
    if (original.hadCreate) URL.createObjectURL = original.createObjectURL;
    else delete URL.createObjectURL;
    if (original.hadRevoke) URL.revokeObjectURL = original.revokeObjectURL;
    else delete URL.revokeObjectURL;
  }

  // Load the real dashboard script: it registers its DOMContentLoaded handler.
  // If loading fails, restore the environment before propagating.
  try {
    delete require.cache[APP_PATH];
    require(APP_PATH);
  } catch (error) {
    restore();
    throw error;
  }

  return {
    doc,
    win,
    createdUrls,
    revokedUrls,
    fetchCalls,
    /** Same element instance app.js sees through $('#selector'). */
    get: (selector) => doc._stub(selector),
    /** Register the element group app.js sees through $$('.selector'). */
    setAll: (selector, elements) => { doc._groups.set(selector, elements); },
    el: (props = {}) => {
      const element = new StubElement(props.tagName || 'div');
      if (props.dataset) Object.assign(element.dataset, props.dataset);
      if (props.textContent !== undefined) element.textContent = props.textContent;
      return element;
    },
    /** Simulate initial page load (or a repeated initialization). */
    boot: () => doc.dispatch('DOMContentLoaded'),
    /** Run every currently scheduled fake window timer callback once. */
    runIntervals: async () => {
      for (const { fn } of [...win.intervals.values()]) {
        await fn();
      }
    },
    restore
  };
}

/** A File-like object with just the surface app.js reads. */
function fakeFile(overrides = {}) {
  return {
    name: 'evidence.png',
    size: 2048,
    type: 'image/png',
    text: async () => '',
    ...overrides
  };
}

/** Flush pending promise/microtask chains. */
function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

module.exports = {
  StubElement,
  FakeDocument,
  createHarness,
  fakeFile,
  settle,
  jsonResponse,
  PAGES_LOCATION,
  LOCAL_LOCATION,
  HEALTH_PAYLOAD
};

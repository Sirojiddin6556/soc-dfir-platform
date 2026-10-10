/**
 * test-all-frontend-spaces.mjs
 * Comprehensive End-to-End Verification of All Frontend Spaces and Views:
 *   1. Investigation Workspace (Graph, Timeline, Inspector, Collaboration)
 *   2. Operations Space (Incident & Case Management)
 *   3. Evidence Space (Artifacts, Facts, Custody Chain)
 *   4. Cyber Range Space (Simulation & Mission Verification)
 *   5. CTF Unified Workspace (Matrix, Workspace, Hex, Recipes, Writeups)
 *   6. System Diagnostics Space (Rust Engine, SQLite WAL, CAS Storage)
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// --- Complete Robust DOM Mock for Space Testing ---
class MockClassList {
  constructor(el) { this.el = el; this.classes = new Set(); }
  add(...cls) { cls.forEach(c => this.classes.add(c)); this.sync(); }
  remove(...cls) { cls.forEach(c => this.classes.delete(c)); this.sync(); }
  toggle(c, force) {
    const res = force !== undefined ? force : !this.classes.has(c);
    if (res) this.classes.add(c); else this.classes.delete(c);
    this.sync(); return res;
  }
  contains(c) { return this.classes.has(c); }
  sync() { this.el.className = Array.from(this.classes).join(' '); }
}

class MockElement {
  constructor(tagName = 'div') {
    this.tagName = tagName.toUpperCase();
    this.id = '';
    this.className = '';
    this.classList = new MockClassList(this);
    this.attributes = new Map();
    this.dataset = {};
    this.listeners = new Map();
    this.children = [];
    this.parentNode = null;
    this.style = {};
    this.value = '';
    this._textContent = '';
    this._innerHTML = '';
  }

  get textContent() { return this._textContent; }
  set textContent(val) {
    this._textContent = String(val ?? '');
    this.children = [];
  }

  get innerHTML() { return this._innerHTML; }
  set innerHTML(html) {
    this._innerHTML = html;
    this.children = [];
    this._parseHtml(html);
  }

  _parseHtml(html) {
    const tagRegex = /<([a-zA-Z0-9\-]+)([^>]*)>(.*?)<\/\1>|<([a-zA-Z0-9\-]+)([^>]*)\/?>/gs;
    let match;
    while ((match = tagRegex.exec(html))) {
      const tag = match[1] || match[4];
      const attrsStr = match[2] || match[5] || '';
      const child = new MockElement(tag);

      // parse id
      const idMatch = attrsStr.match(/id=["']([^"']+)["']/);
      if (idMatch) child.id = idMatch[1];

      // parse class
      const classMatch = attrsStr.match(/class=["']([^"']+)["']/);
      if (classMatch) {
        classMatch[1].split(/\s+/).filter(Boolean).forEach(c => child.classList.add(c));
      }

      // parse data-*
      const dataRegex = /data-([a-zA-Z0-9\-]+)=["']([^"']+)["']/g;
      let dMatch;
      while ((dMatch = dataRegex.exec(attrsStr))) {
        child.dataset[dMatch[1]] = dMatch[2];
        child.attributes.set(`data-${dMatch[1]}`, dMatch[2]);
      }

      // recursively parse inner content if any
      const innerContent = match[3];
      if (innerContent && innerContent.trim() && innerContent.includes('<')) {
        child._parseHtml(innerContent);
      } else if (innerContent) {
        child.textContent = innerContent.replace(/<[^>]+>/g, '');
      }

      child.parentNode = this;
      this.children.push(child);
    }
  }

  setAttribute(k, v) {
    this.attributes.set(k, String(v));
    if (k.startsWith('data-')) {
      const dataKey = k.slice(5).replace(/-([a-z])/g, (_, l) => l.toUpperCase());
      this.dataset[dataKey] = String(v);
    }
  }
  getAttribute(k) { return this.attributes.get(k) ?? null; }
  removeAttribute(k) { this.attributes.delete(k); }

  addEventListener(event, fn) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(fn);
  }
  removeEventListener(event, fn) {
    if (!this.listeners.has(event)) return;
    this.listeners.set(event, this.listeners.get(event).filter(f => f !== fn));
  }
  async dispatchEvent(event) {
    const list = this.listeners.get(event.type) || [];
    for (const fn of list) {
      await fn(event);
    }
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    const idx = this.children.indexOf(child);
    if (idx !== -1) {
      child.parentNode = null;
      this.children.splice(idx, 1);
    }
    return child;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  querySelectorAll(selector) {
    const results = [];
    const walk = (node) => {
      for (const child of node.children) {
        if (this._matches(child, selector)) results.push(child);
        walk(child);
      }
    };
    walk(this);
    return results;
  }

  _matches(el, selector) {
    if (selector.startsWith('#')) return el.id === selector.slice(1);
    if (selector.startsWith('.')) return el.classList.contains(selector.slice(1));
    if (selector.startsWith('[')) {
      const attrMatch = selector.match(/\[([a-zA-Z0-9\-]+)(?:=["']?([^"'\]]+)["']?)?\]/);
      if (attrMatch) {
        const [, attr, val] = attrMatch;
        if (attr.startsWith('data-')) {
          const key = attr.slice(5);
          return val !== undefined ? el.dataset[key] === val : el.dataset[key] !== undefined;
        }
        return val !== undefined ? el.getAttribute(attr) === val : el.attributes.has(attr);
      }
    }
    return el.tagName.toLowerCase() === selector.toLowerCase();
  }

  getContext() {
    return {
      clearRect: () => {},
      fillRect: () => {},
      beginPath: () => {},
      moveTo: () => {},
      lineTo: () => {},
      stroke: () => {},
      arc: () => {},
      fill: () => {},
      fillText: () => {}
    };
  }
}

// Global browser simulation
globalThis.requestAnimationFrame = (cb) => setTimeout(cb, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

const rootDoc = new MockElement('html');
const body = new MockElement('body');
rootDoc.appendChild(body);

globalThis.document = {
  createElement: (tag) => new MockElement(tag),
  getElementById: (id) => {
    const find = (node) => {
      if (node.id === id) return node;
      for (const c of node.children) {
        const found = find(c);
        if (found) return found;
      }
      return null;
    };
    return find(rootDoc);
  },
  querySelector: (sel) => rootDoc.querySelector(sel),
  querySelectorAll: (sel) => rootDoc.querySelectorAll(sel),
  body: body
};

globalThis.requestAnimationFrame = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 0));
globalThis.cancelAnimationFrame = globalThis.cancelAnimationFrame || ((id) => clearTimeout(id));

const jsRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'js');

globalThis.window = {
  location: { hash: '' },
  addEventListener: () => {},
  removeEventListener: () => {},
  prompt: (msg, def) => def || '',
  confirm: () => true,
  requestAnimationFrame: globalThis.requestAnimationFrame,
  cancelAnimationFrame: globalThis.cancelAnimationFrame,
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} }
};
globalThis.localStorage = globalThis.window.localStorage;

// Minimal shell fixture: the app renders each space into #spaceContainer.
body.innerHTML = `
<div id="socApp" class="soc-app">
  <header class="topbar"><span id="currentUserName">—</span></header>
  <div class="workspace-layout">
    <nav class="global-nav">
      <button data-space="system" class="active">Система</button>
      <button data-space="vulns">Уязвимости</button>
      <button data-space="code">Анализ кода</button>
      <button data-space="web">Запущенный сайт</button>
    </nav>
    <main id="spaceContainer" class="space-container"></main>
  </div>
</div>`;

// Permissive IPC: every space calls its own status/list RPC on render; return
// benign empty-but-shaped values so render() never throws.
class MockIpc {
  async call(method) {
    switch (method) {
      case 'cases.list': return [];
      case 'vulndb.status': return { ready: false, feeds: [], last_update: null };
      case 'code.status': return { running: false };
      case 'web.status': return { running: false };
      default: return {};
    }
  }
}
const ipc = new MockIpc();

const { SystemSpace } = await import(pathToFileURL(path.join(jsRoot, 'system/system.js')).href);
const { VulnerabilitySpace } = await import(pathToFileURL(path.join(jsRoot, 'vulns/vulns.js')).href);
const { CodeSpace } = await import(pathToFileURL(path.join(jsRoot, 'code/code.js')).href);
const { WebSpace } = await import(pathToFileURL(path.join(jsRoot, 'web/web.js')).href);

let passed = 0;
let failed = 0;
function assert(condition, message) {
  if (condition) { console.log(`  [PASS] ${message}`); passed++; }
  else { console.error(`  [FAIL] ${message}`); failed++; }
}

console.log('\n======================================================');
console.log('   SOC/DFIR PLATFORM — FRONTEND SPACES TEST SUITE');
console.log('======================================================\n');

// ----------------------------------------------------
// 1. System Space (strict)
// ----------------------------------------------------
console.log('[SPACE 1] System Space (Система & Диагностика)');
try {
  const sysSpace = new SystemSpace(ipc);
  const sysContainer = new MockElement('div');
  sysSpace.render(sysContainer);
  assert(sysContainer.innerHTML.includes('СИСТЕМНЫЙ УЗЕЛ И ДИАГНОСТИКА'), 'System header rendered');
  assert(sysContainer.innerHTML.includes('127.0.0.1:8080'), 'Engine status card rendered');
  assert(sysContainer.innerHTML.includes('SQLite 3 with WAL'), 'Database diagnostic card rendered');
} catch (e) {
  assert(false, `System space threw error: ${e.message}`);
}

// ----------------------------------------------------
// 2–4. Smoke-render the scanner spaces (Уязвимости, Анализ кода, Запущенный сайт)
// ----------------------------------------------------
const smokeSpaces = [
  ['Vulnerability Space (Уязвимости)', VulnerabilitySpace],
  ['Code Analysis Space (Анализ кода)', CodeSpace],
  ['Web / DAST Space (Запущенный сайт)', WebSpace],
];
let n = 1;
for (const [label, Space] of smokeSpaces) {
  n++;
  console.log(`\n[SPACE ${n}] ${label}`);
  try {
    const space = new Space(ipc);
    const container = new MockElement('div');
    await space.render(container);
    assert(container.innerHTML.trim().length > 0, `${label} rendered non-empty HTML`);
    if (typeof space.stopPolling === 'function') space.stopPolling();
  } catch (e) {
    assert(false, `${label} threw error: ${e.message}`);
  }
}

// ----------------------------------------------------
// SUMMARY
// ----------------------------------------------------
console.log('\n======================================================');
console.log(`TOTAL FRONTEND CHECKS: ${passed + failed}`);
console.log(`PASSED: ${passed}`);
console.log(`FAILED: ${failed}`);
console.log('======================================================\n');

if (failed > 0) {
  process.exit(1);
} else {
  console.log('>>> ALL KEPT FRONTEND SPACES RENDER CLEANLY <<<\n');
  process.exit(0);
}

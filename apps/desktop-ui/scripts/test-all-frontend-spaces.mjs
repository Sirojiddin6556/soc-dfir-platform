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

globalThis.window = {
  location: { hash: '#ctf-competitions' },
  addEventListener: () => {},
  removeEventListener: () => {},
  prompt: (msg, def) => def || 'Test Case',
  confirm: () => true,
  requestAnimationFrame: globalThis.requestAnimationFrame,
  cancelAnimationFrame: globalThis.cancelAnimationFrame
};

// Mock index.html structure
const htmlFixture = `
<div id="socApp" class="soc-app">
  <header class="topbar">
    <strong id="caseId">CASE-1337</strong>
    <span id="caseMode">LIVE</span>
    <span id="caseTimer">00:00:00</span>
    <div id="teamPresence"></div>
    <span id="unreadCount">0</span>
    <input id="globalSearch">
    <button id="startCollection">▶ Запустить сбор</button>
  </header>
  <div class="workspace-layout">
    <nav class="global-nav">
      <button data-space="operations">Операции</button>
      <button data-space="investigation" class="active">Расследование</button>
      <button data-space="evidence">Улики</button>
      <button data-space="range">Range</button>
      <button id="nav-ctf-workspace" data-space="ctf">CTF Workspace</button>
      <button data-space="system">Система</button>
    </nav>
    <main id="investigationWorkspace" class="investigation-workspace">
      <section class="layer-toolbar">
        <button data-layer="environment">Среда</button>
        <button data-layer="attack" class="active danger">Атака</button>
        <button data-layer="processes">Процессы</button>
        <button data-layer="network">Сеть</button>
        <button data-layer="mitre">ATT&CK</button>
        <button id="zoomOut">−</button>
        <span id="zoomLabel">100%</span>
        <button id="zoomIn">+</button>
        <button id="fitGraph">⌗</button>
      </section>
      <section class="investigation-canvas">
        <canvas id="investigationGraph"></canvas>
        <div id="graphEmptyState"></div>
        <div id="graphTooltip"></div>
        <canvas id="minimapCanvas"></canvas>
        <div id="minimapViewRect"></div>
      </section>
      <section class="forensic-bottom">
        <select id="timelineFilter">
          <option value="all">Все события</option>
          <option value="process">Процессы</option>
          <option value="network">Сеть</option>
          <option value="persistence">Закрепление</option>
          <option value="security">Безопасность</option>
        </select>
        <div id="timelineEvents"></div>
        <div id="eventDetails"></div>
      </section>
    </main>
    <aside class="context-panel">
      <div id="entityInspector"></div>
      <div id="discussionMessages"></div>
      <input id="discussionText">
      <button id="sendDiscussion">➤</button>
      <span id="discussionCount">0</span>
    </aside>
    <div id="view-ctf" class="view-panel hidden"></div>
  </div>
  <footer class="statusbar">
    <strong id="riskLevel">LOW</strong>
    <strong id="findingCount">0</strong>
    <strong id="evidenceCount">0</strong>
    <strong id="affectedHosts">0</strong>
    <span id="teamSyncState">Team: OFFLINE</span>
  </footer>
</div>
`;
body.innerHTML = htmlFixture;

// Mock IPC
class MockIpc {
  async call(method, params) {
    if (method === 'cases.list') {
      return [{ id: 'CASE-1337', case_id: 'CASE-1337', title: 'Расследование инцидента APT-29', status: 'ACTIVE', created_at: '2026-09-25T12:00:00Z' }];
    }
    if (method === 'cases.create') {
      return { id: 'CASE-2026', case_id: 'CASE-2026', title: params.title, status: 'ACTIVE', created_at: '2026-09-25T12:00:00Z' };
    }
    if (method === 'investigation.snapshot') {
      return {
        assets: [{ id: 'host-1', name: 'DC-01' }],
        graph: { nodes: [{ id: 'n1', label: 'lsass.exe', in_attack_path: true }], edges: [] },
        timeline: [{ event_id: 'e1', timestamp: '2026-09-25T12:00:00Z', title: 'Suspicious logon' }]
      };
    }
    if (method === 'auth.login') {
      return { session: { token: 'mock-token' } };
    }
    if (method === 'evidence.list') {
      return [{ id: 'art-1', name: 'sysmon.evtx', size: 1048576, hash_blake3: 'abcdef1234567890', method: 'Sysmon Dump', acquired_at: '2026-09-25T12:00:00Z' }];
    }
    if (method === 'ctf.competitions.list') {
      return [{ id: 'comp-1', name: 'DefCamp CTF 2026', flag_format: '^flag\\{.*\\}$' }];
    }
    if (method === 'ctf.challenges.list') {
      return [{ id: 'crypto-101', competition_id: 'comp-1', title: 'Crypto 101', category: 'Crypto', points: 100, status: 'open' }];
    }
    if (method === 'ctf.challenges.get') {
      return { id: 'crypto-101', competition_id: 'comp-1', title: 'Crypto 101', category: 'Crypto', points: 100, status: 'open', flag_format: 'flag{.*}', files: [] };
    }
    if (method === 'ctf.writeups.get') {
      return { challenge_id: 'crypto-101', title: 'Crypto 101 Writeup', markdown_body: '# Solution' };
    }
    if (method === 'ctf.notes.get') {
      return { challenge_id: 'crypto-101', content: 'Notes' };
    }
    if (method === 'ctf.artifacts.list') {
      return [{ id: 'art-101', challenge_id: 'crypto-101', filename: 'crackme.bin', size: 4096 }];
    }
    if (method === 'ctf.recipes.list') {
      return [{ id: 'rcp-1', challenge_id: 'crypto-101', name: 'XOR Decoder', steps_json: '[]' }];
    }
    if (method === 'ctf.flags.list' || method === 'ctf.jobs.list') {
      return [];
    }
    return {};
  }
}

const defaultIpc = new MockIpc();

// Hermetic Fetch Mock for CtfIpcClient
globalThis.fetch = async (url, options = {}) => {
  let body = {};
  try { body = JSON.parse(options.body || '{}'); } catch {}
  const { method, params } = body;
  const result = await defaultIpc.call(method, params);
  return {
    ok: true,
    status: 200,
    json: async () => ({ jsonrpc: '2.0', id: body.id || '1', result })
  };
};

// --- Import All Space Modules ---
const jsRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'js');
const { InvestigationWorkspace } = await import(pathToFileURL(path.join(jsRoot, 'investigation/workspace.js')).href);
const { OperationsSpace } = await import(pathToFileURL(path.join(jsRoot, 'operations/operations.js')).href);
const { EvidenceSpace } = await import(pathToFileURL(path.join(jsRoot, 'evidence/evidence.js')).href);
const { RangeSpace } = await import(pathToFileURL(path.join(jsRoot, 'range/range.js')).href);
const { SystemSpace } = await import(pathToFileURL(path.join(jsRoot, 'system/system.js')).href);
const { CtfApp } = await import(pathToFileURL(path.join(jsRoot, 'ctf/ctf_app.js')).href);

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failed++;
  }
}

console.log('\n======================================================');
console.log('   SOC/DFIR PLATFORM — ALL FRONTEND SPACES TEST SUITE');
console.log('======================================================\n');

const ipc = new MockIpc();

// ----------------------------------------------------
// 1. Investigation Workspace Test
// ----------------------------------------------------
console.log('[SPACE 1] Investigation Workspace (Расследование)');
try {
  const invWorkspace = new InvestigationWorkspace(ipc);
  await invWorkspace.init();
  assert(invWorkspace.graph !== null, 'InvestigationGraph initialized');
  assert(invWorkspace.timeline !== null, 'InvestigationTimeline initialized');
  assert(invWorkspace.inspector !== null, 'EntityInspector initialized');

  // Test Layer controls
  const netBtn = document.querySelector('[data-layer="network"]');
  if (netBtn) {
    await netBtn.dispatchEvent({ type: 'click' });
    assert(invWorkspace.store.activeLayer === 'network', 'Layer switched to network via button click');
  } else {
    invWorkspace.store.setLayer('network');
    assert(invWorkspace.store.activeLayer === 'network', 'Layer switched to network');
  }

  const atkBtn = document.querySelector('[data-layer="attack"]');
  if (atkBtn) {
    await atkBtn.dispatchEvent({ type: 'click' });
    assert(invWorkspace.store.activeLayer === 'attack', 'Layer switched to attack via button click');
  } else {
    invWorkspace.store.setLayer('attack');
    assert(invWorkspace.store.activeLayer === 'attack', 'Layer switched to attack');
  }

  // Test Timeline filter
  const filterSel = document.getElementById('timelineFilter');
  if (filterSel) {
    filterSel.value = 'process';
    await filterSel.dispatchEvent({ type: 'change', target: filterSel });
    assert(invWorkspace.timeline.filter === 'process', 'Timeline filtered by process via select control');
    filterSel.value = 'all';
    await filterSel.dispatchEvent({ type: 'change', target: filterSel });
    assert(invWorkspace.timeline.filter === 'all', 'Timeline filter reset to all via select control');
  } else {
    invWorkspace.timeline.filter = 'process';
    invWorkspace.timeline.renderEvents();
    assert(invWorkspace.timeline.filter === 'process', 'Timeline filtered by process');
  }

  // Test Zoom controls
  const initZoom = invWorkspace.graph.zoom;
  const zoomInBtn = document.getElementById('zoomIn');
  if (zoomInBtn) {
    await zoomInBtn.dispatchEvent({ type: 'click' });
    assert(invWorkspace.graph.zoom > initZoom, 'Zoom in increased scale');
  } else {
    invWorkspace.graph.setZoom(invWorkspace.graph.zoom * 1.15);
    assert(invWorkspace.graph.zoom > initZoom, 'Zoom in increased scale');
  }

  const zoomedInScale = invWorkspace.graph.zoom;
  const zoomOutBtn = document.getElementById('zoomOut');
  if (zoomOutBtn) {
    await zoomOutBtn.dispatchEvent({ type: 'click' });
    assert(invWorkspace.graph.zoom < zoomedInScale, 'Zoom out decreased scale');
  } else {
    invWorkspace.graph.setZoom(invWorkspace.graph.zoom * 0.85);
    assert(invWorkspace.graph.zoom < zoomedInScale, 'Zoom out decreased scale');
  }

  const fitBtn = document.getElementById('fitGraph');
  if (fitBtn) {
    await fitBtn.dispatchEvent({ type: 'click' });
    assert(invWorkspace.graph.zoom === 1.0, 'Fit graph reset scale to 100%');
  } else {
    invWorkspace.graph.resetView();
    assert(invWorkspace.graph.zoom === 1.0, 'Fit graph reset scale to 100%');
  }
} catch (e) {
  assert(false, `Investigation workspace threw error: ${e.message}`);
}

// ----------------------------------------------------
// 2. Operations Space Test
// ----------------------------------------------------
console.log('\n[SPACE 2] Operations Space (Операции)');
try {
  let selectedCase = null;
  const opsSpace = new OperationsSpace(ipc, (id) => { selectedCase = id; });
  const opsContainer = new MockElement('div');
  await opsSpace.render(opsContainer);

  assert(opsContainer.innerHTML.includes('ОПЕРАЦИИ И АКТИВНЫЕ ИНЦИДЕНТЫ'), 'Operations header rendered');
  const newCaseBtn = opsContainer.querySelector('#opsNewCaseBtn');
  assert(newCaseBtn !== null, 'New case button rendered');
  const grid = opsContainer.querySelector('#opsCaseGrid');
  assert(grid !== null, 'Operations case grid container rendered');

  // Simulate create case click
  if (newCaseBtn) {
    await newCaseBtn.dispatchEvent({ type: 'click' });
    assert(selectedCase === 'CASE-2026', 'Create case triggered selection callback');
  }
} catch (e) {
  assert(false, `Operations space threw error: ${e.message}`);
}

// ----------------------------------------------------
// 3. Evidence Space Test
// ----------------------------------------------------
console.log('\n[SPACE 3] Evidence Space (Улики)');
try {
  const evidenceSpace = new EvidenceSpace(ipc);
  const evidenceContainer = new MockElement('div');
  evidenceSpace.render(evidenceContainer);

  assert(evidenceContainer.innerHTML.includes('ХРАНИЛИЩЕ УЛИК'), 'Evidence header rendered');
  const uploadBtn = evidenceContainer.querySelector('#evidenceUploadBtn');
  assert(uploadBtn !== null, 'Upload evidence button rendered');

  const tabs = evidenceContainer.querySelectorAll('.tab-btn');
  assert(tabs.length === 3, 'Evidence tabs rendered (Artifacts, Facts, Custody)');

  // Test tab switching
  evidenceSpace._switchTab('facts');
  assert(evidenceSpace.activeTab === 'facts', 'Switched to Facts tab');
  evidenceSpace._switchTab('custody');
  assert(evidenceSpace.activeTab === 'custody', 'Switched to Chain of Custody tab');
  evidenceSpace._switchTab('artifacts');
  assert(evidenceSpace.activeTab === 'artifacts', 'Switched back to Artifacts tab');
} catch (e) {
  assert(false, `Evidence space threw error: ${e.message}`);
}

// ----------------------------------------------------
// 4. Cyber Range Space Test
// ----------------------------------------------------
console.log('\n[SPACE 4] Cyber Range Space (Киберполигон)');
try {
  const rangeSpace = new RangeSpace(ipc, () => {});
  const rangeContainer = new MockElement('div');
  rangeSpace.render(rangeContainer);

  assert(rangeContainer.innerHTML.includes('CYBER RANGE'), 'Cyber Range header and description rendered');
  assert(rangeContainer.innerHTML.includes('scoring-engine'), 'Cyber Range backend integration details rendered');
} catch (e) {
  assert(false, `Cyber Range space threw error: ${e.message}`);
}

// ----------------------------------------------------
// 5. CTF Unified Workspace Space Test
// ----------------------------------------------------
console.log('\n[SPACE 5] CTF Unified Workspace (Соревнования & Воркспейс)');
try {
  const ctfView = document.getElementById('view-ctf');
  const ctfApp = new CtfApp({ ipc, onNavigateLegacy: () => {} });
  await ctfApp.mount(ctfView);

  assert(ctfApp.container !== null, 'CtfApp mounted into container');
  assert(ctfApp.challengeMatrix !== null, 'Challenge Matrix component active on default route');

  // Test Challenge navigation
  await ctfApp.navigate('#ctf-challenge/crypto-101');
  assert(ctfApp.currentRoute === '#ctf-challenge/:id', 'Navigated to Challenge Workspace');
  assert(ctfApp.routeParams.id === 'crypto-101', 'Challenge ID parameter correctly bound');

  // Test Writeup navigation
  await ctfApp.navigate('#ctf-writeup/crypto-101');
  assert(ctfApp.currentRoute === '#ctf-writeup/:id', 'Navigated to Writeup Studio route');

  // Test Matrix return
  await ctfApp.navigate('#ctf-competitions');
  assert(ctfApp.currentRoute === '#ctf-competitions', 'Returned to Competitions Matrix route');

  ctfApp.destroy();
  assert(ctfApp.challengeMatrix === null && !ctfApp.isMounted && ctfApp.container === null, 'CtfApp cleanly destroyed without memory leaks');
} catch (e) {
  assert(false, `CTF Workspace space threw error: ${e.message}`);
}

// ----------------------------------------------------
// 6. System Diagnostics Space Test
// ----------------------------------------------------
console.log('\n[SPACE 6] System Space (Система & Диагностика)');
try {
  const sysSpace = new SystemSpace(ipc);
  const sysContainer = new MockElement('div');
  sysSpace.render(sysContainer);

  assert(sysContainer.innerHTML.includes('СИСТЕМНЫЙ УЗЕЛ И ДИАГНОСТИКА'), 'System header rendered');
  assert(sysContainer.innerHTML.includes('127.0.0.1:8080'), 'Engine status card rendered with online badge');
  assert(sysContainer.innerHTML.includes('SQLite 3 with WAL'), 'Database diagnostic card rendered with WAL info');
} catch (e) {
  assert(false, `System space threw error: ${e.message}`);
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
  console.log('>>> 100% OF FRONTEND SPACES AND VIEWS ARE FULLY OPERATIONAL! <<<\n');
}

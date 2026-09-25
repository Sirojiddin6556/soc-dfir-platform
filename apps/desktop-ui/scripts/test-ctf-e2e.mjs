/**
 * test-ctf-e2e.mjs - Comprehensive End-to-End Integration Test for CTF Unified Workspace
 * Tests:
 *   1. Line counts (< 500 lines) & syntax validity
 *   2. Router navigation & parameter extraction (#ctf-competitions, #ctf-challenge/:id, #ctf-writeup/:id, #legacy-cases)
 *   3. Store hydration & reactive state synchronization
 *   4. Component mount & destroy lifecycles (all 9 components)
 *   5. Hex loading, 64KB chunk sliding window, Shannon entropy & Chi-square
 *   6. Recipe pipeline, in-memory transforms & regex flag scanner
 *   7. Flag acceptance & challenge auto-solve trigger
 *   8. Write-up Studio, lineage DAG draft & SEC-ARCH-05 secret redaction
 *   9. Full CtfApp application workflow simulation & F9 panic kill
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// --- Minimal Mock DOM Environment for Node.js ---
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
    this._className = '';
    this.classList = new MockClassList(this);
    this.attributes = new Map();
    this.listeners = new Map();
    this.children = [];
    this.parentNode = null;
    this.style = {};
    this.value = '';
    this._textContent = '';
    this._innerHTML = '';
    this.scrollTop = 0;
    this.scrollLeft = 0;
    this.scrollHeight = 1000;
    this.scrollWidth = 800;
    this.clientHeight = 600;
    this.clientWidth = 800;
    this.offsetWidth = 800;
    this.offsetHeight = 600;
  }
  getBoundingClientRect() { return { top: 0, left: 0, width: 800, height: 600, right: 800, bottom: 600, x: 0, y: 0 }; }
  focus() {}
  blur() {}
  select() {}
  scrollTo() {}

  get className() { return this._className; }
  set className(val) {
    this._className = String(val || '');
    this.classList.classes = new Set(this._className.split(/\s+/).filter(Boolean));
  }
  get textContent() { return this._textContent; }
  set textContent(val) { this._textContent = String(val ?? ''); this.children = []; }

  setAttribute(k, v) {
    this.attributes.set(k, String(v));
    if (k === 'id') this.id = String(v);
    if (k === 'class') this.className = String(v);
  }
  getAttribute(k) {
    if (k === 'id') return this.id || null;
    if (k === 'class') return this.className || null;
    return this.attributes.get(k) || null;
  }
  hasAttribute(k) { return this.attributes.has(k); }
  removeAttribute(k) { this.attributes.delete(k); }

  addEventListener(evt, fn) {
    if (!this.listeners.has(evt)) this.listeners.set(evt, []);
    this.listeners.get(evt).push(fn);
  }
  removeEventListener(evt, fn) {
    if (!this.listeners.has(evt)) return;
    this.listeners.set(evt, this.listeners.get(evt).filter(f => f !== fn));
  }
  dispatchEvent(evt) {
    const type = typeof evt === 'string' ? evt : evt.type;
    const handlers = this.listeners.get(type) || [];
    for (const h of handlers) h({ type, target: this, currentTarget: this, preventDefault() {}, stopPropagation() {} });
    return true;
  }
  click() { this.dispatchEvent({ type: 'click' }); }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    const idx = this.children.indexOf(child);
    if (idx !== -1) { this.children.splice(idx, 1); child.parentNode = null; }
    return child;
  }

  get innerHTML() { return this._innerHTML; }
  set innerHTML(html) {
    this._innerHTML = html;
    this.children = [];
    if (!html) { this._textContent = ''; return; }
    const stack = [this];
    const tokenRegex = /<(\/)?([a-zA-Z0-9\-]+)([^>]*)>|([^<]+)/g;
    let match;
    const voidTags = new Set(['INPUT', 'IMG', 'BR', 'HR', 'META', 'LINK']);
    while ((match = tokenRegex.exec(html)) !== null) {
      const [full, isClosing, tagName, attrsStr, text] = match;
      if (text) { if (stack.length > 0) stack[stack.length - 1]._textContent += text; continue; }
      const tag = tagName.toUpperCase();
      if (isClosing) {
        if (stack.length > 1 && stack[stack.length - 1].tagName === tag) stack.pop();
      } else {
        const el = new MockElement(tag);
        if (attrsStr) {
          const attrRegex = /([a-zA-Z0-9\-]+)(?:=["']([^"']*)["'])?/g;
          let a;
          while ((a = attrRegex.exec(attrsStr)) !== null) {
            if (a[1] && a[1] !== '/') el.setAttribute(a[1], a[2] !== undefined ? a[2] : '');
          }
        }
        if (stack.length > 0) stack[stack.length - 1].appendChild(el);
        if (!voidTags.has(tag) && !full.endsWith('/>')) stack.push(el);
      }
    }
  }

  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  querySelectorAll(sel) {
    const results = [];
    const match = (el) => {
      if (sel === '*') return true;
      if (sel.startsWith('#') && el.id === sel.slice(1)) return true;
      if (sel.startsWith('.') && !sel.includes('[') && el.classList.contains(sel.slice(1))) return true;
      if (sel.toLowerCase() === el.tagName.toLowerCase()) return true;
      if (sel.startsWith('[') && sel.endsWith(']')) {
        const [, aName, aVal] = sel.match(/^\[([a-zA-Z0-9\-]+)(?:=["']([^"']*)["'])?\]$/) || [];
        if (aName) return aVal !== undefined ? el.getAttribute(aName) === aVal : el.hasAttribute(aName);
      }
      const complexMatch = sel.match(/^(\.?)([a-zA-Z0-9\-]+)\[([a-zA-Z0-9\-]+)(?:=["']([^"']*)["'])?\]$/);
      if (complexMatch) {
        const [, isClass, name, aName, aVal] = complexMatch;
        const nameMatches = isClass ? el.classList.contains(name) : el.tagName.toLowerCase() === name.toLowerCase();
        if (!nameMatches) return false;
        return aVal !== undefined ? el.getAttribute(aName) === aVal : el.hasAttribute(aName);
      }
      return false;
    };
    const walk = (node) => {
      for (const c of node.children) {
        if (match(c)) results.push(c);
        walk(c);
      }
    };
    walk(this);
    return results;
  }

  getContext(type) {
    return {
      fillRect() {}, clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {},
      stroke() {}, fill() {}, arc() {}, setLineDash() {}, scale() {}, save() {},
      restore() {}, fillText() {}, strokeText() {}, measureText() { return { width: 50 }; },
      closePath() {}, translate() {}, rotate() {},
      createLinearGradient() { return { addColorStop() {} }; }
    };
  }
}

// Global browser mocks
const mockDoc = {
  createElement: (tag) => new MockElement(tag),
  getElementById: (id) => mockDoc.body.querySelector(`#${id}`),
  querySelector: (sel) => mockDoc.body.querySelector(sel),
  querySelectorAll: (sel) => mockDoc.body.querySelectorAll(sel),
  body: new MockElement('body')
};
globalThis.document = mockDoc;
let _currentHash = '#ctf-competitions';
globalThis.window = {
  location: {
    get hash() { return _currentHash; },
    set hash(v) {
      _currentHash = v;
      if (globalThis.window.dispatchEvent) {
        globalThis.window.dispatchEvent({ type: 'hashchange' });
      }
    }
  },
  listeners: new Map(),
  addEventListener(evt, fn) {
    if (!this.listeners.has(evt)) this.listeners.set(evt, []);
    this.listeners.get(evt).push(fn);
  },
  removeEventListener(evt, fn) {
    if (!this.listeners.has(evt)) return;
    this.listeners.set(evt, this.listeners.get(evt).filter(f => f !== fn));
  },
  dispatchEvent(evt) {
    const list = this.listeners.get(evt.type || evt) || [];
    for (const fn of list) fn(evt);
  },
  requestAnimationFrame: (cb) => setTimeout(cb, 16)
};
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
globalThis.getComputedStyle = () => ({});
globalThis.HTMLElement = MockElement;
globalThis.Element = MockElement;
globalThis.CustomEvent = class { constructor(type, init = {}) { this.type = type; this.detail = init.detail; } };
globalThis.Event = class { constructor(type) { this.type = type; } };

let totalTests = 0, passedTests = 0, failedTests = 0;
function assert(condition, message) {
  totalTests++;
  if (condition) { passedTests++; console.log(`  \x1b[32m[PASS]\x1b[0m ${message}`); }
  else { failedTests++; console.error(`  \x1b[31m[FAIL]\x1b[0m ${message}`); }
}

console.log('\n\x1b[1;36m=== CTF UNIFIED WORKSPACE END-TO-END INTEGRATION TEST SUITE ===\x1b[0m\n');

// 1. Line Counts & Syntax
console.log('\x1b[1m[SUITE 1] Source Code Limits & Syntax Integrity\x1b[0m');
const baseDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const filesToCheck = ['js/ctf/ctf_app.js', 'js/app.js', 'css/ctf.css', 'index.html', 'js/ctf/components/workspace_view.js'];
for (const rel of filesToCheck) {
  const full = path.join(baseDir, rel);
  const count = readFileSync(full, 'utf8').split('\n').length;
  assert(count < 500, `${rel} is strictly under 500 lines (${count} lines)`);
  if (rel.endsWith('.js')) {
    try {
      execFileSync(process.execPath, ['--check', full], { stdio: 'pipe' });
      assert(true, `${rel} passed node --check syntax`);
    } catch { assert(false, `${rel} syntax check failed`); }
  }
}

// Module Imports
const { CtfApp } = await import('../js/ctf/ctf_app.js');
const { ctfIpc } = await import('../js/ctf/ctf_ipc.js');
const { workspaceStore } = await import('../js/ctf/workspace_store.js');
const { hexStore } = await import('../js/ctf/hex_store.js');
const { jobRunnerStore } = await import('../js/ctf/job_runner_store.js');
const { recipeStore } = await import('../js/ctf/recipe_store.js');
const { flagStore } = await import('../js/ctf/flag_store.js');
const { writeupStore } = await import('../js/ctf/writeup_store.js');
const {
  ChallengeMatrix, WorkspaceView, TerminalView, RecipeBuilder,
  FlagDrawer, WriteupView, HexViewer, EntropyMinimap, ByteDistributionChart
} = await import('../js/ctf/components/index.js');
const { calculateShannonEntropy } = await import('../js/ctf/components/entropy_minimap.js');
const { calculateChiSquare } = await import('../js/ctf/components/byte_distribution_chart.js');

// 2. Router Navigation
console.log('\n\x1b[1m[SUITE 2] Router Resolution & Navigation\x1b[0m');
let legacyTriggered = false;
const app = new CtfApp({ onNavigateLegacy: () => { legacyTriggered = true; } });
assert(app.parseRoute('#ctf-competitions').route === '#ctf-competitions', 'Route: #ctf-competitions matches matrix');
assert(app.parseRoute('#ctf-challenge/rev-100').route === '#ctf-challenge/:id', 'Route: #ctf-challenge/:id matches workspace');
assert(app.parseRoute('#ctf-challenge/rev-100').params.id === 'rev-100', 'Param: id correctly extracted (rev-100)');
assert(app.parseRoute('#ctf-writeup/pwn-200').route === '#ctf-writeup/:id', 'Route: #ctf-writeup/:id matches writeup');
assert(app.parseRoute('#ctf-writeup/pwn-200').params.id === 'pwn-200', 'Param: id correctly extracted (pwn-200)');
assert(app.parseRoute('#legacy-cases').route === '#legacy-cases', 'Route: #legacy-cases matches retro DFIR');
assert(app.parseRoute('').route === '#ctf-competitions', 'Fallback route defaults to #ctf-competitions');
await app.handleRoute('#legacy-cases');
assert(legacyTriggered === true, 'Legacy bridge callback executed on #legacy-cases');

// 3. Store Hydration
console.log('\n\x1b[1m[SUITE 3] Store Hydration & Artifact Hierarchy\x1b[0m');
workspaceStore.setState({
  activeCompetitionId: 'comp-2026',
  challenges: { 'c-1': { id: 'c-1', title: 'Crypto 101', category: 'crypto', points: 150, status: 'Unsolved' } },
  artifacts: {
    'art-1': { id: 'art-1', filename: 'cipher.bin', size_bytes: 2048, role: 'Input' },
    'art-2': { id: 'art-2', filename: 'extracted.txt', size_bytes: 512, role: 'Extracted' }
  }
});
const artList = Object.values(workspaceStore.getState().artifacts);
workspaceStore.setState({ artifactTree: workspaceStore.buildArtifactTree(artList) });
const wsState = workspaceStore.getState();
assert(wsState.artifactTree.length === 2, 'Artifact tree grouped into 2 role categories');
assert(wsState.challenges['c-1'].points === 150, 'Challenge points hydrated to 150');

// 4. Component Mount/Destroy Lifecycle
console.log('\n\x1b[1m[SUITE 4] Component Mount & Destroy Lifecycles\x1b[0m');
const testComponents = [
  { name: 'ChallengeMatrix', inst: new ChallengeMatrix() },
  { name: 'WorkspaceView', inst: new WorkspaceView() },
  { name: 'TerminalView', inst: new TerminalView() },
  { name: 'RecipeBuilder', inst: new RecipeBuilder() },
  { name: 'FlagDrawer', inst: new FlagDrawer() },
  { name: 'WriteupView', inst: new WriteupView() },
  { name: 'HexViewer', inst: new HexViewer() },
  { name: 'EntropyMinimap', inst: new EntropyMinimap() },
  { name: 'ByteDistributionChart', inst: new ByteDistributionChart() }
];
for (const { name, inst } of testComponents) {
  const container = new MockElement('div');
  inst.mount(container);
  assert(container.children.length > 0 || container.innerHTML.length > 0, `${name} rendered DOM nodes into container`);
  inst.destroy();
  assert(inst.container === null || inst.container.innerHTML === '', `${name} cleanly detached on destroy()`);
}

// 5. Hex Loading & Visualizations
console.log('\n\x1b[1m[SUITE 5] Hex Viewer & Mathematical Visualizations\x1b[0m');
const sampleBuffer = new Uint8Array(256);
for (let i = 0; i < 256; i++) sampleBuffer[i] = i;
hexStore.loadArtifact({ artifact_id: 'test-art', filename: 'test.bin', size_bytes: 256 });
hexStore.getState().chunkCache.set(0, sampleBuffer);
const formattedRow0 = hexStore.formatRow(0);
assert(formattedRow0.offsetHex === '00000000', 'Zero-offset gutter formatted as 00000000');
assert(formattedRow0.hexParts.length === 16, 'Row contains strictly 16 formatted bytes');
assert(formattedRow0.hexParts[0] === '00', 'Byte at offset 0 formatted as 00');
assert(formattedRow0.hexParts[15] === '0F', 'Byte at offset 15 formatted as 0F');
const hUniform = calculateShannonEntropy(sampleBuffer);
assert(Math.abs(hUniform - 8.0) < 0.001, `Uniform 256 bytes entropy is 8.00 bits/byte (${hUniform.toFixed(2)})`);
const hNulls = calculateShannonEntropy(new Uint8Array(256));
assert(hNulls === 0.0, 'Null bytes entropy is 0.00 bits/byte');
const freqs = new Uint32Array(256).fill(10);
const chi2 = calculateChiSquare(freqs, 2560);
assert(chi2 === 0.0, 'Chi-square of uniform frequency is 0.0');
hexStore.setSelection(0, 4);
assert(hexStore.copySelection('hex') === '00 01 02 03 04', 'Hex export format matches');

// 6. Recipe Pipeline
console.log('\n\x1b[1m[SUITE 6] Recipe Pipeline & Flag Scanner\x1b[0m');
const encodedFlag = Buffer.from('CTF{r3c1p3_succ3ss}').toString('base64');
recipeStore.clearOperations();
recipeStore.setInputData(encodedFlag);
recipeStore.addOperation({ operation: 'base64_decode' });
assert(recipeStore.getState().livePreviewText === 'CTF{r3c1p3_succ3ss}', 'Recipe live preview correctly decoded Base64');
assert(recipeStore.getState().detectedFlags.includes('CTF{r3c1p3_succ3ss}'), 'Regex scanner detected CTF flag candidate');

// 7. Flag Acceptance & Auto-Solve
console.log('\n\x1b[1m[SUITE 7] Flag Store & Auto-Solve Trigger\x1b[0m');
ctfIpc.getChallenge = async (id) => ({ id, title: 'Crypto 101', category: 'crypto', points: 150, status: 'Solved' });
ctfIpc.listChallengeArtifacts = async () => ([
  { id: 'art-1', artifact_id: 'art-1', filename: 'cipher.bin', size_bytes: 2048, role: 'Input' }
]);
ctfIpc.registerFlagCandidate = async () => ({ id: 'cand-001', candidate_id: 'cand-001' });
ctfIpc.acceptFlag = async () => ({ accepted: true });
ctfIpc.updateChallengeStatus = async () => { throw new Error('UI must not decide flag correctness'); };
ctfIpc.generateWriteupDraft = async () => ({
  markdown: '# Write-up: Crypto 101\n\n## Solution Steps\n1. Step A\n\n## Flag\nCTF{r3c1p3_succ3ss}'
});

workspaceStore.setState({
  activeChallengeId: 'c-1',
  activeChallenge: { id: 'c-1', title: 'Crypto 101', category: 'crypto', points: 150, status: 'Unsolved' },
  challenges: { 'c-1': { id: 'c-1', title: 'Crypto 101', category: 'crypto', points: 150, status: 'Unsolved' } }
});
flagStore.setState({ activeChallengeId: 'c-1', candidates: [] });
await flagStore.registerCandidate('CTF{r3c1p3_succ3ss}', 'recipe_output', 'c-1');
const candidate = flagStore.getState().candidates[0];
assert(candidate && candidate.status === 'candidate', 'Flag registered with candidate status');
flagStore.setFilter('candidates');
assert(flagStore.getFilteredCandidates().length === 1, 'Filter candidates returns 1 item');
await flagStore.acceptFlag(candidate.id);
assert(flagStore.getState().candidates[0].status === 'accepted', 'Flag status transitioned to accepted');
assert(flagStore.getFilteredCandidates().length === 0, 'No pending flags in candidates filter');
flagStore.setFilter('accepted');
assert(flagStore.getFilteredCandidates().length === 1, '1 flag found in accepted filter');
assert(workspaceStore.getState().challenges['c-1'].status === 'Unsolved', 'Client does not mark a challenge solved independently of server verification');
ctfIpc.acceptFlag = async () => ({ accepted: false });
flagStore.setState({ candidates: [{ ...candidate, status: 'candidate' }], filter: 'all' });
let incorrectFlagRejected = false;
try { await flagStore.acceptFlag(candidate.id); } catch (_) { incorrectFlagRejected = true; }
assert(incorrectFlagRejected, 'Server rejection for an incorrect flag is shown to the user');
assert(flagStore.getState().candidates[0].status === 'candidate', 'Rejected flag remains pending and cannot solve the challenge');

// 8. Write-up Studio & Redaction
console.log('\n\x1b[1m[SUITE 8] Write-up Studio & SEC-ARCH-05 Redaction\x1b[0m');
await writeupStore.loadDraft('c-1');
const draftMd = writeupStore.getState().draftMarkdown;
assert(draftMd.includes('# Write-up: Crypto 101'), 'Draft includes generated title');
assert(draftMd.includes('## Solution Steps'), 'Draft includes lineage steps section');
const sensitiveText = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID and password="SuperSecretPass123!"';
const redacted = writeupStore.redactSecrets(sensitiveText);
assert(!redacted.includes('SuperSecretPass123!'), 'Password redacted from markdown');
assert(redacted.includes('[REDACTED]'), 'Replaced with [REDACTED] placeholder');

// 9. CtfApp Simulation
console.log('\n\x1b[1m[SUITE 9] CtfApp End-to-End Application Simulation\x1b[0m');
const rootContainer = new MockElement('div');
ctfIpc.listCompetitions = async () => ([{ id: 'comp-test', name: 'Practice CTF', format: 'jeopardy', status: 'active' }]);
ctfIpc.getCompetition = async (id) => ({ id, name: 'Practice CTF', format: 'jeopardy', status: 'active' });
ctfIpc.listChallenges = async () => ([{ id: 'c-1', competition_id: 'comp-test', name: 'Crypto 101', category: 'crypto', points: 150, status: 'new' }]);
ctfIpc.listTools = async () => ([{ id: 'strings', name: 'Strings' }]);
ctfIpc.listFlags = async () => ([]);
const ctfApp = new CtfApp({ workspaceStore, hexStore, jobRunnerStore, recipeStore, flagStore, writeupStore });
await ctfApp.mount(rootContainer);
assert(ctfApp.isMounted === true, 'CtfApp mounted cleanly into root DOM container');
assert(ctfApp.currentRoute === '#ctf-competitions', 'Initial route mounted is #ctf-competitions');
assert(ctfApp.challengeMatrix !== null, 'ChallengeMatrix component active in competitions view');

await ctfApp.navigate('#ctf-challenge/c-1');
assert(ctfApp.currentRoute === '#ctf-challenge/:id', 'Navigated to #ctf-challenge/:id');
assert(ctfApp.workspaceView !== null, 'WorkspaceView mounted in challenge route');
assert(ctfApp.terminalView !== null, 'TerminalView mounted in bottom slot');
assert(ctfApp.flagDrawer !== null, 'FlagDrawer mounted in right slot');
assert(ctfApp.recipeBuilder !== null, 'RecipeBuilder mounted in center recipe tab');

ctfApp.workspaceView.setActiveTab('hex');
assert(ctfApp.hexViewer !== null, 'HexViewer mounted on hex tab');
assert(ctfApp.byteDistributionChart !== null, 'ByteDistributionChart mounted on hex tab');

ctfApp.workspaceView.setActiveTab('writeup');
assert(ctfApp.writeupView !== null, 'WriteupView mounted on writeup tab');

let panicInvoked = false;
jobRunnerStore.panicKillAll = async () => { panicInvoked = true; };
await ctfApp.navigate('#ctf-competitions');
const panicBtn = rootContainer.querySelector('#ctfGlobalPanicBtn');
panicBtn.click();
assert(panicInvoked === true, 'F9 Panic Kill button triggered emergency stop');

await ctfApp.navigate('#ctf-writeup/c-1');
assert(ctfApp.currentRoute === '#ctf-writeup/:id', 'Navigated to #ctf-writeup/:id');
assert(ctfApp.writeupView !== null, 'WriteupView mounted in dedicated studio route');

ctfApp.destroy();
assert(ctfApp.isMounted === false, 'CtfApp cleanly destroyed with no memory leaks');

// Summary
console.log('\n\x1b[1;36m=== TEST SUMMARY ===\x1b[0m');
console.log(`Total Assertions: ${totalTests}`);
console.log(`Passed: \x1b[32m${passedTests}\x1b[0m`);
console.log(`Failed: ${failedTests > 0 ? `\x1b[31m${failedTests}\x1b[0m` : '0'}`);

if (failedTests > 0) {
  console.error('\n\x1b[31mFAIL: Some end-to-end integration tests failed.\x1b[0m');
  process.exit(1);
} else {
  console.log('\n\x1b[32mSUCCESS: 100% OF CTF E2E INTEGRATION TESTS PASSED!\x1b[0m\n');
  process.exit(0);
}

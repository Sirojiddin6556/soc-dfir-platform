/**
 * test-xss.mjs - regression test for stored/reflected XSS in the desktop UI.
 *
 * Feeds attacker-style payloads (the kind that arrive in process names,
 * command lines, file names, EVTX/PCAP strings, chat messages, CTF challenge
 * text) through the real rendering modules and inspects the HTML they assign
 * to innerHTML with a small tokenizer that follows the HTML spec's tag and
 * attribute states (including RCDATA for <textarea>, so a "</textarea>"
 * breakout is caught). For every rendering path it asserts:
 *   1. the payload produced no injected element (script/img/svg/iframe/...)
 *      and no injected attribute (on*, src, autofocus, ...);
 *   2. the tag/attribute structure is identical to a render with benign data,
 *      i.e. the payload could not change the DOM shape at all;
 *   3. the payload is still shown to the analyst, as escaped text.
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------
const PAYLOAD = [
  '<img src=x onerror=alert(1)>',
  '"><svg onload=alert(1)>',
  '</textarea><script>alert(1)</script>',
  "' onmouseover='alert(1)",
  '" autofocus onfocus="alert(1)',
  '`-alert(1)-`'
].join('');
const BENIGN = 'benign-value';
// Proof the payload is rendered as visible text rather than dropped.
const ESCAPED_IMG = '&lt;img src=x onerror=alert(1)&gt;';

const FORBIDDEN_TAGS = new Set(['script', 'img', 'svg', 'iframe', 'object', 'embed', 'math', 'link', 'meta', 'base', 'style', 'video', 'audio', 'source', 'form']);
const FORBIDDEN_ATTRS = new Set(['src', 'srcdoc', 'href', 'xlink:href', 'formaction', 'autofocus', 'style-src']);

// ---------------------------------------------------------------------------
// Minimal spec-shaped HTML tokenizer (start/end tags + attributes only)
// ---------------------------------------------------------------------------
const WS = /[\t\n\f\r ]/;

function tokenizeHtml(html) {
  const tags = [];
  const n = html.length;
  let i = 0;
  let rawEnd = null; // RCDATA/RAWTEXT element whose end tag we are waiting for

  while (i < n) {
    if (rawEnd) {
      const idx = html.toLowerCase().indexOf(`</${rawEnd}`, i);
      if (idx === -1) break;
      i = idx;
      rawEnd = null;
    }
    const lt = html.indexOf('<', i);
    if (lt === -1) break;
    i = lt + 1;

    if (html[i] === '!') {
      if (html.startsWith('!--', i)) {
        const c = html.indexOf('-->', i + 3);
        i = c === -1 ? n : c + 3;
      } else {
        const c = html.indexOf('>', i);
        i = c === -1 ? n : c + 1;
      }
      continue;
    }

    let isEnd = false;
    if (html[i] === '/') { isEnd = true; i++; }
    if (!/[a-zA-Z]/.test(html[i] || '')) continue; // a bare '<' is just text

    let name = '';
    while (i < n && !WS.test(html[i]) && html[i] !== '/' && html[i] !== '>') name += html[i++];
    name = name.toLowerCase();

    const attrs = [];
    while (i < n) {
      while (i < n && (WS.test(html[i]) || html[i] === '/')) i++;
      if (i >= n) break;
      if (html[i] === '>') { i++; break; }

      let attrName = html[i++]; // first char may be '=' per spec
      while (i < n && !WS.test(html[i]) && html[i] !== '/' && html[i] !== '>' && html[i] !== '=') attrName += html[i++];
      while (i < n && WS.test(html[i])) i++;

      let value = '';
      if (html[i] === '=') {
        i++;
        while (i < n && WS.test(html[i])) i++;
        const q = html[i];
        if (q === '"' || q === "'") {
          const close = html.indexOf(q, i + 1);
          value = close === -1 ? html.slice(i + 1) : html.slice(i + 1, close);
          i = close === -1 ? n : close + 1;
        } else {
          while (i < n && !WS.test(html[i]) && html[i] !== '>') value += html[i++];
        }
      }
      attrs.push({ name: attrName.toLowerCase(), value });
    }

    tags.push({ name, isEnd, attrs });
    if (!isEnd && ['textarea', 'title', 'script', 'style', 'xmp', 'iframe', 'noembed', 'noframes'].includes(name)) {
      rawEnd = name;
    }
  }
  return tags;
}

function structureOf(html) {
  return tokenizeHtml(html)
    .map((t) => `${t.isEnd ? '/' : ''}${t.name}[${t.attrs.map((a) => a.name).join(',')}]`)
    .join(' ');
}

function injectionProblems(html) {
  const problems = [];
  for (const tag of tokenizeHtml(html)) {
    if (tag.isEnd) continue;
    if (FORBIDDEN_TAGS.has(tag.name)) problems.push(`<${tag.name}> element`);
    for (const attr of tag.attrs) {
      if (attr.name.startsWith('on')) problems.push(`${attr.name}= on <${tag.name}>`);
      if (FORBIDDEN_ATTRS.has(attr.name)) problems.push(`${attr.name}= on <${tag.name}>`);
      if (/^\s*(javascript|vbscript|data):/i.test(attr.value)) problems.push(`script URL in ${attr.name}=`);
    }
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Minimal DOM: elements are auto-created per id/selector and remember every
// HTML string assigned to them, which is what this test inspects.
// ---------------------------------------------------------------------------
const noopCtx = new Proxy({}, {
  get: (target, prop) => (prop in target ? target[prop] : () => ({ addColorStop() {} })),
  set: (target, prop, value) => { target[prop] = value; return true; }
});

class StubElement {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.style = {};
    this.dataset = {};
    this.value = '';
    this.textContent = '';
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.htmlLog = [];
    this._html = '';
    this._bySelector = new Map();
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  }
  get innerHTML() { return this._html; }
  set innerHTML(html) { this._html = String(html); this.htmlLog.push(this._html); }
  querySelector(sel) {
    if (!this._bySelector.has(sel)) this._bySelector.set(sel, new StubElement());
    return this._bySelector.get(sel);
  }
  querySelectorAll() { return []; }
  addEventListener() {}
  removeEventListener() {}
  setAttribute() {}
  getAttribute() { return null; }
  getContext() { return noopCtx; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 800, height: 600 }; }
  focus() {}
  click() {}
}

const byId = new Map();
function getElementById(id) {
  if (!byId.has(id)) byId.set(id, new StubElement());
  return byId.get(id);
}

globalThis.document = {
  getElementById,
  createElement: (tag) => new StubElement(tag),
  querySelector: () => null,
  querySelectorAll: () => [],
  body: new StubElement('body')
};
globalThis.window = {
  location: { hash: '' },
  addEventListener() {},
  removeEventListener() {},
  devicePixelRatio: 1,
  prompt: () => null,
  confirm: () => false
};
globalThis.requestAnimationFrame = () => 0; // never schedule the graph's animation loop
globalThis.cancelAnimationFrame = () => {};
globalThis.FileReader = class {
  readAsDataURL() { this.result = 'data:application/octet-stream;base64,AA=='; this.onload?.(); }
};
getElementById('caseId').textContent = 'CASE-XSS';

// ---------------------------------------------------------------------------
// Modules under test (the real ones)
// ---------------------------------------------------------------------------
const jsRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'js');
const load = (rel) => import(pathToFileURL(path.join(jsRoot, rel)).href);

const { escapeHtml, escapeAttr } = await load('util/html.js');
const { ContextDiscussion } = await load('collaboration/discussion.js');
const { TeamPresence } = await load('collaboration/presence.js');
const { EntityInspector } = await load('investigation/inspector.js');
const { InvestigationGraph } = await load('investigation/graph.js');
const { InvestigationTimeline } = await load('investigation/timeline.js');
const { InvestigationWorkspace } = await load('investigation/workspace.js');
const { EvidenceSpace } = await load('evidence/evidence.js');
const { OperationsSpace } = await load('operations/operations.js');
const { ChallengeMatrix } = await load('ctf/components/challenge_matrix.js');
const { FlagDrawer } = await load('ctf/components/flag_drawer.js');
const { WorkspaceView } = await load('ctf/components/workspace_view.js');
const { WriteupView } = await load('ctf/components/writeup_view.js');
const { TerminalView } = await load('ctf/components/terminal_view.js');
const { RecipeBuilder } = await load('ctf/components/recipe_builder.js');
const { CtfApp } = await load('ctf/ctf_app.js');
const { CodeSpace } = await load('code/code.js');
const { WebSpace } = await load('web/web.js');

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;
function check(condition, message, detail = '') {
  if (condition) {
    passed++;
    console.log(`  [PASS] ${message}`);
  } else {
    failed++;
    console.error(`  [FAIL] ${message}${detail ? `\n         ${detail}` : ''}`);
  }
}

/**
 * @param {string} label
 * @param {(value: string) => Promise<string> | string} render returns the HTML produced for `value`
 * @param {{ expectText?: string | null, benign?: string }} [opts] `benign` overrides the
 *   comparison value where the sink legitimately formats some characters (markdown).
 */
async function sink(label, render, { expectText = ESCAPED_IMG, benign: benignValue = BENIGN } = {}) {
  let benign;
  let evil;
  try {
    benign = await render(benignValue);
    evil = await render(PAYLOAD);
  } catch (err) {
    check(false, `${label}: rendered without throwing`, err.stack);
    return;
  }
  const problems = injectionProblems(evil);
  check(problems.length === 0, `${label}: no injected elements/attributes`, problems.join('; '));
  const same = structureOf(evil) === structureOf(benign);
  check(same, `${label}: DOM structure unchanged by payload`,
    same ? '' : `benign: ${structureOf(benign)}\n         payload: ${structureOf(evil)}`);
  if (expectText) {
    check(evil.includes(expectText), `${label}: payload shown as escaped text`);
  }
}

const freshEl = () => new StubElement();
const lastHtml = (el) => el.htmlLog.join('\n');
const store = (state, extra = {}) => ({ subscribe: () => () => {}, getState: () => state, ...extra });

console.log('\n=== XSS regression: shared helper ===');
check(escapeHtml(`&<>"'\``) === '&amp;&lt;&gt;&quot;&#39;&#96;', 'escapeHtml escapes & < > " \' and backtick');
check(escapeHtml(null) === '' && escapeHtml(undefined) === '', 'escapeHtml maps null/undefined to empty string');
check(escapeHtml(0) === '0' && escapeHtml(42) === '42', 'escapeHtml keeps numbers (incl. 0)');
check(escapeHtml('Сироҷиддин lsass.exe') === 'Сироҷиддин lsass.exe', 'escapeHtml leaves benign text untouched');
check(escapeAttr('" onfocus="x') === '&quot; onfocus=&quot;x', 'escapeAttr neutralises attribute breakout');
check(injectionProblems(`<div title="${PAYLOAD}">`).length > 0, 'self-check: tokenizer detects an unescaped attribute payload');
check(injectionProblems(`<textarea>${PAYLOAD}</textarea>`).length > 0, 'self-check: tokenizer detects a </textarea> breakout');

console.log('\n=== Collaboration ===');
await sink('discussion messages (author, body)', (v) => {
  const d = new ContextDiscussion({ call: async () => ({}) });
  d.messages = [{ author_name: v, body: v, created_at: '2026-01-01T10:00:00Z' }];
  d.render();
  return getElementById('discussionMessages').innerHTML;
});
await sink('team presence (title attr, initial)', (v) => {
  const p = new TeamPresence({ call: async () => [] });
  p.presences = [{ user_id: v, status_text: v, is_online: true }];
  p.render();
  return getElementById('teamPresence').innerHTML;
});

console.log('\n=== Investigation ===');
const entityOf = (type, v) => ({
  type, id: v, label: v, name: v, hostname: v, os: v, risk: v, ip: v, criticality: v,
  processes_count: v, sockets_count: v, findings_count: v, evidence_count: v,
  pid: v, ppid: v, host_id: v, state: v, path: v, executable_path: v, command_line: v,
  sha256: v, verification: v, title: v, mitre_technique: v, mitre_tactic: v, subtitle: v,
  severity: v, rule_id: v, entity_key: v
});
for (const type of ['host', 'process', 'finding', 'dns']) {
  await sink(`inspector context tab (${type})`, (v) => {
    const el = freshEl();
    new EntityInspector(el, null).render(entityOf(type, v));
    return el.innerHTML;
  });
}
await sink('inspector evidence tab', (v) => {
  const el = freshEl();
  const insp = new EntityInspector(el, null);
  insp.currentTab = 'evidence';
  insp.render(entityOf('process', v));
  return el.innerHTML;
});
await sink('inspector relations tab', (v) => {
  const el = freshEl();
  const ent = entityOf('process', 'proc-1');
  const insp = new EntityInspector(el, { graph: { edges: [{ source: 'proc-1', target: v, relation: v }] } });
  insp.currentTab = 'relations';
  insp.render(ent);
  return el.innerHTML;
});
await sink('graph node tooltip', (v) => {
  const g = new InvestigationGraph(null);
  g.updateTooltip({ id: v, label: v, type: v, subtitle: v, path: v, in_attack_path: true }, 0, 0);
  return getElementById('graphTooltip').innerHTML;
});
await sink('timeline event list (class, data-event-id, text)', (v) => {
  const el = freshEl();
  new InvestigationTimeline(el).render([{ id: v, category: v, timestamp: v, title: v, detail: v, severity: 'high' }]);
  return el.innerHTML;
});
await sink('timeline event details panel (incl. JSON dump)', (v) => {
  const ws = new InvestigationWorkspace({ call: async () => null });
  ws.loadTimelineEvent({ id: v, title: v, timestamp: v, category: v, detail: v });
  return getElementById('eventDetails').innerHTML;
});

console.log('\n=== Evidence ===');
const evidenceIpc = (v) => ({
  async call(method) {
    if (method === 'evidence.list') return [{ id: v, name: v, size: v, hash_blake3: v, method: v, acquired_at: v }];
    if (method === 'evidence.observations') return [{ event_type: v, timestamp: v, data: { cmd: v } }];
    if (method === 'facts.list') return [{ entity_type: v, entity_key: v, fact_type: v, confidence: v, severity: v, created_at: v }];
    if (method === 'evidence.custody') return [{ event_type: v, timestamp: v, actor: v, prev_hash: v }];
    if (method === 'evidence.ingest') return { events_extracted: v, facts_derived: v };
    return [];
  }
});
async function evidenceSpace(v) {
  const space = new EvidenceSpace(evidenceIpc(v));
  const root = freshEl();
  space.render(root);
  await new Promise((r) => setTimeout(r, 0)); // let render()'s unawaited first load settle
  return { space, root };
}
await sink('evidence artifacts table (text + data-* attrs)', async (v) => {
  const { space, root } = await evidenceSpace(v);
  await space._loadArtifacts();
  return root.querySelector('#tabContent').innerHTML;
});
await sink('evidence observations panel', async (v) => {
  const { space, root } = await evidenceSpace(v);
  await space._showObservations('a1', v);
  return lastHtml(root.querySelector('#obsPanel'));
});
await sink('evidence facts table', async (v) => {
  const { space, root } = await evidenceSpace(v);
  await space._loadFacts();
  return root.querySelector('#tabContent').innerHTML;
});
await sink('evidence custody tab (input value attr + chain)', async (v) => {
  const { space, root } = await evidenceSpace(v);
  space._renderCustodyTab(v);
  root.querySelector('#custodyHashInput').value = 'h';
  await space._loadCustody();
  return `${root.querySelector('#tabContent').innerHTML}\n${root.querySelector('#custodyChain').innerHTML}`;
});
await sink('evidence upload status (file name, ingest result)', async (v) => {
  const { space, root } = await evidenceSpace(v);
  space.activeTab = 'facts';
  await space._uploadFile({ name: v });
  return lastHtml(root.querySelector('#uploadStatus'));
});

console.log('\n=== Operations ===');
await sink('operations case grid (data-case attr, title, status)', async (v) => {
  const ops = new OperationsSpace({ call: async () => [{ id: v, title: v, status: v, created_at: '2026-01-01T00:00:00Z' }] }, null);
  const root = freshEl();
  await ops.render(root);
  return root.querySelector('#opsCaseGrid').innerHTML;
});

console.log('\n=== Code analysis ===');
// File names, code snippets and source notes come from the scanned project,
// which is exactly the code an attacker controls.
const codeStatus = (v, extra = {}) => ({
  running: false, path: v, external_sources: true, include_tests: false,
  started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:00:05Z', error: null,
  report: {
    files: v, lines: v, languages: [[v, v]], skipped: [[v, v]], parse_errors: [v], test_files: v,
    load_ms: v, analysis_ms: v,
    findings: [{
      rule: v, cwe: v, severity: v, title: v, message: v, file: v, line: v, column: v, snippet: v,
      source: { file: v, line: v, column: v, note: v },
      trace: [{ file: v, line: v, column: v, note: v }],
      other_sources: [{ file: v, line: v, column: v, note: v }]
    }]
  },
  ...extra
});
async function codeSpace(status, setup = () => {}) {
  const space = new CodeSpace({ call: async () => status });
  setup(space);
  const root = freshEl();
  await space.render(root);
  return { space, root };
}
await sink('code analysis findings (file, snippet, trace, rule select, parse errors)', async (v) => {
  const { root } = await codeSpace(codeStatus(v));
  return root.querySelector('#codeResultPanel').innerHTML;
});
await sink('code analysis search box value attr', async (v) => {
  // The findings carry the same value, so the filter keeps the row in both renders.
  const { space, root } = await codeSpace(codeStatus(v));
  space.query = v;
  space.renderResult();
  return root.querySelector('#codeResultPanel').innerHTML;
});
await sink('code analysis form (remembered path in value attr)', async (v) => {
  const { root } = await codeSpace({ running: false, report: null }, (space) => { space.path = v; });
  return root.innerHTML;
});
await sink('code analysis progress (running path, engine error)', async (v) => {
  const { space, root } = await codeSpace(codeStatus(v, { running: true, report: null }));
  space.stopPolling();
  const running = root.querySelector('#codeProgress').innerHTML;
  space.status = codeStatus(v, { error: v, report: null });
  space.renderProgress();
  return `${running}\n${root.querySelector('#codeProgress').innerHTML}`;
});

// Package names, versions and advisory text come from the project's
// files and from the public advisory feeds.
const depFinding = (v, malicious) => ({
  rule: v, cwe: v, severity: v, title: v, message: v, file: v, line: v, column: v, snippet: v,
  source: null, trace: [], other_sources: [{ file: v, line: v, column: v, note: v }],
  package: { ecosystem: v, name: v, version: v, kind: v, where: v, requirement: v, fixed_version: v },
  advisories: [{
    id: v, aliases: [v], summary: v, severity: v, cvss_score: v, fixed_version: v, malicious,
    url: v, kev: { name: v, date_added: v }
  }]
});
const depCheck = (v) => ({
  total: v, packages: v, vulnerable: v, advisories: v,
  ecosystems: [{ ecosystem: v, packages: v, loaded: false, checked_at: v, download_mb: v },
    { ecosystem: v, packages: v, loaded: true, checked_at: v, download_mb: v }],
  missing: [v],
  list: [{ ecosystem: v, name: v, version: v, file: v, line: v, kind: v, places: 2, advisories: v, malicious: false }],
  unpinned_total: v,
  unpinned: [{ ecosystem: v, name: v, requirement: v, file: v, line: v, kind: v }],
  undeclared_python: [{ module: v, file: v, line: v, files: v }],
  checked_at: v, error: v
});
await sink('code analysis dependency findings (package, advisories, places)', async (v) => {
  const status = codeStatus(v);
  status.report.findings = [depFinding(v, false), depFinding(v, true)];
  status.report.dependency_check = depCheck(v);
  const { root } = await codeSpace(status);
  return root.querySelector('#codeResultPanel').innerHTML;
});
await sink('code analysis dependency block (ecosystems, unpinned, imports, errors, list)', async (v) => {
  const status = codeStatus(v);
  status.report.dependency_check = depCheck(v);
  const { space, root } = await codeSpace(status);
  space.depsUpdating = true;
  space.depsCurrent = v;
  space.depsError = v;
  space.renderDeps();
  return `${root.querySelector('#codeDeps').innerHTML}\n${space.packagesTable(status.report.dependency_check)}`;
});

console.log('\n=== Running site (DAST) ===');
// URLs, parameter names, evidence snippets and the reproduction request all
// come from the scanned site's own responses, which the attacker controls;
// a reflected-XSS evidence string literally contains injected markup.
const webStatus = (v, extra = {}) => ({
  running: false, target: v, started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:00:05Z', error: null,
  report: {
    target: v, pages_crawled: 3, forms_found: 2, requests_made: 10, authenticated: true,
    notes: [v], duration_ms: 50,
    findings: [{
      rule: v, cwe: v, severity: v, title: v, message: v, url: v, method: v, param: v,
      evidence: v, request: v, request_detail: { method: v, url: v, body: v }
    }]
  },
  ...extra
});
async function webSpace(status, setup = () => {}) {
  const space = new WebSpace({ call: async () => status });
  setup(space);
  const root = freshEl();
  await space.render(root);
  return { space, root };
}
await sink('running-site findings (url, param, evidence, repro request)', async (v) => {
  const { root } = await webSpace(webStatus(v));
  return root.querySelector('#webResultPanel').innerHTML;
});
await sink('running-site form (remembered url and login fields in value attrs)', async (v) => {
  const { space, root } = await webSpace({ running: false, report: null }, (s) => { s.url = v; s.useLogin = true; });
  space.renderResult();
  return root.innerHTML;
});
await sink('running-site progress (running target, engine error)', async (v) => {
  const { space, root } = await webSpace(webStatus(v, { running: true, report: null }));
  space.stopPolling();
  const running = root.querySelector('#webProgress').innerHTML;
  space.status = webStatus(v, { error: v, report: null });
  space.renderProgress();
  return `${running}\n${root.querySelector('#webProgress').innerHTML}`;
});

console.log('\n=== CTF ===');
await sink('challenge matrix (competition, cards, title attr, points)', (v) => {
  const el = freshEl();
  new ChallengeMatrix({
    store: store({
      challenges: { c1: { id: v, title: v, category: 'web', points: v, status: 'Unsolved', tags: [v] } },
      competitions: [{ id: v, name: v }],
      activeCompetitionId: v,
      activeCompetition: { title: v },
      error: v
    })
  }).mount(el);
  return el.innerHTML;
});
await sink('flag drawer (candidate pills, data-flag attr)', (v) => {
  const el = freshEl();
  const flags = [{ id: v, value: v, source: v, status: 'candidate', timestamp: '2026-01-01T00:00:00Z' }];
  new FlagDrawer({
    store: store({ filter: 'all', unreviewedCount: 1, candidates: flags, error: v }, { getFilteredCandidates: () => flags, loadFlags: async () => {} })
  }).mount(el);
  return el.innerHTML;
});
await sink('ctf workspace view (title, category class, artifact tree)', (v) => {
  const el = freshEl();
  new WorkspaceView({
    store: store({
      activeChallenge: { title: v, category: v, points: v, status: 'Unsolved' },
      activePanels: { left: true, bottom: true, rightDrawer: true },
      artifactTree: [{ role: v, items: [{ id: v, filename: v, size_bytes: 10 }] }]
    })
  }).mount(el);
  return el.innerHTML;
});
await sink('write-up studio (textarea, placeholder attr, preview)', (v) => {
  const el = freshEl();
  new WriteupView({
    store: store({ draftMarkdown: v, isDirty: true }),
    workspace: store({ activeChallenge: { title: v } })
  }).mount(el);
  return el.innerHTML;
}, { benign: 'benign `-code-` value' }); // the payload's backticks legitimately form a code span
await sink('terminal view (log lines, tool options, error)', (v) => {
  const el = freshEl();
  new TerminalView({
    store: store({
      activeJobId: 'j1',
      activeJobs: { j1: { id: v, status: 'running' } },
      terminalBuffers: { j1: { lines: [v], droppedBytes: 0 } },
      tools: [{ id: v, name: v }],
      error: v
    })
  }).mount(el);
  return el.innerHTML;
});
await sink('recipe builder (key value attr, preview, detected flags)', (v) => {
  const el = freshEl();
  new RecipeBuilder({
    store: store({ operations: [{ operation: 'xor', params: { key: v } }, { operation: v, params: {} }], livePreviewText: v, detectedFlags: [v] })
  }).mount(el);
  return el.innerHTML;
});

const ctfStores = (v, { failSelect = false } = {}) => ({
  workspaceStore: store({ activeChallenge: { title: v } }, {
    selectChallenge: async () => { if (failSelect) throw new Error(v); }
  }),
  writeupStore: store({ draftMarkdown: '', isDirty: false })
});
await sink('ctf write-up route header (challenge id from URL hash)', async (v) => {
  const app = new CtfApp(ctfStores(v));
  app.viewportEl = freshEl();
  await app.mountWriteupRoute(v);
  return app.viewportEl.innerHTML;
});
await sink('ctf challenge route error banner', async (v) => {
  const app = new CtfApp(ctfStores(v, { failSelect: true }));
  app.viewportEl = freshEl();
  await app.mountChallengeRoute(v);
  return app.viewportEl.innerHTML;
});

console.log('\n=== Visual parity for benign markdown ===');
{
  const el = freshEl();
  new WriteupView({
    store: store({ draftMarkdown: "# Title\n\nUse `strings` on **it's** file\n\n```\nxor key\n```", isDirty: false }),
    workspace: store({ activeChallenge: { title: 'Crypto 101' } })
  }).mount(el);
  const html = el.innerHTML;
  check(/<h1[^>]*>Title<\/h1>/.test(html), 'markdown heading still rendered');
  check(/<code[^>]*>strings<\/code>/.test(html), 'inline `code` still rendered (backticks are escaped first)');
  check(/<pre[^>]*><code>\s*xor key\s*<\/code><\/pre>/.test(html), 'fenced ``` block still rendered');
  check(/<strong>it&#39;s<\/strong>/.test(html), 'bold text with apostrophe rendered');
}

console.log(`\nXSS checks: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);

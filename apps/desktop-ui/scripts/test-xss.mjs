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
const { CodeSpace } = await load('code/code.js');
const { WebSpace } = await load('web/web.js');
const { RemoteHostPanel } = await load('ssh/os-panel.js');
const { ProjectCodePanel } = await load('ssh/code-panel.js');
const { IncidentSpace } = await load('incident/incident.js');
const { IncidentCollectPanel } = await load('incident/collect-panel.js');

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

console.log('\n=== Remote host (SSH) ===');
// The OS name, kernel, ecosystem, host-key fingerprint, collection errors and
// every package finding come from the remote host being scanned, which is
// untrusted input.
function remotePanel() {
  const panel = new RemoteHostPanel({ call: async () => ({}) });
  panel.mount(freshEl());
  return panel;
}
await sink('remote-host report (os, kernel, findings, host key)', async (v) => {
  const panel = remotePanel();
  panel.phase = 'done';
  panel.report = {
    host: v,
    os: v,
    kernel: v,
    ecosystem: v,
    host_key: { algorithm: v, fingerprint: v, sha256: v },
    collection_errors: [v],
    package_report: {
      findings: [
        {
          id: v,
          component: v,
          installed_version: v,
          fixed_version: v,
          status: 'fix_available',
          severity: v,
          url: v,
          kev: { name: v },
        },
      ],
    },
  };
  panel.render();
  return panel.root.innerHTML;
});
await sink('remote-host confirm (host, host-key fingerprint)', async (v) => {
  const panel = remotePanel();
  panel.phase = 'confirm';
  panel.pending = { host: v, port: 22, username: v };
  panel.hostKey = { algorithm: v, fingerprint: v, sha256: v };
  panel.render();
  return panel.root.innerHTML;
});
await sink('remote-host CIS audit (check title, evidence, remediation, refs, framework)', async (v) => {
  // The evidence is literally a line copied out of the host's config files,
  // and the titles/remediation/framework labels are rendered alongside it.
  const panel = remotePanel();
  panel.phase = 'done';
  panel.report = {
    host: v,
    os: v,
    collection_errors: [],
    cis_report: {
      checks: [
        {
          id: v,
          title: v,
          status: 'FAIL',
          severity: 'HIGH',
          evidence: v,
          remediation: v,
          references: [{ framework: v, control: v }],
        },
        {
          id: v,
          title: v,
          status: 'MANUAL',
          severity: 'LOW',
          evidence: v,
          remediation: v,
          references: [{ framework: v, control: v }],
        },
      ],
      summary: {
        pass: 1,
        fail: 1,
        manual: 1,
        not_configured: 1,
        needs_privileges: 1,
        compliance: [{ framework: v, passed: 1, evaluated: 2, undetermined: 0, percent: 50 }],
      },
    },
  };
  panel.render();
  return panel.root.innerHTML;
});

await sink('remote-host VULNDB_EMPTY (ecosystem in download button + hostline)', async (v) => {
  const panel = remotePanel();
  panel.phase = 'done';
  panel.report = {
    host: v,
    os: v,
    ecosystem: v,
    status: 'VULNDB_EMPTY',
    collection_errors: [],
  };
  panel.render();
  return panel.root.innerHTML;
});
await sink('remote-host form prefilled after DB load (host/user value attrs, notice)', async (v) => {
  const panel = remotePanel();
  panel.lastForm = { host: v, port: 22, username: v, method: 'password' };
  panel.formNotice = `База для ${v} загружена. Введите пароль и запустите проверку снова.`;
  panel.phase = 'form';
  panel.renderForm();
  return panel.root.innerHTML;
});
await sink('remote-host Windows result (caption/build/product, KB rollup, program + OS findings)', async (v) => {
  // Every Windows value comes off the host over OpenSSH: the OS caption/build,
  // the KB ids (findings[].sources), the installed-program names/versions and
  // the CIS evidence. All must render as inert text.
  const panel = remotePanel();
  panel.phase = 'done';
  panel.report = {
    host: v,
    platform: 'windows',
    status: 'VULNERABILITIES_FOUND',
    os: v,
    collection_errors: [v],
    host_key: { algorithm: v, fingerprint: v, sha256: v },
    windows: {
      caption: v,
      build: v,
      display_version: v,
      product: v,
      installed_updates: 3,
      os_status: 'VULNERABILITIES_FOUND',
      os_cve: {
        findings: [{
          id: v, component: v, installed_version: v, fixed_version: v, status: 'fix_available',
          severity: 'critical', sources: [v, v], summary: v,
        }],
      },
      app_cve: {
        findings: [{
          id: v, component: v, installed_version: v, fixed_version: v, status: 'fix_available',
          severity: 'high', sources: [v], summary: v,
        }],
        checked: [{ product: v, version: v, cve_count: 1 }],
        unrecognised: 2,
      },
    },
    cis_report: {
      checks: [{
        id: v, title: v, status: 'FAIL', severity: 'HIGH', evidence: v, remediation: v,
        references: [{ framework: v, control: v }],
      }],
      summary: { pass: 0, fail: 1, manual: 0, not_configured: 0, needs_privileges: 0,
        compliance: [{ framework: v, passed: 0, evaluated: 1, undetermined: 0, applicable: 1, percent: 0 }] },
    },
  };
  panel.render();
  return panel.root.innerHTML;
});

console.log('\n=== Project code over SSH ===');
// The project path is resolved by the remote server, and the fetched source
// (file names, snippets, package names, advisory text) is attacker-controlled;
// the findings reuse the shared code report view, so the same escaping holds.
function codePanel() {
  const panel = new ProjectCodePanel({ call: async () => ({}) });
  panel.mount(freshEl());
  return panel;
}
await sink('remote-code report (server path, fetch summary, code findings)', async (v) => {
  const panel = codePanel();
  panel.phase = 'done';
  panel.lastForm = { external: true };
  panel.status = {
    target: v,
    path: v,
    external_sources: true,
    finished_at: '2026-01-01T00:00:05Z',
    report: {
      files: v, lines: v, languages: [[v, v]], load_ms: v, analysis_ms: v,
      fetch: { files: 3, bytes: 4096, skipped_dirs: [v], skipped_binary: [v], skipped_large: [v], skipped_symlinks: [v], truncated: true, limit_hit: v },
      findings: [{
        rule: v, cwe: v, severity: v, title: v, message: v, file: v, line: v, column: v, snippet: v,
        source: { file: v, line: v, column: v, note: v }, trace: [{ file: v, line: v, column: v, note: v }],
        other_sources: []
      }]
    }
  };
  panel.render();
  return panel.root.innerHTML;
});
await sink('remote-code confirm (host, host-key fingerprint)', async (v) => {
  const panel = codePanel();
  panel.phase = 'confirm';
  panel.pending = { host: v, port: 22, username: v, path: v };
  panel.hostKey = { algorithm: v, fingerprint: v, sha256: v };
  panel.render();
  return panel.root.innerHTML;
});
await sink('remote-code form prefilled after DB load (host/user/path value attrs, notice)', async (v) => {
  const panel = codePanel();
  panel.lastForm = { host: v, port: 22, username: v, path: v, method: 'password', external: true, includeTests: true };
  panel.formNotice = `База (${v}) загружена. Введите пароль и запустите проверку снова.`;
  panel.phase = 'form';
  panel.renderForm();
  return panel.root.innerHTML;
});

console.log('\n=== Incident investigation (DFIR timeline) ===');
// Every field on a timeline row comes straight off a log file an attacker can
// write to: the request path and user-agent, the SSH user and source IP, the
// syslog program and message, the file name — and the raw line shown as
// evidence. All must render inert.
async function incidentSpace(status, setup = () => {}) {
  const space = new IncidentSpace({ call: async () => status });
  setup(space);
  const root = freshEl();
  await space.render(root);
  return { space, root };
}
const incidentStatus = (v, extra = {}) => ({
  running: false,
  path: v,
  started_at: '2026-01-01T00:00:00Z',
  finished_at: '2026-01-01T00:00:05Z',
  error: null,
  report: {
    first_event: v,
    last_event: v,
    warnings: [v],
    files: [{ path: v, source: 'web_access', lines: 10, parsed: 9, compressed: true, sha256: v, bytes: 4096 }],
    findings: [{
      rule: v, title: v, severity: 'high', mitre: [v], summary: v, actor: v,
      first_time: v, last_time: v,
      evidence: [{ timestamp: v, source_file: v, line_no: 7, summary: v, raw: v }],
    }],
    links: [{
      rule: v, title: v, severity: 'high', mitre: [v], summary: v, actor: v,
      first_time: v, last_time: v, hosts: [v, v],
      evidence: [{ timestamp: v, source_file: v, line_no: 7, summary: v, raw: v }],
    }],
    summary: { total_events: 1, files: 1, findings: 1, links: 1, by_source: { web_access: 1, auth: 1 } },
    events: [{
      timestamp: v, source: 'web_access', source_file: v, line_no: 7,
      host: v, actor: v, summary: v, outcome: 'failure',
      fields: { method: v, path: v, status: v, user_agent: v }, raw: v,
    }],
  },
  ...extra,
});
await sink('incident timeline (time, host, actor, summary, raw line, files, warnings)', async (v) => {
  const { root } = await incidentSpace(incidentStatus(v));
  return root.querySelector('#incResultPanel').innerHTML;
});
await sink('incident text filter value attr (query echoed into input)', async (v) => {
  const { space, root } = await incidentSpace(incidentStatus(v), (s) => { s.query = v; });
  space.renderResult();
  return root.querySelector('#incResultPanel').innerHTML;
});
await sink('incident progress (running path, engine error)', async (v) => {
  const { space, root } = await incidentSpace(incidentStatus(v, { running: true, report: null }));
  space.stopPolling();
  const running = root.querySelector('#incProgress').innerHTML;
  space.status = incidentStatus(v, { error: v, report: null });
  space.renderProgress();
  return running + root.querySelector('#incProgress').innerHTML;
});
await sink('incident cross-host links panel (host chips, actor, mitre, evidence)', async (v) => {
  const { space } = await incidentSpace(incidentStatus(v));
  return space.linksPanelHtml(space.status.report);
});
await sink('incident evidence panel (marked event summary, file:line)', async (v) => {
  // Marked-evidence fields are copied from log events, so they carry the same
  // attacker-controlled content and must render inert in the evidence panel.
  const { space } = await incidentSpace(incidentStatus(v));
  space.evidence = new Map([[v, {
    key: v, timestamp: v, source: 'auth', source_file: v, line_no: 7, summary: v,
  }]]);
  return space.evidencePanelHtml();
});

await sink('incident SSH-collection done (hostname, os, remote paths, notes, case)', async (v) => {
  // The collection manifest is built from the scanned host: its hostname,
  // OS string, every collected/skipped remote path and the free-text notes are
  // attacker-influenceable and must render inert in the done view.
  const panel = new IncidentCollectPanel({ call: async () => ({}) });
  panel.phase = 'done';
  panel.status = {
    running: false,
    case: { id: v, title: v, dir: v },
    collection: {
      host: v, hostname: v, username: v, os_name: v, kernel: v,
      host_dir: v, journal_mode: v, clock_skew_seconds: 7,
      files: [{ remote_path: v, local_path: v, kind: 'log', bytes: 1, sha256: v }],
      skipped: [{ remote_path: v, reason: 'NO_ACCESS' }],
      notes: [v],
    },
    report: { summary: { total_events: 1 }, findings: [{}], links: [{}], events: [{}] },
    report_error: v,
  };
  const root = freshEl();
  panel.render(root);
  return root.innerHTML;
});

console.log(`\nXSS checks: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);

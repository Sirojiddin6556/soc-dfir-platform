/**
 * e2e-real-engine.mjs
 *
 * End-to-end check of the real application: starts the actual engine-server
 * binary on a temporary database, drives the real UI in Chromium and talks
 * to the real backend (no mocks). It fails on any page error, console error,
 * CSP violation or unexpected HTTP error.
 *
 * Usage (from the repository root, after `cargo build -p engine-server`):
 *   node apps/desktop-ui/scripts/e2e-real-engine.mjs
 *
 * Environment:
 *   ENGINE_BIN       path to engine-server (default target/debug/engine-server[.exe])
 *   PLAYWRIGHT_MODULE  import path of playwright if it is not resolvable normally
 *   CHROMIUM_PATH    Chromium executable to use instead of Playwright's own
 *   E2E_SCREENSHOTS  directory to save screenshots of every space
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..', '..');
const uiDir = path.resolve(here, '..');
const exe = process.platform === 'win32' ? 'engine-server.exe' : 'engine-server';
const engineBin = process.env.ENGINE_BIN || path.join(repoRoot, 'target', 'debug', exe);
const fixture = path.join(repoRoot, 'tests', 'fixtures', 'forensics', 'security_real.evtx');
const shotsDir = process.env.E2E_SCREENSHOTS || null;

async function loadPlaywright() {
  const candidates = [process.env.PLAYWRIGHT_MODULE, 'playwright'].filter(Boolean);
  for (const c of candidates) {
    try {
      const spec = c.startsWith('/') || /^[A-Za-z]:\\/.test(c) ? pathToFileURL(c).href : c;
      return await import(spec);
    } catch (_) { /* try next */ }
  }
  throw new Error('playwright is not installed: npm i --no-save playwright (or set PLAYWRIGHT_MODULE)');
}

/** Copies a harmless system binary into a world-writable dir and runs it. */
function plantSuspiciousProcess() {
  const win = process.platform === 'win32';
  const bases = win ? ['C:\\Users\\Public'] : ['/tmp', '/var/tmp', '/dev/shm'];
  const sources = win ? ['C:\\Windows\\System32\\PING.EXE'] : ['/bin/sleep', '/usr/bin/sleep'];
  const args = win ? ['-n', '300', '127.0.0.1'] : ['300'];
  const source = sources.find((s) => fs.existsSync(s));
  if (!source) throw new Error('no harmless system binary to copy');
  for (const base of bases) {
    const dir = path.join(base, `soc-e2e-${process.pid}-${Date.now()}`);
    try {
      fs.mkdirSync(dir, { recursive: true });
      const exe = path.join(dir, win ? 'ping.exe' : 'sleep');
      fs.copyFileSync(source, exe);
      fs.chmodSync(exe, 0o755);
      const child = spawn(exe, args, { stdio: 'ignore' });
      if (!child.pid) throw new Error('spawn failed');
      return {
        pid: child.pid,
        exe,
        cleanup() {
          child.kill();
          setTimeout(() => fs.rmSync(dir, { recursive: true, force: true }), 500);
        },
      };
    } catch (_) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  throw new Error('could not run a binary from a world-writable directory');
}

let passed = 0;
const failures = [];
function check(cond, label) {
  if (cond) { passed++; console.log(`  [PASS] ${label}`); }
  else { failures.push(label); console.log(`  [FAIL] ${label}`); }
}

function startEngine(dataDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(engineBin, [], {
      env: {
        ...process.env,
        SOC_BIND: '127.0.0.1:0',
        SOC_DATA_DIR: dataDir,
        SOC_UI_DIR: uiDir,
        SOC_NO_BROWSER: '1',
        RUST_LOG: 'info',
        NO_COLOR: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let log = '';
    const onData = (buf) => {
      log += buf.toString();
      const m = log.match(/Listening on http:\/\/(127\.0\.0\.1:\d+)/);
      if (m) resolve({ child, base: `http://${m[1]}` });
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => reject(new Error(`engine exited early (${code}):\n${log}`)));
    setTimeout(() => reject(new Error(`engine did not start:\n${log}`)), 30000);
  });
}

async function main() {
  if (!fs.existsSync(engineBin)) throw new Error(`engine binary not found: ${engineBin} (cargo build -p engine-server)`);
  const { chromium } = await loadPlaywright();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-e2e-'));
  const { child, base } = await startEngine(dataDir);
  console.log(`Engine: ${base}, data: ${dataDir}`);

  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const problems = [];
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
  // 401 is expected exactly where the test provokes it (wrong password).
  let allow401 = false;
  page.on('response', (r) => {
    if (r.status() >= 400 && !(allow401 && r.status() === 401)) problems.push(`http ${r.status()} ${r.url()}`);
  });
  const shot = async (name) => { if (shotsDir) await page.screenshot({ path: path.join(shotsDir, `${name}.png`) }); };
  const password = 'E2e-Strong-Pass-1';

  try {
    console.log('\n[1] First-run setup');
    await page.goto(base);
    await page.waitForSelector('#authOverlay:not([hidden])');
    check((await page.textContent('#authTitle')).includes('Первичная настройка'), 'fresh install asks to set the owner password');
    await shot('01-setup');
    await page.fill('#authPassword', 'short');
    await page.fill('#authConfirm', 'short');
    await page.click('#authSubmit');
    check((await page.textContent('#authError')).includes('не менее'), 'too short password is rejected');
    await page.fill('#authPassword', password);
    await page.fill('#authConfirm', password + 'x');
    await page.click('#authSubmit');
    check((await page.textContent('#authError')).includes('не совпадают'), 'mismatched confirmation is rejected');
    await page.fill('#authConfirm', password);
    await page.click('#authSubmit');
    await page.waitForSelector('#authOverlay', { state: 'hidden' });
    check(true, 'setup completes and the app opens');
    await page.waitForFunction(() => /^[0-9a-f-]{36}$/.test(document.getElementById('caseId').textContent.trim()), null, { timeout: 15000 });
    check(true, 'a real case is created and selected');
    check((await page.textContent('#currentUserName')).trim().length > 0, 'logged-in user name is shown');

    console.log('\n[2] API is closed without a session');
    const anon = await fetch(`${base}/rpc`, {
      method: 'POST',
      body: JSON.stringify({ api_version: 1, request_id: 't', method: 'cases.list', params: {} }),
    });
    check(anon.status === 401, 'cases.list without token returns 401');
    const evil = await fetch(`${base}/rpc`, {
      method: 'POST',
      headers: { Origin: 'https://evil.example' },
      body: JSON.stringify({ api_version: 1, request_id: 't', method: 'health', params: {} }),
    });
    check(evil.status === 403, 'request from a foreign origin is refused');
    const traversal = await fetch(`${base}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts`);
    check(traversal.status === 404, 'path traversal outside the UI directory is refused');

    console.log('\n[3] Evidence ingest of a real EVTX file');
    await page.click('.global-nav button[data-space="evidence"]');
    await page.waitForSelector('#evidenceFileInput', { state: 'attached' });
    await page.setInputFiles('#evidenceFileInput', fixture);
    await page.waitForFunction(() => /✓|✗/.test(document.getElementById('uploadStatus')?.textContent || ''), null, { timeout: 60000 });
    const status = await page.textContent('#uploadStatus');
    check(status.includes('✓'), `EVTX ingested: ${status.trim()}`);
    const events = Number((status.match(/(\d+) событий/) || [])[1] || 0);
    check(events > 0, 'ingest extracted events from the file');
    await page.waitForFunction(() => document.body.innerText.includes('security_real.evtx'), null, { timeout: 15000 });
    check(true, 'artifact appears in the evidence list');
    await shot('02-evidence');

    console.log('\n[4] Every space opens without errors');
    for (const space of ['operations', 'investigation', 'evidence', 'range', 'ctf', 'system']) {
      await page.click(`.global-nav button[data-space="${space}"]`);
      await page.waitForTimeout(1200);
      await shot(`03-${space}`);
      check(true, `space "${space}" opened`);
    }

    console.log('\n[5] Live host collection detects a real suspicious process');
    // A harmless binary copied into a world-writable directory and started:
    // exactly what CORR-LIN-001b / CORR-WIN-001f exist to catch.
    const planted = plantSuspiciousProcess();
    try {
      await page.click('.global-nav button[data-space="investigation"]');
      await page.click('#startCollection');
      await page.waitForFunction(() => {
        const b = document.getElementById('startCollection');
        return b && !b.disabled && b.textContent.includes('Запустить сбор');
      }, null, { timeout: 120000 });
      const token = await page.evaluate(() => localStorage.getItem('soc_session_token'));
      const caseId = (await page.textContent('#caseId')).trim();
      const rpcCall = async (method, params) => {
        const r = await fetch(`${base}/rpc`, {
          method: 'POST',
          body: JSON.stringify({ api_version: 1, request_id: 't', method, params: { ...params, token } }),
        });
        return (await r.json()).result;
      };
      const overview = await rpcCall('host.overview', {});
      check(overview && overview.counts && overview.counts.processes > 0,
        `host snapshot has real processes (${overview?.counts?.processes}), os: ${overview?.os}`);
      const procs = await rpcCall('host.processes', {});
      const seen = (procs?.processes || []).find((p) => p.pid === planted.pid);
      check(Boolean(seen), `snapshot contains the planted process pid ${planted.pid} (${seen?.executable_path})`);
      const facts = await rpcCall('facts.list', { case_id: caseId });
      const needle = JSON.stringify(planted.exe).slice(1, -1);
      const hit = (facts || []).find((f) => JSON.stringify(f).includes(needle));
      check(Boolean(hit), `correlation raised a finding for ${planted.exe}`);
      await page.waitForFunction(() => Number(document.getElementById('findingCount')?.textContent || 0) > 0,
        null, { timeout: 15000 }).catch(() => {});
      const shown = Number(await page.textContent('#findingCount'));
      check(shown > 0, `UI status bar shows findings (${shown})`);
      const snap = await rpcCall('investigation.snapshot', { case_id: caseId });
      check(shown === snap.findings.length,
        `status bar findings (${shown}) match the engine (${snap.findings.length})`);
      const evidenceShown = Number(await page.textContent('#evidenceCount'));
      check(evidenceShown === snap.metrics.evidence && evidenceShown > 0,
        `status bar evidence (${evidenceShown}) is the ingested artifact count (${snap.metrics.evidence})`);
      const panel = await page.textContent('#entityInspector');
      const panelFindings = Number((panel.match(/Находки:\s*(\d+)/) || [])[1]);
      check(panelFindings === snap.findings.length,
        `context panel is refreshed after collection (findings ${panelFindings})`);
      check(panel.includes(`Риск: ${snap.case.risk}`), `context panel shows the real risk (${snap.case.risk})`);
      const plantedNode = snap.graph.nodes.find((n) => n.id === `proc-${planted.pid}`);
      check(Boolean(plantedNode && plantedNode.in_attack_path),
        'planted process is on the attack path in the graph');
      await shot('04-collection');
    } finally {
      planted.cleanup();
    }

    console.log('\n[6] Session survives reload, logout and login work');
    await page.reload();
    await page.waitForFunction(() => /^[0-9a-f-]{36}$/.test(document.getElementById('caseId').textContent.trim()), null, { timeout: 15000 });
    check(await page.isHidden('#authOverlay'), 'reload keeps the session');
    await page.click('#logoutButton');
    await page.waitForSelector('#authOverlay:not([hidden])');
    check((await page.textContent('#authTitle')).includes('Вход'), 'logout shows the login form');
    allow401 = true;
    await page.fill('#authUsername', 'sirojiddin');
    await page.fill('#authPassword', 'wrong-password');
    await page.click('#authSubmit');
    await page.waitForFunction(() => document.getElementById('authError').textContent.length > 0);
    check(await page.isVisible('#authOverlay'), 'wrong password is refused');
    allow401 = false;
    await page.fill('#authPassword', password);
    await page.click('#authSubmit');
    await page.waitForSelector('#authOverlay', { state: 'hidden' });
    check(true, 'correct password logs in');
    await page.waitForTimeout(1500);

    console.log('\n[7] No page errors, console errors or failed requests');
    check(problems.length === 0, problems.length ? `problems:\n    ${problems.join('\n    ')}` : 'clean run');
  } finally {
    await browser.close();
    // Wait for the engine to actually exit before deleting its data dir:
    // on Windows an open SQLite file cannot be unlinked (EBUSY).
    const exited = child.exitCode !== null || child.signalCode !== null
      ? Promise.resolve()
      : new Promise((resolve) => child.once('exit', resolve));
    child.kill();
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 10000))]);
    try {
      fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch (e) {
      console.warn(`could not remove ${dataDir}: ${e.message}`);
    }
  }

  console.log(`\nPASSED: ${passed}  FAILED: ${failures.length}`);
  if (failures.length) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });

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
 *   E2E_REQUIRE_ALL_FEEDS=1  fail unless every feed downloads (OSV or MSRC,
 *                    CISA KEV, FIRST EPSS) and, on Windows, the independent
 *                    check against the MSRC Security Update Guide API runs
 *                    (CI has open internet; some sandboxes block these hosts)
 */

import { spawn, spawnSync } from 'node:child_process';
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

/** dpkg's own comparator, or null where dpkg is not installed. */
function dpkgCompare(a, op, b) {
  const r = spawnSync('dpkg', ['--compare-versions', a, op, b]);
  if (r.error) return null;
  return r.status === 0;
}

/** Installed dpkg source packages and their source versions. */
function dpkgSources() {
  const r = spawnSync('dpkg-query', ['-W', '-f=${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n'], { encoding: 'utf8' });
  if (r.error || r.status !== 0) return null;
  const map = new Map();
  for (const line of r.stdout.split('\n')) {
    const [st, src, ver] = line.split('\t');
    if (!src || !/^[ih]i/.test(st || '')) continue;
    if (!map.has(src)) map.set(src, new Set());
    map.get(src).add(ver);
  }
  return map;
}

/** Values under HKLM\...\Windows NT\CurrentVersion, read with reg.exe. */
function windowsCurrentVersion() {
  const r = spawnSync('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'], { encoding: 'utf8' });
  if (r.error || r.status !== 0) return null;
  const values = {};
  for (const line of r.stdout.split(/\r?\n/)) {
    const m = line.match(/^\s+(\S+)\s+(REG_SZ|REG_DWORD)\s+(.*)$/);
    if (m) values[m[1]] = m[2] === 'REG_DWORD' ? Number.parseInt(m[3], 16) : m[3].trim();
  }
  return values;
}

/** Installed update ids as Get-HotFix lists them. */
function windowsHotfixes() {
  const r = spawnSync('powershell', ['-NoProfile', '-Command', 'Get-HotFix | ForEach-Object { $_.HotFixID }'], { encoding: 'utf8' });
  if (r.error || r.status !== 0) return null;
  return r.stdout.split(/\r?\n/).map((l) => l.trim().toUpperCase()).filter((l) => /^KB\d+$/.test(l));
}

/**
 * Every record of the MSRC Security Update Guide API for one product
 * revised since `since`: a source independent of the CVRF documents the
 * engine imports.
 */
async function securityUpdateGuide(product, since) {
  const filter = `product eq '${product.replace(/'/g, "''")}' and releaseDate gt ${since}`;
  let url = `https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=${encodeURIComponent(filter)}`;
  const records = [];
  for (let page = 0; url && page < 200; page++) {
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(`SUG HTTP ${r.status}`);
    const body = await r.json();
    records.push(...(body.value || []));
    url = body['@odata.nextLink'] || null;
  }
  return records;
}

/**
 * Independent Windows verdicts from SUG records: patched when an installed
 * KB or a build at or past a regular fix of the same branch (hotpatches only
 * at their exact build), unverifiable when every fix is for another branch.
 */
function sugVerdicts(records, documents, build, hotfixes) {
  const host = build.split('.').map(Number);
  const installed = new Set(hotfixes.map((k) => k.replace(/^KB/, '')));
  const byCve = new Map();
  for (const rec of records) {
    if (!documents.includes(rec.releaseNumber)) continue;
    if (!byCve.has(rec.cveNumber)) byCve.set(rec.cveNumber, []);
    byCve.get(rec.cveNumber).push(...(rec.kbArticles || []));
  }
  const vulnerable = new Set();
  const unverified = new Set();
  let patched = 0;
  for (const [cve, kbs] of byCve) {
    if (kbs.some((kb) => installed.has(String(kb.articleName).trim()))) { patched++; continue; }
    const fixes = kbs.map((kb) => ({
      hotpatch: /hotpatch/i.test(kb.downloadName || '') || /hotpatch/i.test(kb.subType || ''),
      build: String(kb.fixedBuildNumber || '').replace(/[^0-9.]/g, '').split('.').map(Number),
    })).filter((f) => f.build.length === 4 && f.build.every(Number.isFinite)
      && f.build[0] === host[0] && f.build[1] === host[1] && f.build[2] === host[2]);
    if (!fixes.length) {
      if (kbs.length) unverified.add(cve); else vulnerable.add(cve);
      continue;
    }
    const ok = fixes.some((f) => (f.hotpatch ? host[3] === f.build[3] : host[3] >= f.build[3]));
    if (ok) patched++; else vulnerable.add(cve);
  }
  return { vulnerable, unverified, patched, total: byCve.size };
}

async function checkWindowsScan(scan, requireAll) {
  const reg = windowsCurrentVersion();
  const hotfixes = windowsHotfixes();
  check(Boolean(reg && hotfixes), 'registry and Get-HotFix are readable for the independent check');
  if (!reg || !hotfixes) return;
  const build = `10.0.${reg.CurrentBuild}.${reg.UBR}`;
  console.log(`  registry: ${reg.ProductName} ${reg.DisplayVersion || ''} ${reg.InstallationType}, build ${build}, ${hotfixes.length} hotfixes`);
  const win = scan.windows;
  check(win.build === build, `engine build ${win.build} matches the registry (${build})`);
  const year = (reg.ProductName.match(/Windows Server (\d{4}(?: R2)?)/) || [])[1];
  if (year) {
    const expected = `Windows Server ${year}${reg.InstallationType === 'Server Core' ? ' (Server Core installation)' : ''}`;
    check(win.product === expected, `engine maps the host to the MSRC product "${expected}" (${win.product})`);
  }
  const engineKbs = new Set((win.installed_updates || []).map((k) => k.toUpperCase()));
  check(hotfixes.every((k) => engineKbs.has(k)), `engine sees every installed update (${hotfixes.join(', ')})`);
  check(scan.summary.patched > 0, `the host's updates close known CVEs (${scan.summary.patched} patched)`);

  // A month before the oldest document, so records released early for it
  // are included; the release number filters the rest out.
  const oldest = win.documents[win.documents.length - 1];
  const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].indexOf(oldest.slice(5));
  const since = new Date(Date.UTC(Number(oldest.slice(0, 4)), month - 1, 1)).toISOString().replace(/\.\d{3}Z$/, 'Z');
  let records;
  try {
    records = await securityUpdateGuide(win.product, since);
  } catch (e) {
    check(!requireAll, `Security Update Guide API is reachable for the independent check (${e.message})`);
    return;
  }
  const sug = sugVerdicts(records, win.documents, build, hotfixes);
  const engineVulnerable = new Set(scan.findings.map((f) => f.id));
  const missed = [...sug.vulnerable].filter((c) => !engineVulnerable.has(c));
  const extra = [...engineVulnerable].filter((c) => !sug.vulnerable.has(c));
  console.log(`  SUG: ${records.length} records, ${sug.total} CVEs in ${win.documents.length} documents; vulnerable ${sug.vulnerable.size}, patched ${sug.patched}, unverified ${sug.unverified.size}`);
  check(sug.total > 0, `Security Update Guide lists CVEs for ${win.product}`);
  check(missed.length === 0 && extra.length === 0,
    `engine findings match the Security Update Guide (${engineVulnerable.size} vs ${sug.vulnerable.size})${missed.length ? `; missed ${missed.slice(0, 5).join(', ')}` : ''}${extra.length ? `; extra ${extra.slice(0, 5).join(', ')}` : ''}`);
  check(scan.summary.patched === sug.patched,
    `engine patched count matches the Security Update Guide (${scan.summary.patched} vs ${sug.patched})`);
}

async function checkVulnerabilityScan(page, base, shot) {
  const token = await page.evaluate(() => localStorage.getItem('soc_session_token'));
  const rpc = async (method, params = {}) => {
    const r = await fetch(`${base}/rpc`, {
      method: 'POST',
      body: JSON.stringify({ api_version: 1, request_id: 't', method, params: { ...params, token } }),
    });
    return r.json();
  };

  await page.click('.global-nav button[data-space="vulns"]');
  await page.waitForSelector('#vulnHostLine');
  const status = (await rpc('vulndb.status')).result;
  const host = status.host;
  const windows = host.platform === 'windows';
  console.log(windows
    ? `  host: ${host.os}, build ${host.build}, MSRC product ${host.product}, updates ${host.installed_updates} (${host.detail || 'supported'})`
    : `  host: ${host.os}, ecosystem ${host.ecosystem}, packages ${host.packages}`);
  if (process.platform === 'win32') {
    check(windows && host.supported, `Windows host is recognised as an MSRC product (${host.product || host.detail})`);
  }

  const before = (await rpc('scan.cve')).result;
  if (host.supported) {
    check(before.status === 'VULNDB_EMPTY', `scan before any update says the database is empty (${before.status})`);
  } else {
    check(before.status === 'UNSUPPORTED_PLATFORM', `unsupported platform is reported honestly (${before.status_detail})`);
  }

  await page.click('#vulnUpdateBtn');
  await page.waitForSelector('#vulnUpdateProgress:not([hidden])', { timeout: 15000 }).catch(() => {});
  await page.waitForFunction(() => {
    const p = document.getElementById('vulnUpdateProgress');
    return document.getElementById('vulnUpdateSteps') && (!p || p.hidden);
  }, null, { timeout: 600000 });
  const after = (await rpc('vulndb.status')).result;
  const steps = after.update.steps;
  for (const st of steps) console.log(`  ${st.ok ? 'ok  ' : 'FAIL'} ${st.feed}: ${st.message}${st.source ? ` (${st.source})` : ''}`);
  const step = (feed) => steps.find((st) => st.feed === feed);
  const requireAll = process.env.E2E_REQUIRE_ALL_FEEDS === '1';
  if (host.supported && windows) {
    check(step('msrc')?.ok, `MSRC monthly security updates downloaded and imported (${step('msrc')?.message})`);
  } else if (host.supported) {
    check(step(`osv:${host.ecosystem}`)?.ok, `OSV advisories for ${host.ecosystem} downloaded and imported`);
  }
  if (requireAll) {
    check(step('cisa-kev')?.ok, 'CISA KEV catalog downloaded and imported');
    check(step('epss')?.ok, 'FIRST EPSS scores downloaded and imported');
  }
  const uiSteps = await page.locator('#vulnUpdateSteps .vuln-step').count();
  check(uiSteps === steps.length, `UI lists every update step (${uiSteps})`);
  await shot('05-vulndb');

  if (!host.supported) {
    await page.click('#vulnScanBtn');
    await page.waitForSelector('#vulnStatus');
    check((await page.getAttribute('#vulnStatus', 'data-status')) === 'UNSUPPORTED_PLATFORM',
      'UI shows that CVE matching is not available on this OS');
    return;
  }

  // The UI runs the scan by itself once the update finishes.
  await page.waitForSelector('#vulnStatus', { timeout: 60000 });
  const scan = (await rpc('scan.cve')).result;
  const uiStatus = await page.getAttribute('#vulnStatus', 'data-status');
  check(uiStatus === scan.status, `UI scan status matches the engine (${uiStatus})`);
  check(['VULNERABILITIES_FOUND', 'NO_KNOWN_MATCHED_VULNERABILITIES'].includes(scan.status),
    `scan ran against a loaded database: ${scan.status_detail}`);
  if (!windows) {
    check(scan.packages_total === host.packages && scan.packages_total > 0,
      `every installed package was checked (${scan.packages_total})`);
  }
  console.log(`  findings: ${scan.summary.total} (critical ${scan.summary.critical}, high ${scan.summary.high}, kev ${scan.summary.kev}, no fix ${scan.summary.no_fix}), patched ${scan.summary.patched}`);
  for (const f of scan.findings.filter((x) => x.status === 'fix_available').slice(0, 10)) {
    console.log(`    ${f.id} ${f.component} ${f.installed_version} -> ${f.fixed_version} [${f.severity}]${f.kev ? ' KEV' : ''}${f.exploited ? ' exploited' : ''} ${(f.sources || []).join(' ')}`);
  }

  if (windows) {
    await checkWindowsScan(scan, requireAll);
    check((await page.textContent('#vulnHostLine')).includes(scan.windows.product), 'UI names the MSRC product of this host');
    check(await page.isVisible('#vulnWindowsMeta'), 'UI says which MSRC months the build was checked against');
    const uiExploited = Number(await page.textContent('#vulnExploited span'));
    check(uiExploited === scan.summary.exploited, `UI exploited count (${uiExploited}) matches the engine`);
  }

  // Independent check with the distribution's own tools.
  const sources = windows ? null : dpkgSources();
  if (sources) {
    const notInstalled = scan.findings.filter((f) => !sources.get(f.component)?.has(f.installed_version));
    check(notInstalled.length === 0,
      `every finding names an installed source package and version${notInstalled.length ? `: ${notInstalled.slice(0, 3).map((f) => `${f.component} ${f.installed_version}`).join(', ')}` : ''}`);
    const wrongFix = scan.findings.filter((f) => f.status === 'fix_available'
      && dpkgCompare(f.installed_version, 'lt', f.fixed_version) !== true);
    check(wrongFix.length === 0,
      `dpkg confirms the installed version is older than the fix for every fixable finding${wrongFix.length ? `: ${wrongFix[0].id}` : ''}`);
  }

  const chipTotal = Number(await page.textContent('#vulnSummary .vuln-chip span'));
  check(chipTotal === scan.summary.total, `UI total (${chipTotal}) matches the engine (${scan.summary.total})`);
  if (scan.findings.length) {
    await page.click('.vuln-filter[data-filter="all"]');
    const rows = await page.locator('#vulnTable tr.vuln-row').count();
    check(rows === Math.min(scan.findings.length, 200), `UI table lists the findings (${rows})`);
    const first = scan.findings[0];
    const firstRow = page.locator('#vulnTable tr.vuln-row').first();
    check((await firstRow.getAttribute('data-id')) === first.id, `UI order matches the engine (${first.id} first)`);
    await firstRow.click();
    check(await page.isVisible('#vulnTable tr.vuln-detail >> nth=0'), 'a finding expands to its description');
  }
  await shot('06-vulns');
}

/**
 * A small project in four languages: each file has one flaw where request
 * data reaches a dangerous call next to a safe variant of the same call, and
 * a test file whose flaw only counts when tests are included.
 */
const CODE_PROJECT = {
  'app/views.py': `import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    os.system('ping -c 1 ' + host)
    subprocess.run(['ping', '-c', '1', host], check=False)
    return 'ok'
`,
  'web/item.php': `<?php
$db = mysqli_connect('localhost', 'shop', 'secret', 'shop');
$id = $_GET['id'];
$rows = mysqli_query($db, "SELECT name FROM items WHERE id = " . $id);
$safe = intval($_GET['id']);
$more = mysqli_query($db, "SELECT name FROM items WHERE id = " . $safe);
echo htmlspecialchars($_GET['q']);
`,
  'src/shop/Download.java': `package shop;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Download extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        FileInputStream in = new FileInputStream(new File("/srv/files", name));
        in.close();
        FileInputStream fixed = new FileInputStream(new File("/srv/files", "index.txt"));
        fixed.close();
    }
}
`,
  'cgi/report.c': `#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char cmd[256];
    const char *q = getenv("QUERY_STRING");
    snprintf(cmd, sizeof(cmd), "grep %s /var/log/app.log", q);
    system(cmd);
    system("date");
    return 0;
}
`,
  'cgi/name.c': `#include <stdlib.h>
#include <string.h>

int main(void) {
    char name[16];
    char safe[16];
    char tag[4];
    const char *q = getenv("QUERY_STRING");
    if (!q)
        return 1;
    strcpy(name, q);
    strncpy(safe, q, sizeof(safe) - 1);
    safe[sizeof(safe) - 1] = 0;
    strcpy(tag, "draft");
    return name[0] + safe[0] + tag[0];
}
`,
  'cgi/users.c': `#include <stdlib.h>
#include <string.h>

struct user { char *name; struct user *next; };

static struct user *find(struct user *list, const char *name) {
    for (; list; list = list->next)
        if (strcmp(list->name, name) == 0)
            return list;
    return NULL;
}

int main(void) {
    struct user *list = NULL;
    struct user *admin = find(list, "admin");
    char *copy = malloc(64);
    strcpy(copy, "guest");
    char *checked = malloc(64);
    if (!checked)
        return 1;
    strcpy(checked, "guest");
    if (admin != NULL)
        checked[0] = admin->name[0];
    return admin->name[0] + copy[0] + checked[0];
}
`,
  'tests/test_views.py': `import os
from flask import request


def check():
    os.system(request.args['cmd'])
`,
};
// The flaws planted above, as "rule file:line".
const CODE_EXPECTED = [
  'command-injection app/views.py:11',
  'sql-injection web/item.php:4',
  'path-traversal src/shop/Download.java:14',
  'command-injection cgi/report.c:8',
  'buffer-overflow cgi/name.c:11',
  'buffer-overflow cgi/name.c:14',
  'unchecked-null cgi/users.c:17',
  'null-dereference cgi/users.c:24',
];
const CODE_EXPECTED_TEST = 'command-injection tests/test_views.py:6';

async function checkCodeScan(page, base, shot, allowIpcError) {
  const token = await page.evaluate(() => localStorage.getItem('soc_session_token'));
  const rpc = async (method, params = {}) => {
    const r = await fetch(`${base}/rpc`, {
      method: 'POST',
      body: JSON.stringify({ api_version: 1, request_id: 't', method, params: { ...params, token } }),
    });
    return r.json();
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-code-'));
  try {
    for (const [file, text] of Object.entries(CODE_PROJECT)) {
      fs.mkdirSync(path.join(dir, path.dirname(file)), { recursive: true });
      fs.writeFileSync(path.join(dir, file), text);
    }
    const anon = await fetch(`${base}/rpc`, {
      method: 'POST',
      body: JSON.stringify({ api_version: 1, request_id: 't', method: 'code.scan', params: { path: dir } }),
    });
    check(anon.status === 401, 'code.scan without a session is refused (it reads folders on the engine machine)');

    await page.click('.global-nav button[data-space="code"]');
    await page.waitForSelector('#codePath');
    // The result panel fills in once the engine answers code.status.
    const empty = await page.waitForSelector('#codeEmpty', { timeout: 15000 }).then(() => true, () => false);
    check(empty, 'code space opens with no analysis yet');

    allowIpcError(true);
    await page.fill('#codePath', path.join(dir, 'missing'));
    await page.click('#codeScanBtn');
    await page.waitForSelector('#codeError');
    check((await page.textContent('#codeError')).includes('недоступна'), 'a missing folder is refused with a message');
    allowIpcError(false);

    const scanned = async (tests) => {
      if ((await page.isChecked('#codeTests')) !== tests) await page.click('#codeTests');
      await page.fill('#codePath', dir);
      // The result of the previous run stays on the page until this one
      // finishes: wait for a result with another finish time.
      const previous = await page.evaluate(() => document.getElementById('codeStatus')?.dataset.finished ?? null);
      await page.click('#codeScanBtn');
      await page.waitForFunction((prev) => {
        const btn = document.getElementById('codeScanBtn');
        const result = document.getElementById('codeStatus');
        return btn && !btn.disabled && result && result.dataset.finished !== prev;
      }, previous, { timeout: 120000 });
      const status = (await rpc('code.status')).result;
      check(!status.running && !status.error && status.include_tests === tests,
        `analysis of ${dir} finished${tests ? ' with tests' : ''} (${status.error || 'no error'})`);
      return status;
    };
    const key = (f) => `${f.rule} ${f.file}:${f.line}`;

    const status = await scanned(false);
    const report = status.report;
    const found = report.findings.map(key);
    console.log(`  engine: ${found.join(', ')}; files ${report.files}, ${report.load_ms + report.analysis_ms} ms`);
    check(JSON.stringify([...found].sort()) === JSON.stringify([...CODE_EXPECTED].sort()),
      `engine reports exactly the planted flaws, not the safe calls or the test (${found.length})`);
    // A string that does not fit and a NULL pointer are flaws without any
    // input.
    const sourced = (f) => f.source || (f.rule === 'buffer-overflow' && f.line === 14)
      || f.rule === 'null-dereference' || f.rule === 'unchecked-null';
    check(report.findings.every((f) => f.trace.length > 0 && sourced(f) && f.snippet),
      'every finding has its source, data path and code line');
    check(report.test_files === 1, `the test file is counted as skipped (${report.test_files})`);

    const count = Number(await page.getAttribute('#codeStatus', 'data-count'));
    check(count === report.findings.length, `UI count (${count}) matches the engine`);
    const rows = await page.$$eval('#codeTable tr.vuln-row',
      (trs) => trs.map((tr) => `${tr.dataset.rule} ${tr.dataset.file}:${tr.dataset.line}`));
    check(JSON.stringify(rows) === JSON.stringify(found), `UI table lists the engine's findings in its order (${rows.length})`);
    const php = page.locator('#codeTable tr.vuln-row[data-file="web/item.php"]');
    check((await php.textContent()).includes("$_GET['id']"), 'the row names where the data comes from');
    await php.click();
    const detail = php.locator('xpath=following-sibling::tr[1]');
    check(await detail.isVisible(), 'a finding expands to its data path');
    check((await detail.locator('.code-trace li').count()) === report.findings.find((f) => f.file === 'web/item.php').trace.length,
      'the expanded path has every step the engine reported');

    const overflow = page.locator('#codeTable tr.vuln-row[data-file="cgi/name.c"][data-line="11"]');
    check((await overflow.textContent()).includes('Переполнение буфера') && (await overflow.textContent()).includes('getenv()'),
      'a network-sized copy is shown as a buffer overflow from QUERY_STRING');
    const constant = page.locator('#codeTable tr.vuln-row[data-file="cgi/name.c"][data-line="14"]');
    await constant.click();
    const constantDetail = await constant.locator('xpath=following-sibling::tr[1]').textContent();
    check(constantDetail.includes('записывает 6 байт в буфер размером 4 байта'),
      `a string longer than its array says by how much (${constantDetail.trim().split('\n')[0]})`);

    const nullRow = page.locator('#codeTable tr.vuln-row[data-file="cgi/users.c"][data-line="24"]');
    check((await nullRow.textContent()).includes('Разыменование нулевого указателя'),
      'a pointer NULL on every path to its use is shown as a NULL dereference');
    const unchecked = page.locator('#codeTable tr.vuln-row[data-file="cgi/users.c"][data-line="17"]');
    await unchecked.click();
    const uncheckedDetail = await unchecked.locator('xpath=following-sibling::tr[1]').textContent();
    check((await unchecked.textContent()).includes('CWE-690') && uncheckedDetail.includes('malloc() в строке 16'),
      `a malloc result used before a check names the allocation (${uncheckedDetail.trim().split('\n')[0]})`);

    await page.selectOption('#codeRule', 'command-injection');
    const shown = await page.locator('#codeTable tr.vuln-row').count();
    check(shown === report.findings.filter((f) => f.rule === 'command-injection').length,
      `the rule filter keeps only command injection (${shown})`);
    await page.fill('#codeSearch', 'report.c');
    const searched = await page.$$eval('#codeTable tr.vuln-row', (trs) => trs.map((tr) => tr.dataset.file));
    check(JSON.stringify(searched) === JSON.stringify(['cgi/report.c']), `search narrows to one file (${searched})`);
    await shot('07-code');

    const withTests = (await scanned(true)).report.findings.map(key);
    check(withTests.includes(CODE_EXPECTED_TEST) && withTests.length === CODE_EXPECTED.length + 1,
      `including tests adds the flaw in the test file (${withTests.length})`);
    const uiWithTests = await page.locator('#codeTable tr.vuln-row').count();
    check(uiWithTests === withTests.length, `UI shows the new run with filters reset (${uiWithTests})`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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
  // A refused request is logged by the IPC client; allowed where the test provokes one.
  let allowIpcError = false;
  page.on('console', (m) => {
    if (m.type() === 'error' && !(allowIpcError && m.text().startsWith('IPC Error'))) problems.push(`console: ${m.text()}`);
  });
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
    for (const space of ['operations', 'investigation', 'evidence', 'vulns', 'code', 'range', 'ctf', 'system']) {
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

    console.log('\n[6] Vulnerability database update and package CVE scan');
    await checkVulnerabilityScan(page, base, shot);

    console.log('\n[7] Source code analysis of a project folder');
    await checkCodeScan(page, base, shot, (on) => { allowIpcError = on; });

    console.log('\n[8] Session survives reload, logout and login work');
    await page.reload();
    await page.waitForFunction(() => /^[0-9a-f-]{36}$/.test(document.getElementById('caseId').textContent.trim()), null, { timeout: 15000 });
    check(await page.isHidden('#authOverlay'), 'reload keeps the session');
    // Let the app finish loading first: a call still in flight when the
    // session ends comes back 401, which is not what this step tests.
    await page.waitForLoadState('networkidle');
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

    console.log('\n[9] No page errors, console errors or failed requests');
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

/**
 * test-report.mjs - checks the HTML report export.
 *
 * The report is opened in a browser, and its findings carry values that came
 * from the scanned code or site — including, for an XSS finding, the very
 * payload that was injected. So the main thing this test proves is that no
 * such value can execute when the report is opened: every dangerous sequence
 * comes out escaped. It also checks the report lists the findings and counts
 * them by severity.
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mod = await import(
  pathToFileURL(path.join(__dirname, '..', 'js', 'report', 'report.js')).href
);
const { buildReportHtml, reportFilename } = mod;

let failures = 0;
const check = (cond, msg) => {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  }
};

const PAYLOAD = '"><svg/onload=alert(1)><img src=x onerror=alert(1)>';

const findings = [
  {
    rule: 'reflected-xss',
    cwe: 79,
    severity: 'high',
    title: 'Отражённый XSS',
    message: `Значение вернулось как есть: ${PAYLOAD}`,
    url: `http://site/search?q=${PAYLOAD}`,
    method: 'GET',
    param: 'q',
    evidence: `Отражено: ${PAYLOAD}`,
    request: `curl -i 'http://site/search?q=${PAYLOAD}'`,
  },
  {
    rule: 'sql-injection',
    cwe: 89,
    severity: 'critical',
    title: 'SQL-инъекция',
    message: 'Одиночная кавычка вызвала ошибку базы.',
    file: 'app/db.py',
    line: 42,
    snippet: 'query("SELECT * FROM users WHERE id=" + id)',
  },
  { rule: 'missing-csp', cwe: 693, severity: 'low', title: 'Нет CSP', message: 'Заголовок CSP отсутствует.' },
];

const html = buildReportHtml(
  { title: 'Тестовый отчёт', target: 'http://site', generatedAt: '2026-10-10' },
  findings
);

// 1. No injected element survives: the only way a handler like onerror runs
// is an unescaped "<tag", so those are what must never appear verbatim. (An
// "onerror=" inside escaped text, after "&lt;img", is inert and allowed.)
for (const bad of ['<svg', '<img', '<script', '<iframe']) {
  check(!html.includes(bad), `report must not contain raw "${bad}"`);
}
// 2. The payload is still present, as escaped text (so the analyst sees it).
check(html.includes('&lt;svg/onload=alert(1)&gt;'), 'payload shown escaped');

// 3. The findings and their locations are in the report.
check(html.includes('Отражённый XSS'), 'reflected-xss title present');
check(html.includes('SQL-инъекция'), 'sql-injection title present');
check(html.includes('app/db.py:42'), 'file:line location present');
check(html.includes('CWE-89'), 'CWE tag present');

// 4. The severity summary counts each level.
check(/Критический<\/span><\/td><td class="num">1/.test(html), 'one critical counted');
check(/Высокий<\/span><\/td><td class="num">1/.test(html), 'one high counted');
check(html.includes('Находок: 3'), 'total count present');

// 5. Empty input still produces a valid, finding-free document.
const emptyHtml = buildReportHtml({ title: 'Пусто' }, []);
check(emptyHtml.includes('Находок нет.'), 'empty report says so');
check(emptyHtml.startsWith('<!doctype html>'), 'empty report is a full document');

// 6. Filenames are timestamped and safe.
check(/^otchet-web-\d{4}-\d{2}-\d{2}\.html$/.test(reportFilename('web')), 'filename shape');

if (failures) {
  console.error(`\ntest-report: ${failures} check(s) failed`);
  process.exit(1);
}
console.log('test-report: all checks passed');

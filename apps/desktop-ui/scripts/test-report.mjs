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
const { buildReportHtml, buildUnifiedReportHtml, reportFilename } = mod;

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

// 7. The unified report combines sections and escapes every value too. Its
// findings also carry scanned payloads, so the same no-execution rule holds.
const unified = buildUnifiedReportHtml(
  { title: 'Единый отчёт', generatedAt: '2026-10-13', confirmedOnly: false },
  [
    { title: 'Запущенный сайт', target: `http://site/${PAYLOAD}`, findings: [findings[0]] },
    { title: 'Анализ кода', target: '/srv/app', findings: [findings[1]] },
    {
      title: 'Удалённый хост (ОС) по SSH',
      target: 'Ubuntu 22.04',
      findings: [{ severity: 'high', title: 'CVE-2024-0001', rule: 'openssl', message: 'overflow', evidence: 'Установлено: 1.1.1', advisories: [{ id: 'USN-1' }] }],
    },
  ]
);
for (const bad of ['<svg', '<img', '<script', '<iframe']) {
  check(!unified.includes(bad), `unified report must not contain raw "${bad}"`);
}
check(unified.includes('&lt;svg/onload=alert(1)&gt;'), 'unified payload shown escaped');
check(unified.includes('Запущенный сайт'), 'unified section title present');
check(unified.includes('Удалённый хост (ОС) по SSH'), 'unified remote section present');
check(unified.includes('CVE-2024-0001'), 'unified package finding present');
check(/Критический<\/span><\/td><td class="num">1/.test(unified), 'unified counts one critical across sections');
check(unified.includes('Находок: 3'), 'unified total across sections');

const emptyUnified = buildUnifiedReportHtml({ title: 'Пусто' }, []);
check(emptyUnified.includes('Находок нет.'), 'empty unified report says so');
check(emptyUnified.startsWith('<!doctype html>'), 'empty unified report is a full document');

// 8. The DFIR incident report (9 sections). Everything in it — log lines,
// IPs, paths, user agents — came from the analysed logs and is therefore
// attacker-controlled, so the same no-execution rule holds: nothing executes
// when the report is opened in a browser.
const incMod = await import(
  pathToFileURL(path.join(__dirname, '..', 'js', 'incident', 'incident-report.js')).href
);
const { buildIncidentReportHtml } = incMod;

const incHtml = buildIncidentReportHtml({
  meta: {
    path: `/var/log/${PAYLOAD}`,
    generatedAt: '2026-10-15T00:00:00Z',
    firstEvent: '2026-10-01T00:00:00Z',
    lastEvent: '2026-10-02T00:00:00Z',
  },
  files: [
    { path: `web01/${PAYLOAD}.log`, parsed: 10, lines: 12, sha256: 'abc123', compressed: false },
  ],
  findings: [
    {
      rule: 'ssh-bruteforce-success',
      severity: 'critical',
      title: 'Подбор пароля SSH с последующим входом',
      summary: `Успешный вход после перебора: ${PAYLOAD}`,
      mitre: ['T1110', 'T1078'],
      hosts: ['web01'],
      actor: '203.0.113.9',
      first_time: '2026-10-01T00:00:00Z',
      last_time: '2026-10-01T00:05:00Z',
      evidence: [{ source_file: `web01/auth.log`, line_no: 5, raw: `Accepted password ${PAYLOAD}` }],
    },
    {
      rule: 'account-created',
      severity: 'medium',
      title: 'Создана учётная запись',
      summary: 'Новый пользователь',
      mitre: ['T1136'],
      hosts: [],
      actor: 'eviluser',
      first_time: '2026-10-01T01:00:00Z',
      last_time: '2026-10-01T01:00:00Z',
      evidence: [],
    },
  ],
  links: [
    {
      rule: 'link-account-multi-host',
      severity: 'high',
      title: 'Учётная запись входит на несколько хостов',
      summary: 'root на web01 и db01',
      mitre: ['T1078'],
      hosts: ['web01', 'db01'],
      actor: 'root',
      first_time: '2026-10-01T00:00:00Z',
      last_time: '2026-10-02T00:00:00Z',
      evidence: [{ source_file: 'db01/auth.log', line_no: 2, raw: 'Accepted publickey for root' }],
    },
  ],
  events: [
    { source_file: `web01/auth.log`, line_no: 5, timestamp: '2026-10-01T00:00:00Z', source: 'auth', summary: 'x', fields: { src_ip: '203.0.113.9' } },
    { source_file: `db01/auth.log`, line_no: 2, timestamp: '2026-10-02T00:00:00Z', source: 'auth', summary: 'y', fields: { src_ip: '198.51.100.7' } },
  ],
  evidence: [
    { key: 'k1', timestamp: '2026-10-01T00:00:00Z', source: 'auth', source_file: `web01/auth.log`, line_no: 5, summary: `отмечено: ${PAYLOAD}` },
  ],
});

for (const bad of ['<svg', '<img', '<script', '<iframe']) {
  check(!incHtml.includes(bad), `incident report must not contain raw "${bad}"`);
}
check(incHtml.includes('&lt;svg/onload=alert(1)&gt;'), 'incident payload shown escaped');
check(incHtml.startsWith('<!doctype html>'), 'incident report is a full document');
// All nine sections are present and numbered.
for (const title of [
  '1. Резюме',
  '2. Исходные данные и цепочка хранения',
  '3. Отмеченные улики',
  '4. Находки',
  '5. Связи между хостами',
  '6. Индикаторы компрометации (IOC)',
  '7. Техники MITRE ATT&amp;CK',
  '8. Оценка воздействия',
  '9. Рекомендации',
]) {
  check(incHtml.includes(title), `incident section "${title}" present`);
}
// Chain of custody, MITRE and IOCs surface real values.
check(incHtml.includes('abc123'), 'incident report shows a file SHA-256');
check(incHtml.includes('Подбор учётных данных (Brute Force)'), 'incident report labels T1110');
check(incHtml.includes('203.0.113.9') && incHtml.includes('198.51.100.7'), 'incident report lists IOC IPs');
check(incHtml.includes('db01') && incHtml.includes('web01'), 'incident report lists hosts');
// A critical finding drives the verdict; impact names the compromise moment.
check(incHtml.includes('вероятна компрометация') || incHtml.includes('Вероятная компрометация'), 'incident verdict/impact reflects compromise');

// Empty investigation still yields a valid, honest document.
const incEmpty = buildIncidentReportHtml({ meta: { path: '/var/log' }, files: [], findings: [], links: [], events: [], evidence: [] });
check(incEmpty.startsWith('<!doctype html>'), 'empty incident report is a full document');
check(incEmpty.includes('9. Рекомендации'), 'empty incident report still has all sections');
check(incEmpty.includes('Явных автоматических признаков'), 'empty incident report states no auto signs');

if (failures) {
  console.error(`\ntest-report: ${failures} check(s) failed`);
  process.exit(1);
}
console.log('test-report: all checks passed');

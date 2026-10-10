/**
 * Builds a self-contained HTML report from a scan's findings and hands it to
 * the browser as a downloadable file.
 *
 * Findings carry values that came from the scanned code or the scanned site —
 * file paths, URLs, snippets, a reflected XSS payload the scan itself found.
 * The report is opened in a browser, so every one of those values is escaped:
 * the file must never execute what the scan merely reported. The page has no
 * external references (styles are inline), so it opens and prints anywhere.
 */

import { escapeHtml } from '../util/html.js';

const SEVERITY_LABELS = {
  critical: 'Критический',
  high: 'Высокий',
  medium: 'Средний',
  low: 'Низкий',
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

/** The location a finding points at: a file:line, or a verb and URL. */
function location(f) {
  if (f.file) return f.line ? `${f.file}:${f.line}` : String(f.file);
  if (f.url) return `${f.method ? f.method + ' ' : ''}${f.url}`;
  return '';
}

/** Longer evidence lines shown under a finding, when present. */
function details(f) {
  const rows = [];
  if (f.snippet) rows.push(['Фрагмент', f.snippet]);
  if (f.evidence) rows.push(['Подтверждение', f.evidence]);
  if (f.package) {
    const p = f.package;
    rows.push(['Пакет', `${p.ecosystem || ''} ${p.name || ''} ${p.version || ''}`.trim()]);
  }
  if (Array.isArray(f.advisories) && f.advisories.length) {
    rows.push(['Уязвимости', f.advisories.map((a) => a.id).filter(Boolean).join(', ')]);
  }
  if (f.request) rows.push(['Запрос', f.request]);
  return rows;
}

/**
 * Renders the full HTML document. `meta` is { title, target, generatedAt }.
 * Returns a string; it references nothing external.
 */
export function buildReportHtml(meta, findings) {
  const list = Array.isArray(findings) ? findings : [];
  const counts = SEVERITY_ORDER.map((s) => ({
    key: s,
    label: SEVERITY_LABELS[s],
    n: list.filter((f) => f.severity === s).length,
  }));

  const ordered = [...list].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const summaryRows = counts
    .map(
      (c) =>
        `<tr><td><span class="sev sev-${escapeHtml(c.key)}">${escapeHtml(c.label)}</span></td><td class="num">${escapeHtml(String(c.n))}</td></tr>`
    )
    .join('');

  const findingBlocks = ordered
    .map((f) => {
      const sev = SEVERITY_LABELS[f.severity] ? f.severity : 'low';
      const loc = location(f);
      const rows = details(f)
        .map(
          ([k, v]) =>
            `<div class="row"><span class="k">${escapeHtml(k)}</span><pre class="v">${escapeHtml(v)}</pre></div>`
        )
        .join('');
      const cwe = f.cwe ? `CWE-${escapeHtml(String(f.cwe))}` : '';
      const tag = [cwe, f.rule ? escapeHtml(f.rule) : ''].filter(Boolean).join(' · ');
      return `
        <article class="finding">
          <header>
            <span class="sev sev-${escapeHtml(sev)}">${escapeHtml(SEVERITY_LABELS[sev])}</span>
            <h3>${escapeHtml(f.title || f.rule || 'Находка')}</h3>
          </header>
          ${tag ? `<div class="tag">${tag}</div>` : ''}
          ${loc ? `<div class="loc">${escapeHtml(loc)}</div>` : ''}
          ${f.message ? `<p class="msg">${escapeHtml(f.message)}</p>` : ''}
          ${rows}
        </article>`;
    })
    .join('');

  const empty = ordered.length
    ? ''
    : '<p class="empty">Находок нет.</p>';

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(meta.title || 'Отчёт')}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #14171a; background: #fff; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .meta { color: #55606a; margin-bottom: 20px; }
  .meta code { background: #f1f3f5; padding: 1px 5px; border-radius: 3px; }
  table.summary { border-collapse: collapse; margin: 0 0 24px; min-width: 240px; }
  table.summary td { border: 1px solid #e4e8eb; padding: 6px 12px; }
  table.summary .num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
  .sev { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; letter-spacing: .3px; border: 1px solid; }
  .sev-critical { color: #fff; background: #b4232a; border-color: #b4232a; }
  .sev-high { color: #1a1205; background: #e0a008; border-color: #e0a008; }
  .sev-medium { color: #9a6b00; border-color: #e0a008; }
  .sev-low { color: #1f6feb; border-color: #1f6feb; }
  .finding { border: 1px solid #e4e8eb; border-left-width: 4px; border-radius: 6px; padding: 12px 16px; margin: 0 0 14px; }
  .finding header { display: flex; align-items: center; gap: 10px; }
  .finding h3 { font-size: 15px; margin: 0; }
  .tag { color: #55606a; font-size: 12px; margin: 4px 0; }
  .loc { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #334; margin: 2px 0 6px; word-break: break-all; }
  .msg { margin: 6px 0; }
  .row { display: flex; gap: 10px; margin: 4px 0; }
  .row .k { flex: 0 0 110px; color: #55606a; font-size: 12px; }
  .row .v { flex: 1; margin: 0; white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; background: #f6f8fa; padding: 6px 8px; border-radius: 4px; }
  .empty { color: #55606a; }
  @media print { body { padding: 0; } .finding { break-inside: avoid; } }
</style>
</head>
<body>
  <h1>${escapeHtml(meta.title || 'Отчёт')}</h1>
  <div class="meta">
    ${meta.target ? `Цель: <code>${escapeHtml(meta.target)}</code><br>` : ''}
    Сформировано: ${escapeHtml(meta.generatedAt || new Date().toISOString())} · Находок: ${escapeHtml(String(list.length))}
  </div>
  <table class="summary"><tbody>${summaryRows}</tbody></table>
  ${empty}
  ${findingBlocks}
</body>
</html>`;
}

/** Hands `html` to the browser as a downloaded file named `filename`. */
export function downloadReport(filename, html) {
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A filesystem-safe timestamped name like `otchet-code-2026-10-10.html`. */
export function reportFilename(kind) {
  const date = new Date().toISOString().slice(0, 10);
  return `otchet-${kind}-${date}.html`;
}

import { escapeAttr, escapeHtml } from '../util/html.js';
import { buildReportHtml, downloadReport, reportFilename } from '../report/report.js';

// The report view for a code-analysis result: the findings table (SAST +
// vulnerable/malicious dependencies), the severity/rule/search filters, the
// dependency-database panel and the HTML export. It is shared by the local
// «Анализ кода» space and the remote «Проверка кода проекта по SSH» panel, so
// the two show an identical, identically-escaped report. Everything printed
// comes from the scanned project, which is untrusted — every value is escaped
// before it reaches the page.

const SEVERITY_LABELS = {
  critical: 'КРИТИЧЕСКИЙ',
  high: 'ВЫСОКИЙ',
  medium: 'СРЕДНИЙ',
  low: 'НИЗКИЙ'
};
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const LANGUAGE_NAMES = { python: 'Python', java: 'Java', php: 'PHP', c: 'C', cpp: 'C++', javascript: 'JavaScript', typescript: 'TypeScript', tsx: 'TypeScript (TSX)' };

/** How the project names a package (dependency `kind`). */
const KIND_LABELS = {
  manifest: 'файл зависимостей',
  lockfile: 'lock-файл',
  bundled: 'копия библиотеки в проекте',
  cdn: 'загрузка с CDN',
  installed: 'установлен в окружении проекта'
};
/** Advisory ratings (CVSS scale of the vulnerability database). */
const ADVISORY_SEVERITY = {
  critical: ['critical', 'критическая'],
  high: ['high', 'высокая'],
  medium: ['medium', 'средняя'],
  low: ['low', 'низкая'],
  none: ['low', 'низкая'],
  unknown: ['low', 'без оценки']
};

export const PAGE_SIZE = 200;

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString('ru-RU');
}

function duration(ms) {
  return ms < 1000 ? `${ms} мс` : `${(ms / 1000).toFixed(1)} с`;
}

function place(loc) {
  return loc ? `${loc.file}:${loc.line}` : '—';
}

export class CodeReportView {
  /**
   * @param {object} [opts]
   * @param {(ecosystems: string[]) => void} [opts.onLoadDepsDb] called when the
   *   "load vulnerability database" button is clicked; the host decides how to
   *   load it (locally via code.deps, or by reconnecting for a remote scan).
   * @param {string} [opts.exportTitle] title used in the exported HTML report.
   * @param {string} [opts.exportKind] slug used in the export file name.
   */
  constructor(opts = {}) {
    this.onLoadDepsDb = opts.onLoadDepsDb || null;
    this.exportTitle = opts.exportTitle || 'Анализ кода';
    this.exportKind = opts.exportKind || 'code';
    this.panel = null;
    this.status = null;
    this.severity = 'all';
    this.rule = 'all';
    this.query = '';
    this.limit = PAGE_SIZE;
    // Loading the vulnerability database for the dependencies.
    this.depsUpdating = false;
    this.depsCurrent = '';
    this.depsError = null;
  }

  /** Resets the filters, e.g. when a new scan starts. */
  resetFilters() {
    this.severity = 'all';
    this.rule = 'all';
    this.query = '';
    this.limit = PAGE_SIZE;
  }

  /** Renders `status` (the scan status, with `.report`) into `panel`. */
  render(panel, status) {
    this.panel = panel;
    this.status = status;
    this.renderInto();
  }

  findings() {
    return this.status?.report?.findings || [];
  }

  filteredFindings() {
    const q = this.query;
    return this.findings().filter(f => {
      if (this.severity !== 'all' && f.severity !== this.severity) return false;
      if (this.rule !== 'all' && f.rule !== this.rule) return false;
      if (!q) return true;
      return [f.file, f.rule, f.title, f.message, f.snippet, `cwe-${f.cwe}`, f.source?.file, f.package?.name,
        ...(f.advisories || []).flatMap(a => [a.id, ...(a.aliases || [])])]
        .some(t => String(t ?? '').toLowerCase().includes(q));
    });
  }

  renderInto() {
    const panel = this.panel;
    if (!panel) return;
    const s = this.status;
    const report = s?.report;
    if (!report) {
      panel.innerHTML = `
        <div class="vuln-panel-title">РЕЗУЛЬТАТ</div>
        <div class="vuln-note" id="codeEmpty">${s?.running ? 'Анализ выполняется...' : 'Анализ ещё не запускался.'}</div>`;
      return;
    }

    const all = this.findings();
    const count = sev => all.filter(f => f.severity === sev).length;
    const languages = (report.languages || [])
      .map(([lang, n]) => `${LANGUAGE_NAMES[lang] || lang} ${n}`)
      .join(', ');
    const parseErrors = report.parse_errors || [];
    const skipped = report.skipped || [];
    const listCounts = pairs => (pairs || []).map(([what, n]) => `${what} ${n}`).join(', ');
    const otherFiles = listCounts(report.other_files);
    const uncheckedFiles = listCounts(report.unchecked_files);
    const rules = [...new Map(all.map(f => [f.rule, f.title])).entries()]
      .map(([rule, title]) => ({ rule, title, n: all.filter(f => f.rule === rule).length }))
      .sort((a, b) => b.n - a.n);
    if (this.rule !== 'all' && !rules.some(r => r.rule === this.rule)) this.rule = 'all';

    const shown = this.filteredFindings();
    const rows = shown.slice(0, this.limit).map((f, i) => this.findingRow(f, i)).join('');
    const sevBtn = (key, label, n) => `
      <button class="code-sev-filter ctf-btn ${this.severity === key ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-severity="${escapeAttr(key)}">${escapeHtml(label)} (${escapeHtml(String(n))})</button>`;

    panel.innerHTML = `
      <div class="vuln-panel-title">РЕЗУЛЬТАТ</div>
      <div id="codeStatus" class="vuln-status ${all.length ? 'vuln-status-found' : 'vuln-status-clean'}" data-count="${escapeAttr(String(all.length))}" data-finished="${escapeAttr(s.finished_at || '')}">
        ${all.length ? `Найдено уязвимостей: ${escapeHtml(String(all.length))}` : 'Уязвимостей не найдено'}
      </div>
      <div class="vuln-chips" id="codeSummary">
        <div class="vuln-chip"><span>${escapeHtml(String(all.length))}</span>всего</div>
        <div class="vuln-chip vuln-sev-critical"><span>${escapeHtml(String(count('critical')))}</span>критических</div>
        <div class="vuln-chip vuln-sev-high"><span>${escapeHtml(String(count('high')))}</span>высоких</div>
        <div class="vuln-chip vuln-sev-medium"><span>${escapeHtml(String(count('medium')))}</span>средних</div>
        <div class="vuln-chip vuln-sev-low"><span>${escapeHtml(String(count('low')))}</span>низких</div>
      </div>
      <div class="vuln-note" id="codeMeta">
        Проверено ${escapeHtml(formatDate(s.finished_at))}: <span class="vuln-mono">${escapeHtml(s.path)}</span>,
        файлов кода ${escapeHtml(String(report.files))}${languages ? ` (${escapeHtml(languages)})` : ''}, строк ${escapeHtml(String(report.lines))},
        за ${escapeHtml(duration(report.load_ms + report.analysis_ms))}.
        ${otherFiles ? `<span id="codeOtherFiles">Остальные файлы проверены на секреты: ${escapeHtml(otherFiles)}.</span>` : ''}
        ${uncheckedFiles ? `<span id="codeUncheckedFiles">Не проверялись: ${escapeHtml(uncheckedFiles)}.</span>` : ''}
        ${report.test_files ? `Тестовых файлов не проверялось: ${escapeHtml(String(report.test_files))}.` : ''}
        ${s.external_sources ? 'Аргументы, окружение и файлы считались входом атакующего.' : ''}
      </div>
      ${parseErrors.length ? `
        <details class="code-issues" id="codeParseErrors">
          <summary>Файлы с ошибками разбора: ${escapeHtml(String(parseErrors.length))} (проверены частично)</summary>
          <div class="vuln-mono">${parseErrors.slice(0, 100).map(p => escapeHtml(p.line ? `${p.path}:${p.line}` : p.path)).join('<br>')}</div>
        </details>` : ''}
      ${skipped.length ? `
        <details class="code-issues" id="codeSkipped">
          <summary>Пропущенные файлы: ${escapeHtml(String(skipped.length))}</summary>
          <div class="vuln-mono">${skipped.slice(0, 100).map(([p, why]) => `${escapeHtml(p)}: ${escapeHtml(why)}`).join('<br>')}</div>
        </details>` : ''}
      <div id="codeDeps" class="code-deps"></div>
      ${all.length ? `
        <div class="vuln-toolbar">
          ${sevBtn('all', 'Все', all.length)}
          ${SEVERITIES.filter(sev => count(sev)).map(sev => sevBtn(sev, SEVERITY_LABELS[sev], count(sev))).join('')}
          <select id="codeRule" class="code-rule">
            <option value="all">Все виды (${escapeHtml(String(all.length))})</option>
            ${rules.map(r => `<option value="${escapeAttr(r.rule)}" ${this.rule === r.rule ? 'selected' : ''}>${escapeHtml(r.title)} (${escapeHtml(String(r.n))})</option>`).join('')}
          </select>
          <input id="codeSearch" type="text" placeholder="Файл, CWE или код..." value="${escapeAttr(this.query)}">
          <button id="codeExport" class="ctf-btn ctf-btn-secondary" title="Сохранить отчёт в HTML-файл">Экспорт в HTML</button>
        </div>
        <table class="vuln-table" id="codeTable">
          <thead><tr>
            <th>Важность</th><th>Уязвимость</th><th>Где</th><th>Откуда данные</th><th>Код</th>
          </tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="vuln-note">Нет записей для выбранного фильтра</td></tr>'}</tbody>
        </table>
        ${shown.length > this.limit ? `<button id="codeMoreBtn" class="ctf-btn ctf-btn-secondary">Показать ещё (${escapeHtml(String(shown.length - this.limit))})</button>` : ''}
      ` : ''}
    `;

    panel.querySelectorAll('.code-sev-filter').forEach(btn => btn.addEventListener('click', () => {
      this.severity = btn.dataset.severity;
      this.limit = PAGE_SIZE;
      this.renderInto();
    }));
    panel.querySelector('#codeRule')?.addEventListener('change', (e) => {
      this.rule = e.target.value;
      this.limit = PAGE_SIZE;
      this.renderInto();
    });
    const search = panel.querySelector('#codeSearch');
    search?.addEventListener('input', (e) => {
      this.query = e.target.value.toLowerCase().trim();
      this.limit = PAGE_SIZE;
      const pos = e.target.selectionStart;
      this.renderInto();
      const again = this.panel.querySelector('#codeSearch');
      again?.focus();
      again?.setSelectionRange(pos, pos);
    });
    panel.querySelector('#codeMoreBtn')?.addEventListener('click', () => {
      this.limit += PAGE_SIZE;
      this.renderInto();
    });
    panel.querySelector('#codeExport')?.addEventListener('click', () => {
      const html = buildReportHtml(
        {
          title: this.exportTitle,
          target: s.path,
          generatedAt: formatDate(s.finished_at),
        },
        all
      );
      downloadReport(reportFilename(this.exportKind), html);
    });
    panel.querySelectorAll('tr.vuln-row').forEach(tr => tr.addEventListener('click', () => {
      const detail = tr.nextElementSibling;
      if (detail?.classList.contains('vuln-detail')) detail.hidden = !detail.hidden;
    }));
    this.renderDeps();
  }

  /**
   * Third-party packages of the project: what was found, whether the
   * vulnerability database has their ecosystems, and a button to load it.
   */
  renderDeps() {
    const box = this.panel?.querySelector('#codeDeps');
    const dc = this.status?.report?.dependency_check;
    if (!box || !dc) return;
    const ecosystems = dc.ecosystems || [];
    const missing = dc.missing || [];
    const undeclared = dc.undeclared_python || [];
    const unpinned = dc.unpinned || [];
    const list = dc.list || [];
    const counted = ecosystems.map(e => `${e.ecosystem} ${e.packages}`).join(', ');
    let html = '<div class="vuln-panel-title">ЗАВИСИМОСТИ</div>';
    if (!dc.packages && !dc.unpinned_total && !undeclared.length) {
      html += '<div class="vuln-note" id="codeDepsNone">Файлов зависимостей, встроенных библиотек и ссылок на CDN не найдено.</div>';
    }
    if (dc.packages) {
      html += `<div class="vuln-note" id="codeDepsSummary" data-packages="${escapeAttr(String(dc.packages))}" data-vulnerable="${escapeAttr(String(dc.vulnerable))}">
        Пакетов с точной версией: ${escapeHtml(String(dc.packages))} (${escapeHtml(counted)}).
        ${missing.length ? '' : `С известными уязвимостями: ${escapeHtml(String(dc.vulnerable))}, они в таблице ниже.`}</div>`;
      html += `<div class="vuln-chips" id="codeDepsEcosystems">${ecosystems.map(e => `
        <div class="vuln-chip ${e.loaded ? 'vuln-chip-ok' : ''}" data-ecosystem="${escapeAttr(e.ecosystem)}" data-loaded="${escapeAttr(String(e.loaded))}">
          <span>${escapeHtml(String(e.packages))}</span>${escapeHtml(e.ecosystem)}:
          ${e.loaded ? `база от ${escapeHtml(formatDate(e.checked_at))}` : 'база не загружена'}
        </div>`).join('')}</div>`;
    }
    if (dc.python_env && dc.python_env.resolved) {
      html += `<div class="vuln-note" id="codeDepsEnv">Версии ${escapeHtml(String(dc.python_env.resolved))} Python-пакетов (без requirements.txt) взяты из установленного окружения${dc.python_env.interpreter ? ` (${escapeHtml(dc.python_env.interpreter)})` : ''} и проверены на уязвимости.</div>`;
    }
    if (missing.length) {
      const mb = ecosystems.filter(e => !e.loaded).reduce((n, e) => n + (e.download_mb || 0), 0);
      html += `<div class="vuln-note" id="codeDepsMissing">Пакеты ${escapeHtml(missing.join(', '))} ещё не проверены: в базе уязвимостей нет данных OSV для этих экосистем. Загрузка нужна один раз, потом базу можно обновлять той же кнопкой.</div>
        <button id="codeDepsLoad" class="primary-action" data-ecosystems="${escapeAttr(missing.join(','))}" ${this.depsUpdating ? 'disabled' : ''}>Загрузить базу уязвимостей: ${escapeHtml(missing.join(', '))} (около ${escapeHtml(String(mb))} МБ)</button>`;
    } else if (dc.packages) {
      html += `<button id="codeDepsLoad" class="ctf-btn ctf-btn-secondary" data-ecosystems="${escapeAttr(ecosystems.map(e => e.ecosystem).join(','))}" ${this.depsUpdating ? 'disabled' : ''}>Обновить базу уязвимостей</button>`;
    }
    if (this.depsUpdating) {
      html += `<div class="vuln-progress" id="codeDepsProgress"><span class="vuln-spinner"></span> ${escapeHtml(this.depsCurrent || 'Загрузка базы...')}</div>`;
    }
    if (this.depsError) html += `<div class="vuln-error" id="codeDepsError">${escapeHtml(this.depsError)}</div>`;
    if (dc.error) html += `<div class="vuln-error">${escapeHtml(dc.error)}</div>`;
    if (undeclared.length) {
      const first = undeclared[0];
      const names = undeclared
        .map(m => (m.dist && m.dist !== m.module) ? `${m.module} (${m.dist})` : m.module)
        .join(', ');
      html += `<div class="vuln-note code-deps-warn" id="codeDepsUndeclared">Код на Python импортирует сторонние модули
        <span class="vuln-mono">${escapeHtml(names)}</span>
        (например, ${escapeHtml(first.file)}:${escapeHtml(String(first.line))}), версии которых не заданы ни в проекте, ни в установленном окружении.
        Поэтому на уязвимости они не проверены. Выполните в папке проекта <span class="vuln-mono">pip freeze &gt; requirements.txt</span> (или <span class="vuln-mono">pipreqs .</span>) и пересканируйте — тогда они тоже будут проверены.</div>`;
    }
    if (dc.unpinned_total) {
      html += `<details class="code-issues" id="codeDepsUnpinned">
        <summary>Без точной версии: ${escapeHtml(String(dc.unpinned_total))} (какая версия установится, неизвестно, поэтому они не проверены)</summary>
        <div class="vuln-mono">${unpinned.map(d => `${escapeHtml(d.ecosystem)} ${escapeHtml(d.name)} ${escapeHtml(d.requirement || 'любая версия')}: ${escapeHtml(d.file)}:${escapeHtml(String(d.line))}`).join('<br>')}</div>
      </details>`;
    }
    if (list.length) {
      html += `<details class="code-issues" id="codeDepsList">
        <summary>Все пакеты: ${escapeHtml(String(dc.packages))}</summary>
        <div class="code-deps-list"></div>
      </details>`;
    }
    box.innerHTML = html;
    box.querySelector('#codeDepsLoad')?.addEventListener('click', (e) => {
      const ecosystems = e.currentTarget.dataset.ecosystems.split(',').filter(Boolean);
      if (this.onLoadDepsDb) this.onLoadDepsDb(ecosystems);
    });
    // The full list can run to thousands of rows: built when opened.
    const details = box.querySelector('#codeDepsList');
    details?.addEventListener('toggle', () => {
      const target = details.querySelector('.code-deps-list');
      if (details.open && !target.childElementCount) target.innerHTML = this.packagesTable(dc);
    });
  }

  /** Every package found, with where it is named and what was found for it. */
  packagesTable(dc) {
    const list = dc.list || [];
    const missing = dc.missing || [];
    return `<table class="vuln-table">
      <thead><tr><th>Экосистема</th><th>Пакет</th><th>Версия</th><th>Где указан</th><th>Уязвимости</th></tr></thead>
      <tbody>${list.map(p => `<tr data-name="${escapeAttr(p.name)}">
        <td>${escapeHtml(p.ecosystem)}</td>
        <td class="vuln-mono">${escapeHtml(p.name)}</td>
        <td class="vuln-mono">${escapeHtml(p.version)}</td>
        <td><span class="vuln-mono">${escapeHtml(p.file)}:${escapeHtml(String(p.line))}</span><div class="vuln-pkgs">${escapeHtml(KIND_LABELS[p.kind] || p.kind)}${p.places > 1 ? `, мест: ${escapeHtml(String(p.places))}` : ''}</div></td>
        <td>${p.malicious ? '<span class="vuln-badge vuln-sev-critical">ВРЕДОНОСНЫЙ</span>' : p.advisories ? escapeHtml(String(p.advisories)) : (missing.includes(p.ecosystem) ? 'не проверен' : 'нет известных')}</td>
      </tr>`).join('')}</tbody>
    </table>${list.length < dc.packages ? `<div class="vuln-note">Показаны первые ${escapeHtml(String(list.length))}.</div>` : ''}`;
  }

  findingRow(f, i) {
    if (f.package) return this.dependencyRow(f, i);
    const sev = SEVERITY_LABELS[f.severity] ? f.severity : 'low';
    const trace = (f.trace || []).map(step => `
      <li><span class="vuln-mono">${escapeHtml(place(step))}</span> ${escapeHtml(step.note)}</li>`).join('');
    const others = f.other_sources || [];
    // Long project paths go on their own line under the file name.
    const slash = String(f.file).lastIndexOf('/');
    const dir = String(f.file).slice(0, slash + 1);
    const name = String(f.file).slice(slash + 1);
    const from = f.source?.file === f.file ? `строка ${f.source.line}` : place(f.source);
    return `
      <tr class="vuln-row" data-index="${escapeAttr(String(i))}" data-rule="${escapeAttr(f.rule)}" data-file="${escapeAttr(f.file)}" data-line="${escapeAttr(String(f.line))}">
        <td><span class="vuln-badge vuln-sev-${escapeAttr(sev)}">${escapeHtml(SEVERITY_LABELS[sev])}</span></td>
        <td><strong>${escapeHtml(f.title)}</strong><div class="vuln-pkgs">CWE-${escapeHtml(String(f.cwe))} · ${escapeHtml(f.rule)}</div></td>
        <td class="code-where"><span class="vuln-mono">${escapeHtml(name)}:${escapeHtml(String(f.line))}</span><div class="vuln-pkgs vuln-mono code-dir">${escapeHtml(dir)}</div></td>
        <td class="code-from">${f.source ? `${escapeHtml(f.source.note)}<div class="vuln-pkgs vuln-mono">${escapeHtml(from)}</div>` : '—'}${others.length ? `<div class="vuln-pkgs">и ещё входов: ${escapeHtml(String(others.length))}</div>` : ''}</td>
        <td class="code-snippet"><code>${escapeHtml(f.snippet)}</code></td>
      </tr>
      <tr class="vuln-detail" hidden>
        <td colspan="5">
          <div>${escapeHtml(f.message)}</div>
          ${trace ? `<div class="vuln-detail-meta">Путь данных:</div><ol class="code-trace">${trace}</ol>` : ''}
          ${others.length ? `<div class="vuln-detail-meta">Другие входы, доходящие до этого вызова:</div>
            <ul class="code-trace">${others.map(o => `<li><span class="vuln-mono">${escapeHtml(place(o))}</span> ${escapeHtml(o.note)}</li>`).join('')}</ul>` : ''}
        </td>
      </tr>`;
  }

  /** A vulnerable or malicious package, with the advisories that name it. */
  dependencyRow(f, i) {
    const sev = SEVERITY_LABELS[f.severity] ? f.severity : 'low';
    const pkg = f.package;
    const others = f.other_sources || [];
    const slash = String(f.file).lastIndexOf('/');
    const dir = String(f.file).slice(0, slash + 1);
    const name = String(f.file).slice(slash + 1);
    const advisories = (f.advisories || []).map(a => {
      const [cls, label] = ADVISORY_SEVERITY[a.severity] || ADVISORY_SEVERITY.unknown;
      // Feed data: only plain web links become clickable.
      const id = a.url && /^https:\/\//i.test(a.url)
        ? `<a href="${escapeAttr(a.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(a.id)}</a>`
        : escapeHtml(a.id);
      return `<li data-id="${escapeAttr(a.id)}">${id}
        ${a.malicious ? '<span class="vuln-badge vuln-sev-critical">ВРЕДОНОСНЫЙ</span>' : `<span class="vuln-badge vuln-sev-${escapeAttr(cls)}">${escapeHtml(label)}</span>`}
        ${a.kev ? `<span class="vuln-badge vuln-kev" title="${escapeAttr(`${a.kev.name}; добавлено ${a.kev.date_added}`)}">KEV</span>` : ''}
        ${escapeHtml(a.summary || '')}
        ${a.malicious ? '' : a.fixed_version ? `<span class="vuln-pkgs">исправлено в ${escapeHtml(a.fixed_version)}</span>` : '<span class="vuln-nofix">нет исправления</span>'}
        ${(a.aliases || []).length ? `<span class="vuln-pkgs">${escapeHtml(a.aliases.join(', '))}</span>` : ''}
      </li>`;
    }).join('');
    return `
      <tr class="vuln-row" data-index="${escapeAttr(String(i))}" data-rule="${escapeAttr(f.rule)}" data-file="${escapeAttr(f.file)}" data-line="${escapeAttr(String(f.line))}" data-package="${escapeAttr(pkg.name)}">
        <td><span class="vuln-badge vuln-sev-${escapeAttr(sev)}">${escapeHtml(SEVERITY_LABELS[sev])}</span></td>
        <td><strong>${escapeHtml(f.title)}</strong><div class="vuln-pkgs">CWE-${escapeHtml(String(f.cwe))} · ${escapeHtml(f.rule)}</div></td>
        <td class="code-where"><span class="vuln-mono">${escapeHtml(name)}:${escapeHtml(String(f.line))}</span><div class="vuln-pkgs vuln-mono code-dir">${escapeHtml(dir)}</div></td>
        <td class="code-from">${escapeHtml(pkg.ecosystem)} <span class="vuln-mono">${escapeHtml(pkg.name)} ${escapeHtml(pkg.version)}</span>${pkg.dev ? ' <span class="vuln-badge vuln-dev" title="Только dev-зависимость: не попадает в сборку">dev</span>' : ''}
          <div class="vuln-pkgs">${escapeHtml(KIND_LABELS[pkg.kind] || pkg.kind)}; уязвимостей: ${escapeHtml(String((f.advisories || []).length))}</div>
          ${others.length ? `<div class="vuln-pkgs">и ещё мест: ${escapeHtml(String(others.length))}</div>` : ''}</td>
        <td class="code-snippet"><code>${escapeHtml(f.snippet)}</code></td>
      </tr>
      <tr class="vuln-detail" hidden>
        <td colspan="5">
          <div>${escapeHtml(f.message)}</div>
          <div class="vuln-detail-meta">Известные уязвимости этой версии:</div>
          <ul class="code-trace code-advisories">${advisories}</ul>
          ${others.length ? `<div class="vuln-detail-meta">Эта же версия указана ещё здесь:</div>
            <ul class="code-trace">${others.map(o => `<li><span class="vuln-mono">${escapeHtml(place(o))}</span> ${escapeHtml(o.note)}</li>`).join('')}</ul>` : ''}
        </td>
      </tr>`;
  }
}

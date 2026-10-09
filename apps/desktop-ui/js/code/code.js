import { escapeAttr, escapeHtml } from '../util/html.js';

const SEVERITY_LABELS = {
  critical: 'КРИТИЧЕСКИЙ',
  high: 'ВЫСОКИЙ',
  medium: 'СРЕДНИЙ',
  low: 'НИЗКИЙ'
};
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const LANGUAGE_NAMES = { python: 'Python', java: 'Java', php: 'PHP', c: 'C', cpp: 'C++' };

const PAGE_SIZE = 200;
const PATH_KEY = 'soc.code.path';

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

function savedPath() {
  try {
    return globalThis.localStorage?.getItem(PATH_KEY) || '';
  } catch {
    return '';
  }
}

function savePath(path) {
  try {
    globalThis.localStorage?.setItem(PATH_KEY, path);
  } catch {
    // Private windows and blocked storage only lose the convenience.
  }
}

/**
 * Code analysis space: runs the engine's taint analysis on a project folder
 * (Python, Java, PHP, C, C++) and lists the flaws where user input reaches a
 * dangerous call, each with the path the data took from source to sink.
 * The code being scanned is untrusted: every value from the report is
 * escaped before it reaches the page.
 */
export class CodeSpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.container = null;
    this.status = null;
    this.error = null;
    this.path = savedPath();
    this.external = false;
    this.includeTests = false;
    this.severity = 'all';
    this.rule = 'all';
    this.query = '';
    this.limit = PAGE_SIZE;
    this.pollTimer = null;
  }

  async render(container) {
    this.container = container;
    container.innerHTML = `
      <div class="vuln-space code-space">
        <div class="vuln-header">
          <div>
            <h2>⌨ АНАЛИЗ КОДА</h2>
            <div class="vuln-subtitle">Уязвимости в исходном коде на Python, Java, PHP, C и C++: путь данных от входа (HTTP-запрос, сокет, CGI) до опасного вызова (SQL, команды ОС, файлы, шаблоны, XSS, LDAP, XML, SSRF, перенаправления), а также слабая криптография, секреты в коде и отключённая проверка TLS</div>
          </div>
        </div>
        <div class="vuln-panel">
          <div class="vuln-panel-title">ПРОЕКТ</div>
          <div class="code-form">
            <input id="codePath" type="text" spellcheck="false" placeholder="/home/user/project или C:\\src\\project" value="${escapeAttr(this.path)}">
            <button id="codeScanBtn" class="primary-action">Проверить</button>
          </div>
          <label class="code-option"><input id="codeExternal" type="checkbox" ${this.external ? 'checked' : ''}>
            Считать входом атакующего и аргументы командной строки, переменные окружения, stdin и файлы (для утилит и служб)</label>
          <label class="code-option"><input id="codeTests" type="checkbox" ${this.includeTests ? 'checked' : ''}>
            Проверять и тесты</label>
          <div class="vuln-note">Папка на машине, где работает движок. В Docker сначала смонтируйте проект в контейнер.</div>
          <div id="codeProgress"></div>
        </div>
        <div id="codeResultPanel" class="vuln-panel"></div>
      </div>
    `;
    container.querySelector('#codeScanBtn').addEventListener('click', () => this.startScan());
    container.querySelector('#codePath').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.startScan();
    });
    container.querySelector('#codeExternal').addEventListener('change', (e) => { this.external = e.target.checked; });
    container.querySelector('#codeTests').addEventListener('change', (e) => { this.includeTests = e.target.checked; });

    await this.refresh();
    if (this.status?.running) this.startPolling();
  }

  async refresh() {
    try {
      this.status = await this.ipc.call('code.status', {});
      this.error = null;
    } catch (e) {
      this.error = `Не удалось получить состояние анализа: ${e.message}`;
    }
    if (!this.path && this.status?.path) this.path = this.status.path;
    this.renderProgress();
    this.renderResult();
  }

  async startScan() {
    const input = this.container?.querySelector('#codePath');
    const path = (input?.value ?? this.path).trim();
    this.path = path;
    if (!path) {
      this.error = 'Укажите папку с исходным кодом';
      this.renderProgress();
      return;
    }
    savePath(path);
    // A second click while the request is on its way would be refused.
    const btn = this.container?.querySelector('#codeScanBtn');
    if (btn) btn.disabled = true;
    try {
      this.status = await this.ipc.call('code.scan', {
        path,
        external_sources: this.external,
        include_tests: this.includeTests
      });
      this.error = null;
      this.severity = 'all';
      this.rule = 'all';
      this.query = '';
      this.limit = PAGE_SIZE;
    } catch (e) {
      this.error = e.message;
      this.renderProgress();
      return;
    }
    this.renderProgress();
    this.renderResult();
    this.startPolling();
  }

  startPolling() {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(async () => {
      if (!this.container?.isConnected) {
        this.stopPolling();
        return;
      }
      await this.refresh();
      if (!this.status?.running) this.stopPolling();
    }, 1000);
  }

  stopPolling() {
    clearInterval(this.pollTimer);
    this.pollTimer = null;
  }

  renderProgress() {
    const panel = this.container?.querySelector('#codeProgress');
    if (!panel) return;
    const s = this.status;
    const btn = this.container.querySelector('#codeScanBtn');
    if (btn) {
      btn.disabled = !!s?.running;
      btn.textContent = s?.running ? 'Анализ...' : 'Проверить';
    }
    let html = '';
    if (s?.running) {
      const since = s.started_at ? Math.max(0, Math.round((Date.now() - new Date(s.started_at).getTime()) / 1000)) : 0;
      html += `<div class="vuln-progress" id="codeRunning"><span class="vuln-spinner"></span> Анализ ${escapeHtml(s.path)}: ${escapeHtml(String(since))} с</div>`;
    }
    if (this.error) html += `<div class="vuln-error" id="codeError">${escapeHtml(this.error)}</div>`;
    else if (s?.error && !s.running) html += `<div class="vuln-error" id="codeError">${escapeHtml(s.error)}</div>`;
    panel.innerHTML = html;
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
      return [f.file, f.rule, f.title, f.message, f.snippet, `cwe-${f.cwe}`, f.source?.file]
        .some(t => String(t ?? '').toLowerCase().includes(q));
    });
  }

  renderResult() {
    const panel = this.container?.querySelector('#codeResultPanel');
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
        ${all.length ? `Найдено уязвимостей: ${escapeHtml(String(all.length))}` : 'Путей от входа пользователя до опасных вызовов не найдено'}
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
          <div class="vuln-mono">${parseErrors.slice(0, 100).map(p => escapeHtml(p)).join('<br>')}</div>
        </details>` : ''}
      ${skipped.length ? `
        <details class="code-issues" id="codeSkipped">
          <summary>Пропущенные файлы: ${escapeHtml(String(skipped.length))}</summary>
          <div class="vuln-mono">${skipped.slice(0, 100).map(([p, why]) => `${escapeHtml(p)}: ${escapeHtml(why)}`).join('<br>')}</div>
        </details>` : ''}
      ${all.length ? `
        <div class="vuln-toolbar">
          ${sevBtn('all', 'Все', all.length)}
          ${SEVERITIES.filter(sev => count(sev)).map(sev => sevBtn(sev, SEVERITY_LABELS[sev], count(sev))).join('')}
          <select id="codeRule" class="code-rule">
            <option value="all">Все виды (${escapeHtml(String(all.length))})</option>
            ${rules.map(r => `<option value="${escapeAttr(r.rule)}" ${this.rule === r.rule ? 'selected' : ''}>${escapeHtml(r.title)} (${escapeHtml(String(r.n))})</option>`).join('')}
          </select>
          <input id="codeSearch" type="text" placeholder="Файл, CWE или код..." value="${escapeAttr(this.query)}">
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
      this.renderResult();
    }));
    panel.querySelector('#codeRule')?.addEventListener('change', (e) => {
      this.rule = e.target.value;
      this.limit = PAGE_SIZE;
      this.renderResult();
    });
    const search = panel.querySelector('#codeSearch');
    search?.addEventListener('input', (e) => {
      this.query = e.target.value.toLowerCase().trim();
      this.limit = PAGE_SIZE;
      const pos = e.target.selectionStart;
      this.renderResult();
      const again = this.container.querySelector('#codeSearch');
      again?.focus();
      again?.setSelectionRange(pos, pos);
    });
    panel.querySelector('#codeMoreBtn')?.addEventListener('click', () => {
      this.limit += PAGE_SIZE;
      this.renderResult();
    });
    panel.querySelectorAll('tr.vuln-row').forEach(tr => tr.addEventListener('click', () => {
      const detail = tr.nextElementSibling;
      if (detail?.classList.contains('vuln-detail')) detail.hidden = !detail.hidden;
    }));
  }

  findingRow(f, i) {
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
}

import { escapeAttr, escapeHtml } from '../util/html.js';
import { CodeReportView, PAGE_SIZE } from './report-view.js';

const PATH_KEY = 'soc.code.path';

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
 * (Python, Java, PHP, C/C++, JavaScript/TypeScript) and lists the flaws where user input reaches a
 * dangerous call, each with the path the data took from source to sink.
 * The report itself is rendered by the shared {@link CodeReportView}; this
 * space owns the folder form, the progress line and the database reload.
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
    this.pollTimer = null;
    this.depsTimer = null;
    this.view = new CodeReportView({
      onLoadDepsDb: (ecosystems) => this.loadDepsDb(ecosystems),
      exportTitle: 'Анализ кода',
      exportKind: 'code',
    });
  }

  // The report filters and database-load state live on the shared view; these
  // accessors keep the space's older field names working (and the regression
  // tests that set them directly).
  get query() { return this.view.query; }
  set query(v) { this.view.query = v; }
  get severity() { return this.view.severity; }
  set severity(v) { this.view.severity = v; }
  get rule() { return this.view.rule; }
  set rule(v) { this.view.rule = v; }
  get limit() { return this.view.limit; }
  set limit(v) { this.view.limit = v; }
  get depsUpdating() { return this.view.depsUpdating; }
  set depsUpdating(v) { this.view.depsUpdating = v; }
  get depsCurrent() { return this.view.depsCurrent; }
  set depsCurrent(v) { this.view.depsCurrent = v; }
  get depsError() { return this.view.depsError; }
  set depsError(v) { this.view.depsError = v; }

  async render(container) {
    this.container = container;
    container.innerHTML = `
      <div class="vuln-space code-space">
        <div class="vuln-header">
          <div>
            <h2>⌨ АНАЛИЗ КОДА</h2>
            <div class="vuln-subtitle">Уязвимости в исходном коде на Python, Java, PHP, C/C++ и JavaScript/TypeScript: путь данных от входа (HTTP-запрос, сокет, CGI) до опасного вызова (SQL, команды ОС, файлы, шаблоны, XSS, LDAP, XML, SSRF, перенаправления), а также слабая криптография, секреты в коде, отключённая проверка TLS и библиотеки с известными уязвимостями (CVE) или вредоносные пакеты из requirements.txt, package.json, pom.xml, composer.json и других файлов зависимостей</div>
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
      this.view.resetFilters();
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

  renderResult() {
    const panel = this.container?.querySelector('#codeResultPanel');
    if (!panel) return;
    this.view.render(panel, this.status);
  }

  renderDeps() {
    this.view.renderDeps();
  }

  packagesTable(dc) {
    return this.view.packagesTable(dc);
  }

  /** Loads the OSV data of `ecosystems`, then checks the packages again. */
  async loadDepsDb(ecosystems) {
    if (this.depsUpdating || !ecosystems.length) return;
    this.depsError = null;
    try {
      await this.ipc.call('vulndb.update', { ecosystems });
    } catch (e) {
      this.depsError = `Не удалось начать загрузку: ${e.message}`;
      this.renderDeps();
      return;
    }
    this.depsUpdating = true;
    this.depsCurrent = 'Подготовка';
    this.renderDeps();
    this.depsTimer = setInterval(async () => {
      let st;
      try {
        st = await this.ipc.call('vulndb.status', {});
      } catch {
        return; // the next tick asks again
      }
      const update = st?.update || {};
      if (update.running) {
        this.depsCurrent = update.current || '';
        if (this.container?.isConnected) this.renderDeps();
        return;
      }
      clearInterval(this.depsTimer);
      this.depsTimer = null;
      const failed = (update.steps || [])
        .filter(step => !step.ok && ecosystems.some(e => step.feed === `osv:${e}`))
        .map(step => step.message);
      try {
        this.status = await this.ipc.call('code.deps', {});
        this.error = null;
      } catch (e) {
        failed.push(e.message);
      }
      this.depsUpdating = false;
      this.depsError = failed.length ? failed.join('; ') : null;
      if (this.container?.isConnected) this.renderResult();
    }, 1000);
  }
}

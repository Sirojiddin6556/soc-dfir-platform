import { escapeAttr, escapeHtml } from '../util/html.js';

const SEVERITY_LABELS = {
  critical: 'КРИТИЧЕСКИЙ',
  high: 'ВЫСОКИЙ',
  medium: 'СРЕДНИЙ',
  low: 'НИЗКИЙ'
};
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const URL_KEY = 'soc.web.url';

function savedUrl() {
  try {
    return globalThis.localStorage?.getItem(URL_KEY) || '';
  } catch {
    return '';
  }
}

function saveUrl(url) {
  try {
    globalThis.localStorage?.setItem(URL_KEY, url);
  } catch {
    // Private windows and blocked storage only lose the convenience.
  }
}

/**
 * Running-site space: a dynamic scan (DAST) of a web application the operator
 * runs. It points the engine's web-scan at a URL, which crawls the site and
 * tests inputs live for reflected XSS, SQL injection, path traversal, open
 * redirects and weak response headers. Everything shown comes from the scanned
 * site and is treated as untrusted: every value is escaped before the page.
 */
export class WebSpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.container = null;
    this.status = null;
    this.error = null;
    this.url = savedUrl();
    this.active = true;
    this.submitForms = true;
    this.useLogin = false;
    this.severity = 'all';
    this.pollTimer = null;
  }

  async render(container) {
    this.container = container;
    container.innerHTML = `
      <div class="vuln-space web-space">
        <div class="vuln-header">
          <div>
            <h2>🌐 ЗАПУЩЕННЫЙ САЙТ</h2>
            <div class="vuln-subtitle">Динамическая проверка работающего веб-приложения: обход страниц и форм и проверка ввода вживую на отражённый XSS, SQL-инъекции, обход каталога и открытые перенаправления, а также заголовки безопасности, флаги cookie и раскрытие версий ПО. Каждая находка с запросом, который её вызвал. Указывайте только тот сайт, который вам разрешено проверять.</div>
          </div>
        </div>
        <div class="vuln-panel">
          <div class="vuln-panel-title">САЙТ</div>
          <div class="code-form">
            <input id="webUrl" type="text" spellcheck="false" placeholder="http://127.0.0.1:8000/" value="${escapeAttr(this.url)}">
            <button id="webScanBtn" class="primary-action">Проверить</button>
          </div>
          <label class="code-option"><input id="webActive" type="checkbox" ${this.active ? 'checked' : ''}>
            Активные проверки (отправлять тестовые запросы). Без них — только обход и проверка заголовков</label>
          <label class="code-option"><input id="webForms" type="checkbox" ${this.submitForms ? 'checked' : ''}>
            Отправлять формы (может изменить данные приложения)</label>
          <label class="code-option"><input id="webUseLogin" type="checkbox" ${this.useLogin ? 'checked' : ''}>
            Сначала войти по форме</label>
          <div id="webLoginFields" class="web-login" style="display:${this.useLogin ? 'grid' : 'none'}">
            <input id="webLoginUrl" type="text" spellcheck="false" placeholder="адрес формы входа, напр. /login">
            <input id="webLoginUser" type="text" spellcheck="false" placeholder="логин">
            <input id="webLoginPass" type="password" placeholder="пароль">
            <input id="webLoginUserField" type="text" spellcheck="false" placeholder="имя поля логина (username)">
            <input id="webLoginPassField" type="text" spellcheck="false" placeholder="имя поля пароля (password)">
            <input id="webLoginSuccess" type="text" spellcheck="false" placeholder="текст на странице после входа (необязательно)">
          </div>
          <div class="vuln-note">Проверка идёт с машины, где работает движок, и только в пределах указанного адреса.</div>
          <div id="webProgress"></div>
        </div>
        <div id="webResultPanel" class="vuln-panel"></div>
      </div>
    `;
    container.querySelector('#webScanBtn').addEventListener('click', () => this.startScan());
    container.querySelector('#webUrl').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.startScan();
    });
    container.querySelector('#webActive').addEventListener('change', (e) => { this.active = e.target.checked; });
    container.querySelector('#webForms').addEventListener('change', (e) => { this.submitForms = e.target.checked; });
    container.querySelector('#webUseLogin').addEventListener('change', (e) => {
      this.useLogin = e.target.checked;
      const fields = this.container.querySelector('#webLoginFields');
      if (fields) fields.style.display = this.useLogin ? 'grid' : 'none';
    });

    await this.refresh();
    if (this.status?.running) this.startPolling();
  }

  async refresh() {
    try {
      this.status = await this.ipc.call('web.status', {});
      this.error = null;
    } catch (e) {
      this.error = `Не удалось получить состояние проверки: ${e.message}`;
    }
    if (!this.url && this.status?.target) this.url = this.status.target;
    this.renderProgress();
    this.renderResult();
  }

  login() {
    if (!this.useLogin) return null;
    const val = (id) => this.container?.querySelector(id)?.value?.trim() || '';
    const url = val('#webLoginUrl');
    if (!url) return null;
    return {
      url,
      username: val('#webLoginUser'),
      password: val('#webLoginPass'),
      user_field: val('#webLoginUserField') || 'username',
      pass_field: val('#webLoginPassField') || 'password',
      success_text: val('#webLoginSuccess')
    };
  }

  async startScan() {
    const input = this.container?.querySelector('#webUrl');
    const url = (input?.value ?? this.url).trim();
    this.url = url;
    if (!url) {
      this.error = 'Укажите адрес сайта';
      this.renderProgress();
      return;
    }
    saveUrl(url);
    const btn = this.container?.querySelector('#webScanBtn');
    if (btn) btn.disabled = true;
    try {
      this.status = await this.ipc.call('web.scan', {
        url,
        active: this.active,
        submit_forms: this.submitForms,
        login: this.login()
      });
      this.error = null;
      this.severity = 'all';
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
    const panel = this.container?.querySelector('#webProgress');
    if (!panel) return;
    const s = this.status;
    const btn = this.container.querySelector('#webScanBtn');
    if (btn) {
      btn.disabled = !!s?.running;
      btn.textContent = s?.running ? 'Проверка...' : 'Проверить';
    }
    let html = '';
    if (s?.running) {
      const since = s.started_at ? Math.max(0, Math.round((Date.now() - new Date(s.started_at).getTime()) / 1000)) : 0;
      html += `<div class="vuln-progress" id="webRunning"><span class="vuln-spinner"></span> Проверка ${escapeHtml(s.target || '')}: ${escapeHtml(String(since))} с</div>`;
    }
    if (this.error) html += `<div class="vuln-error" id="webError">${escapeHtml(this.error)}</div>`;
    else if (s?.error && !s.running) html += `<div class="vuln-error" id="webError">${escapeHtml(s.error)}</div>`;
    panel.innerHTML = html;
  }

  findings() {
    return this.status?.report?.findings || [];
  }

  renderResult() {
    const panel = this.container?.querySelector('#webResultPanel');
    if (!panel) return;
    const s = this.status;
    const report = s?.report;
    if (!report) {
      panel.innerHTML = `
        <div class="vuln-panel-title">РЕЗУЛЬТАТ</div>
        <div class="vuln-note" id="webEmpty">${s?.running ? 'Проверка выполняется...' : 'Проверка ещё не запускалась.'}</div>`;
      return;
    }

    const all = this.findings();
    const count = (sev) => all.filter((f) => f.severity === sev).length;
    const shown = this.severity === 'all' ? all : all.filter((f) => f.severity === this.severity);

    const filter = [['all', 'Все'], ...SEVERITIES.map((s) => [s, SEVERITY_LABELS[s]])]
      .map(([key, label]) => {
        const n = key === 'all' ? all.length : count(key);
        const on = this.severity === key ? 'ctf-btn-primary' : 'ctf-btn-secondary';
        return `<button class="web-sev-filter ctf-btn ${on}" data-sev="${escapeAttr(key)}">${escapeHtml(label)} (${escapeHtml(String(n))})</button>`;
      })
      .join('');
    const auth = report.authenticated ? 'со входом' : 'без входа';
    const notes = (report.notes || []).map((n) => `<li>${escapeHtml(n)}</li>`).join('');

    panel.innerHTML = `
      <div class="vuln-panel-title">РЕЗУЛЬТАТ</div>
      <div class="vuln-chips" id="webSummary">
        <div class="vuln-chip"><span>${escapeHtml(String(all.length))}</span>всего</div>
        <div class="vuln-chip vuln-sev-critical"><span>${escapeHtml(String(count('critical')))}</span>критических</div>
        <div class="vuln-chip vuln-sev-high"><span>${escapeHtml(String(count('high')))}</span>высоких</div>
        <div class="vuln-chip vuln-sev-medium"><span>${escapeHtml(String(count('medium')))}</span>средних</div>
        <div class="vuln-chip vuln-sev-low"><span>${escapeHtml(String(count('low')))}</span>низких</div>
      </div>
      <div class="vuln-host" id="webScanSummary">
        Страниц: ${escapeHtml(String(report.pages_crawled))}, форм: ${escapeHtml(String(report.forms_found))}, запросов: ${escapeHtml(String(report.requests_made))} (${escapeHtml(auth)}).
      </div>
      ${notes ? `<ul class="web-notes" id="webNotesList">${notes}</ul>` : ''}
      <div class="vuln-toolbar" id="webSevFilter">${filter}</div>
      <div class="web-findings" id="webFindings">
        ${shown.length ? shown.map((f) => this.findingCard(f)).join('') : '<div class="vuln-note">Находок этого уровня нет.</div>'}
      </div>
    `;

    panel.querySelectorAll('#webSevFilter .web-sev-filter').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.severity = btn.dataset.sev;
        this.renderResult();
      });
    });
  }

  findingCard(f) {
    const sev = SEVERITY_LABELS[f.severity] || f.severity;
    const param = f.param ? ` · параметр <code>${escapeHtml(f.param)}</code>` : '';
    return `
      <div class="web-finding">
        <div class="web-finding-head">
          <span class="vuln-badge vuln-sev-${escapeAttr(f.severity)}">${escapeHtml(sev)}</span>
          <span class="web-finding-title">${escapeHtml(f.title)}</span>
          <span class="web-finding-cwe">CWE-${escapeHtml(String(f.cwe))}</span>
        </div>
        <div class="web-finding-loc"><code>${escapeHtml(f.method)} ${escapeHtml(f.url)}</code>${param}</div>
        <div class="web-finding-msg">${escapeHtml(f.message)}</div>
        <div class="web-finding-evidence">${escapeHtml(f.evidence)}</div>
        <details class="web-finding-repro">
          <summary>Как повторить</summary>
          <pre>${escapeHtml(f.request)}</pre>
        </details>
      </div>
    `;
  }
}

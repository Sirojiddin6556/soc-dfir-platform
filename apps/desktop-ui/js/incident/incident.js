import { escapeAttr, escapeHtml } from '../util/html.js';

const PATH_KEY = 'incident.lastPath';

function savedPath() {
  try {
    return localStorage.getItem(PATH_KEY) || '';
  } catch {
    return '';
  }
}
function savePath(p) {
  try {
    localStorage.setItem(PATH_KEY, p);
  } catch {
    /* ignore: storage may be unavailable */
  }
}

/** Human labels and CSS classes for each log source. */
const SOURCE = {
  web_access: { label: 'Веб-доступ', cls: 'inc-src-web' },
  web_error: { label: 'Веб-ошибки', cls: 'inc-src-weberr' },
  auth: { label: 'Аутентификация', cls: 'inc-src-auth' },
  syslog: { label: 'Syslog', cls: 'inc-src-syslog' },
};
function sourceLabel(s) {
  return SOURCE[s]?.label || s;
}

/** Human-readable byte size. */
function fmtBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return `${b} Б`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} КБ`;
  return `${(b / (1024 * 1024)).toFixed(1)} МБ`;
}

/** Most events a single render will draw, so a huge timeline stays responsive. */
const MAX_ROWS = 2000;

/**
 * DFIR «Расследование инцидента», stage 1: point the engine at a folder of
 * logs and read back one unified UTC timeline. Each row carries its exact
 * source line as evidence.
 */
export class IncidentSpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.container = null;
    this.status = null;
    this.error = null;
    this.path = savedPath();
    this.year = '';
    this.sourceFilter = '';
    this.query = '';
    this.pollTimer = null;
    // Events the analyst marked as evidence, keyed by a stable event key.
    this.evidence = new Map();
    // Lookup from event key to the event, rebuilt on each result render.
    this.eventsByKey = new Map();
  }

  /** A stable key for an event: its origin plus time. */
  evKey(e) {
    return `${e.source_file || ''}|${e.line_no || ''}|${e.timestamp || ''}`;
  }

  evStoreKey() {
    return `incident.evidence:${this.path || ''}`;
  }

  loadEvidence() {
    this.evidence = new Map();
    try {
      const raw = localStorage.getItem(this.evStoreKey());
      if (raw) for (const item of JSON.parse(raw)) this.evidence.set(item.key, item);
    } catch {
      /* ignore: storage may be unavailable or corrupt */
    }
  }

  saveEvidence() {
    try {
      localStorage.setItem(this.evStoreKey(), JSON.stringify([...this.evidence.values()]));
    } catch {
      /* ignore: storage may be unavailable */
    }
  }

  toggleEvidence(key) {
    if (this.evidence.has(key)) {
      this.evidence.delete(key);
    } else {
      const e = this.eventsByKey.get(key);
      if (!e) return;
      this.evidence.set(key, {
        key,
        timestamp: e.timestamp,
        source: e.source,
        source_file: e.source_file,
        line_no: e.line_no,
        summary: e.summary,
      });
    }
    this.saveEvidence();
    this.renderResult();
  }

  async render(container) {
    this.container = container;
    container.innerHTML = `
      <div class="vuln-space incident-space">
        <div class="vuln-header">
          <div>
            <h2>🔎 РАССЛЕДОВАНИЕ ИНЦИДЕНТА</h2>
            <div class="vuln-subtitle">Единая временная шкала по журналам хоста и веб-сервера (nginx/apache access и error, auth.log/secure, syslog/journald), включая ротированные <code>.1</code> и сжатые <code>.gz</code>. Все метки времени приводятся к UTC, каждое событие сопровождается точной строкой журнала как доказательством. Данные не изменяются — журналы только читаются.</div>
          </div>
        </div>
        <div class="vuln-panel">
          <div class="vuln-panel-title">ЖУРНАЛЫ</div>
          <div class="code-form">
            <input id="incPath" type="text" spellcheck="false" placeholder="/var/log или /var/log/auth.log" value="${escapeAttr(this.path)}">
            <button id="incScanBtn" class="primary-action">Построить шкалу</button>
          </div>
          <label class="code-option">Год для строк syslog без года (например, 2026), если дата файла не подходит:
            <input id="incYear" type="text" spellcheck="false" inputmode="numeric" style="width:6em" value="${escapeAttr(this.year)}"></label>
          <div class="vuln-note">Папка или файл на машине, где работает движок. В Docker сначала смонтируйте журналы в контейнер.</div>
          <div id="incProgress"></div>
        </div>
        <div id="incResultPanel" class="vuln-panel"></div>
      </div>
    `;
    container.querySelector('#incScanBtn').addEventListener('click', () => this.startScan());
    container.querySelector('#incPath').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.startScan();
    });
    container.querySelector('#incYear').addEventListener('input', (e) => {
      this.year = e.target.value.replace(/[^0-9]/g, '').slice(0, 4);
    });

    await this.refresh();
    if (this.status?.running) this.startPolling();
  }

  async refresh() {
    try {
      this.status = await this.ipc.call('incident.status', {});
      this.error = null;
    } catch (e) {
      this.error = `Не удалось получить состояние: ${e.message}`;
    }
    if (!this.path && this.status?.path) this.path = this.status.path;
    this.renderProgress();
    this.renderResult();
  }

  async startScan() {
    const input = this.container?.querySelector('#incPath');
    const path = (input?.value ?? this.path).trim();
    this.path = path;
    if (!path) {
      this.error = 'Укажите папку или файл с логами';
      this.renderProgress();
      return;
    }
    savePath(path);
    const params = { path };
    const year = parseInt(this.year, 10);
    if (Number.isInteger(year) && year >= 1970 && year <= 9999) params.assume_year = year;

    const btn = this.container?.querySelector('#incScanBtn');
    if (btn) btn.disabled = true;
    try {
      this.status = await this.ipc.call('incident.scan', params);
      this.error = null;
      this.sourceFilter = '';
      this.query = '';
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
    const panel = this.container?.querySelector('#incProgress');
    if (!panel) return;
    const s = this.status;
    const btn = this.container.querySelector('#incScanBtn');
    if (btn) {
      btn.disabled = !!s?.running;
      btn.textContent = s?.running ? 'Обработка...' : 'Построить шкалу';
    }
    let html = '';
    if (s?.running) {
      const since = s.started_at
        ? Math.max(0, Math.round((Date.now() - new Date(s.started_at).getTime()) / 1000))
        : 0;
      html += `<div class="vuln-progress" id="incRunning"><span class="vuln-spinner"></span> Разбор журналов ${escapeHtml(s.path || '')}: ${escapeHtml(String(since))} с</div>`;
    }
    if (this.error) html += `<div class="vuln-error" id="incError">${escapeHtml(this.error)}</div>`;
    else if (s?.error && !s.running) html += `<div class="vuln-error" id="incError">${escapeHtml(s.error)}</div>`;
    panel.innerHTML = html;
  }

  renderResult() {
    const panel = this.container?.querySelector('#incResultPanel');
    if (!panel) return;
    const report = this.status?.report;
    if (!report || this.status?.running) {
      panel.innerHTML = '';
      return;
    }
    const events = Array.isArray(report.events) ? report.events : [];
    const summary = report.summary || {};
    const bySource = summary.by_source || {};

    // Rebuild the key→event lookup and load any evidence saved for this path.
    this.eventsByKey = new Map();
    for (const e of events) this.eventsByKey.set(this.evKey(e), e);
    this.loadEvidence();

    let html = '';
    html += '<div class="vuln-panel-title">ВРЕМЕННАЯ ШКАЛА (UTC)</div>';

    // Summary row.
    html += '<div class="inc-summary">';
    html += `<span class="inc-stat"><b>${escapeHtml(String(summary.total_events ?? events.length))}</b> событий</span>`;
    html += `<span class="inc-stat"><b>${escapeHtml(String(summary.files ?? (report.files?.length || 0)))}</b> файлов</span>`;
    if (report.first_event && report.last_event) {
      html += `<span class="inc-stat">${escapeHtml(report.first_event)} — ${escapeHtml(report.last_event)}</span>`;
    }
    html += '</div>';

    // Per-file breakdown, with the SHA-256 (chain of custody).
    if (Array.isArray(report.files) && report.files.length) {
      html += '<details class="inc-files"><summary>Файлы и их SHA-256 (' + report.files.length + ')</summary>';
      for (const f of report.files) {
        html += `<div class="inc-file"><span class="inc-badge ${SOURCE[f.source]?.cls || ''}">${escapeHtml(sourceLabel(f.source))}</span> `;
        html += `<code>${escapeHtml(f.path)}</code>${f.compressed ? ' <span class="inc-gz">gz</span>' : ''} — `;
        html += `${escapeHtml(String(f.parsed))}/${escapeHtml(String(f.lines))} строк, ${escapeHtml(fmtBytes(f.bytes))}`;
        if (f.sha256) html += `<div class="inc-hash">SHA-256: <code>${escapeHtml(f.sha256)}</code></div>`;
        html += '</div>';
      }
      html += '</details>';
    }

    // Evidence the analyst marked (chain-of-custody working set).
    html += this.evidencePanelHtml();

    // Warnings.
    if (Array.isArray(report.warnings) && report.warnings.length) {
      html += `<details class="inc-warnings"><summary>Предупреждения (${report.warnings.length})</summary><ul>`;
      for (const w of report.warnings) html += `<li>${escapeHtml(w)}</li>`;
      html += '</ul></details>';
    }

    // Filters.
    html += '<div class="inc-filters">';
    html += '<select id="incSourceFilter"><option value="">Все источники</option>';
    for (const src of Object.keys(bySource)) {
      const sel = this.sourceFilter === src ? ' selected' : '';
      html += `<option value="${escapeAttr(src)}"${sel}>${escapeHtml(sourceLabel(src))} (${escapeHtml(String(bySource[src]))})</option>`;
    }
    html += '</select>';
    html += `<input id="incQuery" type="text" spellcheck="false" placeholder="Фильтр по тексту (IP, пользователь, путь...)" value="${escapeAttr(this.query)}">`;
    html += '</div>';

    // Filtered timeline.
    const filtered = this.filterEvents(events);
    const shown = filtered.slice(0, MAX_ROWS);
    if (filtered.length > MAX_ROWS) {
      html += `<div class="vuln-note">Показаны первые ${MAX_ROWS} из ${filtered.length} событий. Сузьте фильтр.</div>`;
    }

    html += '<div class="inc-timeline">';
    if (!shown.length) {
      html += '<div class="vuln-note">Нет событий по текущему фильтру.</div>';
    }
    for (const e of shown) {
      html += this.rowHtml(e);
    }
    html += '</div>';

    panel.innerHTML = html;

    const srcSel = panel.querySelector('#incSourceFilter');
    if (srcSel) srcSel.addEventListener('change', (ev) => {
      this.sourceFilter = ev.target.value;
      this.renderResult();
    });
    const q = panel.querySelector('#incQuery');
    if (q) q.addEventListener('input', (ev) => {
      this.query = ev.target.value;
      this.renderTimelineOnly();
    });
    // Evidence: mark a row (★) or remove from the evidence panel (✕).
    panel.addEventListener('click', (ev) => {
      const btn = ev.target.closest('.inc-star, .inc-ev-del');
      if (!btn) return;
      const key = btn.dataset.evkey;
      if (key) this.toggleEvidence(key);
    });
  }

  /** Re-render only the timeline rows (keeps focus in the text filter). */
  renderTimelineOnly() {
    const tl = this.container?.querySelector('.inc-timeline');
    if (!tl) return;
    const events = Array.isArray(this.status?.report?.events) ? this.status.report.events : [];
    const filtered = this.filterEvents(events);
    const shown = filtered.slice(0, MAX_ROWS);
    let html = '';
    if (!shown.length) html += '<div class="vuln-note">Нет событий по текущему фильтру.</div>';
    for (const e of shown) html += this.rowHtml(e);
    tl.innerHTML = html;
  }

  filterEvents(events) {
    const q = this.query.trim().toLowerCase();
    return events.filter((e) => {
      if (this.sourceFilter && e.source !== this.sourceFilter) return false;
      if (!q) return true;
      if ((e.summary || '').toLowerCase().includes(q)) return true;
      if ((e.actor || '').toLowerCase().includes(q)) return true;
      if ((e.host || '').toLowerCase().includes(q)) return true;
      if ((e.raw || '').toLowerCase().includes(q)) return true;
      return false;
    });
  }

  rowHtml(e) {
    const src = SOURCE[e.source] || {};
    const outcomeCls =
      e.outcome === 'failure' ? 'inc-fail' : e.outcome === 'success' ? 'inc-ok' : '';
    const key = this.evKey(e);
    const marked = this.evidence.has(key);
    let html = `<div class="inc-row ${outcomeCls}${marked ? ' inc-marked' : ''}">`;
    html += `<div class="inc-time">${escapeHtml(e.timestamp || '')}</div>`;
    html += '<div class="inc-meta">';
    html += `<button class="inc-star" data-evkey="${escapeAttr(key)}" title="Отметить как улику" aria-pressed="${marked}">${marked ? '★' : '☆'}</button>`;
    html += `<span class="inc-badge ${src.cls || ''}">${escapeHtml(sourceLabel(e.source))}</span>`;
    if (e.host) html += ` <span class="inc-host">${escapeHtml(e.host)}</span>`;
    if (e.actor) html += ` <span class="inc-actor">${escapeHtml(e.actor)}</span>`;
    html += '</div>';
    html += `<div class="inc-summary-text">${escapeHtml(e.summary || '')}</div>`;
    const loc = `${e.source_file || ''}:${e.line_no || ''}`;
    html += `<div class="inc-raw"><span class="inc-loc">${escapeHtml(loc)}</span><code>${escapeHtml(e.raw || '')}</code></div>`;
    html += '</div>';
    return html;
  }

  evidencePanelHtml() {
    const items = [...this.evidence.values()].sort((a, b) =>
      String(a.timestamp).localeCompare(String(b.timestamp))
    );
    if (!items.length) {
      return '<div class="inc-evidence inc-evidence-empty">Улики не отмечены. Нажмите ☆ у события, чтобы добавить его в улики.</div>';
    }
    let html = `<details class="inc-evidence" open><summary>Улики (${items.length})</summary>`;
    for (const it of items) {
      html += '<div class="inc-ev-row">';
      html += `<button class="inc-ev-del" data-evkey="${escapeAttr(it.key)}" title="Убрать из улик">✕</button>`;
      html += `<span class="inc-time">${escapeHtml(it.timestamp || '')}</span> `;
      html += `<span class="inc-badge ${SOURCE[it.source]?.cls || ''}">${escapeHtml(sourceLabel(it.source))}</span> `;
      html += `<span class="inc-summary-text">${escapeHtml(it.summary || '')}</span> `;
      html += `<span class="inc-loc">${escapeHtml(`${it.source_file || ''}:${it.line_no || ''}`)}</span>`;
      html += '</div>';
    }
    html += '</details>';
    return html;
  }
}

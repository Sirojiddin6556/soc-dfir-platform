import { escapeAttr, escapeHtml } from '../util/html.js';

const SEVERITY_LABELS = {
  critical: 'КРИТИЧЕСКИЙ',
  high: 'ВЫСОКИЙ',
  medium: 'СРЕДНИЙ',
  low: 'НИЗКИЙ',
  none: 'НЕТ',
  unknown: 'НЕ ОЦЕНЁН'
};

const FEED_TITLES = {
  osv: 'OSV',
  msrc: 'Microsoft MSRC',
  kev: 'CISA KEV',
  epss: 'FIRST EPSS'
};

const PAGE_SIZE = 200;

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString('ru-RU');
}

function formatEpss(f) {
  if (f.epss === null || f.epss === undefined) return '—';
  return `${(f.epss * 100).toFixed(2)}%`;
}

/**
 * Vulnerability space: keeps the local vulnerability database up to date
 * (OSV distribution advisories, Microsoft MSRC security updates, CISA KEV,
 * FIRST EPSS) and lists the CVEs that affect the machine the engine runs on:
 * its installed packages on Linux, its OS build and updates on Windows.
 */
export class VulnerabilitySpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.container = null;
    this.status = null;
    this.scan = null;
    this.error = null;
    this.filter = null; // 'fix' | 'nofix' | 'all'; chosen after the first scan
    this.query = '';
    this.limit = PAGE_SIZE;
    this.pollTimer = null;
    this.scanning = false;
  }

  async render(container) {
    this.container = container;
    container.innerHTML = `
      <div class="vuln-space">
        <div class="vuln-header">
          <div>
            <h2>⛨ УЯЗВИМОСТИ СИСТЕМЫ</h2>
            <div class="vuln-subtitle">Известные CVE на этой машине: пакеты Linux по базам OSV (Debian, Ubuntu, AlmaLinux, Rocky Linux), сборка и обновления Windows по бюллетеням безопасности Microsoft (MSRC); CISA KEV и FIRST EPSS</div>
          </div>
          <div class="vuln-actions">
            <button id="vulnUpdateBtn" class="ctf-btn ctf-btn-secondary">⟳ Обновить базу</button>
            <button id="vulnScanBtn" class="primary-action">Проверить</button>
          </div>
        </div>
        <div id="vulnDbPanel" class="vuln-panel"></div>
        <div id="vulnResultPanel" class="vuln-panel"></div>
      </div>
    `;
    container.querySelector('#vulnUpdateBtn').addEventListener('click', () => this.startUpdate());
    container.querySelector('#vulnScanBtn').addEventListener('click', () => this.runScan());

    await this.refreshStatus();
    if (this.status?.update?.running) {
      this.startPolling();
    } else if (!this.scan && this.hostDatabaseLoaded()) {
      await this.runScan();
    } else {
      this.renderResult();
    }
  }

  isWindows() {
    return this.status?.host?.platform === 'windows';
  }

  scanLabel() {
    return this.isWindows() ? 'Проверить Windows' : 'Проверить пакеты';
  }

  hostDatabaseLoaded() {
    const host = this.status?.host;
    const feeds = this.status?.feeds || [];
    if (!host?.supported) return false;
    if (host.platform === 'windows') return feeds.some(f => f.kind === 'msrc');
    return !!host.ecosystem && feeds.some(f => f.kind === 'osv' && f.ecosystem === host.ecosystem);
  }

  async refreshStatus() {
    try {
      this.status = await this.ipc.call('vulndb.status', {});
      this.error = null;
    } catch (e) {
      this.error = `Не удалось получить состояние базы: ${e.message}`;
    }
    this.renderDb();
  }

  async startUpdate() {
    try {
      await this.ipc.call('vulndb.update', {});
      this.error = null;
    } catch (e) {
      this.error = e.message;
      this.renderDb();
      return;
    }
    await this.refreshStatus();
    this.startPolling();
  }

  startPolling() {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(async () => {
      if (!this.container?.isConnected) {
        this.stopPolling();
        return;
      }
      await this.refreshStatus();
      if (!this.status?.update?.running) {
        this.stopPolling();
        if (this.hostDatabaseLoaded()) await this.runScan();
      }
    }, 1000);
  }

  stopPolling() {
    clearInterval(this.pollTimer);
    this.pollTimer = null;
  }

  async runScan() {
    if (this.scanning) return;
    this.scanning = true;
    const btn = this.container?.querySelector('#vulnScanBtn');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Проверка...';
    }
    try {
      this.scan = await this.ipc.call('scan.cve', {});
      this.error = null;
      if (this.filter === null) {
        const hasFix = (this.scan.findings || []).some(f => f.status === 'fix_available');
        this.filter = hasFix ? 'fix' : 'all';
      }
      this.limit = PAGE_SIZE;
    } catch (e) {
      this.error = `Проверка не выполнена: ${e.message}`;
    } finally {
      this.scanning = false;
      if (btn) {
        btn.disabled = false;
        btn.textContent = this.scanLabel();
      }
    }
    this.renderResult();
  }

  renderDb() {
    const panel = this.container?.querySelector('#vulnDbPanel');
    if (!panel) return;
    const s = this.status;
    if (!s) {
      panel.innerHTML = `<div class="vuln-error">${escapeHtml(this.error || 'Загрузка...')}</div>`;
      return;
    }
    const host = s.host || {};
    const update = s.update || {};
    const feeds = s.feeds || [];
    const updateBtn = this.container.querySelector('#vulnUpdateBtn');
    if (updateBtn) updateBtn.disabled = !!update.running;
    const scanBtn = this.container.querySelector('#vulnScanBtn');
    if (scanBtn && !this.scanning) scanBtn.textContent = this.scanLabel();

    const feedRows = feeds.map(f => `
      <tr data-feed="${escapeAttr(f.name)}">
        <td>${escapeHtml(FEED_TITLES[f.kind] || f.kind)}${f.ecosystem ? ` <span class="vuln-mono">${escapeHtml(f.ecosystem)}</span>` : ''}</td>
        <td class="vuln-num">${escapeHtml(String(f.records))}</td>
        <td>${escapeHtml(f.version_date)}</td>
        <td>${escapeHtml(formatDate(f.checked_at))}${f.stale ? ' <span class="vuln-badge vuln-sev-high">УСТАРЕЛА</span>' : ''}</td>
        <td class="vuln-source">${escapeHtml(f.source || '—')}</td>
      </tr>`).join('');

    const steps = (update.steps || []).map(st => `
      <div class="vuln-step ${st.ok ? 'ok' : 'fail'}" data-feed="${escapeAttr(st.feed)}">
        ${st.ok ? '✓' : '✗'} <strong>${escapeHtml(st.feed)}</strong>: ${escapeHtml(st.message)}
      </div>`).join('');

    let hostLine;
    if (host.platform === 'windows' && host.supported) {
      hostLine = `Эта машина: <strong>${escapeHtml(host.os)}</strong>, сборка <span class="vuln-mono">${escapeHtml(host.build)}</span>, продукт в бюллетенях MSRC: <strong>${escapeHtml(host.product)}</strong>, установленных обновлений: <strong>${escapeHtml(String(host.installed_updates ?? 0))}</strong>`;
    } else if (host.platform === 'windows') {
      hostLine = `Эта машина: <strong>${escapeHtml(host.os || 'Windows')}</strong>. ${escapeHtml(host.detail || 'Версию Windows определить не удалось')}`;
    } else if (host.supported) {
      hostLine = `Эта машина: <strong>${escapeHtml(host.os)}</strong>, пакетов: <strong>${escapeHtml(String(host.packages))}</strong>, база: <span class="vuln-mono">${escapeHtml(host.ecosystem)}</span>`;
    } else {
      hostLine = `Эта машина: <strong>${escapeHtml(host.os || 'неизвестная ОС')}</strong>. Поиск CVE в пакетах работает для Debian, Ubuntu, AlmaLinux и Rocky Linux`;
    }
    const emptyNote = host.platform === 'windows'
      ? 'База пуста: нажмите «Обновить базу», чтобы скачать бюллетени безопасности Microsoft за последние 12 месяцев, CISA KEV и FIRST EPSS.'
      : 'База пуста: нажмите «Обновить базу», чтобы скачать данные OSV, CISA KEV и FIRST EPSS.';

    panel.innerHTML = `
      <div class="vuln-panel-title">БАЗА УЯЗВИМОСТЕЙ</div>
      <div class="vuln-host" id="vulnHostLine">${hostLine}</div>
      ${s.offline_dir ? `<div class="vuln-note">Офлайн-режим: файлы баз берутся из <span class="vuln-mono">${escapeHtml(s.offline_dir)}</span></div>` : ''}
      ${s.available ? '' : `<div class="vuln-error">${escapeHtml(s.error || 'База недоступна')}</div>`}
      ${feeds.length
        ? `<table class="vuln-table vuln-feeds" id="vulnDbFeeds">
            <thead><tr><th>Источник</th><th class="vuln-num">Записей</th><th>Версия данных</th><th>Проверено</th><th>Откуда</th></tr></thead>
            <tbody>${feedRows}</tbody>
          </table>`
        : `<div class="vuln-note" id="vulnDbEmpty">${escapeHtml(emptyNote)}</div>`}
      <div id="vulnUpdateProgress" class="vuln-progress" ${update.running ? '' : 'hidden'}>
        <span class="vuln-spinner"></span> ${escapeHtml(update.current || 'Обновление...')}
      </div>
      ${steps ? `<div id="vulnUpdateSteps" class="vuln-steps">${update.running ? '' : `<div class="vuln-note">Обновление завершено ${escapeHtml(formatDate(update.finished_at))}</div>`}${steps}</div>` : ''}
      ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
    `;
  }

  filteredFindings() {
    const all = this.scan?.findings || [];
    const q = this.query;
    return all.filter(f => {
      if (this.filter === 'fix' && f.status !== 'fix_available') return false;
      if (this.filter === 'nofix' && f.status !== 'no_fix') return false;
      if (!q) return true;
      return f.id.toLowerCase().includes(q)
        || f.component.toLowerCase().includes(q)
        || (f.packages || []).some(p => p.toLowerCase().includes(q))
        || (f.sources || []).some(src => src.toLowerCase().includes(q));
    });
  }

  renderResult() {
    const panel = this.container?.querySelector('#vulnResultPanel');
    if (!panel) return;
    const scan = this.scan;
    if (!scan) {
      panel.innerHTML = `
        <div class="vuln-panel-title">РЕЗУЛЬТАТ ПРОВЕРКИ</div>
        <div class="vuln-note">Проверка ещё не запускалась.</div>`;
      return;
    }

    const sm = scan.summary || {};
    const findings = scan.findings || [];
    const fixCount = findings.filter(f => f.status === 'fix_available').length;
    const statusClass = {
      VULNERABILITIES_FOUND: 'vuln-status-found',
      NO_KNOWN_MATCHED_VULNERABILITIES: 'vuln-status-clean'
    }[scan.status] || 'vuln-status-warn';

    const chips = scan.summary ? `
      <div class="vuln-chips" id="vulnSummary">
        <div class="vuln-chip"><span>${escapeHtml(String(sm.total))}</span>всего</div>
        <div class="vuln-chip vuln-sev-critical"><span>${escapeHtml(String(sm.critical))}</span>критических</div>
        <div class="vuln-chip vuln-sev-high"><span>${escapeHtml(String(sm.high))}</span>высоких</div>
        <div class="vuln-chip vuln-sev-medium"><span>${escapeHtml(String(sm.medium))}</span>средних</div>
        <div class="vuln-chip vuln-sev-low"><span>${escapeHtml(String(sm.low))}</span>низких</div>
        <div class="vuln-chip"><span>${escapeHtml(String(sm.unknown))}</span>без оценки</div>
        <div class="vuln-chip vuln-kev-chip"><span>${escapeHtml(String(sm.kev))}</span>в CISA KEV</div>
        ${sm.exploited !== undefined ? `<div class="vuln-chip vuln-exploited-chip" id="vulnExploited"><span>${escapeHtml(String(sm.exploited))}</span>атакуются (Microsoft)</div>` : ''}
        <div class="vuln-chip"><span>${escapeHtml(String(fixCount))}</span>есть исправление</div>
        <div class="vuln-chip"><span>${escapeHtml(String(sm.no_fix))}</span>исправления нет</div>
        <div class="vuln-chip vuln-chip-ok"><span>${escapeHtml(String(sm.patched))}</span>уже исправлено</div>
        ${sm.unverified ? `<div class="vuln-chip" title="Исправления выпущены только для другой ветки сборок"><span>${escapeHtml(String(sm.unverified))}</span>не проверить</div>` : ''}
      </div>` : '';

    const feedNotes = `
        ${scan.database && !scan.database.epss_loaded ? 'Оценки EPSS не загружены.' : ''}
        ${scan.database && !scan.database.kev_loaded ? 'Каталог CISA KEV не загружен.' : ''}`;
    const win = scan.windows;
    let meta = '';
    if (win && (win.documents || []).length) {
      const docs = win.documents;
      const range = docs.length > 1 ? `${docs[docs.length - 1]} – ${docs[0]}` : docs[0];
      meta = `
      <div class="vuln-note" id="vulnWindowsMeta">
        Проверено ${escapeHtml(formatDate(scan.scanned_at))}: сборка <span class="vuln-mono">${escapeHtml(win.build)}</span>
        (${escapeHtml(win.product)}), установленных обновлений: ${escapeHtml(String((win.installed_updates || []).length))},
        по бюллетеням MSRC за ${escapeHtml(String(docs.length))} мес. (${escapeHtml(range)}).
        ${feedNotes}
      </div>`;
    } else if (scan.ecosystem) {
      meta = `
      <div class="vuln-note">
        Проверено ${escapeHtml(formatDate(scan.scanned_at))}: ${escapeHtml(String(scan.packages_total))} пакетов
        (${escapeHtml(String(scan.components_checked))} исходных компонентов, по ${escapeHtml(String(scan.components_with_advisories))} есть бюллетени) по базе
        <span class="vuln-mono">${escapeHtml(scan.ecosystem)}</span>.
        ${feedNotes}
      </div>`;
    }

    const shown = this.filteredFindings();
    const rows = shown.slice(0, this.limit).map(f => this.findingRow(f)).join('');
    const filterBtn = (key, label, count) => `
      <button class="vuln-filter ctf-btn ${this.filter === key ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-filter="${key}">${label} (${count})</button>`;

    panel.innerHTML = `
      <div class="vuln-panel-title">РЕЗУЛЬТАТ ПРОВЕРКИ</div>
      <div id="vulnStatus" class="vuln-status ${statusClass}" data-status="${escapeAttr(scan.status)}">
        ${escapeHtml(scan.status_detail || scan.status)}
        ${scan.dataset_stale ? ' <span class="vuln-badge vuln-sev-high">БАЗА УСТАРЕЛА</span>' : ''}
      </div>
      ${chips}
      ${meta}
      ${findings.length ? `
        <div class="vuln-toolbar">
          ${filterBtn('fix', 'Есть исправление', fixCount)}
          ${filterBtn('nofix', 'Исправления нет', sm.no_fix ?? 0)}
          ${filterBtn('all', 'Все', findings.length)}
          <input id="vulnSearch" type="text" placeholder="${win ? 'CVE, компонент или KB...' : 'CVE или пакет...'}" value="${escapeAttr(this.query)}">
        </div>
        <table class="vuln-table" id="vulnTable">
          <thead><tr>
            <th>CVE</th><th>Компонент</th><th>Установлено</th><th>Исправлено в</th>
            <th>Важность</th><th class="vuln-num">CVSS</th><th class="vuln-num">EPSS</th><th>Атаки</th>
          </tr></thead>
          <tbody>${rows || '<tr><td colspan="8" class="vuln-note">Нет записей для выбранного фильтра</td></tr>'}</tbody>
        </table>
        ${shown.length > this.limit ? `<button id="vulnMoreBtn" class="ctf-btn ctf-btn-secondary">Показать ещё (${shown.length - this.limit})</button>` : ''}
      ` : ''}
      ${(scan.collection_errors || []).length ? `<div class="vuln-note">Замечания сбора: ${escapeHtml(scan.collection_errors.join('; '))}</div>` : ''}
    `;

    panel.querySelectorAll('.vuln-filter').forEach(btn => btn.addEventListener('click', () => {
      this.filter = btn.dataset.filter;
      this.limit = PAGE_SIZE;
      this.renderResult();
    }));
    const search = panel.querySelector('#vulnSearch');
    search?.addEventListener('input', (e) => {
      this.query = e.target.value.toLowerCase().trim();
      this.limit = PAGE_SIZE;
      const pos = e.target.selectionStart;
      this.renderResult();
      const again = this.container.querySelector('#vulnSearch');
      again?.focus();
      again?.setSelectionRange(pos, pos);
    });
    panel.querySelector('#vulnMoreBtn')?.addEventListener('click', () => {
      this.limit += PAGE_SIZE;
      this.renderResult();
    });
    panel.querySelectorAll('tr.vuln-row').forEach(tr => tr.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      const detail = tr.nextElementSibling;
      if (detail?.classList.contains('vuln-detail')) detail.hidden = !detail.hidden;
    }));
  }

  findingRow(f) {
    const sev = f.severity || 'unknown';
    const windows = !!this.scan?.windows;
    const rater = windows ? 'Оценка Microsoft' : 'Оценка дистрибутива';
    const firstUpdate = windows ? (f.sources || [])[0] : null;
    // Feed data: only plain web links become clickable.
    const idCell = f.url && /^https?:\/\//i.test(f.url)
      ? `<a href="${escapeAttr(f.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(f.id)}</a>`
      : escapeHtml(f.id);
    const fixed = f.status === 'fix_available'
      ? `<span class="vuln-mono">${escapeHtml(f.fixed_version)}</span>${firstUpdate ? `<div class="vuln-pkgs">${escapeHtml(firstUpdate)}</div>` : ''}`
      : '<span class="vuln-nofix">нет исправления</span>';
    const kev = f.kev
      ? `<span class="vuln-badge vuln-kev" title="${escapeAttr(`${f.kev.name}; добавлено ${f.kev.date_added}`)}">KEV</span>`
      : '';
    const exploited = f.exploited
      ? ' <span class="vuln-badge vuln-exploited" title="Microsoft сообщает об эксплуатации в атаках">АТАКУЕТСЯ</span>'
      : '';
    const prio = f.distro_priority ? ` title="${rater}: ${escapeAttr(f.distro_priority)}"` : '';
    return `
      <tr class="vuln-row" data-id="${escapeAttr(f.id)}" data-component="${escapeAttr(f.component)}" data-status="${escapeAttr(f.status)}">
        <td class="vuln-mono">${idCell}</td>
        <td><strong>${escapeHtml(f.component)}</strong><div class="vuln-pkgs">${escapeHtml((f.packages || []).join(', '))}</div></td>
        <td class="vuln-mono">${escapeHtml(f.installed_version)}</td>
        <td>${fixed}</td>
        <td><span class="vuln-badge vuln-sev-${escapeAttr(sev)}"${prio}>${escapeHtml(SEVERITY_LABELS[sev] || sev)}</span></td>
        <td class="vuln-num">${f.cvss_score !== null && f.cvss_score !== undefined ? escapeHtml(f.cvss_score.toFixed(1)) : '—'}</td>
        <td class="vuln-num">${escapeHtml(formatEpss(f))}</td>
        <td>${kev}${exploited}</td>
      </tr>
      <tr class="vuln-detail" hidden>
        <td colspan="8">
          <div>${escapeHtml(f.summary || 'Описание отсутствует')}</div>
          <div class="vuln-detail-meta">
            ${windows ? 'Обновления с исправлением' : 'Источники'}: ${escapeHtml((f.sources || []).join(', ') || '—')}
            ${f.distro_priority ? ` · ${rater}: ${escapeHtml(f.distro_priority)}` : ''}
            ${f.cvss_vector ? ` · <span class="vuln-mono">${escapeHtml(f.cvss_vector)}</span>` : ''}
            ${f.published ? ` · Опубликовано: ${escapeHtml(formatDate(f.published))}` : ''}
          </div>
        </td>
      </tr>`;
  }
}

import { escapeAttr, escapeHtml } from '../util/html.js';

// Credentialed remote-host scan over SSH. The flow is deliberately two-step:
// first fetch and show the server's host-key fingerprint, and only after the
// operator confirms it do we send the password/key and run the scan. The
// password lives only in this object for the duration of a scan and is never
// stored or logged.

const SEV_CLASS = {
  Critical: 'vuln-sev-critical',
  High: 'vuln-sev-high',
  Medium: 'vuln-sev-medium',
  Low: 'vuln-sev-low',
  Unknown: '',
};

const STATUS_TEXT = {
  UNSUPPORTED_PLATFORM: 'Дистрибутив хоста не поддерживается для сверки пакетов (поддержаны Debian, Ubuntu, AlmaLinux, Rocky Linux, openSUSE Leap, Alpine).',
  NO_PACKAGE_INVENTORY: 'Не удалось прочитать список установленных пакетов на хосте.',
  VULNDB_EMPTY: 'База уязвимостей для этого дистрибутива не загружена — обновите базу, иначе проверка ничего не доказывает.',
  NO_KNOWN_MATCHED_VULNERABILITIES: 'Известных уязвимостей в пакетах хоста не найдено.',
  VULNERABILITIES_FOUND: '',
};

export class RemoteHostPanel {
  constructor(ipc) {
    this.ipc = ipc;
    this.root = null;
    this.phase = 'form'; // 'form' | 'confirm' | 'scanning' | 'done'
    this.error = null;
    this.pending = null; // host/port/username/credential awaiting key confirmation
    this.hostKey = null;
    this.report = null;
    this.pollTimer = null;
  }

  mount(root) {
    this.root = root;
    this.renderForm();
  }

  // Reads the form back into a plain object. The credential stays only here.
  readForm() {
    const q = (sel) => this.root.querySelector(sel);
    const host = q('#rhHost').value.trim();
    const port = parseInt(q('#rhPort').value, 10) || 22;
    const username = q('#rhUser').value.trim();
    const method = q('input[name="rhAuth"]:checked')?.value || 'password';
    const credential =
      method === 'key'
        ? { private_key: q('#rhKey').value, passphrase: q('#rhPass').value || undefined }
        : { password: q('#rhPassword').value };
    return { host, port, username, method, credential };
  }

  async discover() {
    const form = this.readForm();
    if (!form.host) return this.fail('Укажите адрес хоста');
    if (!form.username) return this.fail('Укажите логин');
    if (form.method === 'password' && !form.credential.password) return this.fail('Введите пароль');
    if (form.method === 'key' && !form.credential.private_key.trim()) return this.fail('Вставьте приватный ключ');

    this.error = null;
    this.phase = 'confirm';
    this.hostKey = null;
    this.pending = form;
    this.render();
    try {
      const res = await this.ipc.call('remote.discover', {
        host: form.host,
        port: form.port,
        username: form.username,
      });
      this.hostKey = res.host_key;
      this.render();
    } catch (e) {
      this.phase = 'form';
      this.fail(`Не удалось получить ключ хоста: ${e.message}`);
    }
  }

  cancel() {
    this.pending = null;
    this.hostKey = null;
    this.phase = 'form';
    this.renderForm();
  }

  async confirmAndScan() {
    if (!this.pending || !this.hostKey) return;
    const p = this.pending;
    this.phase = 'scanning';
    this.error = null;
    this.render();
    try {
      await this.ipc.call('remote.scan', {
        host: p.host,
        port: p.port,
        username: p.username,
        expected_fingerprint: this.hostKey.sha256,
        ...p.credential,
      });
    } catch (e) {
      this.phase = 'form';
      // Drop the credential from memory on failure too.
      this.pending = null;
      this.fail(e.message);
      return;
    }
    // The secret has been sent; we no longer need it in memory.
    this.pending = null;
    this.poll();
  }

  poll() {
    this.stopPolling();
    this.pollTimer = setInterval(async () => {
      if (!this.root?.isConnected) return this.stopPolling();
      let st;
      try {
        st = await this.ipc.call('remote.status', {});
      } catch {
        return;
      }
      if (!st.running) {
        this.stopPolling();
        this.phase = 'done';
        this.report = st.report || null;
        this.error = st.error || null;
        this.render();
      }
    }, 1200);
  }

  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  fail(message) {
    this.error = message;
    this.render();
  }

  render() {
    if (!this.root) return;
    if (this.phase === 'confirm') return this.renderConfirm();
    if (this.phase === 'scanning') return this.renderScanning();
    if (this.phase === 'done') return this.renderDone();
    return this.renderForm();
  }

  renderForm() {
    this.root.innerHTML = `
      <div class="vuln-remote-head">
        <h3>🖧 Удалённый хост по SSH</h3>
        <div class="vuln-subtitle">Проверка CVE в пакетах удалённого Linux-сервера с учётными данными. Выполняются только команды чтения, на сервере ничего не меняется. Сканируйте только свои серверы или те, на проверку которых у вас есть разрешение.</div>
      </div>
      <div class="vuln-remote-form">
        <div class="vuln-remote-row">
          <label>Адрес <input id="rhHost" type="text" placeholder="192.0.2.10 или server.example" autocomplete="off"></label>
          <label>Порт <input id="rhPort" type="number" value="22" min="1" max="65535"></label>
          <label>Логин <input id="rhUser" type="text" placeholder="root или ubuntu" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row">
          <label><input type="radio" name="rhAuth" value="password" checked> Пароль</label>
          <label><input type="radio" name="rhAuth" value="key"> Приватный ключ</label>
        </div>
        <div class="vuln-remote-row" data-auth="password">
          <label>Пароль <input id="rhPassword" type="password" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row" data-auth="key" hidden>
          <label>Приватный ключ (OpenSSH/PEM)<textarea id="rhKey" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" autocomplete="off"></textarea></label>
          <label>Пароль ключа (если есть) <input id="rhPass" type="password" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-actions">
          <button id="rhScanBtn" class="primary-action">Проверить хост</button>
        </div>
        <div class="vuln-note">Пароль не сохраняется, не пишется в отчёт и журналы, и отправляется только после того, как вы подтвердите отпечаток ключа сервера.</div>
        ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      </div>
    `;
    const toggle = () => {
      const method = this.root.querySelector('input[name="rhAuth"]:checked')?.value || 'password';
      this.root.querySelector('[data-auth="password"]').hidden = method !== 'password';
      this.root.querySelector('[data-auth="key"]').hidden = method !== 'key';
    };
    this.root.querySelectorAll('input[name="rhAuth"]').forEach((el) => el.addEventListener('change', toggle));
    this.root.querySelector('#rhScanBtn').addEventListener('click', () => this.discover());
  }

  renderConfirm() {
    const k = this.hostKey;
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🖧 Подтвердите ключ сервера</h3></div>
      <div class="vuln-remote-confirm">
        <div class="vuln-subtitle">Сервер <strong>${escapeHtml(this.pending.host)}</strong> предъявил ключ. Убедитесь, что отпечаток совпадает с вашим сервером — иначе это может быть подмена (MITM), и подключаться нельзя.</div>
        ${
          k
            ? `<div class="vuln-remote-fp">
                 <div>Алгоритм: <span class="vuln-mono">${escapeHtml(k.algorithm)}</span></div>
                 <div>Отпечаток: <span class="vuln-mono">${escapeHtml(k.fingerprint)}</span></div>
               </div>
               <div class="vuln-remote-actions">
                 <button id="rhConfirmBtn" class="primary-action">Это мой сервер — продолжить</button>
                 <button id="rhCancelBtn" class="ctf-btn ctf-btn-secondary">Отмена</button>
               </div>`
            : `<div class="vuln-remote-wait"><span class="vuln-spinner"></span> Получение ключа сервера...</div>
               <div class="vuln-remote-actions"><button id="rhCancelBtn" class="ctf-btn ctf-btn-secondary">Отмена</button></div>`
        }
        ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      </div>
    `;
    this.root.querySelector('#rhCancelBtn')?.addEventListener('click', () => this.cancel());
    this.root.querySelector('#rhConfirmBtn')?.addEventListener('click', () => this.confirmAndScan());
  }

  renderScanning() {
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🖧 Удалённый хост по SSH</h3></div>
      <div class="vuln-remote-wait"><span class="vuln-spinner"></span> Проверяю ${escapeHtml(this.pending?.host || 'хост')}: сбор пакетов и сверка с базой CVE...</div>
    `;
  }

  renderDone() {
    const r = this.report;
    const back = '<div class="vuln-remote-actions"><button id="rhBackBtn" class="ctf-btn ctf-btn-secondary">← Проверить другой хост</button></div>';
    if (!r) {
      this.root.innerHTML = `
        <div class="vuln-remote-head"><h3>🖧 Удалённый хост по SSH</h3></div>
        <div class="vuln-error">${escapeHtml(this.error || 'Проверка не выполнена')}</div>
        ${back}`;
      this.root.querySelector('#rhBackBtn').addEventListener('click', () => this.cancel());
      return;
    }
    const findings = r.package_report?.findings || [];
    const note = STATUS_TEXT[r.status] || '';
    const errors = (r.collection_errors || [])
      .map((e) => `<div class="vuln-note">${escapeHtml(e)}</div>`)
      .join('');
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🖧 ${escapeHtml(r.host)}</h3></div>
      <div class="vuln-remote-hostline">
        <strong>${escapeHtml(r.os || 'ОС не определена')}</strong>
        ${r.kernel ? ` · ядро <span class="vuln-mono">${escapeHtml(r.kernel)}</span>` : ''}
        ${r.ecosystem ? ` · база <span class="vuln-mono">${escapeHtml(r.ecosystem)}</span>` : ''}
      </div>
      ${r.host_key ? `<div class="vuln-note">Ключ хоста: <span class="vuln-mono">${escapeHtml(r.host_key.fingerprint)}</span> (подтверждён)</div>` : ''}
      ${note ? `<div class="vuln-note">${escapeHtml(note)}</div>` : ''}
      ${errors}
      ${findings.length ? `<h4 class="vuln-remote-section">Уязвимости в пакетах</h4>${this.renderFindings(findings)}` : ''}
      ${r.cis_report ? this.renderCis(r.cis_report) : ''}
      ${back}
    `;
    this.root.querySelector('#rhBackBtn').addEventListener('click', () => this.cancel());
  }

  // The configuration audit. Each row is one check whose verdict comes only
  // from a fact read off the host; FAIL/MANUAL are shown first, and the
  // evidence behind every verdict is printed so nothing is taken on faith.
  renderCis(cis) {
    const checks = Array.isArray(cis.checks) ? cis.checks : [];
    if (!checks.length) return '';
    const summary = cis.summary || {};

    const STATUS = {
      FAIL: { label: 'НЕ ПРОЙДЕНО', cls: 'vuln-cis-fail' },
      PASS: { label: 'ПРОЙДЕНО', cls: 'vuln-cis-pass' },
      MANUAL: { label: 'ВРУЧНУЮ', cls: 'vuln-cis-manual' },
      NEEDS_PRIVILEGES: { label: 'НЕТ ДОСТУПА', cls: 'vuln-cis-na' },
      NOT_CONFIGURED: { label: 'НЕ ЗАДАНО', cls: 'vuln-cis-na' },
    };
    const SEV = { HIGH: 'vuln-sev-high', MEDIUM: 'vuln-sev-medium', LOW: 'vuln-sev-low' };
    // Fails first (by severity), then items needing attention, then the rest.
    const order = { FAIL: 0, MANUAL: 1, NEEDS_PRIVILEGES: 2, NOT_CONFIGURED: 3, PASS: 4 };
    const sevOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    const sorted = [...checks].sort(
      (a, b) =>
        (order[a.status] ?? 9) - (order[b.status] ?? 9) ||
        (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9),
    );

    const scores = (summary.compliance || [])
      .map((f) => {
        const pct = typeof f.percent === 'number' ? `${f.percent}%` : '—';
        const detail =
          f.evaluated > 0
            ? `${f.passed} из ${f.evaluated}`
            : 'нет проверок с точным результатом';
        return `<div class="vuln-cis-score">
            <div class="vuln-cis-score-pct">${escapeHtml(pct)}</div>
            <div class="vuln-cis-score-name">${escapeHtml(String(f.framework ?? ''))}</div>
            <div class="vuln-cis-score-detail">${escapeHtml(detail)}</div>
          </div>`;
      })
      .join('');

    const rows = sorted
      .map((c) => {
        const st = STATUS[c.status] || { label: String(c.status ?? '—'), cls: 'vuln-cis-na' };
        const sev = SEV[c.severity] || '';
        // Remediation is only actionable guidance for things that aren't OK.
        const showFix = c.status === 'FAIL' || c.status === 'MANUAL';
        const refs = Array.isArray(c.references)
          ? c.references.map((r) => escapeHtml(`${r.framework} ${r.control}`)).join(' · ')
          : '';
        return `
          <tr class="vuln-cis-row ${st.cls}-row">
            <td><span class="vuln-badge ${st.cls}">${escapeHtml(st.label)}</span></td>
            <td><span class="vuln-badge ${sev}">${escapeHtml(String(c.severity ?? '—'))}</span></td>
            <td>
              <div class="vuln-cis-title">${escapeHtml(c.title ?? c.id ?? '')}</div>
              <div class="vuln-cis-evidence vuln-mono">${escapeHtml(c.evidence ?? '')}</div>
              ${showFix && c.remediation ? `<div class="vuln-cis-fix">▸ ${escapeHtml(c.remediation)}</div>` : ''}
              ${refs ? `<div class="vuln-cis-refs">${refs}</div>` : ''}
            </td>
          </tr>`;
      })
      .join('');

    return `
      <h4 class="vuln-remote-section">Аудит конфигурации (CIS)</h4>
      <div class="vuln-note">Каждая проверка оценивается только по реальным данным хоста. «Не задано» и «нет доступа» — это не нарушение: значение по умолчанию не видно без прав или без запуска sshd -T, поэтому такие пункты не считаются провалом.</div>
      ${scores ? `<div class="vuln-cis-scores">${scores}</div>` : ''}
      <div class="vuln-cis-counts">
        Пройдено: ${Number(summary.pass) || 0} ·
        Не пройдено: ${Number(summary.fail) || 0} ·
        Вручную: ${Number(summary.manual) || 0} ·
        Не задано: ${Number(summary.not_configured) || 0} ·
        Нет доступа: ${Number(summary.needs_privileges) || 0}
      </div>
      <table class="vuln-table vuln-cis-table">
        <thead><tr><th>Статус</th><th>Уровень</th><th>Проверка</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  renderFindings(findings) {
    const rows = findings
      .map((f) => {
        const sev = SEV_CLASS[f.severity] ?? '';
        const fix =
          f.status === 'fix_available' && f.fixed_version
            ? escapeHtml(f.fixed_version)
            : '<span class="vuln-sev-high">нет</span>';
        const kev = f.kev ? ' <span class="vuln-badge vuln-kev-chip">KEV</span>' : '';
        // Only ever build a link for an http(s) URL, so an unexpected value
        // (e.g. a javascript: scheme) can never become a clickable sink.
        const safeUrl = typeof f.url === 'string' && /^https?:\/\//i.test(f.url) ? f.url : null;
        const link = safeUrl
          ? `<a href="${escapeAttr(safeUrl)}" target="_blank" rel="noreferrer noopener">${escapeHtml(f.id)}</a>`
          : escapeHtml(f.id);
        return `
          <tr>
            <td>${link}${kev}</td>
            <td>${escapeHtml(f.component)}</td>
            <td class="vuln-mono">${escapeHtml(f.installed_version)}</td>
            <td class="vuln-mono">${fix}</td>
            <td><span class="vuln-badge ${sev}">${escapeHtml(String(f.severity ?? '—'))}</span></td>
          </tr>`;
      })
      .join('');
    return `
      <table class="vuln-table">
        <thead><tr><th>CVE</th><th>Компонент</th><th>Установлено</th><th>Исправлено в</th><th>Уровень</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }
}

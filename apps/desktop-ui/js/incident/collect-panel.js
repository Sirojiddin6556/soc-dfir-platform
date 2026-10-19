import { escapeAttr, escapeHtml } from '../util/html.js';

// «Сбор по SSH»: gather a Linux host's investigation artifacts over SSH into a
// case, then analyse them. The flow mirrors the other SSH features — fetch and
// confirm the server's host-key fingerprint first, and only then send the
// password/key. The engine copies the host's logs, account files, cron/systemd
// units and SSH configuration to itself over SFTP (read-only — nothing is
// written on the server), records each file as a case artifact with its
// SHA-256, and builds the same timeline «Расследование» builds for a folder.
// The password lives only in this object for the duration of a run and is
// never stored or logged.

const KIND_LABEL = {
  log: 'журналы',
  account: 'учётные записи',
  sudo: 'sudo',
  cron: 'cron (задания)',
  systemd: 'systemd (юниты)',
  ssh: 'SSH (ключи/конфиг)',
  shell: 'оболочка (history/rc)',
  system: 'система',
};
const JOURNAL_LABEL = {
  text_logs: 'взяты текстовые журналы (/var/log)',
  journal_export: 'взят экспорт journald за 30 дней (UTC)',
  unavailable: 'системные журналы недоступны этому пользователю (нужен root или группа adm/systemd-journal)',
};

export class IncidentCollectPanel {
  constructor(ipc, { onOpenTimeline } = {}) {
    this.ipc = ipc;
    this.onOpenTimeline = onOpenTimeline || (() => {});
    this.root = null;
    this.phase = 'form'; // 'form' | 'confirm' | 'collecting' | 'done'
    this.error = null;
    this.pending = null; // form awaiting host-key confirmation
    this.hostKey = null;
    this.status = null; // the incident.collect_status payload
    this.cases = []; // existing cases, for the «add to case» choice
    this.pollTimer = null;
    this.lastForm = null; // non-secret fields, to re-show the form prefilled
  }

  render(root) {
    if (root) this.root = root;
    if (!this.root) return;
    if (this.phase === 'confirm') return this.renderConfirm();
    if (this.phase === 'collecting') return this.renderCollecting();
    if (this.phase === 'done') return this.renderDone();
    return this.renderForm();
  }

  async loadCases() {
    try {
      const list = await this.ipc.call('cases.list', {});
      this.cases = Array.isArray(list) ? list : [];
    } catch {
      this.cases = [];
    }
  }

  readForm() {
    const q = (sel) => this.root.querySelector(sel);
    const host = q('#icHost').value.trim();
    const port = parseInt(q('#icPort').value, 10) || 22;
    const username = q('#icUser').value.trim();
    const method = q('input[name="icAuth"]:checked')?.value || 'password';
    const credential =
      method === 'key'
        ? { private_key: q('#icKey').value, passphrase: q('#icPass').value || undefined }
        : { password: q('#icPassword').value };
    const caseChoice = q('#icCase')?.value || 'new';
    const caseTitle = q('#icCaseTitle')?.value.trim() || '';
    return { host, port, username, method, credential, caseChoice, caseTitle };
  }

  fail(message) {
    this.error = message;
    this.render();
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
    this.stopPolling();
    this.pending = null;
    this.hostKey = null;
    this.status = null;
    this.lastForm = null;
    this.phase = 'form';
    this.error = null;
    this.render();
  }

  async confirmAndCollect() {
    if (!this.pending || !this.hostKey) return;
    const p = this.pending;
    this.lastForm = {
      host: p.host, port: p.port, username: p.username, method: p.method,
      caseChoice: p.caseChoice, caseTitle: p.caseTitle,
    };
    this.phase = 'collecting';
    this.error = null;
    this.render();
    const params = {
      host: p.host,
      port: p.port,
      username: p.username,
      expected_fingerprint: this.hostKey.sha256,
      ...p.credential,
    };
    if (p.caseChoice && p.caseChoice !== 'new') params.case_id = p.caseChoice;
    else if (p.caseTitle) params.case_title = p.caseTitle;
    try {
      await this.ipc.call('incident.collect', params);
    } catch (e) {
      this.phase = 'form';
      this.pending = null; // drop the credential on failure too
      this.fail(e.message);
      return;
    }
    this.pending = null; // the secret has been sent; forget it
    this.poll();
  }

  poll() {
    this.stopPolling();
    this.pollTimer = setInterval(async () => {
      if (!this.root?.isConnected) return this.stopPolling();
      let st;
      try {
        st = await this.ipc.call('incident.collect_status', {});
      } catch {
        return;
      }
      if (!st.running) {
        this.stopPolling();
        this.phase = 'done';
        this.status = st;
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

  renderForm() {
    const pf = this.lastForm || {};
    const isKey = pf.method === 'key';
    const caseOptions = [
      `<option value="new"${!pf.caseChoice || pf.caseChoice === 'new' ? ' selected' : ''}>— новое дело —</option>`,
      ...this.cases.map(
        (c) =>
          `<option value="${escapeAttr(c.id)}"${pf.caseChoice === c.id ? ' selected' : ''}>${escapeHtml(c.title || c.id)}</option>`
      ),
    ].join('');
    this.root.innerHTML = `
      <div class="vuln-remote-head">
        <h3>🛱 Сбор артефактов по SSH</h3>
        <div class="vuln-subtitle">Собирает с Linux-сервера журналы, учётные записи, задания cron, юниты systemd, ключи и конфигурацию SSH, историю команд — и сразу строит по ним шкалу. Движок копирует файлы к себе по SFTP <strong>только для чтения</strong>: на сервере ничего не создаётся и не меняется, пароль не сохраняется. Собирайте только свои серверы или те, на которые у вас есть разрешение.</div>
      </div>
      <div class="vuln-remote-form">
        <div class="vuln-remote-row">
          <label>Адрес <input id="icHost" type="text" value="${escapeAttr(pf.host || '')}" placeholder="192.0.2.10 или server.example" autocomplete="off"></label>
          <label>Порт <input id="icPort" type="number" value="${escapeAttr(String(pf.port || 22))}" min="1" max="65535"></label>
          <label>Логин <input id="icUser" type="text" value="${escapeAttr(pf.username || '')}" placeholder="root или ubuntu" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row">
          <label class="vuln-remote-wide">Дело
            <select id="icCase">${caseOptions}</select>
          </label>
        </div>
        <div class="vuln-remote-row" id="icCaseTitleRow"${pf.caseChoice && pf.caseChoice !== 'new' ? ' hidden' : ''}>
          <label class="vuln-remote-wide">Название нового дела (необязательно)
            <input id="icCaseTitle" type="text" value="${escapeAttr(pf.caseTitle || '')}" placeholder="Инцидент: <хост> (<дата>)" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row">
          <label><input type="radio" name="icAuth" value="password" ${isKey ? '' : 'checked'}> Пароль</label>
          <label><input type="radio" name="icAuth" value="key" ${isKey ? 'checked' : ''}> Приватный ключ</label>
        </div>
        <div class="vuln-remote-row" data-auth="password" ${isKey ? 'hidden' : ''}>
          <label>Пароль <input id="icPassword" type="password" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row" data-auth="key" ${isKey ? '' : 'hidden'}>
          <label>Приватный ключ (OpenSSH/PEM)<textarea id="icKey" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" autocomplete="off"></textarea></label>
          <label>Пароль ключа (если есть) <input id="icPass" type="password" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-actions">
          <button id="icCollectBtn" class="primary-action">Собрать артефакты</button>
        </div>
        <div class="vuln-note">Собираются только журналы и точки закрепления (persistence), не весь сервер. То, что недоступно этому пользователю (например, /etc/shadow или системные журналы), будет отмечено в отчёте как «нужны права», а не обойдено. Пароль не сохраняется, не пишется в отчёт и журналы, и отправляется только после того, как вы подтвердите отпечаток ключа сервера.</div>
        ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      </div>
    `;
    const toggle = () => {
      const method = this.root.querySelector('input[name="icAuth"]:checked')?.value || 'password';
      this.root.querySelector('[data-auth="password"]').hidden = method !== 'password';
      this.root.querySelector('[data-auth="key"]').hidden = method !== 'key';
    };
    this.root.querySelectorAll('input[name="icAuth"]').forEach((el) => el.addEventListener('change', toggle));
    const caseSel = this.root.querySelector('#icCase');
    if (caseSel) caseSel.addEventListener('change', () => {
      const row = this.root.querySelector('#icCaseTitleRow');
      if (row) row.hidden = caseSel.value !== 'new';
    });
    this.root.querySelector('#icCollectBtn').addEventListener('click', () => this.discover());
  }

  renderConfirm() {
    const k = this.hostKey;
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🛱 Подтвердите ключ сервера</h3></div>
      <div class="vuln-remote-confirm">
        <div class="vuln-subtitle">Сервер <strong>${escapeHtml(this.pending.host)}</strong> предъявил ключ. Убедитесь, что отпечаток совпадает с вашим сервером — иначе это может быть подмена (MITM), и подключаться нельзя.</div>
        ${
          k
            ? `<div class="vuln-remote-fp">
                 <div>Алгоритм: <span class="vuln-mono">${escapeHtml(k.algorithm)}</span></div>
                 <div>Отпечаток: <span class="vuln-mono">${escapeHtml(k.fingerprint)}</span></div>
               </div>
               <div class="vuln-remote-actions">
                 <button id="icConfirmBtn" class="primary-action">Это мой сервер — собрать</button>
                 <button id="icCancelBtn" class="ctf-btn ctf-btn-secondary">Отмена</button>
               </div>`
            : `<div class="vuln-remote-wait"><span class="vuln-spinner"></span> Получение ключа сервера...</div>
               <div class="vuln-remote-actions"><button id="icCancelBtn" class="ctf-btn ctf-btn-secondary">Отмена</button></div>`
        }
        ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      </div>
    `;
    this.root.querySelector('#icCancelBtn')?.addEventListener('click', () => this.cancel());
    this.root.querySelector('#icConfirmBtn')?.addEventListener('click', () => this.confirmAndCollect());
  }

  renderCollecting() {
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🛱 Сбор артефактов по SSH</h3></div>
      <div class="vuln-remote-wait"><span class="vuln-spinner"></span> Собираю журналы и артефакты с ${escapeHtml(this.pending?.host || 'сервера')} по SFTP и строю шкалу...</div>
      <div class="vuln-note">Копируются журналы, учётные записи, cron, systemd, ключи и история. На сервере с большими журналами это может занять некоторое время.</div>
    `;
  }

  renderDone() {
    const back = '<div class="vuln-remote-actions"><button id="icBackBtn" class="ctf-btn ctf-btn-secondary">← Собрать другой хост</button></div>';
    const st = this.status || {};
    const m = st.collection;
    if (!m) {
      this.root.innerHTML = `
        <div class="vuln-remote-head"><h3>🛱 Сбор артефактов по SSH</h3></div>
        <div class="vuln-error">${escapeHtml(this.error || 'Сбор не выполнен')}</div>
        ${back}`;
      this.root.querySelector('#icBackBtn').addEventListener('click', () => this.cancel());
      return;
    }

    const files = Array.isArray(m.files) ? m.files : [];
    const counts = {};
    for (const f of files) counts[f.kind] = (counts[f.kind] || 0) + 1;
    const kindBits = Object.keys(counts)
      .map((k) => `${escapeHtml(KIND_LABEL[k] || k)}: ${counts[k]}`)
      .join(', ');

    const needsPriv = (m.skipped || []).filter((s) => s.reason === 'NO_ACCESS').map((s) => s.remote_path);
    const report = st.report || {};
    const findings = Array.isArray(report.findings) ? report.findings.length : 0;
    const links = Array.isArray(report.links) ? report.links.length : 0;
    const events = report?.summary?.total_events ?? (Array.isArray(report.events) ? report.events.length : 0);
    const caseInfo = st.case || {};
    const skew = typeof m.clock_skew_seconds === 'number' ? m.clock_skew_seconds : null;

    let html = `<div class="vuln-remote-head"><h3>🛱 ${escapeHtml(m.hostname || m.host || 'Хост')}</h3></div>`;
    html += `<div class="vuln-remote-hostline">Дело: <span class="vuln-mono">${escapeHtml(caseInfo.title || caseInfo.id || '')}</span></div>`;
    if (m.os_name) html += `<div class="vuln-remote-hostline">ОС: <span class="vuln-mono">${escapeHtml(m.os_name)}</span>${m.kernel ? ` · ядро <span class="vuln-mono">${escapeHtml(m.kernel)}</span>` : ''}</div>`;

    html += '<div class="inc-collect-summary">';
    html += `<div class="inc-collect-stat"><b>${escapeHtml(String(files.length))}</b> файлов собрано${kindBits ? ` (${kindBits})` : ''}</div>`;
    html += `<div class="inc-collect-stat"><b>${escapeHtml(String(findings))}</b> находок · <b>${escapeHtml(String(links))}</b> связей · <b>${escapeHtml(String(events))}</b> событий на шкале</div>`;
    html += `<div class="inc-collect-stat">Источник событий: ${escapeHtml(JOURNAL_LABEL[m.journal_mode] || String(m.journal_mode || ''))}</div>`;
    if (skew !== null && Math.abs(skew) >= 2) {
      html += `<div class="inc-collect-stat inc-collect-warn">Часы сервера отличаются от часов движка на ${escapeHtml(String(skew))} с — учитывайте при сопоставлении времени.</div>`;
    }
    html += '</div>';

    if (needsPriv.length) {
      html += `<details class="inc-collect-priv"><summary>Нужны права root/adm: не прочитано файлов — ${needsPriv.length}</summary><div class="vuln-note">Эти файлы существуют, но недоступны пользователю <span class="vuln-mono">${escapeHtml(m.username || '')}</span>. Повторите сбор под root или пользователем группы adm/systemd-journal, чтобы добрать их:</div><ul>`;
      for (const p of needsPriv.slice(0, 40)) html += `<li><span class="vuln-mono">${escapeHtml(p)}</span></li>`;
      html += '</ul></details>';
    }

    if (Array.isArray(m.notes) && m.notes.length) {
      html += `<details class="inc-collect-notes"><summary>Примечания сбора (${m.notes.length})</summary><ul>`;
      for (const n of m.notes) html += `<li>${escapeHtml(n)}</li>`;
      html += '</ul></details>';
    }

    if (st.report_error) {
      html += `<div class="vuln-note vuln-remote-warn">Файлы собраны, но шкалу построить не удалось: ${escapeHtml(st.report_error)}</div>`;
    }

    html += '<div class="vuln-remote-actions">';
    if (caseInfo.dir && events > 0) {
      html += '<button id="icOpenTimelineBtn" class="primary-action">Открыть полную шкалу по собранным данным</button>';
    }
    html += '<button id="icBackBtn" class="ctf-btn ctf-btn-secondary">← Собрать другой хост</button>';
    html += '</div>';

    this.root.innerHTML = html;
    this.root.querySelector('#icBackBtn').addEventListener('click', () => this.cancel());
    const open = this.root.querySelector('#icOpenTimelineBtn');
    if (open) open.addEventListener('click', () => this.onOpenTimeline(caseInfo.dir));
  }
}

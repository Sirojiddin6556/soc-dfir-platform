import { escapeAttr, escapeHtml } from '../util/html.js';
import { CodeReportView } from '../code/report-view.js';

// Source-code analysis of a project on a remote host over SSH. The flow mirrors
// the remote OS scan: fetch and confirm the server's host-key fingerprint
// first, and only then send the password/key. The engine copies the project
// down over SFTP (read-only — nothing is written on the server), runs the same
// analysis the local «Анализ кода» uses, and deletes the copy. The password
// lives only in this object for the duration of a scan and is never stored or
// logged. The findings are rendered by the shared CodeReportView, so a remote
// project reads exactly like a local one.

export class ProjectCodePanel {
  constructor(ipc) {
    this.ipc = ipc;
    this.root = null;
    this.phase = 'form'; // 'form' | 'confirm' | 'scanning' | 'dbloading' | 'done'
    this.error = null;
    this.pending = null; // host/port/username/credential/path/options awaiting confirmation
    this.hostKey = null;
    this.status = null; // the remote.code_status payload, with .report
    this.pollTimer = null;
    // Non-secret fields, kept so the form can be re-shown prefilled after a
    // database download (the password is never kept).
    this.lastForm = null;
    this.formNotice = null;
    // State while a vuln-DB download runs.
    this.dbStatus = null;
    this.dbEcosystems = null;
    this.dbTimer = null;
    this.view = new CodeReportView({
      onLoadDepsDb: (ecosystems) => this.loadDbForEcosystems(ecosystems),
      exportTitle: 'Код проекта по SSH',
      exportKind: 'remote-code',
    });
  }

  mount(root) {
    this.root = root;
    this.renderForm();
  }

  readForm() {
    const q = (sel) => this.root.querySelector(sel);
    const host = q('#rcHost').value.trim();
    const port = parseInt(q('#rcPort').value, 10) || 22;
    const username = q('#rcUser').value.trim();
    const path = q('#rcPath').value.trim();
    const method = q('input[name="rcAuth"]:checked')?.value || 'password';
    const credential =
      method === 'key'
        ? { private_key: q('#rcKey').value, passphrase: q('#rcPass').value || undefined }
        : { password: q('#rcPassword').value };
    const external = !!q('#rcExternal')?.checked;
    const includeTests = !!q('#rcTests')?.checked;
    return { host, port, username, path, method, credential, external, includeTests };
  }

  async discover() {
    const form = this.readForm();
    if (!form.host) return this.fail('Укажите адрес хоста');
    if (!form.username) return this.fail('Укажите логин');
    if (!form.path) return this.fail('Укажите путь к проекту на сервере');
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
    this.stopDbPolling();
    this.pending = null;
    this.hostKey = null;
    this.status = null;
    this.lastForm = null;
    this.formNotice = null;
    this.phase = 'form';
    this.renderForm();
  }

  async confirmAndScan() {
    if (!this.pending || !this.hostKey) return;
    const p = this.pending;
    // Remember the non-secret fields so the form can be re-shown prefilled if a
    // vuln DB has to be downloaded and the scan run again. No credential kept.
    this.lastForm = {
      host: p.host, port: p.port, username: p.username, method: p.method,
      path: p.path, external: p.external, includeTests: p.includeTests,
    };
    this.phase = 'scanning';
    this.error = null;
    this.view.resetFilters();
    this.render();
    try {
      await this.ipc.call('remote.code_scan', {
        host: p.host,
        port: p.port,
        username: p.username,
        expected_fingerprint: this.hostKey.sha256,
        path: p.path,
        external_sources: p.external,
        include_tests: p.includeTests,
        ...p.credential,
      });
    } catch (e) {
      this.phase = 'form';
      this.pending = null; // drop the credential on failure too
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
        st = await this.ipc.call('remote.code_status', {});
      } catch {
        return;
      }
      if (!st.running) {
        this.stopPolling();
        this.phase = 'done';
        // Carry the attacker-input flag through for the report's note.
        if (st.report && this.lastForm) st.external_sources = this.lastForm.external;
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

  fail(message) {
    this.error = message;
    this.render();
  }

  render() {
    if (!this.root) return;
    if (this.phase === 'confirm') return this.renderConfirm();
    if (this.phase === 'scanning') return this.renderScanning();
    if (this.phase === 'dbloading') return this.renderDbLoading();
    if (this.phase === 'done') return this.renderDone();
    return this.renderForm();
  }

  renderForm() {
    const pf = this.lastForm || {};
    const host = pf.host || '';
    const port = pf.port || 22;
    const user = pf.username || '';
    const projectPath = pf.path || '';
    const isKey = pf.method === 'key';
    this.root.innerHTML = `
      <div class="vuln-remote-head">
        <h3>🖧 Код проекта по SSH</h3>
        <div class="vuln-subtitle">Анализ исходного кода проекта на удалённом сервере. Движок копирует проект к себе по SFTP только для чтения — на сервере ничего не создаётся и не меняется, временная копия удаляется сразу после проверки. Проверяйте только свои серверы или те, на которые у вас есть разрешение.</div>
      </div>
      <div class="vuln-remote-form">
        ${this.formNotice ? `<div class="vuln-remote-ok">${escapeHtml(this.formNotice)}</div>` : ''}
        <div class="vuln-remote-row">
          <label>Адрес <input id="rcHost" type="text" value="${escapeAttr(host)}" placeholder="192.0.2.10 или server.example" autocomplete="off"></label>
          <label>Порт <input id="rcPort" type="number" value="${escapeAttr(String(port))}" min="1" max="65535"></label>
          <label>Логин <input id="rcUser" type="text" value="${escapeAttr(user)}" placeholder="root или ubuntu" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row">
          <label class="vuln-remote-wide">Путь к проекту <input id="rcPath" type="text" value="${escapeAttr(projectPath)}" placeholder="/home/user/app или ~/projects/api" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row">
          <label><input type="radio" name="rcAuth" value="password" ${isKey ? '' : 'checked'}> Пароль</label>
          <label><input type="radio" name="rcAuth" value="key" ${isKey ? 'checked' : ''}> Приватный ключ</label>
        </div>
        <div class="vuln-remote-row" data-auth="password" ${isKey ? 'hidden' : ''}>
          <label>Пароль <input id="rcPassword" type="password" autocomplete="off"></label>
        </div>
        <div class="vuln-remote-row" data-auth="key" ${isKey ? '' : 'hidden'}>
          <label>Приватный ключ (OpenSSH/PEM)<textarea id="rcKey" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" autocomplete="off"></textarea></label>
          <label>Пароль ключа (если есть) <input id="rcPass" type="password" autocomplete="off"></label>
        </div>
        <label class="code-option"><input id="rcExternal" type="checkbox" ${pf.external ? 'checked' : ''}>
          Считать входом атакующего и аргументы командной строки, переменные окружения, stdin и файлы (для утилит и служб)</label>
        <label class="code-option"><input id="rcTests" type="checkbox" ${pf.includeTests ? 'checked' : ''}>
          Проверять и тесты</label>
        <div class="vuln-remote-actions">
          <button id="rcScanBtn" class="primary-action">Проверить код</button>
        </div>
        <div class="vuln-note">Папки зависимостей и сборки (node_modules, vendor, .git, target и т. п.) и двоичные файлы не копируются. Пароль не сохраняется, не пишется в отчёт и журналы, и отправляется только после того, как вы подтвердите отпечаток ключа сервера.</div>
        ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      </div>
    `;
    const toggle = () => {
      const method = this.root.querySelector('input[name="rcAuth"]:checked')?.value || 'password';
      this.root.querySelector('[data-auth="password"]').hidden = method !== 'password';
      this.root.querySelector('[data-auth="key"]').hidden = method !== 'key';
    };
    this.root.querySelectorAll('input[name="rcAuth"]').forEach((el) => el.addEventListener('change', toggle));
    this.root.querySelector('#rcScanBtn').addEventListener('click', () => this.discover());
    this.formNotice = null;
  }

  async loadDbForEcosystems(ecosystems) {
    const list = (ecosystems || []).filter(Boolean);
    if (!list.length) return;
    this.dbEcosystems = list;
    this.dbStatus = null;
    this.error = null;
    this.phase = 'dbloading';
    this.render();
    try {
      await this.ipc.call('vulndb.update', { ecosystems: list });
    } catch (e) {
      this.phase = 'done';
      this.fail(`Не удалось начать загрузку базы: ${e.message}`);
      return;
    }
    this.pollDb();
  }

  pollDb() {
    this.stopDbPolling();
    this.dbTimer = setInterval(async () => {
      if (!this.root?.isConnected) return this.stopDbPolling();
      let st;
      try {
        st = await this.ipc.call('vulndb.status', {});
      } catch {
        return;
      }
      this.dbStatus = st;
      if (!st?.update?.running) {
        this.stopDbPolling();
        // Base is ready; go back to the form prefilled (minus the password) so
        // the project can be fetched and checked again against the loaded base.
        this.phase = 'form';
        this.status = null;
        this.formNotice = `База (${this.dbEcosystems.join(', ')}) загружена. Введите пароль и запустите проверку снова.`;
        this.render();
      } else {
        this.render();
      }
    }, 1000);
  }

  stopDbPolling() {
    if (this.dbTimer) {
      clearInterval(this.dbTimer);
      this.dbTimer = null;
    }
  }

  renderDbLoading() {
    const step = this.dbStatus?.update?.current || 'Подготовка';
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🖧 Загрузка базы уязвимостей</h3></div>
      <div class="vuln-remote-wait"><span class="vuln-spinner"></span> ${escapeHtml((this.dbEcosystems || []).join(', '))}: ${escapeHtml(step)}...</div>
      <div class="vuln-note">Скачиваются бюллетени OSV для экосистем зависимостей проекта. Это разовая операция — потом проверка будет быстрой.</div>
    `;
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
                 <button id="rcConfirmBtn" class="primary-action">Это мой сервер — продолжить</button>
                 <button id="rcCancelBtn" class="ctf-btn ctf-btn-secondary">Отмена</button>
               </div>`
            : `<div class="vuln-remote-wait"><span class="vuln-spinner"></span> Получение ключа сервера...</div>
               <div class="vuln-remote-actions"><button id="rcCancelBtn" class="ctf-btn ctf-btn-secondary">Отмена</button></div>`
        }
        ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      </div>
    `;
    this.root.querySelector('#rcCancelBtn')?.addEventListener('click', () => this.cancel());
    this.root.querySelector('#rcConfirmBtn')?.addEventListener('click', () => this.confirmAndScan());
  }

  renderScanning() {
    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🖧 Код проекта по SSH</h3></div>
      <div class="vuln-remote-wait"><span class="vuln-spinner"></span> Копирую проект с ${escapeHtml(this.pending?.host || 'сервера')} по SFTP и анализирую код...</div>
      <div class="vuln-note">Загружается только исходный код (без папок зависимостей и двоичных файлов). На большом проекте это может занять некоторое время.</div>
    `;
  }

  renderDone() {
    const back = '<div class="vuln-remote-actions"><button id="rcBackBtn" class="ctf-btn ctf-btn-secondary">← Проверить другой проект</button></div>';
    const report = this.status?.report;
    if (!report) {
      this.root.innerHTML = `
        <div class="vuln-remote-head"><h3>🖧 Код проекта по SSH</h3></div>
        <div class="vuln-error">${escapeHtml(this.error || 'Проверка не выполнена')}</div>
        ${back}`;
      this.root.querySelector('#rcBackBtn').addEventListener('click', () => this.cancel());
      return;
    }
    const fetch = report.fetch || {};
    const fetchBits = [];
    if (typeof fetch.files === 'number') {
      const mb = (fetch.bytes || 0) / (1024 * 1024);
      fetchBits.push(`скопировано файлов: ${fetch.files} (${mb >= 1 ? `${mb.toFixed(1)} МБ` : `${Math.round((fetch.bytes || 0) / 1024)} КБ`})`);
    }
    if ((fetch.skipped_dirs || []).length) fetchBits.push(`пропущено папок зависимостей/сборки: ${fetch.skipped_dirs.length}`);
    if ((fetch.skipped_binary || []).length) fetchBits.push(`двоичных/медиа файлов пропущено: ${fetch.skipped_binary.length}`);
    if ((fetch.skipped_large || []).length) fetchBits.push(`слишком больших файлов пропущено: ${fetch.skipped_large.length}`);
    if ((fetch.skipped_symlinks || []).length) fetchBits.push(`символьных ссылок не переходилось: ${fetch.skipped_symlinks.length}`);

    this.root.innerHTML = `
      <div class="vuln-remote-head"><h3>🖧 ${escapeHtml(this.status.target || 'Код проекта')}</h3></div>
      <div class="vuln-remote-hostline">Проект: <span class="vuln-mono">${escapeHtml(this.status.path || '')}</span></div>
      ${fetchBits.length ? `<div class="vuln-note" id="rcFetchNote">${escapeHtml(fetchBits.join('; '))}.</div>` : ''}
      ${fetch.truncated && fetch.limit_hit ? `<div class="vuln-note vuln-remote-warn" id="rcFetchTrunc">${escapeHtml(fetch.limit_hit)}</div>` : ''}
      <div id="rcCodeReport" class="vuln-remote-report"></div>
      ${back}
    `;
    this.root.querySelector('#rcBackBtn').addEventListener('click', () => this.cancel());
    const panel = this.root.querySelector('#rcCodeReport');
    this.view.render(panel, this.status);
  }
}

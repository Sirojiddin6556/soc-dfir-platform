import { RemoteHostPanel } from './os-panel.js';
import { ProjectCodePanel } from './code-panel.js';

// «Проверка по SSH»: credentialed checks of a remote host over SSH, grouped as
// two sub-tabs — the OS/package + configuration audit («Проверка ОС»), and the
// source-code analysis of a project on that host («Проверка кода проекта»).
// Each sub-panel keeps its own mount element so a scan running in one does not
// disturb the other when the operator switches tabs; the panel objects live on
// the space, so their state survives re-entering the space too.

const TABS = [
  { key: 'os', label: 'Проверка ОС' },
  { key: 'code', label: 'Проверка кода проекта' },
];

export class SshSpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.container = null;
    this.active = 'os';
    this.osPanel = new RemoteHostPanel(ipc);
    this.codePanel = new ProjectCodePanel(ipc);
  }

  render(container) {
    this.container = container;
    container.innerHTML = `
      <div class="vuln-space ssh-space">
        <div class="vuln-header">
          <div>
            <h2>🖧 ПРОВЕРКА ПО SSH</h2>
            <div class="vuln-subtitle">Проверка удалённого хоста с учётными данными по SSH: уязвимости ОС и пакетов с аудитом конфигурации (CIS), а также анализ исходного кода проекта на сервере. Выполняется только чтение, на сервере ничего не меняется.</div>
          </div>
        </div>
        <div class="ssh-subtabs">
          ${TABS.map((t) => `<button class="ssh-subtab ctf-btn ${this.active === t.key ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-tab="${t.key}">${t.label}</button>`).join('')}
        </div>
        <div id="sshMountOs" class="vuln-panel vuln-remote-panel" ${this.active === 'os' ? '' : 'hidden'}></div>
        <div id="sshMountCode" class="vuln-panel vuln-remote-panel" ${this.active === 'code' ? '' : 'hidden'}></div>
      </div>
    `;
    // Re-attach each panel to its (fresh) mount, re-rendering its current phase
    // so state survives re-entering the space.
    this.osPanel.root = container.querySelector('#sshMountOs');
    this.osPanel.render();
    this.codePanel.root = container.querySelector('#sshMountCode');
    this.codePanel.render();

    container.querySelectorAll('.ssh-subtab').forEach((btn) =>
      btn.addEventListener('click', () => this.selectTab(btn.dataset.tab))
    );
  }

  selectTab(key) {
    if (!this.container) return;
    this.active = key;
    this.container.querySelectorAll('.ssh-subtab').forEach((btn) => {
      const on = btn.dataset.tab === key;
      btn.classList.toggle('ctf-btn-primary', on);
      btn.classList.toggle('ctf-btn-secondary', !on);
    });
    const os = this.container.querySelector('#sshMountOs');
    const code = this.container.querySelector('#sshMountCode');
    if (os) os.hidden = key !== 'os';
    if (code) code.hidden = key !== 'code';
  }
}

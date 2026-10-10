import { IpcClient } from './ipc.js';
import { SystemSpace } from './system/system.js';
import { VulnerabilitySpace } from './vulns/vulns.js';
import { CodeSpace } from './code/code.js';
import { WebSpace } from './web/web.js';
import { ensureSession, clearSessionToken, logout } from './auth.js';

/** The space shown first, and the fallback when none is selected. */
const DEFAULT_SPACE = 'system';

class SocDfirApplication {
  constructor() {
    this.ipc = new IpcClient();
    this.spaces = {
      system: new SystemSpace(this.ipc),
      vulns: new VulnerabilitySpace(this.ipc),
      code: new CodeSpace(this.ipc),
      web: new WebSpace(this.ipc),
    };
    this.currentSpace = DEFAULT_SPACE;
  }

  async start() {
    this.setupGlobalNavigation();

    try {
      this.user = await ensureSession(this.ipc);
    } catch (e) {
      console.error('[Auth]', e.message);
      this.showFatal(`Движок недоступен: ${e.message}`);
      return;
    }
    this.setupSessionHandling();

    const btn =
      document.querySelector(`.global-nav button[data-space="${DEFAULT_SPACE}"]`) ||
      document.querySelector('.global-nav button[data-space]');
    if (btn) btn.click();
    else this.openSpace(this.currentSpace);
  }

  setupSessionHandling() {
    const nameEl = document.getElementById('currentUserName');
    if (nameEl && this.user) nameEl.textContent = this.user.display_name || this.user.username;
    document.getElementById('logoutButton')?.addEventListener('click', () => logout(this.ipc));
    // A session that expires or is revoked mid-work sends the user back to login.
    window.addEventListener(
      'soc:unauthorized',
      () => {
        clearSessionToken();
        window.location.reload();
      },
      { once: true }
    );
  }

  showFatal(message) {
    const overlay = document.getElementById('authOverlay');
    const error = document.getElementById('authError');
    const form = document.getElementById('authForm');
    if (overlay && error && form) {
      form.querySelectorAll('label, button').forEach((el) => {
        el.hidden = true;
      });
      document.getElementById('authTitle').textContent = 'Нет связи с движком';
      document.getElementById('authHint').textContent = '';
      error.textContent = message;
      overlay.hidden = false;
    }
  }

  setupGlobalNavigation() {
    document.querySelectorAll('.global-nav button').forEach((button) => {
      button.addEventListener('click', () => {
        const space = button.dataset.space;
        if (!space) return;
        document.querySelectorAll('.global-nav button').forEach((b) => b.classList.remove('active'));
        button.classList.add('active');
        this.openSpace(space);
      });
    });
  }

  openSpace(space) {
    this.currentSpace = space;
    let container = document.getElementById('spaceContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'spaceContainer';
      const layout = document.querySelector('.workspace-layout');
      if (layout) layout.appendChild(container);
    }
    this.spaces[space]?.render(container);
  }
}

const application = new SocDfirApplication();
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    application.start();
  });
}

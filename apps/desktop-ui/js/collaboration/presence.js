import { escapeAttr, escapeHtml } from '../util/html.js';

export class TeamPresence {
  constructor(ipc) {
    this.ipc = ipc;
    this.presences = [];
  }

  async init() {
    await this.refresh();
    setInterval(() => this.refresh(), 10000);
  }

  async refresh() {
    try {
      const list = await this.ipc.call('presence.list', {});
      if (list) {
        this.presences = list;
      }
    } catch { /* team server offline */ }
    this.render();
  }

  render() {
    const container = document.getElementById('teamPresence');
    const syncLabel = document.getElementById('teamSyncState');

    if (container) {
      if (this.presences.length === 0) {
        container.innerHTML = `
          <div style="display: flex; align-items: center; gap: 4px;">
            <span style="width: 22px; height: 22px; border-radius: 50%; background: var(--accent-info); color: #fff; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold;">С</span>
            <span style="font-size: 11px; color: var(--text-secondary);">Сироҷиддин (Lead)</span>
          </div>
        `;
      } else {
        container.innerHTML = this.presences.map(p => {
          const userId = String(p.user_id ?? '');
          return `
          <span title="${escapeAttr(`${userId}: ${p.status_text || 'Online'}`)}" style="width: 22px; height: 22px; border-radius: 50%; background: var(--accent-info); color: #fff; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold; border: 1.5px solid ${p.is_online ? 'var(--accent-success)' : 'var(--text-muted)'};">
            ${escapeHtml(userId.charAt(0).toUpperCase())}
          </span>
        `;
        }).join('');
      }
    }

    if (syncLabel) {
      syncLabel.textContent = this.presences.length > 1 ? `Team: ${this.presences.length} ONLINE` : 'Team: LOCAL MESH';
    }
  }
}

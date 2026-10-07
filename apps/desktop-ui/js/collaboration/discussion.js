import { escapeHtml } from '../util/html.js';

export class ContextDiscussion {
  constructor(ipc) {
    this.ipc = ipc;
    this.currentEntity = null;
    this.messages = [];
    this.initEvents();
  }

  initEvents() {
    const btnSend = document.getElementById('sendDiscussion');
    const input = document.getElementById('discussionText');

    if (btnSend && input) {
      const send = () => this.sendMessage();
      btnSend.addEventListener('click', send);
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') send();
      });
    }

    const openBtn = document.getElementById('openDiscussion');
    if (openBtn) {
      openBtn.addEventListener('click', () => {
        const inputEl = document.getElementById('discussionText');
        if (inputEl) inputEl.focus();
      });
    }
  }

  async loadForEntity(entity) {
    this.currentEntity = entity;
    try {
      const caseId = document.getElementById('caseId')?.textContent.trim();
      const res = await this.ipc.call('chat.entity.thread', {
        entity_type: entity?.type || 'case',
        entity_id: entity?.id || caseId
      });
      if (res && res.messages) {
        this.messages = res.messages;
      } else {
        const history = await this.ipc.call('chat.history', { limit: 15 });
        this.messages = Array.isArray(history) ? history : [];
      }
    } catch {
      this.messages = [];
    }
    this.render();
  }

  async sendMessage() {
    const input = document.getElementById('discussionText');
    if (!input || !input.value.trim()) return;

    const body = input.value.trim();
    input.value = '';

    const ent = this.currentEntity;
    const refs = ent ? [{ ref_type: 'Finding', ref_id: ent.id, title: ent.label || ent.id }] : [];

    try {
      await this.ipc.call('chat.send', {
        body,
        author_name: 'Сироҷиддин',
        author_role: 'Owner',
        references: refs
      });
    } catch { /* silent */ }

    await this.loadForEntity(this.currentEntity);
  }

  render() {
    const container = document.getElementById('discussionMessages');
    const countEl = document.getElementById('discussionCount');
    if (countEl) countEl.textContent = this.messages.length;

    if (!container) return;

    if (this.messages.length === 0) {
      container.innerHTML = '<div style="font-size: 10px; color: var(--text-muted); text-align: center; margin-top: 20px;">Нет сообщений. Начните обсуждение объекта.</div>';
      return;
    }

    let html = '';
    for (const m of this.messages) {
      const time = m.created_at ? new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      html += `
        <div class="discussion-msg">
          <div class="discussion-author">${escapeHtml(m.author_name || 'Аналитик')} <span style="font-size: 9px; color: var(--text-muted); font-weight: normal; margin-left: 4px;">${escapeHtml(time)}</span></div>
          <div style="color: var(--text-primary); font-size: 11px;">${escapeHtml(m.body)}</div>
        </div>
      `;
    }
    container.innerHTML = html;
    container.scrollTop = container.scrollHeight;
  }
}

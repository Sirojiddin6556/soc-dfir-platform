function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

export class OperationsSpace {
  constructor(ipc, onSelectCase) {
    this.ipc = ipc;
    this.onSelectCase = onSelectCase;
  }

  async render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">◈ ОПЕРАЦИИ И АКТИВНЫЕ ИНЦИДЕНТЫ</h2>
            <div style="font-size: 12px; color: var(--text-muted);">Центр оперативного дежурства аналитиков первой и второй линии SOC</div>
          </div>
          <button id="opsNewCaseBtn" class="primary-action">+ Новое дело</button>
        </div>

        <div style="font-weight: 700; font-size: 12px; color: var(--text-secondary); margin-bottom: 10px; letter-spacing: 0.5px;">АКТИВНЫЕ РАССЛЕДОВАНИЯ</div>
        <div id="opsCaseGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px;">
          <div style="color: var(--text-muted); font-size: 12px;">Загрузка дел...</div>
        </div>
      </div>
    `;

    const newBtn = container.querySelector('#opsNewCaseBtn');
    if (newBtn) {
      newBtn.addEventListener('click', async () => {
        const title = window.prompt(
          'Название нового дела:',
          `Расследование от ${new Date().toLocaleDateString('ru-RU')}`
        );
        if (!title) return;
        try {
          const created = await this.ipc.call('cases.create', { title });
          const realId = created && (created.case_id || created.id);
          if (realId && this.onSelectCase) this.onSelectCase(realId);
          this.render(container);
        } catch (e) {
          console.warn('[Operations] Не удалось создать дело:', e.message);
        }
      });
    }

    await this.renderCaseGrid(container);
  }

  async renderCaseGrid(container) {
    const grid = container.querySelector('#opsCaseGrid');
    if (!grid) return;

    let cases = [];
    try {
      cases = (await this.ipc.call('cases.list', {})) || [];
    } catch (e) {
      grid.innerHTML = `<div style="color: var(--accent-critical); font-size: 12px;">Не удалось загрузить дела: ${escapeHtml(e.message)}</div>`;
      return;
    }

    if (cases.length === 0) {
      grid.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Активных дел нет. Создайте новое дело, чтобы начать расследование.</div>';
      return;
    }

    grid.innerHTML = cases
      .map(
        (c) => `
      <div class="op-case-card" data-case="${escapeHtml(c.id)}" style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px; cursor: pointer;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-family: var(--font-mono); font-weight: bold; font-size: 12px;">${escapeHtml(c.id.slice(0, 8))}</span>
          <span class="badge badge-net">${escapeHtml(c.status)}</span>
        </div>
        <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px;">${escapeHtml(c.title)}</div>
        <div style="font-size: 11px; color: var(--text-muted);">Создано: ${new Date(c.created_at).toLocaleString('ru-RU')}</div>
      </div>
    `
      )
      .join('');

    grid.querySelectorAll('.op-case-card').forEach((card) => {
      card.addEventListener('click', () => {
        const caseId = card.dataset.case;
        if (this.onSelectCase) this.onSelectCase(caseId);
      });
    });
  }
}

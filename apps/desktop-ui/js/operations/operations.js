function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

export class OperationsSpace {
  constructor(ipc, onSelectCase) {
    this.ipc = ipc;
    this.onSelectCase = onSelectCase;
    this.filterStatus = 'ALL';
    this.searchQuery = '';
    this.container = null;
  }

  async render(container) {
    this.container = container;
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
          <div>
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">◈ ОПЕРАЦИИ И АКТИВНЫЕ ИНЦИДЕНТЫ</h2>
            <div style="font-size: 12px; color: var(--text-muted);">Центр оперативного дежурства аналитиков первой и второй линии SOC</div>
          </div>
          <div style="display: flex; gap: 10px; align-items: center;">
            <button id="opsNewCaseBtn" class="primary-action">+ Новое дело</button>
          </div>
        </div>

        <!-- Filters & Search Toolbar -->
        <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 16px; flex-wrap: wrap;">
          <input
            type="text"
            id="opsSearchInput"
            placeholder="Поиск по названию или ID..."
            value="${escapeHtml(this.searchQuery)}"
            style="width: 260px; height: 30px; background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 4px; padding: 0 10px; color: var(--text-primary); font-size: 12px;"
          />
          <div style="display: flex; gap: 4px;">
            <button class="ops-filter-btn ctf-btn ${this.filterStatus === 'ALL' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-status="ALL">Все</button>
            <button class="ops-filter-btn ctf-btn ${this.filterStatus === 'ACTIVE' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-status="ACTIVE">Активные</button>
            <button class="ops-filter-btn ctf-btn ${this.filterStatus === 'CLOSED' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-status="CLOSED">Закрытые</button>
          </div>
        </div>

        <div style="font-weight: 700; font-size: 12px; color: var(--text-secondary); margin-bottom: 10px; letter-spacing: 0.5px;">СПИСОК ИНЦИДЕНТОВ</div>
        <div id="opsCaseGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px;">
          <div style="color: var(--text-muted); font-size: 12px;">Загрузка дел...</div>
        </div>
      </div>
    `;

    this.bindEvents(container);
    await this.renderCaseGrid(container);
  }

  bindEvents(container) {
    const newBtn = container.querySelector('#opsNewCaseBtn');
    const searchInput = container.querySelector('#opsSearchInput');

    newBtn?.addEventListener('click', async () => {
      const defaultTitle = `Расследование от ${new Date().toLocaleDateString('ru-RU')}`;
      const title = (typeof window !== 'undefined' && typeof window.prompt === 'function')
        ? window.prompt('Название нового дела:', defaultTitle)
        : defaultTitle;
      if (!title) return;

      try {
        const created = await this.ipc.call('cases.create', { title });
        const realId = created && (created.case_id || created.id);
        if (realId && this.onSelectCase) this.onSelectCase(realId);
        await this.render(container);
      } catch (e) {
        console.warn('[Operations] Не удалось создать дело:', e.message);
      }
    });

    searchInput?.addEventListener('input', (e) => {
      this.searchQuery = e.target.value.toLowerCase().trim();
      this.renderCaseGrid(container);
    });

    container.querySelectorAll('.ops-filter-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        this.filterStatus = e.currentTarget.getAttribute('data-status') || 'ALL';
        container.querySelectorAll('.ops-filter-btn').forEach((b) => {
          b.className = `ops-filter-btn ctf-btn ${b.getAttribute('data-status') === this.filterStatus ? 'ctf-btn-primary' : 'ctf-btn-secondary'}`;
        });
        this.renderCaseGrid(container);
      });
    });
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

    let filtered = cases;
    if (this.filterStatus !== 'ALL') {
      filtered = filtered.filter((c) => (c.status || 'ACTIVE').toUpperCase() === this.filterStatus);
    }
    if (this.searchQuery) {
      filtered = filtered.filter((c) =>
        (c.title || '').toLowerCase().includes(this.searchQuery) ||
        (c.id || '').toLowerCase().includes(this.searchQuery)
      );
    }

    if (filtered.length === 0) {
      grid.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Дел по заданным критериям не найдено. Нажмите «+ Новое дело» для создания.</div>';
      return;
    }

    grid.innerHTML = filtered
      .map((c) => {
        const id = c.id || c.case_id || 'unknown';
        const shortId = id.length > 8 ? id.slice(0, 8) : id;
        const status = (c.status || 'ACTIVE').toUpperCase();
        const dateStr = c.created_at ? new Date(c.created_at).toLocaleString('ru-RU') : 'Не указана';

        return `
          <div class="op-case-card" data-case="${escapeHtml(id)}" style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px; cursor: pointer; display: flex; flex-direction: column; justify-content: space-between; transition: border-color 0.15s ease;">
            <div>
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-family: var(--font-mono); font-weight: bold; font-size: 12px; color: var(--accent-info);">${escapeHtml(shortId)}</span>
                <span class="badge ${status === 'ACTIVE' ? 'badge-net' : 'badge-host'}">${escapeHtml(status)}</span>
              </div>
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px; color: var(--text-primary); line-height: 1.4;">${escapeHtml(c.title || 'Безымянное дело')}</div>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 12px; border-top: 1px solid var(--border-muted); padding-top: 8px; display: flex; justify-content: space-between; align-items: center;">
              <span>Создано: ${escapeHtml(dateStr)}</span>
              <span style="color: var(--accent-info); font-size: 11px;">Открыть ▶</span>
            </div>
          </div>
        `;
      })
      .join('');

    grid.querySelectorAll('.op-case-card').forEach((card) => {
      card.addEventListener('click', () => {
        const caseId = card.getAttribute('data-case');
        if (caseId && this.onSelectCase) {
          this.onSelectCase(caseId);
        }
      });
    });
  }
}

/**
 * challenge_matrix.js - Jeopardy Challenge Matrix Component
 * Displays competition challenges in a categorized Jeopardy grid with filters,
 * progress metrics, and dual-channel status indicators (Contract B / Role 18).
 */

import { workspaceStore } from '../workspace_store.js';

const CATEGORY_META = {
  web: { label: 'Web', code: 'W', glyph: '◈', badgeClass: 'ctf-badge-web' },
  crypto: { label: 'Crypto', code: 'C', glyph: '⬡', badgeClass: 'ctf-badge-crypto' },
  reverse: { label: 'Reverse', code: 'R', glyph: '⎔', badgeClass: 'ctf-badge-reverse' },
  pwn: { label: 'Pwn', code: 'P', glyph: '▲', badgeClass: 'ctf-badge-pwn' },
  forensics: { label: 'Forensics', code: 'F', glyph: '◼', badgeClass: 'ctf-badge-forensics' },
  stego: { label: 'Stego', code: 'S', glyph: '●', badgeClass: 'ctf-badge-stego' },
  osint: { label: 'OSINT', code: 'O', glyph: '◉', badgeClass: 'ctf-badge-osint' },
  misc: { label: 'Misc', code: 'M', glyph: '★', badgeClass: 'ctf-badge-misc' }
};

const STATUS_META = {
  Unsolved: { label: 'Unsolved', glyph: '○', badgeClass: 'ctf-status-unsolved' },
  InProgress: { label: 'In Progress', glyph: '●', badgeClass: 'ctf-status-inprogress' },
  Solved: { label: 'Solved', glyph: '◼', badgeClass: 'ctf-status-solved' },
  Blocked: { label: 'Blocked', glyph: '▲', badgeClass: 'ctf-status-blocked' }
};

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

export class ChallengeMatrix {
  /**
   * @param {Object} [options]
   * @param {import('../workspace_store.js').WorkspaceStore} [options.store=workspaceStore]
   * @param {(challengeId: string) => void} [options.onSelectChallenge]
   */
  constructor(options = {}) {
    this.store = options.store || workspaceStore;
    this.onSelectChallenge = options.onSelectChallenge || null;
    this.onSeedDemo = options.onSeedDemo || null;

    this.container = null;
    this.selectedCategory = 'all';
    this.searchQuery = '';
    this.unsubscribe = null;
  }

  mount(container) {
    this.container = container;
    this.unsubscribe = this.store.subscribe(() => this.render());
    this.render();
  }

  destroy() {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    if (this.container) {
      this.container.innerHTML = '';
      this.container = null;
    }
  }

  setCategoryFilter(category) {
    this.selectedCategory = category;
    this.render();
  }

  setSearchQuery(query) {
    this.searchQuery = (query || '').toLowerCase().trim();
    this.render();
  }

  getFilteredChallenges() {
    const { challenges } = this.store.getState();
    const list = Object.values(challenges || {});

    return list.filter((ch) => {
      const cat = (ch.category || 'misc').toLowerCase();
      if (this.selectedCategory !== 'all' && cat !== this.selectedCategory) {
        return false;
      }
      if (this.searchQuery) {
        const titleMatch = (ch.title || '').toLowerCase().includes(this.searchQuery);
        const descMatch = (ch.description || '').toLowerCase().includes(this.searchQuery);
        if (!titleMatch && !descMatch) return false;
      }
      return true;
    });
  }

  render() {
    if (!this.container) return;

    const state = this.store.getState();
    const allChallenges = Object.values(state.challenges || {});
    const filtered = this.getFilteredChallenges();

    const totalCount = allChallenges.length;
    const solvedCount = allChallenges.filter((c) => c.status === 'Solved').length;
    const totalPoints = allChallenges.reduce((acc, c) => acc + (Number(c.points) || 0), 0);
    const solvedPoints = allChallenges
      .filter((c) => c.status === 'Solved')
      .reduce((acc, c) => acc + (Number(c.points) || 0), 0);
    const progressPercent = totalCount > 0 ? Math.round((solvedCount / totalCount) * 100) : 0;

    const compTitle = state.activeCompetition?.title || 'CTF Competition Matrix';
    const hasCompetition = Boolean(state.activeCompetitionId);

    this.container.innerHTML = `
      <div class="ctf-matrix-view">
        <div class="ctf-matrix-toolbar">
          <div class="ctf-matrix-title">
            <span>⬡</span>
            <span>${escapeHtml(compTitle)}</span>
          </div>

          <div class="ctf-matrix-progress">
            <span>Solved: <strong>${solvedCount}/${totalCount}</strong></span>
            <span>Score: <strong>${solvedPoints}/${totalPoints} pts</strong></span>
            <div class="ctf-progress-bar-wrap" title="${progressPercent}% Solved">
              <div class="ctf-progress-bar-fill" style="width: ${progressPercent}%;"></div>
            </div>
          </div>
          <div class="ctf-matrix-actions" style="display:flex;gap:8px;align-items:center;">
            <label for="ctfCompetitionSelect">Соревнование</label>
            <select id="ctfCompetitionSelect" aria-label="Выбрать CTF соревнование">
              ${(state.competitions || []).map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.activeCompetitionId ? 'selected' : ''}>${escapeHtml(item.name)}</option>`).join('')}
            </select>
            <button class="ctf-btn ctf-btn-secondary" id="ctfCreateCompetition">Новое соревнование</button>
            <button class="ctf-btn ctf-btn-secondary" id="ctfSeedDemoBtn" title="Загрузить тренировочный CTF полигон">⚡ Demo Lab</button>
            ${hasCompetition ? '<button class="ctf-btn ctf-btn-primary" id="ctfCreateChallenge">Добавить задание</button>' : ''}
          </div>
        </div>

        ${state.isLoading ? '<div role="status" class="ctf-empty-state">Загрузка соревнований…</div>' : ''}
        ${state.error ? `<div role="alert" class="ctf-empty-state">Не удалось загрузить CTF данные: ${escapeHtml(state.error)} <button class="ctf-btn ctf-btn-secondary" id="ctfRetryLoad">Повторить</button></div>` : ''}

        <div class="ctf-matrix-filters">
          <button class="ctf-btn ${this.selectedCategory === 'all' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-cat="all">
            All (${totalCount})
          </button>
          ${Object.entries(CATEGORY_META).map(([catKey, meta]) => {
            const count = allChallenges.filter((c) => (c.category || '').toLowerCase() === catKey).length;
            const isSelected = this.selectedCategory === catKey;
            return `
              <button class="ctf-btn ${isSelected ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-cat="${catKey}">
                <span class="ctf-badge ${meta.badgeClass}">[${meta.code}] ${meta.glyph}</span>
                <span>${meta.label}</span>
                <span style="opacity: 0.7;">(${count})</span>
              </button>
            `;
          }).join('')}
        </div>

        <div class="ctf-matrix-body">
          ${filtered.length === 0 ? (totalCount === 0 ? `
              <div style="font-size:14px;font-weight:600;color:var(--ctf-text-primary);margin-bottom:8px;">
                ${hasCompetition ? 'В этом соревновании пока нет заданий' : 'Платформа готова к работе'}
              </div>
              <div style="font-size:12px;margin-bottom:16px;">
                ${hasCompetition ? 'Вы можете создать задание вручную или загрузить готовый тренировочный стенд.' : 'Создайте соревнование или мгновенно разверните тренировочный полигон (5 тасков с артефактами).'}
              </div>
              <div style="display:flex;gap:10px;justify-content:center;">
                <button class="ctf-btn ctf-btn-primary" id="ctfSeedDemoEmptyBtn">⚡ Загрузить тренировочный полигон (Demo Lab)</button>
                ${hasCompetition ? '<button class="ctf-btn ctf-btn-secondary" id="ctfCreateChallengeEmpty">+ Создать задание</button>' : '<button class="ctf-btn ctf-btn-secondary" id="ctfCreateCompetitionEmpty">+ Создать турнир</button>'}
              </div>
            </div>
          ` : `
            <div style="text-align: center; padding: 48px; color: var(--ctf-text-secondary); font-family: var(--ctf-font-mono);">
              Ничего не найдено. Очистите поиск или фильтры.
              <button class="ctf-btn ctf-btn-secondary" id="ctfClearFilters">Сбросить фильтры</button>
            </div>
          `) : `
            <div class="ctf-matrix-grid">
              ${filtered.map((chal) => this.renderCardHtml(chal, state.activeChallengeId)).join('')}
            </div>
          `}
        </div>
      </div>
    `;

    this.bindEvents();
  }

  renderCardHtml(chal, activeId) {
    const catKey = (chal.category || 'misc').toLowerCase();
    const catMeta = CATEGORY_META[catKey] || CATEGORY_META.misc;
    const statusMeta = STATUS_META[chal.status] || STATUS_META.Unsolved;
    const isSelected = chal.id === activeId;
    const isSolved = chal.status === 'Solved';
    const isInProgress = chal.status === 'InProgress';

    return `
      <div class="ctf-challenge-card ${isSelected ? 'selected' : ''} ${isSolved ? 'solved' : ''} ${isInProgress ? 'inprogress' : ''}" data-challenge-id="${escapeHtml(chal.id)}">
        <div class="ctf-card-header">
          <span class="ctf-badge ${catMeta.badgeClass}">[${catMeta.code}] ${catMeta.glyph} ${catMeta.label}</span>
          <span class="ctf-card-points">${chal.points || 100} pts</span>
        </div>

        <div class="ctf-card-title" title="${escapeHtml(chal.title || chal.id)}">
          ${escapeHtml(chal.title || 'Untitled Challenge')}
        </div>

        <div class="ctf-card-footer">
          <span class="ctf-badge ${statusMeta.badgeClass}">
            ${statusMeta.glyph} ${statusMeta.label}
          </span>
          <span style="font-family: var(--ctf-font-mono); font-size: 11px; opacity: 0.8;">
            ${chal.tags && chal.tags.length ? escapeHtml(chal.tags.slice(0, 2).join(', ')) : ''}
          </span>
        </div>
      </div>
    `;
  }

  bindEvents() {
    if (!this.container) return;

    const select = this.container.querySelector('#ctfCompetitionSelect');
    select?.addEventListener('change', async (e) => {
      try { await this.store.loadCompetition(e.target.value); }
      catch (_) { /* the store exposes the error state */ }
    });
    this.container.querySelector('#ctfRetryLoad')?.addEventListener('click', () => this.store.loadCompetitions().catch(() => {}));
    this.container.querySelector('#ctfClearFilters')?.addEventListener('click', () => { this.selectedCategory = 'all'; this.searchQuery = ''; this.render(); });
    const createCompetition = async () => {
      const name = window.prompt('Название соревнования');
      if (!name?.trim()) return;
      try { await this.store.createCompetition({ name }); } catch (_) { /* visible store error */ }
    };
    this.container.querySelector('#ctfCreateCompetition')?.addEventListener('click', createCompetition);
    this.container.querySelector('#ctfCreateCompetitionEmpty')?.addEventListener('click', createCompetition);
    const triggerSeed = async () => {
      if (this.onSeedDemo) {
        await this.onSeedDemo();
      }
    };
    this.container.querySelector('#ctfSeedDemoBtn')?.addEventListener('click', triggerSeed);
    this.container.querySelector('#ctfSeedDemoEmptyBtn')?.addEventListener('click', triggerSeed);
    const createChallenge = async () => {
      const name = window.prompt('Название задания');
      if (!name?.trim()) return;
      const category = window.prompt('Категория (forensics, web, crypto, pwn, reverse, misc, osint, stego, network)', 'forensics');
      if (!category?.trim()) return;
      const expected_flag = window.prompt('Эталонный флаг (хранится в виде SHA-256, никогда не показывается участникам)');
      if (!expected_flag?.trim()) return;
      try { await this.store.createChallenge({ name, category: category.trim().toLowerCase(), expected_flag }); } catch (_) { /* visible store error */ }
    };
    this.container.querySelector('#ctfCreateChallenge')?.addEventListener('click', createChallenge);
    this.container.querySelector('#ctfCreateChallengeEmpty')?.addEventListener('click', createChallenge);

    // Category filter clicks
    this.container.querySelectorAll('.ctf-matrix-filters button[data-cat]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const cat = e.currentTarget.getAttribute('data-cat');
        this.setCategoryFilter(cat);
      });
    });

    // Challenge card clicks
    this.container.querySelectorAll('.ctf-challenge-card[data-challenge-id]').forEach((card) => {
      card.addEventListener('click', async (e) => {
        const chalId = e.currentTarget.getAttribute('data-challenge-id');
        if (!chalId) return;

        try {
          await this.store.selectChallenge(chalId);
          if (this.onSelectChallenge) {
            this.onSelectChallenge(chalId);
          }
        } catch (err) {
          this.store.setState({ error: err.message });
        }
      });
    });
  }
}

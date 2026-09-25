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
        </div>

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
          ${filtered.length === 0 ? `
            <div style="text-align: center; padding: 48px; color: var(--ctf-text-secondary); font-family: var(--ctf-font-mono);">
              [!] Нет задач, удовлетворяющих заданным критериям фильтра
            </div>
          ` : `
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
          console.error('[ChallengeMatrix] Failed to select challenge:', err);
        }
      });
    });
  }
}

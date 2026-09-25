/**
 * flag_drawer.js - Flag Candidates Drawer & Validation Component
 * Implements Contract B (FlagCandidatePill & FlagDrawer) from docs/it-company/16-frontend-architect.md
 * Multi-status pills, quick accept/reject actions, and hotkeys (Ctrl+Shift+A / Ctrl+Shift+R).
 */

import { flagStore } from '../flag_store.js';

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

export class FlagDrawer {
  /**
   * @param {Object} [options]
   * @param {import('../flag_store.js').FlagStore} [options.store=flagStore]
   */
  constructor(options = {}) {
    this.store = options.store || flagStore;
    this.container = null;
    this.unsubscribe = null;
    this.keydownHandler = null;
  }

  mount(container) {
    this.container = container;
    this.unsubscribe = this.store.subscribe(() => this.render());
    this.setupKeybindings();
    this.render();
    const challengeId = this.store.workspaceStore?.getState?.().activeChallengeId;
    if (challengeId) this.store.loadFlags(challengeId).catch(() => {});
  }

  destroy() {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    if (this.keydownHandler) {
      window.removeEventListener('keydown', this.keydownHandler);
      this.keydownHandler = null;
    }
    if (this.container) {
      this.container.innerHTML = '';
      this.container = null;
    }
  }

  setupKeybindings() {
    this.keydownHandler = (e) => {
      // Ctrl+Shift+A: Accept top candidate
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'a') {
        e.preventDefault();
        this.acceptTopCandidate();
      }
      // Ctrl+Shift+R: Reject top candidate
      else if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'r') {
        e.preventDefault();
        this.rejectTopCandidate();
      }
    };
    window.addEventListener('keydown', this.keydownHandler);
  }

  async acceptTopCandidate() {
    const { candidates } = this.store.getState();
    const top = candidates.find((c) => c.status === 'candidate');
    if (top) {
      try {
        await this.store.acceptFlag(top.id);
      } catch (err) {
        console.error('[FlagDrawer] Failed to accept top candidate:', err);
      }
    }
  }

  async rejectTopCandidate() {
    const { candidates } = this.store.getState();
    const top = candidates.find((c) => c.status === 'candidate');
    if (top) {
      try {
        await this.store.rejectFlag(top.id, 'User rejected via hotkey');
      } catch (err) {
        console.error('[FlagDrawer] Failed to reject top candidate:', err);
      }
    }
  }

  render() {
    if (!this.container) return;

    const state = this.store.getState();
    const { filter, unreviewedCount } = state;
    const filtered = this.store.getFilteredCandidates();

    this.container.innerHTML = `
      <div style="padding: 12px; display: flex; flex-direction: column; height: 100%; gap: 10px;">
        <!-- Filter Tabs -->
        <div style="display: flex; gap: 4px; border-bottom: 1px solid var(--ctf-border-default); padding-bottom: 8px;">
          <button class="ctf-btn ${filter === 'all' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-filter="all" style="height: 24px; font-size: 11px;">
            All
          </button>
          <button class="ctf-btn ${filter === 'candidates' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-filter="candidates" style="height: 24px; font-size: 11px;">
            Pending (${unreviewedCount})
          </button>
          <button class="ctf-btn ${filter === 'accepted' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-filter="accepted" style="height: 24px; font-size: 11px;">
            Solved
          </button>
          <button class="ctf-btn ${filter === 'rejected' ? 'ctf-btn-primary' : 'ctf-btn-secondary'}" data-filter="rejected" style="height: 24px; font-size: 11px;">
            Rejected
          </button>
        </div>

        <!-- Manual Flag Submission Input -->
        <div style="display: flex; gap: 6px;">
          <input
            type="text"
            id="ctfManualFlagInput"
            class="ctf-terminal-input"
            placeholder="flag{...}"
            style="flex: 1; height: 28px;"
          />
          <button class="ctf-btn ctf-btn-primary" id="ctfSubmitManualFlagBtn" style="height: 28px;">
            + Отправить на проверку
          </button>
        </div>

        ${state.isLoading ? '<div role="status">Загрузка флагов…</div>' : ''}
        ${state.error ? `<div role="alert">${escapeHtml(state.error)}</div>` : ''}

        <!-- Candidate Pills List -->
        <div style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px;">
          ${filtered.length === 0 ? `
            <div style="text-align: center; padding: 24px; color: var(--ctf-text-muted); font-size: 11px; font-family: var(--ctf-font-mono);">
              [Нет кандидатов флагов]
            </div>
          ` : `
            ${filtered.map((item, idx) => this.renderCandidatePillHtml(item, idx)).join('')}
          `}
        </div>
      </div>
    `;

    this.bindEvents();
  }

  renderCandidatePillHtml(c, idx) {
    const isCandidate = c.status === 'candidate';
    const isAccepted = c.status === 'accepted';
    const isRejected = c.status === 'rejected';

    let glyph = '⬡';
    let statusLabel = 'CANDIDATE';
    let pillClass = '';

    if (isAccepted) {
      glyph = '◼';
      statusLabel = 'SOLVED';
      pillClass = 'accepted';
    } else if (isRejected) {
      glyph = '▲';
      statusLabel = 'REJECTED';
      pillClass = 'rejected';
    }

    const flagValue = c.value ?? c.flag ?? '';
    const timeStr = (c.timestamp || c.submitted_at) ? new Date(c.timestamp || c.submitted_at).toLocaleTimeString() : '';

    return `
      <div class="ctf-flag-candidate-pill ${pillClass}" data-candidate-id="${escapeHtml(c.id)}">
        <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px;">
          <span style="font-weight: 700; color: ${isAccepted ? 'var(--ctf-accent-emerald)' : isRejected ? 'var(--ctf-accent-rose)' : 'var(--ctf-accent-amber)'};">
            ${glyph} ${statusLabel} #${String(idx + 1).padStart(2, '0')}
          </span>
          <span class="ctf-badge ctf-badge-misc" style="height: 18px; font-size: 9px;">
            SRC: ${escapeHtml(c.source || 'unknown')}
          </span>
          <span style="font-family: var(--ctf-font-mono); font-size: 10px; color: var(--ctf-text-muted);">
            ${timeStr}
          </span>
        </div>

        <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin: 4px 0;">
          <div class="ctf-flag-string">
            ${escapeHtml(flagValue)}
          </div>
          <button class="ctf-btn ctf-btn-ghost ctf-copy-flag-btn" data-flag="${escapeHtml(flagValue)}" style="height: 22px; padding: 0 6px;" title="Копировать в буфер">
            📋
          </button>
        </div>

        ${isCandidate ? `
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 4px;">
            <button class="ctf-btn ctf-btn-accept ctf-accept-flag-btn" data-candidate-id="${escapeHtml(c.id)}" style="height: 24px; font-size: 11px;" title="Принять флаг (Ctrl+Shift+A)">
              ✔ Проверить <span class="ctf-hotkey" style="font-size: 9px; padding: 0 3px;">^⇧A</span>
            </button>
            <button class="ctf-btn ctf-btn-reject ctf-reject-flag-btn" data-candidate-id="${escapeHtml(c.id)}" style="height: 24px; font-size: 11px;" title="Отклонить ложное срабатывание (Ctrl+Shift+R)">
              ✕ Reject <span class="ctf-hotkey" style="font-size: 9px; padding: 0 3px;">^⇧R</span>
            </button>
          </div>
        ` : ''}
      </div>
    `;
  }

  bindEvents() {
    if (!this.container) return;

    // Filter Buttons
    this.container.querySelectorAll('button[data-filter]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const f = e.currentTarget.getAttribute('data-filter');
        this.store.setFilter(f);
      });
    });

    // Manual Submit
    const manualInput = this.container.querySelector('#ctfManualFlagInput');
    const submitBtn = this.container.querySelector('#ctfSubmitManualFlagBtn');

    const handleManualSubmit = async () => {
      const val = manualInput?.value.trim();
      if (!val) return;
      try {
        await this.store.registerCandidate(val, 'manual');
        if (manualInput) manualInput.value = '';
      } catch (err) {
        console.error('[FlagDrawer] Failed to submit manual flag:', err);
      }
    };

    submitBtn?.addEventListener('click', handleManualSubmit);
    manualInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleManualSubmit();
    });

    // Accept / Reject buttons
    this.container.querySelectorAll('.ctf-accept-flag-btn').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-candidate-id');
        try {
          await this.store.acceptFlag(id);
        } catch (err) {
          console.error('[FlagDrawer] Accept flag error:', err);
        }
      });
    });

    this.container.querySelectorAll('.ctf-reject-flag-btn').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-candidate-id');
        try {
          await this.store.rejectFlag(id, 'User rejected from UI drawer');
        } catch (err) {
          console.error('[FlagDrawer] Reject flag error:', err);
        }
      });
    });

    // Copy button
    this.container.querySelectorAll('.ctf-copy-flag-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const flag = e.currentTarget.getAttribute('data-flag');
        if (flag) this.store.copyFlagToClipboard(flag);
      });
    });
  }
}

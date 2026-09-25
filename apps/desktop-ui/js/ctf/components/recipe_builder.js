/**
 * recipe_builder.js - CyberChef-like Visual Transformation Pipeline Component
 * Implements Contract B (RecipeBuilder & RecipeStepCard) from docs/it-company/16-frontend-architect.md
 * Interactive step card list, in-memory live preview, flag detection, and CAS export.
 */

import { recipeStore } from '../recipe_store.js';
import { flagStore } from '../flag_store.js';

const AVAILABLE_OPERATIONS = [
  { id: 'base64_decode', name: 'From Base64', desc: 'Декодирование Base64 строки в байты/текст' },
  { id: 'base64_encode', name: 'To Base64', desc: 'Кодирование текста или байт в Base64' },
  { id: 'hex_decode', name: 'From Hex', desc: 'Преобразование hex-строки (41 42 43) в байты' },
  { id: 'hex_encode', name: 'To Hex', desc: 'Преобразование байт в hex-строку' },
  { id: 'xor', name: 'XOR', desc: 'Побитовый XOR с текстовым или hex-ключом', hasKey: true },
  { id: 'rot13', name: 'ROT13', desc: 'Симметричный шифр сдвига алфавита на 13 позиций' },
  { id: 'url_decode', name: 'URL Decode', desc: 'Декодирование percent-encoding' },
  { id: 'url_encode', name: 'URL Encode', desc: 'Кодирование строки в URL percent-encoding' },
  { id: 'reverse', name: 'Reverse', desc: 'Инвертирование порядка символов/байт' }
];

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

export class RecipeBuilder {
  /**
   * @param {Object} [options]
   * @param {import('../recipe_store.js').RecipeStore} [options.store=recipeStore]
   * @param {import('../flag_store.js').FlagStore} [options.flags=flagStore]
   */
  constructor(options = {}) {
    this.store = options.store || recipeStore;
    this.flags = options.flags || flagStore;

    this.container = null;
    this.unsubscribe = null;
    this.isSaving = false;
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

  render() {
    if (!this.container) return;

    const state = this.store.getState();
    const ops = state.operations || [];
    const preview = state.livePreviewText || '';
    const detectedFlags = state.detectedFlags || [];

    this.container.innerHTML = `
      <div class="ctf-recipe-view">
        <!-- Top Action Bar -->
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-weight: 700; color: var(--ctf-text-primary); font-size: 14px;">⚙ TRANSFORMATION RECIPE</span>
            <span class="ctf-badge ctf-badge-crypto">${ops.length} STEPS</span>
          </div>

          <div style="display: flex; gap: 8px; align-items: center;">
            <select id="ctfAddOpSelect" class="ctf-terminal-input" style="height: 28px;">
              <option value="">+ Add Operation...</option>
              ${AVAILABLE_OPERATIONS.map((o) => `<option value="${o.id}">${o.name}</option>`).join('')}
            </select>

            <button class="ctf-btn ctf-btn-secondary" id="ctfClearRecipeBtn">
              Clear All
            </button>

            <button class="ctf-btn ctf-btn-primary" id="ctfSaveArtifactBtn" ${this.isSaving ? 'disabled' : ''}>
              ${this.isSaving ? 'Saving...' : '💾 Save as Artifact'}
            </button>
          </div>
        </div>

        <!-- Detected Flags Alert Banner -->
        ${detectedFlags.length > 0 ? `
          <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid var(--ctf-accent-emerald); border-radius: var(--ctf-radius-md); padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <span style="font-weight: 700; color: var(--ctf-accent-emerald); font-size: 12px;">
                ⬡ DETECTED ${detectedFlags.length} FLAG CANDIDATE(S):
              </span>
              <button class="ctf-btn ctf-btn-accept" id="ctfSendAllFlagsBtn" style="height: 22px; font-size: 11px;">
                + Send to Flag Drawer
              </button>
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
              ${detectedFlags.map((f) => `
                <span class="ctf-badge ctf-status-solved" style="font-size: 11px; padding: 2px 8px; height: auto;">
                  ${escapeHtml(f)}
                </span>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Dual Pane: Input + Steps List -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; flex: 1; min-height: 0;">
          <!-- Left: Input Payload & Pipeline Cards -->
          <div style="display: flex; flex-direction: column; gap: 10px; overflow-y: auto;">
            <div>
              <div style="font-size: 11px; font-weight: 700; color: var(--ctf-text-secondary); margin-bottom: 4px;">
                INPUT PAYLOAD (ASCII / HEX):
              </div>
              <textarea
                id="ctfRecipeInputTextarea"
                class="ctf-terminal-input"
                style="width: 100%; height: 90px; resize: vertical; font-family: var(--ctf-font-mono); font-size: 12px;"
                placeholder="Вставьте анализируемые данные (Base64, Hex, зашифрованный текст)..."
              ></textarea>
            </div>

            <div style="font-size: 11px; font-weight: 700; color: var(--ctf-text-secondary);">
              TRANSFORMATION STEPS:
            </div>

            ${ops.length === 0 ? `
              <div style="padding: 24px; text-align: center; border: 1px dashed var(--ctf-border-default); border-radius: var(--ctf-radius-md); color: var(--ctf-text-muted); font-size: 12px; font-family: var(--ctf-font-mono);">
                [Конвейер пуст. Выберите операцию сверху для добавления]
              </div>
            ` : `
              <div style="display: flex; flex-direction: column; gap: 8px;">
                ${ops.map((op, idx) => this.renderStepCardHtml(op, idx, ops.length)).join('')}
              </div>
            `}
          </div>

          <!-- Right: Live Preview Box -->
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <span style="font-size: 11px; font-weight: 700; color: var(--ctf-text-secondary);">
                LIVE OUTPUT PREVIEW:
              </span>
              <span style="font-family: var(--ctf-font-mono); font-size: 11px; color: var(--ctf-text-offset);">
                Length: ${preview.length} chars
              </span>
            </div>

            <div class="ctf-recipe-preview-box" id="ctfRecipePreviewContainer">
              ${escapeHtml(preview || '[No output preview]')}
            </div>
          </div>
        </div>
      </div>
    `;

    this.bindEvents();
  }

  renderStepCardHtml(op, index, total) {
    const isMuted = Boolean(op.isMuted);
    const meta = AVAILABLE_OPERATIONS.find((o) => o.id === op.operation) || { name: op.operation };
    const stepNum = String(index + 1).padStart(2, '0');

    return `
      <div class="ctf-recipe-step-card ${isMuted ? 'muted' : ''}" data-step-index="${index}">
        <div class="ctf-recipe-step-header">
          <div style="display: flex; align-items: center; gap: 6px;">
            <span class="ctf-drag-handle" title="Drag to reorder">::</span>
            <span class="ctf-step-num">#${stepNum}</span>
            <span class="ctf-step-title">${escapeHtml(meta.name)}</span>
          </div>

          <div style="display: flex; align-items: center; gap: 4px;">
            <button class="ctf-btn ctf-btn-ghost ctf-move-up-btn" data-index="${index}" ${index === 0 ? 'disabled' : ''} title="Move Up">
              ▲
            </button>
            <button class="ctf-btn ctf-btn-ghost ctf-move-down-btn" data-index="${index}" ${index === total - 1 ? 'disabled' : ''} title="Move Down">
              ▼
            </button>
            <button class="ctf-btn ${isMuted ? 'ctf-btn-secondary' : 'ctf-btn-ghost'} ctf-mute-step-btn" data-index="${index}" title="Toggle Step Mute">
              ${isMuted ? '● Unmute' : '○ Mute'}
            </button>
            <button class="ctf-btn ctf-btn-ghost ctf-remove-step-btn" data-index="${index}" style="color: var(--ctf-accent-rose);" title="Remove Step">
              ✕
            </button>
          </div>
        </div>

        ${meta.hasKey ? `
          <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
            <span style="font-size: 11px; color: var(--ctf-text-secondary);">Key:</span>
            <input
              type="text"
              class="ctf-terminal-input ctf-step-key-input"
              data-index="${index}"
              value="${escapeHtml(op.params?.key ?? '')}"
              placeholder="e.g. secret or 0x5A"
              style="height: 24px; font-size: 11px; flex: 1;"
            />
          </div>
        ` : ''}
      </div>
    `;
  }

  bindEvents() {
    if (!this.container) return;

    // Add operation select
    const addSelect = this.container.querySelector('#ctfAddOpSelect');
    addSelect?.addEventListener('change', (e) => {
      const opId = e.target.value;
      if (!opId) return;
      this.store.addOperation({ operation: opId, params: {} });
      addSelect.value = '';
    });

    // Clear all steps
    this.container.querySelector('#ctfClearRecipeBtn')?.addEventListener('click', () => {
      this.store.clearOperations();
    });

    // Input text change
    const inputArea = this.container.querySelector('#ctfRecipeInputTextarea');
    inputArea?.addEventListener('input', (e) => {
      this.store.setInputData(e.target.value);
    });

    // Save as artifact
    this.container.querySelector('#ctfSaveArtifactBtn')?.addEventListener('click', async () => {
      this.isSaving = true;
      this.render();
      try {
        await this.store.executeAndSaveArtifact();
      } catch (err) {
        console.error('[RecipeBuilder] Save artifact error:', err);
      } finally {
        this.isSaving = false;
        this.render();
      }
    });

    // Send detected flags to Flag Store
    this.container.querySelector('#ctfSendAllFlagsBtn')?.addEventListener('click', async () => {
      const state = this.store.getState();
      const detected = state.detectedFlags || [];
      for (const flag of detected) {
        try {
          await this.flags.registerCandidate(flag, 'recipe');
        } catch (err) {
          console.error('[RecipeBuilder] Failed to register flag candidate:', err);
        }
      }
    });

    // Step card actions (Mute, Remove, Reorder, Param edit)
    this.container.querySelectorAll('.ctf-mute-step-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const idx = Number(e.currentTarget.getAttribute('data-index'));
        this.store.toggleMute(idx);
      });
    });

    this.container.querySelectorAll('.ctf-remove-step-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const idx = Number(e.currentTarget.getAttribute('data-index'));
        this.store.removeOperation(idx);
      });
    });

    this.container.querySelectorAll('.ctf-move-up-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const idx = Number(e.currentTarget.getAttribute('data-index'));
        if (idx > 0) this.store.reorderOperations(idx, idx - 1);
      });
    });

    this.container.querySelectorAll('.ctf-move-down-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const idx = Number(e.currentTarget.getAttribute('data-index'));
        this.store.reorderOperations(idx, idx + 1);
      });
    });

    this.container.querySelectorAll('.ctf-step-key-input').forEach((input) => {
      input.addEventListener('change', (e) => {
        const idx = Number(e.currentTarget.getAttribute('data-index'));
        const newKey = e.currentTarget.value;
        this.store.updateParams(idx, { key: newKey });
      });
    });
  }
}

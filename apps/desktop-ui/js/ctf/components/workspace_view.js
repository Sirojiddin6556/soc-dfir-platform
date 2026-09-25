/**
 * workspace_view.js - 4-Sector Unified Workspace Component
 * Implements Contract B (SplitPane Architecture) from docs/it-company/16-frontend-architect.md
 * Left (Scope & Artifact Tree) | Center (Main Tabs) | Bottom (Terminal) | Right (Flags Drawer)
 */

import { workspaceStore } from '../workspace_store.js';

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return `${(b / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export class WorkspaceView {
  /**
   * @param {Object} [options]
   * @param {import('../workspace_store.js').WorkspaceStore} [options.store=workspaceStore]
   * @param {(tabId: string) => void} [options.onTabChange]
   * @param {(artifactId: string) => void} [options.onSelectArtifact]
   */
  constructor(options = {}) {
    this.store = options.store || workspaceStore;
    this.onTabChange = options.onTabChange || null;
    this.onSelectArtifact = options.onSelectArtifact || null;
    this.onRenderSlots = options.onRenderSlots || null;
    this.onNavigateBack = options.onNavigateBack || null;

    this.container = null;
    this.activeTab = options.initialTab || 'recipe'; // 'hex' | 'recipe' | 'writeup'
    this.selectedArtifactId = null;
    this.unsubscribe = null;
  }

  mount(container) {
    this.container = container;
    this.unsubscribe = this.store.subscribe(() => this.render());
    this.setupKeybindings();
    this.render();
  }

  destroy() {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    this.onRenderSlots = null;
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
      // Ctrl+B: Toggle Left Artifact Pane
      if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        this.store.togglePanel('left');
      }
      // Ctrl+J: Toggle Bottom Terminal Pane
      else if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === 'j') {
        e.preventDefault();
        this.store.togglePanel('bottom');
      }
      // Ctrl+Shift+F: Toggle Right Flags Drawer
      else if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        this.store.togglePanel('rightDrawer');
      }
    };
    window.addEventListener('keydown', this.keydownHandler);
  }

  setActiveTab(tabId) {
    this.activeTab = tabId;
    if (this.onTabChange) this.onTabChange(tabId);
    this.render();
  }

  getCenterSlotElement() {
    return this.container?.querySelector('#ctfCenterSlot') || null;
  }

  getBottomSlotElement() {
    return this.container?.querySelector('#ctfBottomSlot') || null;
  }

  getRightSlotElement() {
    return this.container?.querySelector('#ctfRightSlot') || null;
  }

  render() {
    if (!this.container) return;

    const state = this.store.getState();
    const chal = state.activeChallenge;
    const { left, bottom, rightDrawer } = state.activePanels;

    const chalTitle = chal?.title || chal?.name || 'No Challenge Selected';
    const chalCategory = (chal?.category || 'misc').toUpperCase();
    const chalPoints = chal?.points || 0;
    const chalStatus = chal?.status || 'Unsolved';

    this.container.innerHTML = `
      <div class="ctf-workspace" style="
        grid-template-columns: ${left ? '280px' : '0px'} 1fr ${rightDrawer ? '360px' : '0px'};
        grid-template-rows: 1fr ${bottom ? '260px' : '0px'};
      ">
        <!-- 1. LEFT PANE: Scope & Artifacts Tree -->
        <div class="ctf-pane-left" style="display: ${left ? 'flex' : 'none'};">
          <div class="ctf-pane-header">
            <div class="ctf-pane-header-title">
              <span>◈</span>
              <span>ARTIFACT TREE</span>
            </div>
            <div style="display: flex; gap: 4px; align-items: center;">
              <span class="ctf-hotkey">Ctrl+B</span>
              <button class="ctf-btn ctf-btn-ghost" id="ctfCloseLeftBtn" title="Скрыть панель (Ctrl+B)">✕</button>
            </div>
          </div>

          <div style="padding: 8px 12px; border-bottom: 1px solid var(--ctf-border-subtle); display: flex; gap: 6px;">
            <input type="file" id="ctfArtifactFileInput" style="display: none;" />
            <button class="ctf-btn ctf-btn-primary" id="ctfImportArtifactBtn" style="flex: 1; height: 26px;">
              + Import File
            </button>
          </div>

          <div style="flex: 1; overflow-y: auto; padding: 6px 0;">
            ${this.renderArtifactTreeHtml(state.artifactTree)}
          </div>
        </div>

        <!-- 2. CENTER PANE: Header & Main Tabs -->
        <div class="ctf-pane-center">
          <div class="ctf-pane-header" style="height: 44px; padding: 0 16px; border-bottom: 1px solid var(--ctf-border-default);">
            <div class="ctf-pane-header-title" style="font-size: 14px; display:flex; align-items:center; gap:8px;">
              <button class="ctf-btn ctf-btn-ghost" id="ctfBackToMatrixBtn" title="Вернуться к матрице заданий" style="height:26px;font-size:11px;padding:0 6px;">◀ К матрице</button>
              <span class="ctf-badge ctf-badge-${chalCategory.toLowerCase()}">[${chalCategory.slice(0, 1)}] ${chalCategory}</span>
              <span style="font-weight: 700; color: var(--ctf-text-primary);">${escapeHtml(chalTitle)}</span>
              <span style="font-family: var(--ctf-font-mono); font-size: 12px; color: var(--ctf-accent-cyan); font-weight: 700;">(${chalPoints} pts)</span>
            </div>

            <div style="display: flex; align-items: center; gap: 10px;">
              <select id="ctfChallengeStatusSelect" class="ctf-terminal-input" style="height: 26px; padding: 2px 6px;">
                <option value="Unsolved" ${chalStatus === 'Unsolved' ? 'selected' : ''}>○ Unsolved</option>
                <option value="InProgress" ${chalStatus === 'InProgress' ? 'selected' : ''}>● In Progress</option>
                <option value="Solved" ${chalStatus === 'Solved' ? 'selected' : ''}>◼ Solved</option>
                <option value="Blocked" ${chalStatus === 'Blocked' ? 'selected' : ''}>▲ Blocked</option>
              </select>

              <button class="ctf-btn ctf-btn-secondary" id="ctfToggleLeftBtn" title="Toggle Tree (Ctrl+B)">
                ${left ? '◀ Hide Tree' : '▶ Tree'}
              </button>
              <button class="ctf-btn ctf-btn-secondary" id="ctfToggleBottomBtn" title="Toggle Terminal (Ctrl+J)">
                ${bottom ? '▼ Terminal' : '▲ Terminal'}
              </button>
              <button class="ctf-btn ctf-btn-secondary" id="ctfToggleRightBtn" title="Toggle Flags Drawer (Ctrl+Shift+F)">
                ${rightDrawer ? '▶ Flags' : '◀ Flags'}
              </button>
            </div>
          </div>

          <!-- Tab Navigation -->
          <div class="ctf-tabs-nav">
            <button class="ctf-tab-item ${this.activeTab === 'hex' ? 'active' : ''}" data-tab="hex">
              🔬 Hex & Analysis
            </button>
            <button class="ctf-tab-item ${this.activeTab === 'recipe' ? 'active' : ''}" data-tab="recipe">
              ⚙ Recipe Studio
            </button>
            <button class="ctf-tab-item ${this.activeTab === 'writeup' ? 'active' : ''}" data-tab="writeup">
              📝 Write-up Studio
            </button>
          </div>

          <!-- Main View Slot -->
          <div id="ctfCenterSlot" style="flex: 1; overflow: hidden; position: relative;"></div>
        </div>

        <!-- 3. RIGHT DRAWER: Flags & Hypotheses -->
        <div class="ctf-drawer-right" style="display: ${rightDrawer ? 'flex' : 'none'};">
          <div class="ctf-pane-header">
            <div class="ctf-pane-header-title">
              <span>⬡</span>
              <span>FLAG CANDIDATES</span>
            </div>
            <div style="display: flex; gap: 4px; align-items: center;">
              <span class="ctf-hotkey">Ctrl+Shift+F</span>
              <button class="ctf-btn ctf-btn-ghost" id="ctfCloseRightBtn">✕</button>
            </div>
          </div>
          <div id="ctfRightSlot" style="flex: 1; overflow-y: auto;"></div>
        </div>

        <!-- 4. BOTTOM PANE: Terminal & Process Runner -->
        <div class="ctf-pane-bottom" style="display: ${bottom ? 'flex' : 'none'};">
          <div id="ctfBottomSlot" style="flex: 1; overflow: hidden;"></div>
        </div>
      </div>
    `;

    this.bindEvents();
    if (this.onRenderSlots) {
      this.onRenderSlots({
        center: this.getCenterSlotElement(),
        bottom: this.getBottomSlotElement(),
        right: this.getRightSlotElement()
      });
    }
  }

  renderArtifactTreeHtml(tree) {
    if (!tree || tree.length === 0) {
      return `
        <div style="padding: 16px; color: var(--ctf-text-muted); font-size: 11px; text-align: center; font-family: var(--ctf-font-mono);">
          [Нет прикрепленных артефактов]
        </div>
      `;
    }

    return tree.map((group) => {
      const items = group.items || [];
      return `
        <div style="margin-bottom: 8px;">
          <div style="padding: 4px 12px; font-size: 11px; font-weight: 700; color: var(--ctf-text-secondary); text-transform: uppercase;">
            📁 ${escapeHtml(group.role)} (${items.length})
          </div>
          ${items.map((art) => {
            const isSelected = art.id === this.selectedArtifactId;
            return `
              <div class="ctf-tree-node ${isSelected ? 'active' : ''}" data-artifact-id="${escapeHtml(art.id)}">
                <span>📄</span>
                <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                  ${escapeHtml(art.filename || art.id)}
                </span>
                <span style="font-size: 10px; color: var(--ctf-text-muted);">
                  ${formatBytes(art.size_bytes)}
                </span>
              </div>
            `;
          }).join('')}
        </div>
      `;
    }).join('');
  }

  bindEvents() {
    if (!this.container) return;

    this.container.querySelector('#ctfBackToMatrixBtn')?.addEventListener('click', () => {
      if (this.onNavigateBack) this.onNavigateBack();
    });

    // Tab buttons
    this.container.querySelectorAll('.ctf-tab-item[data-tab]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const tab = e.currentTarget.getAttribute('data-tab');
        this.setActiveTab(tab);
      });
    });

    // Panel toggle buttons
    this.container.querySelector('#ctfToggleLeftBtn')?.addEventListener('click', () => {
      this.store.togglePanel('left');
    });
    this.container.querySelector('#ctfCloseLeftBtn')?.addEventListener('click', () => {
      this.store.togglePanel('left');
    });
    this.container.querySelector('#ctfToggleBottomBtn')?.addEventListener('click', () => {
      this.store.togglePanel('bottom');
    });
    this.container.querySelector('#ctfToggleRightBtn')?.addEventListener('click', () => {
      this.store.togglePanel('rightDrawer');
    });
    this.container.querySelector('#ctfCloseRightBtn')?.addEventListener('click', () => {
      this.store.togglePanel('rightDrawer');
    });

    // Challenge Status Selector
    this.container.querySelector('#ctfChallengeStatusSelect')?.addEventListener('change', async (e) => {
      const newStatus = e.target.value;
      try {
        await this.store.updateChallengeStatus(newStatus, 'Manual user status update');
      } catch (err) {
        console.error('[WorkspaceView] Failed to update challenge status:', err);
      }
    });

    // Artifact Selection
    this.container.querySelectorAll('.ctf-tree-node[data-artifact-id]').forEach((node) => {
      node.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-artifact-id');
        this.selectedArtifactId = id;
        if (this.onSelectArtifact) this.onSelectArtifact(id);
        this.render();
      });
    });

    // Import Artifact File Upload
    const fileInput = this.container.querySelector('#ctfArtifactFileInput');
    const importBtn = this.container.querySelector('#ctfImportArtifactBtn');
    importBtn?.addEventListener('click', () => fileInput?.click());

    fileInput?.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async () => {
        const base64 = reader.result.split(',')[1];
        try {
          await this.store.importArtifact({
            filename: file.name,
            data_base64: base64,
            role: 'Input'
          });
        } catch (err) {
          console.error('[WorkspaceView] Artifact upload failed:', err);
        }
      };
      reader.readAsDataURL(file);
    });
  }
}

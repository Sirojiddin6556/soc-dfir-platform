/**
 * ctf_app.js - CTF Unified Workspace Root Application & Router Controller
 * Implements Role 21 (Frontend Integration Engineer) specification.
 * Connects Contract A Stores with Contract B UI Components & Visualizations.
 * Routes:
 *   - #ctf-competitions   : Competition Hub & Jeopardy Challenge Matrix
 *   - #ctf-challenge/:id  : 4-Sector Workspace (Artifacts, Hex/Recipe, Terminal, Flags)
 *   - #ctf-writeup/:id    : Write-up Studio & Secret Redaction
 *   - #legacy-cases       : Bridge back to SOC/DFIR Retro Workspace
 */

import { ctfIpc } from './ctf_ipc.js';
import { workspaceStore } from './workspace_store.js';
import { hexStore } from './hex_store.js';
import { jobRunnerStore } from './job_runner_store.js';
import { recipeStore } from './recipe_store.js';
import { flagStore } from './flag_store.js';
import { writeupStore } from './writeup_store.js';

import { ChallengeMatrix } from './components/challenge_matrix.js';
import { WorkspaceView } from './components/workspace_view.js';
import { TerminalView } from './components/terminal_view.js';
import { RecipeBuilder } from './components/recipe_builder.js';
import { FlagDrawer } from './components/flag_drawer.js';
import { WriteupView } from './components/writeup_view.js';
import { HexViewer } from './components/hex_viewer.js';
import { EntropyMinimap } from './components/entropy_minimap.js';
import { ByteDistributionChart } from './components/byte_distribution_chart.js';
import { seedDemoLab as seedDemoLabHelper } from './demo_lab.js';
import { escapeHtml } from '../util/html.js';

export class CtfApp {
  /**
   * @param {Object} [options]
   * @param {import('./ctf_ipc.js').CtfIpcClient} [options.ipc=ctfIpc]
   * @param {import('./workspace_store.js').WorkspaceStore} [options.workspaceStore=workspaceStore]
   * @param {import('./hex_store.js').HexStore} [options.hexStore=hexStore]
   * @param {import('./job_runner_store.js').JobRunnerStore} [options.jobRunnerStore=jobRunnerStore]
   * @param {import('./recipe_store.js').RecipeStore} [options.recipeStore=recipeStore]
   * @param {import('./flag_store.js').FlagStore} [options.flagStore=flagStore]
   * @param {import('./writeup_store.js').WriteupStore} [options.writeupStore=writeupStore]
   * @param {() => void} [options.onNavigateLegacy]
   */
  constructor(options = {}) {
    this.ipc = options.ipc || ctfIpc;
    this.workspaceStore = options.workspaceStore || workspaceStore;
    this.hexStore = options.hexStore || hexStore;
    this.jobRunnerStore = options.jobRunnerStore || jobRunnerStore;
    this.recipeStore = options.recipeStore || recipeStore;
    this.flagStore = options.flagStore || flagStore;
    this.writeupStore = options.writeupStore || writeupStore;
    this.onNavigateLegacy = options.onNavigateLegacy || null;

    this.container = null;
    this.viewportEl = null;
    this.currentRoute = '#ctf-competitions';
    this.routeParams = {};
    this.isMounted = false;

    // Active component instances
    this.challengeMatrix = null;
    this.workspaceView = null;
    this.hexViewer = null;
    this.entropyMinimap = null;
    this.byteDistributionChart = null;
    this.terminalView = null;
    this.recipeBuilder = null;
    this.flagDrawer = null;
    this.writeupView = null;

    // Listeners
    this.hashChangeHandler = null;
    this.keydownHandler = null;
  }

  /**
   * Parses route hash into route pattern and parameter dictionary.
   * @param {string} hash
   * @returns {{ route: string, params: Record<string, string> }}
   */
  parseRoute(hash) {
    const raw = (hash || '').trim();
    if (!raw || raw === '#' || raw === '#ctf-competitions') {
      return { route: '#ctf-competitions', params: {} };
    }
    const challengeMatch = raw.match(/^#ctf-challenge\/([^/?#]+)/);
    if (challengeMatch) {
      return { route: '#ctf-challenge/:id', params: { id: challengeMatch[1] } };
    }
    const writeupMatch = raw.match(/^#ctf-writeup\/([^/?#]+)/);
    if (writeupMatch) {
      return { route: '#ctf-writeup/:id', params: { id: writeupMatch[1] } };
    }
    if (raw === '#legacy-cases') {
      return { route: '#legacy-cases', params: {} };
    }
    return { route: '#ctf-competitions', params: {} };
  }

  /**
   * Mounts the CTF Application into the specified DOM container.
   * @param {HTMLElement} container
   */
  async mount(container) {
    this.container = container;
    this.isMounted = true;

    // Render Shell Layout
    this.container.innerHTML = `
      <div class="ctf-app-shell" style="display:flex; flex-direction:column; height:100%; width:100%; background:var(--ctf-bg-void, #090A0F); overflow:hidden;">
        <!-- CTF Header & Command Center Bar -->
        <header class="ctf-app-header" style="height:44px; background:var(--ctf-bg-surface-0, #0D1117); border-bottom:1px solid var(--ctf-border-default, #30363D); display:flex; align-items:center; justify-content:space-between; padding:0 16px; user-select:none; flex-shrink:0;">
          <div style="display:flex; align-items:center; gap:16px;">
            <div style="display:flex; align-items:center; gap:8px; font-weight:700; color:var(--ctf-accent-cyan, #00E5FF); letter-spacing:0.5px;">
              <span style="font-size:16px;">⬡</span>
              <span style="color:var(--ctf-text-primary, #F0F6FC); font-size:13px;">CTF UNIFIED WORKSPACE</span>
              <span style="font-size:10px;color:var(--ctf-text-muted,#8b949e);font-weight:400;">Учебный режим · данные CTF не входят в кейс расследования</span>
            </div>

            <nav class="ctf-subnav" style="display:flex; align-items:center; gap:4px;">
              <button class="ctf-btn ctf-btn-secondary" id="ctfNavCompetitions" style="height:26px; font-size:11px;">
                Jeopardy Matrix
              </button>
              <button class="ctf-btn ctf-btn-secondary" id="ctfNavChallenge" style="height:26px; font-size:11px;">
                Challenge Workspace
              </button>
              <button class="ctf-btn ctf-btn-secondary" id="ctfNavWriteup" style="height:26px; font-size:11px;">
                Write-up Studio
              </button>
              <button class="ctf-btn ctf-btn-ghost" id="ctfNavLegacy" style="height:26px; font-size:11px; color:var(--ctf-text-muted);">
                ↩ SOC/DFIR View
              </button>
            </nav>
          </div>

          <div style="display:flex; align-items:center; gap:12px;">
            <button class="ctf-btn ctf-btn-panic" id="ctfGlobalPanicBtn" title="Emergency Stop All Processes (F9)">
              ⚡ Panic Kill (F9)
            </button>
          </div>
        </header>

        <!-- Main Viewport Router Slot -->
        <div id="ctfAppViewport" style="flex:1; min-height:0; position:relative; overflow:hidden;"></div>
      </div>
    `;

    this.viewportEl = this.container.querySelector('#ctfAppViewport');
    this.setupListeners();

    // Initial Route Hydration
    const initialHash = typeof window !== 'undefined' && window.location ? window.location.hash : '#ctf-competitions';
    await this.navigate(initialHash || '#ctf-competitions');
  }

  setupListeners() {
    // Navigation Button Bindings
    this.container.querySelector('#ctfNavCompetitions')?.addEventListener('click', () => {
      this.navigate('#ctf-competitions');
    });

    this.container.querySelector('#ctfNavChallenge')?.addEventListener('click', () => {
      const activeId = this.workspaceStore.getState().activeChallengeId || 'chal-001';
      this.navigate(`#ctf-challenge/${activeId}`);
    });

    this.container.querySelector('#ctfNavWriteup')?.addEventListener('click', () => {
      const activeId = this.workspaceStore.getState().activeChallengeId || 'chal-001';
      this.navigate(`#ctf-writeup/${activeId}`);
    });

    this.container.querySelector('#ctfNavLegacy')?.addEventListener('click', () => {
      this.navigate('#legacy-cases');
    });

    // Panic Kill Button
    this.container.querySelector('#ctfGlobalPanicBtn')?.addEventListener('click', async () => {
      await this.jobRunnerStore.panicKillAll();
    });

    // Hashchange Handler
    if (typeof window !== 'undefined') {
      this.hashChangeHandler = () => {
        this.handleRoute(window.location.hash);
      };
      window.addEventListener('hashchange', this.hashChangeHandler);

      // Global F9 Panic Kill & Hotkeys
      this.keydownHandler = (e) => {
        if (e.key === 'F9') {
          e.preventDefault();
          this.jobRunnerStore.panicKillAll();
        }
      };
      window.addEventListener('keydown', this.keydownHandler);
    }
  }

  /**
   * Navigates to target route and updates browser history/hash if available.
   * @param {string} routeWithParams
   */
  async navigate(routeWithParams) {
    if (typeof window !== 'undefined' && window.location && window.location.hash !== routeWithParams) {
      window.location.hash = routeWithParams;
    }
    await this.handleRoute(routeWithParams);
  }

  /**
   * Router resolution and component mounting.
   * @param {string} hash
   */
  async handleRoute(hash) {
    const { route, params } = this.parseRoute(hash);
    this.currentRoute = route;
    this.routeParams = params;
    this.updateHeaderActiveState(route);

    if (route === '#legacy-cases') {
      if (this.onNavigateLegacy) {
        this.onNavigateLegacy();
      }
      return;
    }

    if (!this.viewportEl) return;

    if (route === '#ctf-competitions') {
      await this.mountCompetitionsRoute();
    } else if (route === '#ctf-challenge/:id') {
      await this.mountChallengeRoute(params.id);
    } else if (route === '#ctf-writeup/:id') {
      await this.mountWriteupRoute(params.id);
    }
  }

  updateHeaderActiveState(route) {
    if (!this.container) return;
    const compBtn = this.container.querySelector('#ctfNavCompetitions');
    const chalBtn = this.container.querySelector('#ctfNavChallenge');
    const wrtBtn = this.container.querySelector('#ctfNavWriteup');

    compBtn?.classList.toggle('ctf-btn-primary', route === '#ctf-competitions');
    chalBtn?.classList.toggle('ctf-btn-primary', route === '#ctf-challenge/:id');
    wrtBtn?.classList.toggle('ctf-btn-primary', route === '#ctf-writeup/:id');
  }

  destroyActiveComponents() {
    if (this.challengeMatrix) { this.challengeMatrix.destroy(); this.challengeMatrix = null; }
    if (this.workspaceView) { this.workspaceView.destroy(); this.workspaceView = null; }
    if (this.hexViewer) { this.hexViewer.destroy(); this.hexViewer = null; }
    if (this.entropyMinimap) { this.entropyMinimap.destroy(); this.entropyMinimap = null; }
    if (this.byteDistributionChart) { this.byteDistributionChart.destroy(); this.byteDistributionChart = null; }
    if (this.terminalView) { this.terminalView.destroy(); this.terminalView = null; }
    if (this.recipeBuilder) { this.recipeBuilder.destroy(); this.recipeBuilder = null; }
    if (this.flagDrawer) { this.flagDrawer.destroy(); this.flagDrawer = null; }
    if (this.writeupView) { this.writeupView.destroy(); this.writeupView = null; }

    if (this.viewportEl) {
      this.viewportEl.innerHTML = '';
    }
  }

  async mountCompetitionsRoute() {
    this.destroyActiveComponents();
    try {
      const competitions = await this.workspaceStore.loadCompetitions();
      const active = this.workspaceStore.getState().activeCompetitionId;
      if (competitions.length > 0 && !competitions.some((item) => item.id === active)) {
        await this.workspaceStore.loadCompetition(competitions[0].id);
      } else if (active) {
        await this.workspaceStore.loadCompetition(active);
      }
    } catch (_) {
      // The store keeps the error for the matrix retry state.
    }
    this.challengeMatrix = new ChallengeMatrix({
      store: this.workspaceStore,
      onSelectChallenge: (id) => this.navigate(`#ctf-challenge/${id}`),
      onSeedDemo: () => this.seedDemoLab()
    });
    this.challengeMatrix.mount(this.viewportEl);
  }

  async mountChallengeRoute(challengeId) {
    this.destroyActiveComponents();

    try {
      await this.workspaceStore.selectChallenge(challengeId);
    } catch (err) {
      this.viewportEl.innerHTML = `<div role="alert" class="ctf-empty-state">Не удалось открыть задание: ${escapeHtml(err.message)}<button class="ctf-btn ctf-btn-secondary" id="ctfRetryChallenge">Повторить</button><button class="ctf-btn ctf-btn-ghost" id="ctfBackToChallenges">К списку заданий</button></div>`;
      this.viewportEl.querySelector('#ctfRetryChallenge')?.addEventListener('click', () => this.mountChallengeRoute(challengeId));
      this.viewportEl.querySelector('#ctfBackToChallenges')?.addEventListener('click', () => this.navigate('#ctf-competitions'));
      return;
    }

    this.workspaceView = new WorkspaceView({
      store: this.workspaceStore,
      onTabChange: (tab) => this.mountWorkspaceCenterTab(tab),
      onSelectArtifact: (artId) => this.handleArtifactSelect(artId),
      onRenderSlots: (slots) => this.mountWorkspaceSlots(slots),
      onNavigateBack: () => this.navigate('#ctf-competitions')
    });

    this.workspaceView.mount(this.viewportEl);
  }

  mountWorkspaceSlots(slots) {
    if (!slots) return;

    // 1. Right Slot: FlagDrawer
    if (slots.right) {
      this.flagStore.workspaceStore = this.workspaceStore;
      if (!this.flagDrawer) {
        this.flagDrawer = new FlagDrawer({ store: this.flagStore });
      }
      this.flagDrawer.mount(slots.right);
    }

    // 2. Bottom Slot: TerminalView
    if (slots.bottom) {
      if (!this.terminalView) {
        this.terminalView = new TerminalView({
          store: this.jobRunnerStore,
          onCommandSubmit: (job) => this.jobRunnerStore.submitJob({ ...job, challenge_id: this.workspaceStore.getState().activeChallengeId })
        });
      }
      this.terminalView.mount(slots.bottom);
    }

    // 3. Center Slot: activeTab content
    if (slots.center) {
      const activeTab = this.workspaceView?.activeTab || 'recipe';
      this.mountWorkspaceCenterTab(activeTab, slots.center);
    }
  }

  mountWorkspaceCenterTab(tabId, customSlot = null) {
    const centerSlot = customSlot || this.workspaceView?.getCenterSlotElement();
    if (!centerSlot) return;

    // Clean previous tab components
    if (this.recipeBuilder) { this.recipeBuilder.destroy(); this.recipeBuilder = null; }
    if (this.hexViewer) { this.hexViewer.destroy(); this.hexViewer = null; }
    if (this.byteDistributionChart) { this.byteDistributionChart.destroy(); this.byteDistributionChart = null; }
    if (this.writeupView) { this.writeupView.destroy(); this.writeupView = null; }
    centerSlot.innerHTML = '';

    if (tabId === 'recipe') {
      this.recipeBuilder = new RecipeBuilder({
        store: this.recipeStore,
        flags: this.flagStore
      });
      this.recipeBuilder.mount(centerSlot);
    } else if (tabId === 'hex') {
      centerSlot.innerHTML = `
        <div style="display:grid; grid-template-rows: 1fr 180px; height:100%; width:100%;">
          <div id="ctfHexTopSlot" style="min-height:0; overflow:hidden;"></div>
          <div id="ctfHexBottomSlot" style="min-height:0; border-top:1px solid var(--ctf-border-default, #30363D); overflow:hidden;"></div>
        </div>
      `;
      const topSlot = centerSlot.querySelector('#ctfHexTopSlot');
      const bottomSlot = centerSlot.querySelector('#ctfHexBottomSlot');

      this.hexViewer = new HexViewer({
        store: this.hexStore,
        showMinimap: true,
        onSendToRecipe: (bytes) => {
          this.recipeStore.setInputData(bytes);
          this.workspaceView.setActiveTab('recipe');
        }
      });
      this.hexViewer.mount(topSlot);
      this.entropyMinimap = this.hexViewer.minimap;

      this.byteDistributionChart = new ByteDistributionChart({ store: this.hexStore });
      this.byteDistributionChart.mount(bottomSlot);
    } else if (tabId === 'writeup') {
      this.writeupView = new WriteupView({
        store: this.writeupStore,
        workspace: this.workspaceStore
      });
      this.writeupView.mount(centerSlot);
    }
  }

  handleArtifactSelect(artifactId) {
    const arts = this.workspaceStore.getState().artifacts || {};
    const item = arts[artifactId];
    const meta = item
      ? { ...item, artifact_id: item.artifact_id || item.id || artifactId }
      : { artifact_id: artifactId, filename: artifactId, size_bytes: 1024 };
    this.hexStore.loadArtifact(meta);
    if (this.workspaceView && this.workspaceView.activeTab !== 'hex') {
      this.workspaceView.setActiveTab('hex');
    }
  }

  async mountWriteupRoute(challengeId) {
    this.destroyActiveComponents();

    try {
      await this.workspaceStore.selectChallenge(challengeId);
    } catch (err) {
      this.viewportEl.innerHTML = `<div role="alert" class="ctf-empty-state">Не удалось загрузить задание для write-up: ${escapeHtml(err.message)} <button class="ctf-btn ctf-btn-secondary" id="ctfRetryWriteup">Повторить</button><button class="ctf-btn ctf-btn-ghost" id="ctfBackFromWriteup">К списку заданий</button></div>`;
      this.viewportEl.querySelector('#ctfRetryWriteup')?.addEventListener('click', () => this.mountWriteupRoute(challengeId));
      this.viewportEl.querySelector('#ctfBackFromWriteup')?.addEventListener('click', () => this.navigate('#ctf-competitions'));
      return;
    }

    this.viewportEl.innerHTML = `
      <div style="display:flex; flex-direction:column; height:100%; width:100%;">
        <div style="height:36px; padding:0 16px; background:var(--ctf-bg-surface-1); border-bottom:1px solid var(--ctf-border-default); display:flex; align-items:center; justify-content:space-between;">
          <button class="ctf-btn ctf-btn-secondary" id="ctfWriteupBackBtn">
            ◀ Back to Workspace
          </button>
          <span style="font-size:12px; font-weight:700; color:var(--ctf-text-secondary);">
            Write-up Studio: ${escapeHtml(challengeId)}
          </span>
        </div>
        <div id="ctfWriteupSlot" style="flex:1; min-height:0; overflow:hidden;"></div>
      </div>
    `;

    this.viewportEl.querySelector('#ctfWriteupBackBtn')?.addEventListener('click', () => {
      this.navigate(`#ctf-challenge/${challengeId}`);
    });

    const slot = this.viewportEl.querySelector('#ctfWriteupSlot');
    this.writeupView = new WriteupView({
      store: this.writeupStore,
      workspace: this.workspaceStore
    });
    this.writeupView.mount(slot);
  }

  async seedDemoLab() {
    await seedDemoLabHelper(this.workspaceStore);
    this.render();
  }

  render() {
    if (this.currentRoute) {
      this.handleRoute(this.currentRoute);
    }
  }

  destroy() {
    this.destroyActiveComponents();
    if (typeof window !== 'undefined') {
      if (this.hashChangeHandler) {
        window.removeEventListener('hashchange', this.hashChangeHandler);
        this.hashChangeHandler = null;
      }
      if (this.keydownHandler) {
        window.removeEventListener('keydown', this.keydownHandler);
        this.keydownHandler = null;
      }
    }
    if (this.container) {
      this.container.innerHTML = '';
      this.container = null;
    }
    this.isMounted = false;
  }
}

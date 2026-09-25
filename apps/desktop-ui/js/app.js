import { IpcClient } from './ipc.js';
import { InvestigationWorkspace } from './investigation/workspace.js';
import { OperationsSpace } from './operations/operations.js';
import { EvidenceSpace } from './evidence/evidence.js';
import { RangeSpace } from './range/range.js';
import { SystemSpace } from './system/system.js';
import { TeamPresence } from './collaboration/presence.js';
import { CtfApp } from './ctf/ctf_app.js';
import { ctfIpc } from './ctf/ctf_ipc.js';

class SocDfirApplication {
  constructor() {
    this.ipc = new IpcClient();
    this.workspace = new InvestigationWorkspace(this.ipc);
    this.presence = new TeamPresence(this.ipc);

    this.operations = new OperationsSpace(this.ipc, (caseId) => this.switchCase(caseId));
    this.evidence = new EvidenceSpace(this.ipc, (art) => this.openInCtfHex(art));
    this.range = new RangeSpace(this.ipc, (missionId) => this.launchMission(missionId), () => {
      document.getElementById('nav-ctf-workspace')?.click();
    });
    this.system = new SystemSpace(this.ipc);
    this.ctfApp = new CtfApp({
      ipc: ctfIpc,
      onNavigateLegacy: (caseId) => this.switchCase(caseId)
    });
    this.ctfMounted = false;

    this.currentSpace = 'investigation';
    this.timerSeconds = 0;
  }

  openInCtfHex(art) {
    const ctfBtn = document.getElementById('nav-ctf-workspace');
    if (ctfBtn) ctfBtn.click();
    if (art && this.ctfApp) {
      this.ctfApp.handleArtifactSelect(art.id || art.artifact_id, art);
    }
  }

  async start() {
    this.setupGlobalNavigation();
    this.setupLiveTimer();
    this.setupGlobalSearch();

    try { await this.ensureLocalAuth(); } catch (e) { console.warn('[Auth]', e.message); }
    try { await this.ensureActiveCase(); } catch (e) { console.warn('[Case]', e.message); }
    try { await this.workspace.init(); } catch (e) { console.warn('[Workspace]', e.message); }
    try { await this.presence.init(); } catch (e) { console.warn('[Presence]', e.message); }
    if (typeof window !== 'undefined' && window.location && window.location.hash.startsWith('#ctf-')) {
      const ctfBtn = document.getElementById('nav-ctf-workspace');
      if (ctfBtn) ctfBtn.click();
    }
  }

  /**
   * Guarantees a real, persisted case exists and is selected before the
   * workspace loads. Without this, the UI falls back to the placeholder
   * case id baked into index.html, which does not exist in the database.
   */
  async ensureActiveCase() {
    const cases = await this.ipc.call('cases.list', {});
    let active = Array.isArray(cases) && cases.length > 0 ? cases[0] : null;

    if (!active) {
      active = await this.ipc.call('cases.create', {
        title: `Расследование от ${new Date().toLocaleDateString('ru-RU')}`
      });
    }

    const realId = active && (active.case_id || active.id);
    const caseEl = document.getElementById('caseId');
    if (caseEl && realId) {
      caseEl.textContent = realId;
    }
  }

  async ensureLocalAuth() {
    const token = typeof localStorage !== 'undefined' ? localStorage.getItem('soc_session_token') : null;
    if (!token) {
      const res = await this.ipc.call('auth.login', { username: 'sirojiddin', password: 'admin' });
      if (res && res.session) {
        localStorage.setItem('soc_session_token', res.session.token);
      }
    }
  }

  setupGlobalNavigation() {
    document.querySelectorAll('.global-nav button').forEach(button => {
      button.addEventListener('click', () => {
        const space = button.dataset.space;
        if (!space) return;

        document.querySelectorAll('.global-nav button').forEach(b => b.classList.remove('active'));
        button.classList.add('active');
        this.openSpace(space);
      });
    });
  }

  openSpace(space) {
    this.currentSpace = space;
    const invWorkspace = document.getElementById('investigationWorkspace');
    const contextPanel = document.querySelector('.context-panel');
    const ctfView = document.getElementById('view-ctf');
    let altContainer = document.getElementById('altSpaceContainer');

    if (space === 'investigation') {
      if (invWorkspace) invWorkspace.style.display = 'grid';
      if (contextPanel) contextPanel.style.display = 'grid';
      if (ctfView) ctfView.classList.add('hidden');
      if (altContainer) altContainer.style.display = 'none';
      this.workspace.render();
    } else if (space === 'ctf') {
      if (invWorkspace) invWorkspace.style.display = 'none';
      if (contextPanel) contextPanel.style.display = 'none';
      if (altContainer) altContainer.style.display = 'none';
      if (ctfView) {
        ctfView.classList.remove('hidden');
        if (!this.ctfMounted) {
          this.ctfApp.mount(ctfView);
          this.ctfMounted = true;
        } else {
          this.ctfApp.render();
        }
      }
    } else {
      if (invWorkspace) invWorkspace.style.display = 'none';
      if (contextPanel) contextPanel.style.display = 'none';
      if (ctfView) ctfView.classList.add('hidden');

      if (!altContainer) {
        altContainer = document.createElement('div');
        altContainer.id = 'altSpaceContainer';
        altContainer.style.gridColumn = '2 / span 2';
        altContainer.style.overflow = 'hidden';
        altContainer.style.background = 'var(--bg-canvas)';
        const layout = document.querySelector('.workspace-layout');
        if (layout) layout.appendChild(altContainer);
      }

      altContainer.style.display = 'block';

      if (space === 'operations') {
        this.operations.render(altContainer);
      } else if (space === 'evidence') {
        this.evidence.render(altContainer);
      } else if (space === 'range') {
        this.range.render(altContainer);
      } else if (space === 'system') {
        this.system.render(altContainer);
      }
    }
  }

  switchCase(caseId) {
    const caseEl = document.getElementById('caseId');
    if (caseEl) caseEl.textContent = caseId;

    const navBtn = document.querySelector('.global-nav button[data-space="investigation"]');
    if (navBtn) navBtn.click();
    this.workspace.refresh();
  }

  launchMission(missionId) {
    const caseEl = document.getElementById('caseId');
    if (caseEl) caseEl.textContent = missionId;

    const navBtn = document.querySelector('.global-nav button[data-space="investigation"]');
    if (navBtn) navBtn.click();
    this.workspace.refresh();
  }

  setupLiveTimer() {
    const timerEl = document.getElementById('caseTimer');
    setInterval(() => {
      this.timerSeconds++;
      const hrs = String(Math.floor(this.timerSeconds / 3600)).padStart(2, '0');
      const mins = String(Math.floor((this.timerSeconds % 3600) / 60)).padStart(2, '0');
      const secs = String(this.timerSeconds % 60).padStart(2, '0');
      if (timerEl) timerEl.textContent = `${hrs}:${mins}:${secs}`;
    }, 1000);
  }

  setupGlobalSearch() {
    const searchInput = document.getElementById('globalSearch');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        if (!query) {
          this.workspace.render();
          return;
        }
        const filteredNodes = this.workspace.store.graph.nodes.filter(n =>
          (n.label && n.label.toLowerCase().includes(query)) ||
          (n.id && n.id.toLowerCase().includes(query)) ||
          (n.subtitle && n.subtitle.toLowerCase().includes(query))
        );
        this.workspace.graph.render({
          nodes: filteredNodes,
          edges: this.workspace.store.graph.edges
        }, this.workspace.store.activeLayer);
      });

      window.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
          e.preventDefault();
          searchInput.focus();
        }
      });
    }
  }
}

const application = new SocDfirApplication();
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    application.start();
  });
}

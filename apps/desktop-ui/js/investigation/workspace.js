import { InvestigationStore } from './investigation-store.js';
import { InvestigationGraph } from './graph.js';
import { InvestigationTimeline } from './timeline.js';
import { EntityInspector } from './inspector.js';
import { ContextDiscussion } from '../collaboration/discussion.js';
import { escapeHtml } from '../util/html.js';

export class InvestigationWorkspace {
  constructor(ipc) {
    this.ipc = ipc;
    this.store = new InvestigationStore();
    this.graph = new InvestigationGraph(document.getElementById('investigationGraph'));
    this.timeline = new InvestigationTimeline(document.getElementById('timelineEvents'));
    this.inspector = new EntityInspector(document.getElementById('entityInspector'), this.store);
    this.discussion = new ContextDiscussion(ipc);
    this._entityLoadToken = 0;
  }

  async init() {
    this.bindLayerControls();
    this.bindComponents();
    this.bindZoomControls();
    this.bindCollectionAction();
    await this.refresh();
  }

  async refresh() {
    try {
      const snapshot = await this.ipc.call('investigation.snapshot', {
        case_id: this.getCurrentCaseId()
      });
      if (!snapshot) return;
      this.store.update(snapshot);
      this.render();
    } catch (e) {
      console.warn('[Investigation] refresh failed:', e.message);
    }
  }

  render() {
    this.graph.render(this.store.graph, this.store.activeLayer);
    this.timeline.render(this.store.timeline);
    this.updateMetrics();

    // Select first asset or attack entity by default if none selected
    if (!this.store.selectedEntity && this.store.assets.length > 0) {
      const defaultEnt = this.store.graph.nodes.find(n => n.in_attack_path) || this.store.graph.nodes[0];
      if (defaultEnt) {
        this.store.selectEntity(defaultEnt);
        this.inspector.render(defaultEnt);
        this.discussion.loadForEntity(defaultEnt);
      }
    }
  }

  bindComponents() {
    this.graph.onSelect = async (entity) => {
      this.store.selectEntity(entity);
      await this.loadEntity(entity);
    };

    this.timeline.onSelect = (event) => {
      this.loadTimelineEvent(event);
    };
  }

  bindLayerControls() {
    document.querySelectorAll('[data-layer]').forEach(button => {
      button.addEventListener('click', () => {
        document.querySelectorAll('[data-layer]').forEach(b => b.classList.remove('active'));
        button.classList.add('active');

        const layer = button.dataset.layer;
        this.store.setLayer(layer);
        this.graph.render(this.store.graph, layer);
      });
    });
  }

  bindZoomControls() {
    document.getElementById('zoomIn')?.addEventListener('click', () => {
      this.graph.setZoom(this.graph.zoom * 1.15);
    });
    document.getElementById('zoomOut')?.addEventListener('click', () => {
      this.graph.setZoom(this.graph.zoom * 0.85);
    });
    document.getElementById('fitGraph')?.addEventListener('click', () => {
      this.graph.resetView();
    });
  }

  bindCollectionAction() {
    const btn = document.getElementById('startCollection');
    if (!btn) return;

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = '⏳ Сбор данных...';
      try {
        const caseId = this.getCurrentCaseId();
        await this.ipc.call('scan.network', { subnet: '127.0.0.1', mode: 'quick' });
        await this.ipc.call('host.correlate', { case_id: caseId, refresh: true });
        await this.refresh();
      } catch (err) {
        console.warn('Collection error:', err);
        btn.textContent = '⚠ Ошибка сбора';
        setTimeout(() => { btn.textContent = '▶ Запустить сбор'; }, 2500);
        return;
      } finally {
        btn.disabled = false;
      }
      btn.textContent = '▶ Запустить сбор';
    });
  }

  async loadEntity(entity) {
    // Guards against two problems that otherwise make the context panel show
    // data from the wrong entity ("windows mixing up"):
    // 1. entity.get only has a real lookup for Finding/Evidence today; for
    //    process/host/network it honestly answers {found:false, ...}. That
    //    stub must not overwrite the richer data the graph node already has.
    // 2. Clicking a second node before the first entity.get resolves must not
    //    let the slower, stale response clobber the newer selection.
    const token = ++this._entityLoadToken;
    let result = null;
    try {
      result = await this.ipc.call('entity.get', {
        type: entity.type,
        id: entity.id
      });
    } catch (e) {
      console.warn('[Investigation] entity.get failed:', e.message);
    }

    if (token !== this._entityLoadToken) return;

    const fullEntity = (result && result.found) ? { ...entity, ...result } : entity;
    this.inspector.render(fullEntity);
    await this.discussion.loadForEntity(fullEntity);
  }

  loadTimelineEvent(event) {
    const target = document.getElementById('eventDetails');
    if (!target) return;

    target.innerHTML = `
      <div style="font-weight: 700; font-size: 13px; color: var(--text-primary); margin-bottom: 4px;">${escapeHtml(event.title)}</div>
      <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">Время: ${escapeHtml(event.timestamp)} • Категория: ${escapeHtml(event.category)}</div>
      <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 6px; padding: 10px; font-size: 11px; line-height: 1.5; color: var(--text-primary); margin-bottom: 12px;">
        ${escapeHtml(event.detail || 'Нет дополнительных сведений.')}
      </div>
      <pre style="font-size: 10px; color: var(--text-secondary); background: var(--bg-canvas); border: 1px solid var(--border-muted); padding: 8px; border-radius: 4px; overflow-x: auto;">${escapeHtml(JSON.stringify(event, null, 2))}</pre>
    `;
  }

  updateMetrics() {
    const findingsEl = document.getElementById('findingCount');
    const evidenceEl = document.getElementById('evidenceCount');
    const hostsEl = document.getElementById('affectedHosts');
    const riskEl = document.getElementById('riskLevel');

    if (findingsEl) findingsEl.textContent = this.store.findings.length;
    if (evidenceEl) evidenceEl.textContent = this.store.evidence.length;
    if (hostsEl) hostsEl.textContent = this.store.assets.length;

    if (riskEl) {
      const risk = this.store.case && this.store.case.risk;
      riskEl.textContent = risk || '—';
      riskEl.style.color = (risk === 'HIGH' || risk === 'CRITICAL') ? 'var(--accent-critical)' : 'var(--accent-info)';
    }
  }

  getCurrentCaseId() {
    return document.getElementById('caseId')?.textContent.trim() || null;
  }

  show() {
    const el = document.getElementById('investigationWorkspace');
    if (el) el.style.display = 'grid';
  }

  hide() {
    const el = document.getElementById('investigationWorkspace');
    if (el) el.style.display = 'none';
  }
}

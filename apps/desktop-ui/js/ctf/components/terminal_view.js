/**
 * terminal_view.js - Terminal & Process Runner Component
 * Implements Contract B (TerminalView) from docs/it-company/16-frontend-architect.md
 * ANSI log rendering, Backpressure Alert badge, and F9 Panic Kill Button.
 */

import { jobRunnerStore } from '../job_runner_store.js';
import { escapeAttr, escapeHtml } from '../../util/html.js';

/**
 * Basic ANSI-to-HTML converter for terminal logs.
 */
function ansiToHtml(text) {
  if (!text) return '';
  let escaped = escapeHtml(text);

  // Common ANSI color mappings
  escaped = escaped
    .replace(/\x1b\[30m/g, '<span class="ansi-black">')
    .replace(/\x1b\[31m/g, '<span class="ansi-red">')
    .replace(/\x1b\[32m/g, '<span class="ansi-green">')
    .replace(/\x1b\[33m/g, '<span class="ansi-yellow">')
    .replace(/\x1b\[34m/g, '<span class="ansi-blue">')
    .replace(/\x1b\[35m/g, '<span class="ansi-magenta">')
    .replace(/\x1b\[36m/g, '<span class="ansi-cyan">')
    .replace(/\x1b\[37m/g, '<span class="ansi-white">')
    .replace(/\x1b\[1m/g, '<span class="ansi-bold">')
    .replace(/\x1b\[0m/g, '</span>');

  return escaped;
}

export class TerminalView {
  /**
   * @param {Object} [options]
   * @param {import('../job_runner_store.js').JobRunnerStore} [options.store=jobRunnerStore]
   * @param {(cmd: string) => void} [options.onCommandSubmit]
   */
  constructor(options = {}) {
    this.store = options.store || jobRunnerStore;
    this.onCommandSubmit = options.onCommandSubmit || null;

    this.container = null;
    this.autoScroll = true;
    this.isTerminating = false;
    this.unsubscribe = null;
    this.keydownHandler = null;
  }

  mount(container) {
    this.container = container;
    this.unsubscribe = this.store.subscribe(() => this.render());
    this.setupKeybindings();
    this.render();
    if (typeof this.store.loadTools === 'function' && !(this.store.getState().tools || []).length) {
      this.store.loadTools().catch(() => {});
    }
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
      // F9 Panic Kill Shortcut
      if (e.key === 'F9') {
        e.preventDefault();
        this.triggerPanicKill();
      }
    };
    window.addEventListener('keydown', this.keydownHandler);
  }

  async triggerPanicKill() {
    if (this.isTerminating) return;
    this.isTerminating = true;
    this.render();

    try {
      await this.store.panicKillAll();
    } catch (err) {
      console.error('[TerminalView] Panic kill error:', err);
    } finally {
      setTimeout(() => {
        this.isTerminating = false;
        this.render();
      }, 1000);
    }
  }

  render() {
    if (!this.container) return;

    const state = this.store.getState();
    const activeJob = state.activeJobId ? state.activeJobs[state.activeJobId] : null;
    const activeCount = Object.keys(state.activeJobs || {}).length;
    const ring = state.activeJobId ? state.terminalBuffers[state.activeJobId] : null;

    const lines = ring ? ring.lines : [];
    const isRunning = Boolean(activeJob && (activeJob.status === 'running' || activeJob.status === 'pending'));
    const isBackpressureActive = Boolean(state.isBackpressureActive);
    const droppedBytes = ring?.droppedBytes || 0;
    const tools = state.tools || [];

    this.container.innerHTML = `
      <div class="ctf-terminal-view">
        <!-- Terminal Top Bar -->
        <div class="ctf-terminal-bar">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-weight: 700; color: var(--ctf-text-primary);">▶ JOB RUNNER</span>
            ${isRunning ? `
              <span class="ctf-badge ctf-status-inprogress">
                ⟳ RUNNING [Job: ${escapeHtml(activeJob.id.slice(0, 8))}]
              </span>
            ` : `
              <span class="ctf-badge ctf-status-unsolved">IDLE</span>
            `}

            ${isBackpressureActive ? `
              <span class="ctf-backpressure-badge">
                ⚡ Backpressure Active: 60 FPS Throttled | CAS Spooling
              </span>
            ` : ''}

            ${droppedBytes > 0 ? `
              <span style="color: var(--ctf-accent-amber); font-size: 11px;">
                ⚠️ [${(droppedBytes / (1024 * 1024)).toFixed(2)} MB DROPPED]
              </span>
            ` : ''}
          </div>

          <div style="display: flex; align-items: center; gap: 8px;">
            <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--ctf-text-secondary); cursor: pointer;">
              <input type="checkbox" id="ctfAutoScrollToggle" ${this.autoScroll ? 'checked' : ''} />
              Auto-scroll
            </label>

            <button class="ctf-btn ctf-btn-secondary" id="ctfClearTerminalBtn" style="height: 24px;">
              Clear
            </button>

            <!-- F9 Panic Kill Button (Role 18 Section 5.1 / Role 16 Section 4.5) -->
            <button class="ctf-btn ctf-btn-panic ${this.isTerminating ? 'terminating' : ''}" id="ctfPanicKillBtn" title="Emergency Stop All Jobs (F9)">
              ■ ${this.isTerminating ? 'Terminating...' : `Kill Tree (F9)${activeCount > 0 ? ` [${activeCount}]` : ''}`}
            </button>
          </div>
        </div>

        <!-- Terminal Log Output Area -->
        <div class="ctf-terminal-logs" id="ctfTerminalLogsContainer">
          ${lines.length === 0 ? `
            <div style="color: var(--ctf-text-muted); font-size: 11px;">
              [CTF Engine Terminal - Ready. Submit a job or pipeline step.]
            </div>
          ` : `
            <div>${lines.map((l) => ansiToHtml(l)).join('\n')}</div>
          `}
          ${state.error ? `<div role="alert" style="color:var(--ctf-accent-red,#ff6b6b);padding:8px;">${escapeHtml(state.error)}</div>` : ''}
        </div>

        <!-- Command Input Runner -->
        <div class="ctf-terminal-input-bar">
          <select id="ctfToolSelect" aria-label="Инструмент" ${state.isLoadingTools || tools.length === 0 ? 'disabled' : ''}>
            ${tools.length ? tools.map((tool) => `<option value="${escapeAttr(tool.id)}">${escapeHtml(tool.name || tool.id)} (${escapeHtml(tool.id)})</option>`).join('') : '<option value="">Нет доступных инструментов</option>'}
          </select>
          <input
            type="text"
            id="ctfCommandInput"
            class="ctf-terminal-input"
            placeholder="Аргументы через запятую; оболочка и команды запрещены"
            aria-label="Аргументы инструмента"
          />
          <button class="ctf-btn ctf-btn-primary" id="ctfRunCommandBtn" style="height: 26px;">
            ${state.isLoadingTools ? 'Загрузка…' : 'Запустить'}
          </button>
        </div>
      </div>
    `;

    this.bindEvents();

    if (this.autoScroll) {
      const logs = this.container.querySelector('#ctfTerminalLogsContainer');
      if (logs) logs.scrollTop = logs.scrollHeight;
    }
  }

  bindEvents() {
    if (!this.container) return;

    // Auto-scroll toggle
    this.container.querySelector('#ctfAutoScrollToggle')?.addEventListener('change', (e) => {
      this.autoScroll = e.target.checked;
    });

    // Clear button
    this.container.querySelector('#ctfClearTerminalBtn')?.addEventListener('click', () => {
      const state = this.store.getState();
      if (state.activeJobId) {
        this.store.clearTerminal(state.activeJobId);
      }
    });

    // Panic Kill Button
    this.container.querySelector('#ctfPanicKillBtn')?.addEventListener('click', () => {
      this.triggerPanicKill();
    });

    // Command submission
    const input = this.container.querySelector('#ctfCommandInput');
    const runBtn = this.container.querySelector('#ctfRunCommandBtn');

    const submit = () => {
      const raw = input?.value.trim();
      const toolId = this.container.querySelector('#ctfToolSelect')?.value;
      if (!toolId) return;
      const argv = raw ? raw.split(',').map((arg) => arg.trim()).filter(Boolean) : [];
      if (this.onCommandSubmit) {
        Promise.resolve(this.onCommandSubmit({ tool_id: toolId, argv })).catch((err) => this.store.setState({ error: err.message }));
      }
      if (input) input.value = '';
    };

    runBtn?.addEventListener('click', submit);
    input?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submit();
    });
  }
}

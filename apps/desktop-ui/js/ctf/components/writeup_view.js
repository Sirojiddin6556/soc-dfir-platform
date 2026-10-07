/**
 * writeup_view.js - Write-up Studio Dual-Pane Component
 * Dual-pane Markdown editor & live preview with Lineage DAG draft generation,
 * SEC-ARCH-05 secret redaction pills, and export options.
 */

import { writeupStore } from '../writeup_store.js';
import { workspaceStore } from '../workspace_store.js';
import { escapeAttr, escapeHtml } from '../../util/html.js';

/**
 * Lightweight safe markdown formatter with secret redaction pill rendering.
 */
function renderMarkdown(md) {
  if (!md) return '<p style="color: var(--ctf-text-muted);">[Черновик пуст. Нажмите "Generate Draft" для генерации отчета]</p>';

  let html = escapeHtml(md);

  // Replace secret redaction tokens: [REDACTED] or [REDACTED:...]
  html = html.replace(/\[REDACTED(?::[^\]]+)?\]/g, '<span class="ctf-redaction-pill">🔒 [REDACTED]</span>');

  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3 style="font-size: 14px; font-weight: 700; margin: 12px 0 6px; color: var(--ctf-text-primary);">$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2 style="font-size: 16px; font-weight: 700; margin: 16px 0 8px; color: var(--ctf-text-primary); border-bottom: 1px solid var(--ctf-border-default); padding-bottom: 4px;">$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1 style="font-size: 18px; font-weight: 800; margin: 20px 0 10px; color: var(--ctf-text-primary);">$1</h1>');

  // Bold & Italic
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

  // Fenced Code blocks (backticks arrive escaped as &#96;)
  html = html.replace(/&#96;&#96;&#96;([\s\S]*?)&#96;&#96;&#96;/g, '<pre style="background: var(--ctf-bg-surface-1); border: 1px solid var(--ctf-border-default); border-radius: var(--ctf-radius-sm); padding: 10px; font-family: var(--ctf-font-mono); font-size: 12px; overflow-x: auto; margin: 8px 0;"><code>$1</code></pre>');

  // Inline Code
  html = html.replace(/&#96;((?:(?!&#96;)[\s\S])+)&#96;/g, '<code style="background: var(--ctf-bg-surface-2); padding: 1px 4px; border-radius: 2px; font-family: var(--ctf-font-mono); font-size: 12px; color: var(--ctf-text-offset);">$1</code>');

  // Bullet Lists
  html = html.replace(/^\- (.*$)/gim, '<li style="margin-left: 20px;">$1</li>');

  // Paragraph breaks
  html = html.replace(/\n\n/g, '<br/><br/>');

  return html;
}

export class WriteupView {
  /**
   * @param {Object} [options]
   * @param {import('../writeup_store.js').WriteupStore} [options.store=writeupStore]
   * @param {import('../workspace_store.js').WorkspaceStore} [options.workspace=workspaceStore]
   */
  constructor(options = {}) {
    this.store = options.store || writeupStore;
    this.workspace = options.workspace || workspaceStore;

    this.container = null;
    this.unsubscribe = null;
    this.isGenerating = false;
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
    const md = state.draftMarkdown || '';
    const activeChal = this.workspace.getState().activeChallenge;

    this.container.innerHTML = `
      <div style="display: flex; flex-direction: column; height: 100%; background: var(--ctf-bg-surface-0);">
        <!-- Top Studio Action Bar -->
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 8px 14px; background: var(--ctf-bg-surface-1); border-bottom: 1px solid var(--ctf-border-default); flex-wrap: wrap; gap: 8px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-weight: 700; color: var(--ctf-text-primary); font-size: 13px;">📝 WRITE-UP STUDIO</span>
            ${state.isDirty ? `
              <span class="ctf-badge ctf-badge-crypto" style="font-size: 10px;">Unsaved Changes</span>
            ` : ''}
          </div>

          <div style="display: flex; align-items: center; gap: 8px;">
            <button class="ctf-btn ctf-btn-secondary" id="ctfGenerateDraftBtn" ${this.isGenerating ? 'disabled' : ''}>
              ${this.isGenerating ? 'Generating...' : '⚡ Generate Draft (Lineage DAG)'}
            </button>

            <button class="ctf-btn ctf-btn-secondary" id="ctfRedactSecretsBtn" title="Mask passwords, tokens and secrets">
              🔒 Redact Secrets
            </button>

            <div style="display: flex; gap: 2px;">
              <button class="ctf-btn ctf-btn-primary" id="ctfExportMdBtn" style="height: 28px;">
                Export .md
              </button>
            </div>
          </div>
        </div>

        <!-- Dual Pane: Editor (Left) & Preview (Right) -->
        <div class="ctf-writeup-container" style="flex: 1; min-height: 0;">
          <!-- Left: Markdown Raw Editor -->
          <div class="ctf-writeup-pane">
            <div style="padding: 6px 12px; background: var(--ctf-bg-surface-1); border-bottom: 1px solid var(--ctf-border-subtle); font-size: 11px; font-weight: 700; color: var(--ctf-text-secondary); display: flex; justify-content: space-between;">
              <span>MARKDOWN SOURCE</span>
              <span style="font-family: var(--ctf-font-mono);">${md.length} chars</span>
            </div>
            <textarea
              id="ctfWriteupEditorTextarea"
              class="ctf-writeup-textarea"
              placeholder="# Write-up: ${escapeAttr(activeChal?.title || 'Challenge')}&#10;&#10;## Overview&#10;Describe vulnerability and approach...&#10;&#10;## Solution Steps&#10;1. Ingest artifact&#10;2. Apply transformation..."
            >${escapeHtml(md)}</textarea>
          </div>

          <!-- Right: Safe Live Preview with Redaction Pills -->
          <div class="ctf-writeup-pane" style="border-right: none;">
            <div style="padding: 6px 12px; background: var(--ctf-bg-surface-1); border-bottom: 1px solid var(--ctf-border-subtle); font-size: 11px; font-weight: 700; color: var(--ctf-text-secondary); display: flex; justify-content: space-between;">
              <span>LIVE PREVIEW (SEC-ARCH-05 ISOLATED)</span>
              <span class="ctf-badge ctf-badge-forensics">AAA CONTRAST</span>
            </div>
            <div class="ctf-writeup-preview" id="ctfWriteupPreviewContainer">
              ${renderMarkdown(md)}
            </div>
          </div>
        </div>
      </div>
    `;

    this.bindEvents();
  }

  bindEvents() {
    if (!this.container) return;

    // Textarea input
    const textarea = this.container.querySelector('#ctfWriteupEditorTextarea');
    textarea?.addEventListener('input', (e) => {
      this.store.updateMarkdown(e.target.value);
    });

    // Generate draft
    this.container.querySelector('#ctfGenerateDraftBtn')?.addEventListener('click', async () => {
      const chalId = this.workspace.getState().activeChallengeId;
      if (!chalId) {
        alert('Пожалуйста, выберите задачу перед генерацией черновика отчета.');
        return;
      }

      this.isGenerating = true;
      this.render();
      try {
        await this.store.loadDraft(chalId);
      } catch (err) {
        console.error('[WriteupView] Draft generation error:', err);
      } finally {
        this.isGenerating = false;
        this.render();
      }
    });

    // Redact secrets
    this.container.querySelector('#ctfRedactSecretsBtn')?.addEventListener('click', () => {
      const current = this.store.getState().draftMarkdown || '';
      const redacted = this.store.redactSecrets(current);
      this.store.updateMarkdown(redacted);
    });

    // Export .md
    this.container.querySelector('#ctfExportMdBtn')?.addEventListener('click', async () => {
      try {
        const chalTitle = this.workspace.getState().activeChallenge?.title || 'ctf-writeup';
        const sanitized = chalTitle.toLowerCase().replace(/[^a-z0-9_-]/g, '_');
        await this.store.exportWriteup('markdown', `${sanitized}_report.md`);
      } catch (err) {
        console.error('[WriteupView] Export error:', err);
      }
    });
  }
}

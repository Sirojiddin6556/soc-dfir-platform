/**
 * writeup_store.js - CTF Writeup Studio & Markdown Report Store
 * Manages writeup drafting, lineage DAG integration, section editing,
 * secret redaction ([REDACTED] per SEC-ARCH-05), and markdown exporting.
 * Implements Contract A & TASK-FE-07 for Role 16.
 */

import { ctfIpc } from './ctf_ipc.js';

export const COMMON_SECRET_PATTERNS = [
  /password\s*[:=]\s*['"]?([^\s'"]+)['"]?/gi,
  /api[_-]?key\s*[:=]\s*['"]?([^\s'"]+)['"]?/gi,
  /bearer\s+([a-zA-Z0-9_\-\.]{20,})/gi,
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
  /ghp_[a-zA-Z0-9]{36}/g,
  /glpat-[a-zA-Z0-9\-_]{20}/g,
  /xox[baprs]-[0-9a-zA-Z]{10,48}/g
];

export class WriteupStore {
  /**
   * @param {import('./ctf_ipc.js').CtfIpcClient} [ipc=ctfIpc]
   */
  constructor(ipc = ctfIpc) {
    this.ipc = ipc;
    this.listeners = new Set();

    this.state = {
      challengeId: null,
      draftMarkdown: '',
      sections: {
        overview: '',
        steps: '',
        flag: '',
        timeline: ''
      },
      isGenerating: false,
      isSaving: false,
      isDirty: false,
      exportPath: null,
      customSecrets: [],
      error: null
    };
  }

  getState = () => this.state;

  setState = (updater) => {
    const next = typeof updater === 'function' ? updater(this.state) : updater;
    this.state = { ...this.state, ...next };
    this.notify();
  };

  subscribe = (listener) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  notify() {
    for (const listener of this.listeners) {
      try {
        listener(this.state);
      } catch (err) {
        console.error('[WriteupStore] Listener error:', err);
      }
    }
  }

  /**
   * Generates or loads a Markdown writeup draft from the backend.
   * @param {string} challengeId
   * @param {boolean} [includeTimeline=true]
   */
  async loadDraft(challengeId, includeTimeline = true) {
    if (!challengeId) return;

    this.setState({ isGenerating: true, error: null, challengeId });
    try {
      const resp = await this.ipc.generateWriteupDraft(challengeId, includeTimeline);
      const markdown = resp.markdown || '';

      const sections = this.parseSectionsFromMarkdown(markdown);

      this.setState({
        draftMarkdown: markdown,
        sections,
        isGenerating: false,
        isDirty: false
      });

      return markdown;
    } catch (err) {
      this.setState({ error: err.message, isGenerating: false });
      throw err;
    }
  }

  /**
   * Parses common Markdown section headings (Overview, Steps / Solution, Flag, Timeline).
   * @param {string} markdown
   * @returns {{ overview: string, steps: string, flag: string, timeline: string }}
   */
  parseSectionsFromMarkdown(markdown) {
    const sections = {
      overview: '',
      steps: '',
      flag: '',
      timeline: ''
    };

    if (!markdown) return sections;

    const parts = markdown.split(/^##\s+/m);
    for (const part of parts) {
      const lines = part.split('\n');
      const title = lines[0].trim().toLowerCase();
      const content = lines.slice(1).join('\n').trim();

      if (title.includes('overview') || title.includes('description') || title.includes('введение')) {
        sections.overview = content;
      } else if (title.includes('step') || title.includes('solution') || title.includes('решение')) {
        sections.steps = content;
      } else if (title.includes('flag') || title.includes('флаг')) {
        sections.flag = content;
      } else if (title.includes('timeline') || title.includes('хронология')) {
        sections.timeline = content;
      }
    }

    return sections;
  }

  /**
   * Sets raw markdown editor content.
   * @param {string} markdown
   */
  setMarkdown(markdown) {
    this.setState({
      draftMarkdown: markdown,
      sections: this.parseSectionsFromMarkdown(markdown),
      isDirty: true
    });
  }

  /**
   * Updates a specific writeup section and synchronizes with the backend.
   * @param {'overview' | 'steps' | 'flag' | 'timeline'} section
   * @param {string} content
   */
  async updateSection(section, content) {
    const { challengeId, sections } = this.state;
    const updatedSections = { ...sections, [section]: content };

    // Reconstruct full markdown document
    const reconstructed = this.reconstructMarkdown(updatedSections);

    this.setState({
      sections: updatedSections,
      draftMarkdown: reconstructed,
      isDirty: true
    });

    if (challengeId) {
      try {
        await this.ipc.updateWriteupSection(challengeId, section, content);
      } catch (err) {
        console.warn(`[WriteupStore] Backend section sync warning (${section}):`, err.message);
      }
    }
  }

  /**
   * Reassembles full markdown text from structured sections.
   * @param {{ overview: string, steps: string, flag: string, timeline: string }} sections
   * @returns {string}
   */
  reconstructMarkdown(sections) {
    const chunks = [];
    if (sections.overview) chunks.push(`## Overview\n\n${sections.overview}`);
    if (sections.steps) chunks.push(`## Solution Steps\n\n${sections.steps}`);
    if (sections.flag) chunks.push(`## Flag\n\n${sections.flag}`);
    if (sections.timeline) chunks.push(`## Timeline\n\n${sections.timeline}`);
    return chunks.join('\n\n');
  }

  /**
   * Redacts sensitive credentials, tokens, and custom secrets from markdown content (SEC-ARCH-05).
   * @param {string} [customContent] - Optional content to redact (defaults to draftMarkdown)
   * @param {string[]} [extraSecrets=[]] - Additional strings to mask
   * @returns {string} Redacted content
   */
  redactSecrets(customContent = null, extraSecrets = []) {
    let content = customContent !== null ? customContent : this.state.draftMarkdown;
    if (!content) return '';

    // Apply regex patterns
    for (const pattern of COMMON_SECRET_PATTERNS) {
      content = content.replace(pattern, (match, p1) => {
        if (p1) {
          return match.replace(p1, '[REDACTED]');
        }
        return '[REDACTED]';
      });
    }

    // Apply exact secret matches
    const allCustom = [...this.state.customSecrets, ...extraSecrets];
    for (const secret of allCustom) {
      if (secret && typeof secret === 'string' && secret.trim().length > 2) {
        const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        content = content.replace(new RegExp(escaped, 'g'), '[REDACTED]');
      }
    }

    return content;
  }

  /**
   * Registers custom sensitive tokens for redaction masking.
   * @param {string[]} secrets
   */
  registerSecrets(secrets) {
    if (!Array.isArray(secrets)) return;
    this.setState((prev) => ({
      customSecrets: Array.from(new Set([...prev.customSecrets, ...secrets]))
    }));
  }

  /**
   * Appends an executed transformation step into the Solution Steps section.
   * @param {{ operation: string, params: object, outputArtifactId?: string, hash?: string }} step
   */
  insertStepFromDAG(step) {
    const formatted = `\n- **Step: ${step.operation}**\n  - Parameters: \`${JSON.stringify(step.params || {})}\`\n` +
      (step.outputArtifactId ? `  - Output Artifact: \`${step.outputArtifactId}\`\n` : '');

    const currentSteps = this.state.sections.steps;
    this.updateSection('steps', currentSteps ? `${currentSteps}\n${formatted}` : formatted);
  }

  /**
   * Exports the writeup markdown to local destination path via backend IPC.
   * @param {string} destPath
   * @returns {Promise<{ bytes_written: number }>}
   */
  async exportMarkdown(destPath) {
    const { challengeId, draftMarkdown } = this.state;
    if (!challengeId) {
      throw new Error('No challenge selected for writeup export');
    }
    if (!destPath || !destPath.trim()) {
      throw new Error('Destination path cannot be empty');
    }

    this.setState({ isSaving: true, error: null });
    try {
      // First ensure the latest section state is saved
      const redacted = this.redactSecrets(draftMarkdown);
      const resp = await this.ipc.exportWriteup(challengeId, destPath);

      this.setState({
        isSaving: false,
        isDirty: false,
        exportPath: destPath
      });

      return resp;
    } catch (err) {
      this.setState({ error: err.message, isSaving: false });
      throw err;
    }
  }
}

export const writeupStore = new WriteupStore();

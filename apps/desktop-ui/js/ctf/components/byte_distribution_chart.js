/**
 * byte_distribution_chart.js - 256-Bin Byte Frequency Histogram Component
 * Analyzes byte distributions (0x00..0xFF) for cryptography, steganography, and filetype detection.
 * Provides interactive hover, Shannon entropy, Chi-Square statistic, and top byte frequencies.
 * Role: 20a (Data Visualization Engineer)
 */

import { hexStore } from '../hex_store.js';
import { calculateShannonEntropy } from './entropy_minimap.js';

/**
 * Calculates Chi-Square statistic against uniform distribution (E = N / 256).
 * @param {Uint32Array} freqs
 * @param {number} totalBytes
 * @returns {number}
 */
export function calculateChiSquare(freqs, totalBytes) {
  if (totalBytes === 0) return 0;
  const expected = totalBytes / 256;
  let chi2 = 0;
  for (let i = 0; i < 256; i++) {
    const diff = freqs[i] - expected;
    chi2 += (diff * diff) / expected;
  }
  return chi2;
}

export class ByteDistributionChart {
  /**
   * @param {Object} [options]
   * @param {import('../hex_store.js').HexStore} [options.store=hexStore]
   * @param {string} [options.title='Byte Frequency Distribution (0x00 - 0xFF)']
   */
  constructor(options = {}) {
    this.store = options.store || hexStore;
    this.title = options.title || 'Byte Frequency Distribution (0x00 - 0xFF)';

    this.container = null;
    this.canvas = null;
    this.ctx = null;
    this.tooltip = null;
    this.statsContainer = null;
    this.unsubscribe = null;

    this.freqs = new Uint32Array(256);
    this.totalBytes = 0;
    this.maxFreq = 0;
    this.entropy = 0;
    this.chiSquare = 0;
    this.hoveredBin = -1;
    this.topBytes = [];
  }

  mount(container) {
    this.container = container;
    this.container.innerHTML = `
      <div class="ctf-byte-chart-container" style="
        display: flex;
        flex-direction: column;
        height: 100%;
        background: var(--ctf-bg-surface-0, #0D1117);
        border: 1px solid var(--ctf-border-default, #30363D);
        border-radius: var(--ctf-radius-md, 4px);
        overflow: hidden;
        user-select: none;
      ">
        <!-- Header -->
        <div style="
          height: 32px;
          padding: 0 12px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          background: var(--ctf-bg-surface-1, #161B22);
          border-bottom: 1px solid var(--ctf-border-subtle, #21262D);
          font-size: 11px;
          font-weight: 600;
          color: var(--ctf-text-secondary, #8B949E);
        ">
          <div style="display: flex; align-items: center; gap: 6px; color: var(--ctf-text-primary, #F0F6FC);">
            <span style="color: var(--ctf-accent-cyan, #00E5FF);">📊</span>
            <span>${this.title}</span>
          </div>
          <div id="ctfByteScopeLabel" style="font-family: var(--ctf-font-mono, monospace); font-size: 10px;">
            Scope: Full File (Sample)
          </div>
        </div>

        <!-- Canvas Histogram Wrapper -->
        <div style="flex: 1; min-height: 120px; position: relative; padding: 10px 12px 4px 12px;" id="ctfChartWrapper">
          <canvas class="ctf-byte-canvas" style="width: 100%; height: 100%; display: block;"></canvas>
          <div class="ctf-chart-tooltip" style="
            position: absolute;
            display: none;
            background: var(--ctf-bg-surface-3, #30363D);
            border: 1px solid var(--ctf-border-focus, #00E5FF);
            border-radius: 4px;
            padding: 4px 8px;
            font-family: var(--ctf-font-mono, monospace);
            font-size: 11px;
            color: var(--ctf-text-primary, #F0F6FC);
            pointer-events: none;
            z-index: 10;
            box-shadow: 0 4px 12px rgba(0,0,0,0.6);
          "></div>
        </div>

        <!-- Legend / Axis Markers -->
        <div style="
          height: 18px;
          padding: 0 12px;
          display: flex;
          justify-content: space-between;
          font-family: var(--ctf-font-mono, monospace);
          font-size: 9px;
          color: var(--ctf-text-muted, #6E7681);
          border-bottom: 1px solid var(--ctf-border-subtle, #21262D);
        ">
          <span>0x00</span>
          <span>0x20 [Space]</span>
          <span>0x40 [@]</span>
          <span>0x60 [\`]</span>
          <span>0x7F [DEL]</span>
          <span>0xA0</span>
          <span>0xC0</span>
          <span>0xFF</span>
        </div>

        <!-- Statistics & Top Frequency Bar -->
        <div class="ctf-chart-stats" style="
          padding: 8px 12px;
          background: var(--ctf-bg-surface-1, #161B22);
          display: grid;
          grid-template-columns: repeat(4, 1fr) 2fr;
          gap: 8px;
          font-family: var(--ctf-font-mono, monospace);
          font-size: 11px;
          align-items: center;
        ">
          <div>
            <div style="font-size: 9px; color: var(--ctf-text-secondary, #8B949E);">TOTAL BYTES</div>
            <div id="ctfStatTotal" style="font-weight: 700; color: var(--ctf-text-primary, #F0F6FC);">0 B</div>
          </div>
          <div>
            <div style="font-size: 9px; color: var(--ctf-text-secondary, #8B949E);">ENTROPY H(x)</div>
            <div id="ctfStatEntropy" style="font-weight: 700; color: var(--ctf-accent-cyan, #00E5FF);">0.00 / 8.0</div>
          </div>
          <div>
            <div style="font-size: 9px; color: var(--ctf-text-secondary, #8B949E);">CHI-SQUARE χ²</div>
            <div id="ctfStatChi2" style="font-weight: 700; color: var(--ctf-text-primary, #F0F6FC);">0.0</div>
          </div>
          <div>
            <div style="font-size: 9px; color: var(--ctf-text-secondary, #8B949E);">CLASSIFICATION</div>
            <div id="ctfStatClass" style="font-weight: 700; color: var(--ctf-accent-amber, #F59E0B);">Unknown</div>
          </div>
          <div>
            <div style="font-size: 9px; color: var(--ctf-text-secondary, #8B949E);">TOP BYTES (FREQ)</div>
            <div id="ctfStatTop" style="font-size: 10px; color: var(--ctf-text-offset, #79C0FF); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">-</div>
          </div>
        </div>
      </div>
    `;

    this.canvas = this.container.querySelector('.ctf-byte-canvas');
    this.ctx = this.canvas.getContext('2d');
    this.tooltip = this.container.querySelector('.ctf-chart-tooltip');

    this.setupEvents();
    this.resizeCanvas();

    this.unsubscribe = this.store.subscribe(() => {
      this.refreshFromStore();
    });

    this.refreshFromStore();
  }

  destroy() {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    if (this.container) {
      this.container.innerHTML = '';
      this.container = null;
    }
  }

  resizeCanvas() {
    if (!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.max(1, Math.floor(rect.width * dpr));
    this.canvas.height = Math.max(1, Math.floor(rect.height * dpr));
    if (this.ctx) {
      this.ctx.scale(dpr, dpr);
    }
    this.render();
  }

  setupEvents() {
    const wrapper = this.container.querySelector('#ctfChartWrapper');
    if (!wrapper) return;

    this.resizeObserver = new ResizeObserver(() => {
      this.resizeCanvas();
    });
    this.resizeObserver.observe(wrapper);

    wrapper.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const binWidth = rect.width / 256;
      const bin = Math.max(0, Math.min(255, Math.floor(x / binWidth)));

      this.hoveredBin = bin;
      this.render();

      const count = this.freqs[bin];
      const pct = this.totalBytes > 0 ? ((count / this.totalBytes) * 100).toFixed(2) : '0.00';
      const hex = '0x' + bin.toString(16).padStart(2, '0').toUpperCase();
      const asciiChar = bin >= 32 && bin <= 126 ? `'${String.fromCharCode(bin)}'` : 'non-printable';

      this.tooltip.innerHTML = `
        <div style="font-weight: 700; color: var(--ctf-accent-cyan, #00E5FF);">${hex} (${bin}) - ${asciiChar}</div>
        <div>Count: <strong>${count.toLocaleString()}</strong></div>
        <div>Frequency: <strong>${pct}%</strong></div>
      `;

      let tooltipX = x + 16;
      if (tooltipX + 160 > rect.width) tooltipX = x - 165;
      this.tooltip.style.left = `${tooltipX}px`;
      this.tooltip.style.top = `${Math.max(10, e.clientY - rect.top - 30)}px`;
      this.tooltip.style.display = 'block';
    });

    wrapper.addEventListener('mouseleave', () => {
      this.hoveredBin = -1;
      this.tooltip.style.display = 'none';
      this.render();
    });
  }

  refreshFromStore() {
    const state = this.store.getState();
    const scopeLabel = this.container?.querySelector('#ctfByteScopeLabel');

    if (!state.artifact) {
      this.clearData();
      return;
    }

    if (state.selection && state.selection.start <= state.selection.end) {
      const selectedBytes = this.store.getSelectedBytes();
      if (scopeLabel) {
        scopeLabel.textContent = `Selection [0x${state.selection.start.toString(16).toUpperCase()}..0x${state.selection.end.toString(16).toUpperCase()}] (${selectedBytes.length} B)`;
      }
      this.analyzeBytes(selectedBytes);
    } else {
      // Analyze first loaded chunk or all loaded chunks
      const chunks = Array.from(state.chunkCache.values());
      if (chunks.length > 0) {
        if (scopeLabel) {
          scopeLabel.textContent = `Cached Memory (${chunks.reduce((acc, c) => acc + c.length, 0)} B)`;
        }
        this.analyzeChunks(chunks);
      } else {
        this.clearData();
      }
    }
  }

  clearData() {
    this.freqs.fill(0);
    this.totalBytes = 0;
    this.maxFreq = 0;
    this.entropy = 0;
    this.chiSquare = 0;
    this.topBytes = [];
    this.updateStatsUI();
    this.render();
  }

  analyzeChunks(chunks) {
    this.freqs.fill(0);
    let total = 0;
    for (const chunk of chunks) {
      for (let i = 0; i < chunk.length; i++) {
        this.freqs[chunk[i]]++;
      }
      total += chunk.length;
    }
    this.finishAnalysis(total);
  }

  analyzeBytes(bytes) {
    this.freqs.fill(0);
    if (!bytes || bytes.length === 0) {
      this.clearData();
      return;
    }
    for (let i = 0; i < bytes.length; i++) {
      this.freqs[bytes[i]]++;
    }
    this.finishAnalysis(bytes.length);
  }

  finishAnalysis(total) {
    this.totalBytes = total;
    let max = 0;
    for (let i = 0; i < 256; i++) {
      if (this.freqs[i] > max) max = this.freqs[i];
    }
    this.maxFreq = max;

    // Entropy
    let ent = 0;
    for (let i = 0; i < 256; i++) {
      const c = this.freqs[i];
      if (c > 0) {
        const p = c / total;
        ent -= p * Math.log2(p);
      }
    }
    this.entropy = Math.min(8.0, Math.max(0.0, ent));
    this.chiSquare = calculateChiSquare(this.freqs, total);

    // Top 5 bytes
    const sorted = [];
    for (let i = 0; i < 256; i++) {
      if (this.freqs[i] > 0) {
        sorted.push({ byte: i, count: this.freqs[i], pct: (this.freqs[i] / total) * 100 });
      }
    }
    sorted.sort((a, b) => b.count - a.count);
    this.topBytes = sorted.slice(0, 5);

    this.updateStatsUI();
    this.render();
  }

  updateStatsUI() {
    if (!this.container) return;
    const totalEl = this.container.querySelector('#ctfStatTotal');
    const entEl = this.container.querySelector('#ctfStatEntropy');
    const chiEl = this.container.querySelector('#ctfStatChi2');
    const classEl = this.container.querySelector('#ctfStatClass');
    const topEl = this.container.querySelector('#ctfStatTop');

    if (totalEl) totalEl.textContent = `${this.totalBytes.toLocaleString()} B`;
    if (entEl) entEl.textContent = `${this.entropy.toFixed(2)} / 8.00`;
    if (chiEl) chiEl.textContent = this.chiSquare.toFixed(1);

    if (classEl) {
      if (this.entropy >= 7.8) {
        classEl.textContent = 'Encrypted / Stego (Uniform)';
        classEl.style.color = 'var(--ctf-accent-crimson, #EF4444)';
      } else if (this.entropy >= 6.8) {
        classEl.textContent = 'Compressed / Archive';
        classEl.style.color = 'var(--ctf-accent-amber, #F59E0B)';
      } else if (this.entropy >= 4.5) {
        classEl.textContent = 'Native Code / Binary';
        classEl.style.color = 'var(--ctf-accent-cyan, #00E5FF)';
      } else if (this.entropy >= 2.0) {
        classEl.textContent = 'Structured Text / Log';
        classEl.style.color = 'var(--ctf-accent-emerald, #10B981)';
      } else {
        classEl.textContent = 'Low Entropy / Sparse';
        classEl.style.color = 'var(--ctf-text-secondary, #8B949E)';
      }
    }

    if (topEl) {
      if (this.topBytes.length === 0) {
        topEl.textContent = 'None';
      } else {
        topEl.innerHTML = this.topBytes.map(b => {
          const hex = '0x' + b.byte.toString(16).padStart(2, '0').toUpperCase();
          const ch = b.byte >= 32 && b.byte <= 126 ? ` '${String.fromCharCode(b.byte)}'` : '';
          return `<span style="margin-right: 8px;">${hex}${ch}: <strong>${b.pct.toFixed(1)}%</strong></span>`;
        }).join('');
      }
    }
  }

  render() {
    if (!this.canvas || !this.ctx) return;
    const width = this.canvas.clientWidth;
    const height = this.canvas.clientHeight;
    if (width === 0 || height === 0) return;

    this.ctx.clearRect(0, 0, width, height);

    // Uniform expected line (if totalBytes > 0)
    if (this.totalBytes > 0 && this.maxFreq > 0) {
      const expected = this.totalBytes / 256;
      const expectedY = height - (expected / this.maxFreq) * (height - 10);
      this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
      this.ctx.lineWidth = 1;
      this.ctx.setLineDash([3, 3]);
      this.ctx.beginPath();
      this.ctx.moveTo(0, expectedY);
      this.ctx.lineTo(width, expectedY);
      this.ctx.stroke();
      this.ctx.setLineDash([]);
    }

    const binWidth = width / 256;

    for (let i = 0; i < 256; i++) {
      const count = this.freqs[i];
      const barHeight = this.maxFreq > 0 ? (count / this.maxFreq) * (height - 10) : 0;
      const x = i * binWidth;
      const y = height - barHeight;

      if (i === this.hoveredBin) {
        this.ctx.fillStyle = '#FFFFFF';
      } else if (i === 0) {
        this.ctx.fillStyle = '#484F58'; // Zero byte
      } else if (i >= 32 && i <= 126) {
        this.ctx.fillStyle = '#00E5FF'; // Printable ASCII: Cyan
      } else if (i < 32) {
        this.ctx.fillStyle = '#6E7681'; // Control characters: Muted slate
      } else {
        this.ctx.fillStyle = '#A78BFA'; // High/Extended: Violet
      }

      this.ctx.fillRect(x, y, Math.max(1, binWidth - 0.5), Math.max(1, barHeight));
    }
  }
}

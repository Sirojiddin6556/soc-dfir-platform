/**
 * entropy_minimap.js - Shannon Entropy Minimap Component
 * Visualizes Shannon entropy (0.0 to 8.0 bits/byte) across file offsets on a Canvas strip.
 * Features colorblind-safe spectrum, zero UI freeze for 500MB files, and click-to-scroll.
 * Role: 20a (Data Visualization Engineer)
 */

import { hexStore, CHUNK_SIZE } from '../hex_store.js';

/**
 * Calculates Shannon entropy for a given Uint8Array slice:
 * H = - SUM( p_i * log2(p_i) ) for i in 0..255
 * @param {Uint8Array} bytes
 * @returns {number} Entropy in range [0.0, 8.0]
 */
export function calculateShannonEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0.0;
  const len = bytes.length;
  const freqs = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    freqs[bytes[i]]++;
  }
  let entropy = 0.0;
  for (let i = 0; i < 256; i++) {
    const c = freqs[i];
    if (c > 0) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.min(8.0, Math.max(0.0, entropy));
}

/**
 * Maps entropy value [0.0 .. 8.0] to a colorblind-safe color representation.
 * - [0.0 .. 3.5): Low entropy / Nulls / Repetitive (Dark Slate / Sky)
 * - [3.5 .. 5.8): Text / Structured data (Cyan)
 * - [5.8 .. 7.2): Executable code / Native binary (Amber)
 * - [7.2 .. 8.0]: Encrypted / Compressed / High entropy (Crimson)
 * @param {number} entropy
 * @param {number} [alpha=1.0]
 * @returns {string} CSS rgba color
 */
export function getEntropyColor(entropy, alpha = 1.0) {
  if (entropy < 3.5) {
    // Low entropy: from dark surface (#161b22) to soft sky (#38bdf8)
    const factor = Math.max(0, entropy) / 3.5;
    const r = Math.round(22 + (56 - 22) * factor);
    const g = Math.round(27 + (189 - 27) * factor);
    const b = Math.round(34 + (248 - 34) * factor);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  } else if (entropy < 5.8) {
    // Text / ASCII: Cyan (#00E5FF)
    const factor = (entropy - 3.5) / 2.3;
    const r = 0;
    const g = Math.round(200 + (229 - 200) * factor);
    const b = 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  } else if (entropy < 7.2) {
    // Code: Amber (#F59E0B)
    const factor = (entropy - 5.8) / 1.4;
    const r = 245;
    const g = Math.round(180 - (180 - 158) * factor);
    const b = Math.round(50 - (50 - 11) * factor);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  } else {
    // Encrypted / Compressed: Crimson (#EF4444)
    const factor = Math.min(1.0, (entropy - 7.2) / 0.8);
    const r = Math.round(220 + (239 - 220) * factor);
    const g = Math.round(50 - 50 * factor);
    const b = Math.round(50 - 50 * factor);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
}

export class EntropyMinimap {
  /**
   * @param {Object} [options]
   * @param {import('../hex_store.js').HexStore} [options.store=hexStore]
   * @param {(offset: number) => void} [options.onSeek]
   * @param {number} [options.numBins=300]
   */
  constructor(options = {}) {
    this.store = options.store || hexStore;
    this.onSeek = options.onSeek || null;
    this.numBins = options.numBins || 300;

    this.container = null;
    this.canvas = null;
    this.ctx = null;
    this.tooltip = null;
    this.unsubscribe = null;

    this.binEntropy = new Float32Array(this.numBins);
    this.binCalculated = new Uint8Array(this.numBins); // 1 = calculated, 0 = pending
    this.viewportRange = { startRow: 0, endRow: 0 };
    this.isDragging = false;
  }

  mount(container) {
    this.container = container;
    this.container.innerHTML = `
      <div class="ctf-entropy-minimap-container" style="
        position: relative;
        width: 38px;
        height: 100%;
        background: var(--ctf-bg-surface-1, #161B22);
        border-left: 1px solid var(--ctf-border-subtle, #21262D);
        user-select: none;
        display: flex;
        flex-direction: column;
      ">
        <div style="
          height: 24px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: var(--ctf-font-mono, monospace);
          font-size: 9px;
          font-weight: 700;
          color: var(--ctf-text-secondary, #8B949E);
          border-bottom: 1px solid var(--ctf-border-subtle, #21262D);
        " title="Shannon Entropy Strip (0.0 - 8.0 bits/byte)">
          H(x)
        </div>
        <div style="flex: 1; position: relative; overflow: hidden;" id="ctfMinimapCanvasWrapper">
          <canvas class="ctf-entropy-canvas" style="width: 100%; height: 100%; display: block; cursor: pointer;"></canvas>
          <div class="ctf-minimap-viewport" style="
            position: absolute;
            left: 0;
            width: 100%;
            border: 1px solid var(--ctf-accent-cyan, #00E5FF);
            background: rgba(0, 229, 255, 0.15);
            pointer-events: none;
            display: none;
          "></div>
        </div>
        <div class="ctf-entropy-tooltip" style="
          position: absolute;
          display: none;
          right: 44px;
          background: var(--ctf-bg-surface-3, #30363D);
          border: 1px solid var(--ctf-border-default, #484F58);
          border-radius: 4px;
          padding: 4px 8px;
          font-family: var(--ctf-font-mono, monospace);
          font-size: 10px;
          color: var(--ctf-text-primary, #F0F6FC);
          white-space: nowrap;
          z-index: 100;
          box-shadow: 0 4px 12px rgba(0,0,0,0.5);
          pointer-events: none;
        "></div>
      </div>
    `;

    this.canvas = this.container.querySelector('.ctf-entropy-canvas');
    this.ctx = this.canvas.getContext('2d');
    this.viewportEl = this.container.querySelector('.ctf-minimap-viewport');
    this.tooltip = this.container.querySelector('.ctf-entropy-tooltip');

    this.setupEvents();
    this.resizeCanvas();

    this.unsubscribe = this.store.subscribe((state) => {
      this.handleStateChange(state);
    });

    this.handleStateChange(this.store.getState());
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
    const wrapper = this.container.querySelector('#ctfMinimapCanvasWrapper');
    if (!wrapper) return;

    this.resizeObserver = new ResizeObserver(() => {
      this.resizeCanvas();
    });
    this.resizeObserver.observe(wrapper);

    const onPointerAction = (e) => {
      const rect = wrapper.getBoundingClientRect();
      const y = Math.max(0, Math.min(rect.height, e.clientY - rect.top));
      const ratio = y / rect.height;
      const totalSize = this.store.getState().totalSize;
      const targetOffset = Math.floor(ratio * totalSize);

      if (this.onSeek) {
        this.onSeek(targetOffset);
      } else {
        this.store.setCursor(targetOffset);
      }
    };

    wrapper.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      onPointerAction(e);
    });

    window.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        onPointerAction(e);
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    wrapper.addEventListener('mousemove', (e) => {
      const rect = wrapper.getBoundingClientRect();
      const y = Math.max(0, Math.min(rect.height, e.clientY - rect.top));
      const ratio = y / rect.height;
      const totalSize = this.store.getState().totalSize;
      const offset = Math.floor(ratio * totalSize);
      const binIdx = Math.floor(ratio * this.numBins);
      const entropy = this.binEntropy[Math.min(this.numBins - 1, binIdx)] || 0.0;

      let classification = 'Low';
      if (entropy >= 7.2) classification = 'Encrypted/Compressed';
      else if (entropy >= 5.8) classification = 'Code/Binary';
      else if (entropy >= 3.5) classification = 'Text/Data';

      const offsetHex = '0x' + offset.toString(16).padStart(8, '0').toUpperCase();
      this.tooltip.innerHTML = `
        <div style="font-weight: 700; color: var(--ctf-text-offset, #79C0FF);">${offsetHex}</div>
        <div>H: <span style="font-weight: 700; color: ${getEntropyColor(entropy)};">${entropy.toFixed(2)}</span> bits/byte</div>
        <div style="font-size: 9px; color: var(--ctf-text-secondary, #8B949E);">${classification}</div>
      `;
      this.tooltip.style.top = `${Math.min(rect.height - 50, Math.max(0, y - 20))}px`;
      this.tooltip.style.display = 'block';
    });

    wrapper.addEventListener('mouseleave', () => {
      this.tooltip.style.display = 'none';
    });
  }

  handleStateChange(state) {
    if (!state.artifact) {
      this.binEntropy.fill(0);
      this.binCalculated.fill(0);
      this.render();
      return;
    }

    const { totalSize, chunkCache } = state;
    if (totalSize === 0) return;

    // Fast calculation of entropy for all loaded chunks
    const bytesPerBin = totalSize / this.numBins;
    for (let b = 0; b < this.numBins; b++) {
      const binStart = Math.floor(b * bytesPerBin);
      const chunkIdx = Math.floor(binStart / CHUNK_SIZE);
      const chunk = chunkCache.get(chunkIdx);

      if (chunk && !this.binCalculated[b]) {
        const offsetInChunk = binStart % CHUNK_SIZE;
        const sampleLen = Math.min(256, chunk.length - offsetInChunk);
        if (sampleLen > 0) {
          const sample = chunk.subarray(offsetInChunk, offsetInChunk + sampleLen);
          this.binEntropy[b] = calculateShannonEntropy(sample);
          this.binCalculated[b] = 1;
        }
      }
    }

    this.render();
  }

  setViewportRange(startRow, endRow, totalRows) {
    this.viewportRange = { startRow, endRow };
    if (!this.viewportEl || !this.canvas || totalRows <= 0) return;

    const wrapper = this.container.querySelector('#ctfMinimapCanvasWrapper');
    if (!wrapper) return;
    const height = wrapper.clientHeight;

    const topPct = (startRow / totalRows) * height;
    const boxHeight = Math.max(4, ((endRow - startRow) / totalRows) * height);

    this.viewportEl.style.top = `${topPct}px`;
    this.viewportEl.style.height = `${boxHeight}px`;
    this.viewportEl.style.display = 'block';
  }

  render() {
    if (!this.canvas || !this.ctx) return;
    const width = this.canvas.clientWidth;
    const height = this.canvas.clientHeight;
    if (width === 0 || height === 0) return;

    this.ctx.clearRect(0, 0, width, height);

    const binHeight = height / this.numBins;
    for (let i = 0; i < this.numBins; i++) {
      const y = i * binHeight;
      const h = Math.max(1, binHeight + 0.5);
      const entropy = this.binEntropy[i];
      const isCalc = this.binCalculated[i];

      // Draw background bar
      this.ctx.fillStyle = isCalc ? getEntropyColor(entropy, 0.9) : '#1E242C';
      this.ctx.fillRect(0, y, width - 4, h);

      // Draw entropy indicator bar width (0.0 to 8.0 maps to 0 to width)
      if (isCalc && entropy > 0.1) {
        const barWidth = Math.min(width, (entropy / 8.0) * width);
        this.ctx.fillStyle = getEntropyColor(entropy, 1.0);
        this.ctx.fillRect(0, y, barWidth, h);
      }
    }
  }
}

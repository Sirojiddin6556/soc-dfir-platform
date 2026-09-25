/**
 * hex_viewer.js - Virtualized Hex Viewport Component
 * Consumes hex_store.js. Implements 16 bytes/row, zero-offset starts (0x00000000),
 * synchronized Hex & ASCII selection, byte inspector tooltip, search result highlighting,
 * and sliding window virtualization for 500MB+ CAS files.
 * Role: 20a (Data Visualization Engineer)
 */

import { hexStore, BYTES_PER_ROW } from '../hex_store.js';
import { EntropyMinimap } from './entropy_minimap.js';

export const ROW_HEIGHT = 20; // 20px fixed row height per design spec
export const OVERSCAN_ROWS = 15;

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

export class HexViewer {
  /**
   * @param {Object} [options]
   * @param {import('../hex_store.js').HexStore} [options.store=hexStore]
   * @param {boolean} [options.showMinimap=true]
   * @param {(bytes: Uint8Array) => void} [options.onSendToRecipe]
   */
  constructor(options = {}) {
    this.store = options.store || hexStore;
    this.showMinimap = options.showMinimap !== false;
    this.onSendToRecipe = options.onSendToRecipe || null;

    this.container = null;
    this.scrollEl = null;
    this.contentEl = null;
    this.phantomEl = null;
    this.tooltipEl = null;
    this.minimap = null;
    this.unsubscribe = null;

    this.isSelecting = false;
    this.selectionAnchor = null;
    this.isHexSearch = false;
  }

  mount(container) {
    this.container = container;
    this.container.innerHTML = `
      <div class="ctf-hex-viewport-root" style="display:flex; flex-direction:column; height:100%; background:var(--ctf-bg-surface-0, #0D1117); font-family:var(--ctf-font-mono, monospace); color:var(--ctf-text-primary, #F0F6FC); overflow:hidden;">
        <!-- Top Toolbar -->
        <div class="ctf-hex-toolbar" style="height:38px; padding:0 12px; display:flex; align-items:center; justify-content:space-between; background:var(--ctf-bg-surface-1, #161B22); border-bottom:1px solid var(--ctf-border-default, #30363D); font-size:12px; gap:8px; flex-shrink:0;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="color:var(--ctf-text-secondary, #8B949E); font-size:11px;">Go:</span>
            <input type="text" id="ctfHexGotoInput" placeholder="0x0000 or Dec" class="ctf-terminal-input" style="width:110px; height:24px; font-size:11px;" />
            <button class="ctf-btn ctf-btn-secondary" id="ctfHexGotoBtn" style="height:24px; padding:0 8px; font-size:11px;">Go</button>
            <span id="ctfHexFileMeta" style="color:var(--ctf-text-secondary, #8B949E); font-size:11px; margin-left:6px;"></span>
          </div>

          <div style="display:flex; align-items:center; gap:6px;">
            <input type="text" id="ctfHexSearchInput" placeholder="Search string / hex..." class="ctf-terminal-input" style="width:160px; height:24px; font-size:11px;" />
            <button class="ctf-btn ctf-btn-ghost" id="ctfHexSearchModeBtn" style="height:24px; padding:0 6px; font-size:10px; border:1px solid var(--ctf-border-default, #30363D);" title="Toggle Hex/ASCII">ASCII</button>
            <button class="ctf-btn ctf-btn-secondary" id="ctfHexSearchPrevBtn" style="height:24px; padding:0 6px;" title="Prev match">▲</button>
            <button class="ctf-btn ctf-btn-secondary" id="ctfHexSearchNextBtn" style="height:24px; padding:0 6px;" title="Next match">▼</button>
            <span id="ctfHexSearchStatus" style="font-size:10px; color:var(--ctf-accent-amber, #F59E0B);"></span>
          </div>

          <div style="display:flex; align-items:center; gap:6px;">
            <span id="ctfHexSelectionInfo" style="font-size:11px; color:var(--ctf-text-secondary, #8B949E);">Sel: 0 B</span>
            <select id="ctfHexCopySelect" class="ctf-terminal-input" style="height:24px; font-size:11px; padding:0 4px;">
              <option value="">Copy...</option>
              <option value="hex">Copy Hex</option>
              <option value="c-array">Copy C-Array</option>
              <option value="ascii">Copy ASCII</option>
              <option value="base64">Copy Base64</option>
            </select>
            <button class="ctf-btn ctf-btn-primary" id="ctfHexSendRecipeBtn" style="height:24px; padding:0 8px; font-size:11px;" title="Send selection to Recipe">⚙ Recipe</button>
          </div>
        </div>

        <!-- Body with Grid & Minimap -->
        <div style="flex:1; display:flex; overflow:hidden; position:relative;">
          <div style="flex:1; display:flex; flex-direction:column; overflow:hidden;">
            <!-- Column Gutter Header -->
            <div style="height:24px; display:flex; align-items:center; background:var(--ctf-bg-surface-1, #161B22); border-bottom:1px solid var(--ctf-border-subtle, #21262D); font-size:11px; color:var(--ctf-text-secondary, #8B949E); user-select:none; padding-right:14px;">
              <div class="ctf-hex-offset" style="font-weight:700;">OFFSET</div>
              <div style="display:flex; gap:6px; padding:0 10px;">
                <span style="width:176px; letter-spacing:0.15em;">00 01 02 03 04 05 06 07</span>
                <span style="width:12px;"></span>
                <span style="width:176px; letter-spacing:0.15em;">08 09 0A 0B 0C 0D 0E 0F</span>
              </div>
              <div style="width:150px; padding-left:12px; font-weight:700;">ASCII DECODE</div>
            </div>

            <!-- Virtual Scroll Container -->
            <div id="ctfHexScrollContainer" style="flex:1; overflow-y:auto; overflow-x:hidden; position:relative; outline:none;" tabindex="0">
              <div id="ctfHexPhantom" style="width:100%; pointer-events:none;"></div>
              <div id="ctfHexContent" style="position:absolute; top:0; left:0; right:0; will-change:transform;"></div>
            </div>
          </div>

          <div id="ctfHexMinimapSlot" style="width:38px; height:100%; display:${this.showMinimap ? 'block' : 'none'};"></div>
        </div>

        <div id="ctfByteInspectorTooltip" style="position:absolute; display:none; background:var(--ctf-bg-surface-3, #30363D); border:1px solid var(--ctf-border-focus, #00E5FF); border-radius:4px; padding:6px 10px; font-size:11px; color:var(--ctf-text-primary, #F0F6FC); pointer-events:none; z-index:200; box-shadow:0 4px 16px rgba(0,0,0,0.6); line-height:1.4;"></div>
      </div>
    `;

    this.scrollEl = this.container.querySelector('#ctfHexScrollContainer');
    this.phantomEl = this.container.querySelector('#ctfHexPhantom');
    this.contentEl = this.container.querySelector('#ctfHexContent');
    this.tooltipEl = this.container.querySelector('#ctfByteInspectorTooltip');

    if (this.showMinimap) {
      const minimapSlot = this.container.querySelector('#ctfHexMinimapSlot');
      this.minimap = new EntropyMinimap({
        store: this.store,
        onSeek: (offset) => this.scrollToOffset(offset)
      });
      this.minimap.mount(minimapSlot);
    }

    this.setupEvents();
    this.unsubscribe = this.store.subscribe((s) => this.updateFromStore(s));
    this.updateFromStore(this.store.getState());
  }

  destroy() {
    if (this.unsubscribe) { this.unsubscribe(); this.unsubscribe = null; }
    if (this.minimap) { this.minimap.destroy(); this.minimap = null; }
    if (this.container) { this.container.innerHTML = ''; this.container = null; }
  }

  setupEvents() {
    this.scrollEl.addEventListener('scroll', () => this.renderVisibleRows(), { passive: true });

    const gotoInput = this.container.querySelector('#ctfHexGotoInput');
    const doGoto = () => {
      const val = gotoInput.value.trim();
      if (!val) return;
      const offset = val.startsWith('0x') || val.startsWith('0X') ? parseInt(val, 16) : parseInt(val, 10);
      if (!isNaN(offset)) this.scrollToOffset(offset);
    };
    this.container.querySelector('#ctfHexGotoBtn').addEventListener('click', doGoto);
    gotoInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doGoto(); });

    const searchInput = this.container.querySelector('#ctfHexSearchInput');
    const modeBtn = this.container.querySelector('#ctfHexSearchModeBtn');
    modeBtn.addEventListener('click', () => {
      this.isHexSearch = !this.isHexSearch;
      modeBtn.textContent = this.isHexSearch ? 'HEX' : 'ASCII';
      this.executeSearch(searchInput.value);
    });
    searchInput.addEventListener('input', () => this.executeSearch(searchInput.value));

    this.container.querySelector('#ctfHexSearchPrevBtn').addEventListener('click', () => {
      this.store.prevHit();
      const s = this.store.getState();
      if (s.cursorOffset !== undefined) this.scrollToOffset(s.cursorOffset);
    });
    this.container.querySelector('#ctfHexSearchNextBtn').addEventListener('click', () => {
      this.store.nextHit();
      const s = this.store.getState();
      if (s.cursorOffset !== undefined) this.scrollToOffset(s.cursorOffset);
    });

    const copySelect = this.container.querySelector('#ctfHexCopySelect');
    copySelect.addEventListener('change', () => {
      if (copySelect.value) {
        const text = this.store.copySelection(copySelect.value);
        if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text);
        copySelect.value = '';
      }
    });

    this.container.querySelector('#ctfHexSendRecipeBtn').addEventListener('click', () => {
      if (this.onSendToRecipe) {
        this.store.sendSelectionToRecipe(this.onSendToRecipe);
      } else {
        const bytes = this.store.getSelectedBytes();
        window.dispatchEvent(new CustomEvent('ctf:sendToRecipe', { detail: { bytes } }));
      }
    });

    this.contentEl.addEventListener('mousedown', (e) => {
      const target = e.target.closest('[data-offset]');
      if (!target) return;
      const offset = parseInt(target.getAttribute('data-offset'), 10);
      if (isNaN(offset)) return;
      this.isSelecting = true;
      this.selectionAnchor = offset;
      if (e.shiftKey && this.store.getState().selection) {
        this.store.setSelection(this.store.getState().selection.start, offset);
      } else {
        this.store.setSelection(offset, offset);
      }
      this.store.setCursor(offset);
    });

    window.addEventListener('mousemove', (e) => {
      if (!this.isSelecting || this.selectionAnchor === null) return;
      const target = document.elementFromPoint(e.clientX, e.clientY)?.closest('[data-offset]');
      if (target) {
        const offset = parseInt(target.getAttribute('data-offset'), 10);
        if (!isNaN(offset)) this.store.setSelection(this.selectionAnchor, offset);
      }
    });

    window.addEventListener('mouseup', () => { this.isSelecting = false; });

    this.contentEl.addEventListener('mouseover', (e) => {
      const target = e.target.closest('[data-offset]');
      if (!target) { this.tooltipEl.style.display = 'none'; return; }
      this.showByteTooltip(parseInt(target.getAttribute('data-offset'), 10), e);
    });

    this.contentEl.addEventListener('mouseout', (e) => {
      if (!e.relatedTarget || !e.relatedTarget.closest('[data-offset]')) {
        this.tooltipEl.style.display = 'none';
      }
    });

    this.scrollEl.addEventListener('keydown', (e) => {
      const s = this.store.getState();
      let cur = s.cursorOffset || 0;
      if (e.key === 'ArrowUp') { cur = Math.max(0, cur - 16); e.preventDefault(); }
      else if (e.key === 'ArrowDown') { cur = Math.min(s.totalSize - 1, cur + 16); e.preventDefault(); }
      else if (e.key === 'ArrowLeft') { cur = Math.max(0, cur - 1); e.preventDefault(); }
      else if (e.key === 'ArrowRight') { cur = Math.min(s.totalSize - 1, cur + 1); e.preventDefault(); }
      else if (e.key === 'PageUp') { cur = Math.max(0, cur - 256); e.preventDefault(); }
      else if (e.key === 'PageDown') { cur = Math.min(s.totalSize - 1, cur + 256); e.preventDefault(); }
      else return;

      this.store.setCursor(cur);
      if (!e.shiftKey) this.store.setSelection(cur, cur);
      else if (this.selectionAnchor !== null) this.store.setSelection(this.selectionAnchor, cur);
      this.scrollToOffset(cur);
    });
  }

  executeSearch(term) {
    const hits = this.store.search(term, this.isHexSearch);
    const statusEl = this.container.querySelector('#ctfHexSearchStatus');
    if (statusEl) statusEl.textContent = term ? (hits.length > 0 ? `${hits.length} found` : 'No matches') : '';
  }

  scrollToOffset(offset) {
    const targetScrollTop = Math.floor(offset / BYTES_PER_ROW) * ROW_HEIGHT;
    this.scrollEl.scrollTop = targetScrollTop;
    this.renderVisibleRows();
  }

  updateFromStore(state) {
    if (!this.container) return;
    const { totalRows, totalSize, selection, searchHits, currentHitIndex } = state;
    this.phantomEl.style.height = `${totalRows * ROW_HEIGHT}px`;

    const metaEl = this.container.querySelector('#ctfHexFileMeta');
    if (metaEl) {
      metaEl.textContent = state.artifact ? `${state.artifact.filename || 'artifact'} (${(totalSize / 1024).toFixed(1)} KB)` : 'No file loaded';
    }

    const selEl = this.container.querySelector('#ctfHexSelectionInfo');
    if (selEl) {
      selEl.textContent = selection ? `0x${selection.start.toString(16).toUpperCase()}..0x${selection.end.toString(16).toUpperCase()} (${selection.end - selection.start + 1} B)` : 'Sel: 0 B';
      selEl.style.color = selection ? 'var(--ctf-accent-cyan, #00E5FF)' : 'var(--ctf-text-secondary, #8B949E)';
    }

    const searchStatus = this.container.querySelector('#ctfHexSearchStatus');
    if (searchStatus && searchHits.length > 0) {
      searchStatus.textContent = `[${currentHitIndex + 1}/${searchHits.length}]`;
    }

    this.renderVisibleRows();
  }

  renderVisibleRows() {
    if (!this.scrollEl || !this.contentEl) return;
    const scrollTop = this.scrollEl.scrollTop;
    const clientHeight = this.scrollEl.clientHeight || 400;
    const totalRows = this.store.getState().totalRows;

    const startRow = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN_ROWS);
    const endRow = Math.min(totalRows - 1, Math.ceil((scrollTop + clientHeight) / ROW_HEIGHT) + OVERSCAN_ROWS);

    this.store.prefetchChunks(startRow, endRow);
    if (this.minimap) this.minimap.setViewportRange(startRow, endRow, totalRows);

    this.contentEl.style.transform = `translateY(${startRow * ROW_HEIGHT}px)`;
    const { selection, cursorOffset, searchHits } = this.store.getState();

    let html = '';
    for (let r = startRow; r <= endRow; r++) {
      const row = this.store.formatRow(r);
      const isCursorRow = cursorOffset >= row.offset && cursorOffset < row.offset + BYTES_PER_ROW;
      let hex1 = '', hex2 = '', ascii = '';

      for (let i = 0; i < 16; i++) {
        const off = row.offset + i;
        const hexVal = row.hexParts[i];
        const ascVal = row.ascii[i];
        const isSel = selection && off >= selection.start && off <= selection.end;
        const isCur = off === cursorOffset;
        const isHit = searchHits && searchHits.includes(off);
        const isZero = hexVal === '00';

        const hexClasses = `ctf-hex-byte ${i % 2 === 0 ? 'even' : 'odd'} ${isZero ? 'zero-byte' : ''} ${isSel ? 'selected' : ''} ${isCur ? 'cursor' : ''} ${isHit ? 'search-hit' : ''}`;
        const asciiClasses = `ctf-ascii-char ${ascVal === '.' ? 'dot' : ''} ${isSel ? 'selected' : ''} ${isHit ? 'search-hit' : ''}`;

        const hSpan = `<span class="${hexClasses}" data-offset="${off}">${hexVal}</span>`;
        const aSpan = `<span class="${asciiClasses}" data-offset="${off}">${escapeHtml(ascVal)}</span>`;

        if (i < 8) hex1 += hSpan + (i < 7 ? ' ' : '');
        else hex2 += hSpan + (i < 15 ? ' ' : '');
        ascii += aSpan;
      }

      html += `
        <div class="ctf-hex-row" style="background:${isCursorRow ? 'rgba(255,255,255,0.03)' : 'transparent'};">
          <div class="ctf-hex-offset">${row.offsetHex}</div>
          <div style="display:flex; gap:16px; padding:0 10px;">
            <div style="display:flex;">${hex1}</div>
            <div style="display:flex;">${hex2}</div>
          </div>
          <div style="padding-left:12px; letter-spacing:0.02em;">${ascii}</div>
        </div>
      `;
    }

    this.contentEl.innerHTML = html;
  }

  showByteTooltip(offset, e) {
    const chunkIdx = Math.floor(offset / (64 * 1024));
    const chunk = this.store.getState().chunkCache.get(chunkIdx);
    const offInChunk = offset % (64 * 1024);
    if (!chunk || offInChunk >= chunk.length) {
      this.tooltipEl.style.display = 'none';
      return;
    }

    const b0 = chunk[offInChunk];
    const b1 = offInChunk + 1 < chunk.length ? chunk[offInChunk + 1] : 0;
    const b2 = offInChunk + 2 < chunk.length ? chunk[offInChunk + 2] : 0;
    const b3 = offInChunk + 3 < chunk.length ? chunk[offInChunk + 3] : 0;

    const u16 = (b1 << 8) | b0;
    const u32 = ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0) >>> 0;
    const s8 = (b0 << 24) >> 24;
    const binStr = b0.toString(2).padStart(8, '0');
    const ch = b0 >= 32 && b0 <= 126 ? `'${String.fromCharCode(b0)}'` : 'non-printable';

    this.tooltipEl.innerHTML = `
      <div style="font-weight:700; color:var(--ctf-text-offset, #79C0FF); margin-bottom:2px;">Offset: 0x${offset.toString(16).padStart(8, '0').toUpperCase()} (${offset})</div>
      <div>Hex: <strong style="color:var(--ctf-accent-cyan, #00E5FF);">0x${b0.toString(16).padStart(2, '0').toUpperCase()}</strong> (${ch})</div>
      <div>uint8: <strong>${b0}</strong> | int8: <strong>${s8}</strong></div>
      <div>Binary: <span style="letter-spacing:0.1em; color:var(--ctf-accent-emerald, #10B981);">${binStr}</span></div>
      <div>uint16 LE: <strong>${u16}</strong> (0x${u16.toString(16).toUpperCase()})</div>
      <div>uint32 LE: <strong>${u32}</strong></div>
    `;

    const rootRect = this.container.getBoundingClientRect();
    let x = e.clientX - rootRect.left + 16;
    let y = e.clientY - rootRect.top + 16;
    if (x + 220 > rootRect.width) x -= 240;
    if (y + 130 > rootRect.height) y -= 140;

    this.tooltipEl.style.left = `${Math.max(10, x)}px`;
    this.tooltipEl.style.top = `${Math.max(10, y)}px`;
    this.tooltipEl.style.display = 'block';
  }
}

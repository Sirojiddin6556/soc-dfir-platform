/**
 * hex_store.js - Virtualized CAS Hex Viewer State Store
 * Implements 64KB chunk LRU cache (32 slots / 2MB RAM), cursor/selection management,
 * byte format exports, and fast sliding-window row rendering for files up to 500MB+.
 * Implements Contract A (useHexViewerStore) for Role 16.
 */

import { ctfIpc } from './ctf_ipc.js';

export const CHUNK_SIZE = 64 * 1024; // 64 KB per IPC chunk
export const BYTES_PER_ROW = 16;
export const ROWS_PER_CHUNK = CHUNK_SIZE / BYTES_PER_ROW; // 4096 rows
export const MAX_CACHE_CHUNKS = 32; // 32 chunks * 64KB = 2 MB memory cap

/**
 * Cross-platform Base64 -> Uint8Array decoder.
 */
function base64ToBytes(b64) {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  throw new Error('Base64 decoder unavailable');
}

/**
 * Cross-platform Uint8Array -> Base64 encoder.
 */
function bytesToBase64(bytes) {
  if (typeof btoa === 'function') {
    let binary = '';
    const len = bytes.length;
    for (let i = 0; i < len; i += 8192) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, len)));
    }
    return btoa(binary);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  throw new Error('Base64 encoder unavailable');
}

export class HexStore {
  /**
   * @param {import('./ctf_ipc.js').CtfIpcClient} [ipc=ctfIpc]
   */
  constructor(ipc = ctfIpc) {
    this.ipc = ipc;
    this.listeners = new Set();
    this.inFlightRequests = new Map(); // chunkIndex -> Promise<Uint8Array>

    this.state = {
      artifact: null,
      totalSize: 0,
      totalRows: 0,
      chunkCache: new Map(), // chunkIndex -> Uint8Array (LRU via insertion order)
      cursorOffset: 0,
      selection: null, // { start: number, end: number }
      searchHits: [],
      currentHitIndex: -1,
      isSearching: false,
      isLoadingChunk: false,
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
        console.error('[HexStore] Listener error:', err);
      }
    }
  }

  /**
   * Loads an artifact for virtualized hex exploration.
   * @param {{ artifact_id: string, filename?: string, size_bytes: number, blake3?: string, sha256?: string }} artifact
   */
  loadArtifact(artifact) {
    if (!artifact || !artifact.artifact_id) {
      throw new Error('Invalid artifact provided to loadArtifact');
    }

    const totalSize = Number(artifact.size_bytes || 0);
    const totalRows = Math.ceil(totalSize / BYTES_PER_ROW);

    this.inFlightRequests.clear();
    const newCache = new Map();

    this.setState({
      artifact,
      totalSize,
      totalRows,
      chunkCache: newCache,
      cursorOffset: 0,
      selection: null,
      searchHits: [],
      currentHitIndex: -1,
      error: null
    });

    // Prefetch initial chunk (chunk 0)
    if (totalSize > 0) {
      this.fetchChunk(0).catch((err) => {
        console.warn('[HexStore] Failed initial prefetch:', err);
      });
    }
  }

  /**
   * Fetches a 64KB chunk by chunk index with LRU caching.
   * @param {number} chunkIndex
   * @returns {Promise<Uint8Array>}
   */
  async fetchChunk(chunkIndex) {
    const { artifact, totalSize, chunkCache } = this.state;
    if (!artifact) {
      throw new Error('No artifact loaded in HexStore');
    }

    // Cache hit: touch for LRU ordering (delete + set moves to end)
    if (chunkCache.has(chunkIndex)) {
      const data = chunkCache.get(chunkIndex);
      chunkCache.delete(chunkIndex);
      chunkCache.set(chunkIndex, data);
      return data;
    }

    // Deduplicate in-flight requests
    if (this.inFlightRequests.has(chunkIndex)) {
      return this.inFlightRequests.get(chunkIndex);
    }

    const offset = chunkIndex * CHUNK_SIZE;
    if (offset >= totalSize) {
      return new Uint8Array(0);
    }

    const length = Math.min(CHUNK_SIZE, totalSize - offset);
    const fetchPromise = (async () => {
      this.setState({ isLoadingChunk: true });
      try {
        const resp = await this.ipc.getArtifactSlice(artifact.artifact_id, offset, length);
        const bytes = base64ToBytes(resp.bytes_base64 || '');

        // Evict oldest chunk if LRU cache exceeds capacity
        if (chunkCache.size >= MAX_CACHE_CHUNKS) {
          const oldestKey = chunkCache.keys().next().value;
          chunkCache.delete(oldestKey);
        }

        chunkCache.set(chunkIndex, bytes);
        this.setState({ chunkCache, isLoadingChunk: false });
        return bytes;
      } catch (err) {
        this.setState({ error: err.message, isLoadingChunk: false });
        throw err;
      } finally {
        this.inFlightRequests.delete(chunkIndex);
      }
    })();

    this.inFlightRequests.set(chunkIndex, fetchPromise);
    return fetchPromise;
  }

  /**
   * Prefetches chunks surrounding the visible row range with overscan.
   * @param {number} visibleStartRow
   * @param {number} visibleEndRow
   * @param {number} [overscanChunks=1]
   */
  prefetchChunks(visibleStartRow, visibleEndRow, overscanChunks = 1) {
    const startChunk = Math.max(0, Math.floor(visibleStartRow / ROWS_PER_CHUNK) - overscanChunks);
    const endChunk = Math.min(
      Math.floor(this.state.totalSize / CHUNK_SIZE),
      Math.floor(visibleEndRow / ROWS_PER_CHUNK) + overscanChunks
    );

    for (let c = startChunk; c <= endChunk; c++) {
      if (!this.state.chunkCache.has(c) && !this.inFlightRequests.has(c)) {
        this.fetchChunk(c).catch(() => {});
      }
    }
  }

  /**
   * Returns a 16-byte slice for the given row index, or null if chunk is not yet loaded.
   * @param {number} rowIndex
   * @returns {Uint8Array | null}
   */
  getRowBytes(rowIndex) {
    const chunkIndex = Math.floor(rowIndex / ROWS_PER_CHUNK);
    const chunk = this.state.chunkCache.get(chunkIndex);
    if (!chunk) {
      this.fetchChunk(chunkIndex).catch(() => {});
      return null;
    }

    const rowOffsetInChunk = (rowIndex % ROWS_PER_CHUNK) * BYTES_PER_ROW;
    const end = Math.min(chunk.length, rowOffsetInChunk + BYTES_PER_ROW);
    if (rowOffsetInChunk >= chunk.length) return null;

    return chunk.subarray(rowOffsetInChunk, end);
  }

  /**
   * Formats a row into hex representations and ASCII characters.
   * @param {number} rowIndex
   * @returns {{ offset: number, offsetHex: string, hexParts: string[], ascii: string, isLoaded: boolean }}
   */
  formatRow(rowIndex) {
    const byteOffset = rowIndex * BYTES_PER_ROW;
    const offsetHex = byteOffset.toString(16).padStart(8, '0').toUpperCase();
    const rowBytes = this.getRowBytes(rowIndex);

    if (!rowBytes) {
      return {
        offset: byteOffset,
        offsetHex,
        hexParts: Array(16).fill('..'),
        ascii: '................',
        isLoaded: false
      };
    }

    const hexParts = [];
    let ascii = '';
    for (let i = 0; i < 16; i++) {
      if (i < rowBytes.length) {
        const b = rowBytes[i];
        hexParts.push(b.toString(16).padStart(2, '0').toUpperCase());
        ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
        ascii += ' ';
      }
    }

    return {
      offset: byteOffset,
      offsetHex,
      hexParts,
      ascii,
      isLoaded: true
    };
  }

  /**
   * Sets cursor offset with boundary validation.
   * @param {number} offset
   */
  setCursor(offset) {
    const clamped = Math.max(0, Math.min(offset, Math.max(0, this.state.totalSize - 1)));
    this.setState({ cursorOffset: clamped });
  }

  /**
   * Sets byte selection range (normalized start <= end).
   * @param {number} start
   * @param {number} end
   */
  setSelection(start, end) {
    const min = Math.max(0, Math.min(start, end));
    const max = Math.min(this.state.totalSize - 1, Math.max(start, end));
    this.setState({ selection: { start: min, end: max } });
  }

  clearSelection() {
    this.setState({ selection: null });
  }

  /**
   * Selects a range from offset with given length.
   * @param {number} offset
   * @param {number} length
   */
  selectRange(offset, length) {
    this.setSelection(offset, offset + Math.max(0, length - 1));
  }

  /**
   * Extracts bytes in current selection across loaded chunks.
   * @returns {Uint8Array}
   */
  getSelectedBytes() {
    const { selection, totalSize, chunkCache } = this.state;
    if (!selection) return new Uint8Array(0);

    const length = Math.max(0, selection.end - selection.start + 1);
    const result = new Uint8Array(length);

    for (let i = 0; i < length; i++) {
      const byteIdx = selection.start + i;
      if (byteIdx >= totalSize) break;

      const chunkIdx = Math.floor(byteIdx / CHUNK_SIZE);
      const chunk = chunkCache.get(chunkIdx);
      if (chunk) {
        result[i] = chunk[byteIdx % CHUNK_SIZE];
      }
    }
    return result;
  }

  /**
   * Formats selected bytes into specific export representation.
   * @param {'hex' | 'c-array' | 'ascii' | 'base64'} format
   * @returns {string}
   */
  copySelection(format = 'hex') {
    const bytes = this.getSelectedBytes();
    if (bytes.length === 0) return '';

    switch (format) {
      case 'hex':
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
      case 'c-array':
        return Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ');
      case 'ascii':
        return Array.from(bytes).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      case 'base64':
        return bytesToBase64(bytes);
      default:
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
  }

  /**
   * Dispatches selected bytes to an external handler (e.g. recipe_store).
   * @param {(data: Uint8Array) => void} targetCallback
   */
  sendSelectionToRecipe(targetCallback) {
    const bytes = this.getSelectedBytes();
    if (bytes.length > 0 && typeof targetCallback === 'function') {
      targetCallback(bytes);
    }
  }

  /**
   * Searches for a string or hex pattern across loaded chunks.
   * @param {string} pattern
   * @param {boolean} [isHex=false]
   */
  search(pattern, isHex = false) {
    if (!pattern || !pattern.trim()) {
      this.setState({ searchHits: [], currentHitIndex: -1, isSearching: false });
      return [];
    }

    let targetBytes;
    if (isHex) {
      const cleanHex = pattern.replace(/\s+/g, '');
      const len = Math.floor(cleanHex.length / 2);
      targetBytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        targetBytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16) || 0;
      }
    } else {
      const enc = new TextEncoder();
      targetBytes = enc.encode(pattern);
    }

    if (targetBytes.length === 0) return [];

    const hits = [];
    const { chunkCache, totalSize } = this.state;

    // Scan through all currently cached chunks
    for (const [chunkIdx, chunk] of chunkCache.entries()) {
      const baseOffset = chunkIdx * CHUNK_SIZE;
      for (let i = 0; i <= chunk.length - targetBytes.length; i++) {
        let match = true;
        for (let j = 0; j < targetBytes.length; j++) {
          if (chunk[i + j] !== targetBytes[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          const hitOffset = baseOffset + i;
          if (hitOffset < totalSize) {
            hits.push(hitOffset);
          }
        }
      }
    }

    hits.sort((a, b) => a - b);
    this.setState({
      searchHits: hits,
      currentHitIndex: hits.length > 0 ? 0 : -1,
      isSearching: true
    });

    if (hits.length > 0) {
      this.selectRange(hits[0], targetBytes.length);
      this.setCursor(hits[0]);
    }

    return hits;
  }

  nextHit() {
    const { searchHits, currentHitIndex } = this.state;
    if (searchHits.length === 0) return;
    const nextIdx = (currentHitIndex + 1) % searchHits.length;
    this.setState({ currentHitIndex: nextIdx });
    this.setCursor(searchHits[nextIdx]);
  }

  prevHit() {
    const { searchHits, currentHitIndex } = this.state;
    if (searchHits.length === 0) return;
    const prevIdx = (currentHitIndex - 1 + searchHits.length) % searchHits.length;
    this.setState({ currentHitIndex: prevIdx });
    this.setCursor(searchHits[prevIdx]);
  }
}

export const hexStore = new HexStore();

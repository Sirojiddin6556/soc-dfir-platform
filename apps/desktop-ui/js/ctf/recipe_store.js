/**
 * recipe_store.js - CyberChef-style In-Memory Transformation & Recipe Store
 * Supports chaining operations (Hex, Base64, XOR, ROT13, URL, Reverse, zlib),
 * 0ms client-side live preview, automated regex flag extraction, and CAS artifact persistence.
 * Implements Contract A (useRecipeStore) for Role 16.
 */

import { ctfIpc } from './ctf_ipc.js';

export const DEFAULT_FLAG_REGEX = /([a-zA-Z0-9_-]{3,20}\{[A-Za-z0-9_!@#$%^&*()-+=<>?]{4,100}\})/g;

/**
 * Normalizes input (Uint8Array, string, base64) into Uint8Array.
 */
function toUint8Array(input) {
  if (!input) return new Uint8Array(0);
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') {
    return new TextEncoder().encode(input);
  }
  return new Uint8Array(0);
}

/**
 * Safe conversion from Uint8Array to string.
 */
function bytesToString(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch (_) {
    return Array.from(bytes).map(b => String.fromCharCode(b)).join('');
  }
}

export class RecipeStore {
  /**
   * @param {import('./ctf_ipc.js').CtfIpcClient} [ipc=ctfIpc]
   */
  constructor(ipc = ctfIpc) {
    this.ipc = ipc;
    this.listeners = new Set();
    this.flagScannerCallbacks = new Set();

    this.state = {
      operations: [],           // Array of { id, operation, name, params, isMuted }
      inputData: null,          // Uint8Array | string
      livePreviewText: '',      // Preview output string
      livePreviewBytes: null,   // Uint8Array result
      detectedFlags: [],        // Scanned CTF flag candidates
      flagPattern: DEFAULT_FLAG_REGEX.source,
      isProcessing: false,
      stepErrors: {},           // stepIndex -> error message
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
        console.error('[RecipeStore] Listener error:', err);
      }
    }
  }

  /**
   * Registers a listener triggered whenever flags are detected in pipeline preview.
   * @param {(flags: string[]) => void} callback
   */
  onFlagsDetected(callback) {
    this.flagScannerCallbacks.add(callback);
    return () => this.flagScannerCallbacks.delete(callback);
  }

  /**
   * Sets raw input data and triggers pipeline recalculation.
   * @param {Uint8Array | string} data
   */
  setInputData(data) {
    this.setState({ inputData: data });
    this.computePipeline();
  }

  /**
   * Sets custom flag pattern regex string.
   * @param {string} pattern
   */
  setFlagPattern(pattern) {
    this.setState({ flagPattern: pattern });
    this.scanFlags(this.state.livePreviewText);
  }

  /**
   * Adds an operation to the recipe pipeline.
   * @param {{ operation: string, name?: string, params?: Record<string, unknown>, isMuted?: boolean }} op
   */
  addOperation(op) {
    const newOp = {
      id: `op_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      operation: op.operation,
      name: op.name || op.operation,
      params: op.params || {},
      isMuted: Boolean(op.isMuted)
    };

    this.setState((prev) => ({
      operations: [...prev.operations, newOp]
    }));
    this.computePipeline();
  }

  /**
   * Removes an operation by index.
   * @param {number} index
   */
  removeOperation(index) {
    this.setState((prev) => ({
      operations: prev.operations.filter((_, idx) => idx !== index)
    }));
    this.computePipeline();
  }

  /**
   * Reorders operations in the pipeline.
   * @param {number} fromIndex
   * @param {number} toIndex
   */
  reorderOperations(fromIndex, toIndex) {
    this.setState((prev) => {
      const ops = [...prev.operations];
      const [moved] = ops.splice(fromIndex, 1);
      ops.splice(toIndex, 0, moved);
      return { operations: ops };
    });
    this.computePipeline();
  }

  /**
   * Toggles mute state of a specific operation.
   * @param {number} index
   */
  toggleMute(index) {
    this.setState((prev) => {
      const ops = prev.operations.map((op, idx) =>
        idx === index ? { ...op, isMuted: !op.isMuted } : op
      );
      return { operations: ops };
    });
    this.computePipeline();
  }

  /**
   * Updates parameters for an operation.
   * @param {number} index
   * @param {Record<string, unknown>} params
   */
  updateParams(index, params) {
    this.setState((prev) => {
      const ops = prev.operations.map((op, idx) =>
        idx === index ? { ...op, params: { ...op.params, ...params } } : op
      );
      return { operations: ops };
    });
    this.computePipeline();
  }

  /**
   * Clears all operations from the recipe.
   */
  clearOperations() {
    this.setState({ operations: [], stepErrors: {} });
    this.computePipeline();
  }

  /**
   * Executes the pipeline in-memory to provide instantaneous 0ms live preview and flag scanning.
   */
  computePipeline() {
    const { inputData, operations } = this.state;
    if (!inputData) {
      this.setState({
        livePreviewText: '',
        livePreviewBytes: null,
        detectedFlags: [],
        stepErrors: {}
      });
      return;
    }

    this.setState({ isProcessing: true });
    let currentBytes = toUint8Array(inputData);
    const stepErrors = {};

    for (let i = 0; i < operations.length; i++) {
      const op = operations[i];
      if (op.isMuted) continue;

      try {
        currentBytes = this.executeLocalOp(op.operation, currentBytes, op.params);
      } catch (err) {
        stepErrors[i] = err.message;
        break; // Stop downstream operations if one fails
      }
    }

    const previewText = bytesToString(currentBytes);
    this.setState({
      livePreviewBytes: currentBytes,
      livePreviewText: previewText,
      stepErrors,
      isProcessing: false
    });

    this.scanFlags(previewText);
  }

  /**
   * Local transformation operations engine.
   * @param {string} opName
   * @param {Uint8Array} bytes
   * @param {Record<string, unknown>} params
   * @returns {Uint8Array}
   */
  executeLocalOp(opName, bytes, params = {}) {
    const normOp = opName.toLowerCase().replace(/[\s-]/g, '_');

    switch (normOp) {
      case 'hex_decode':
      case 'from_hex': {
        const str = bytesToString(bytes).replace(/[^0-9a-fA-F]/g, '');
        const out = new Uint8Array(Math.floor(str.length / 2));
        for (let i = 0; i < out.length; i++) {
          out[i] = parseInt(str.substr(i * 2, 2), 16) || 0;
        }
        return out;
      }

      case 'hex_encode':
      case 'to_hex': {
        const hexStr = Array.from(bytes)
          .map(b => b.toString(16).padStart(2, '0'))
          .join(params.delimiter || '');
        return new TextEncoder().encode(hexStr);
      }

      case 'base64_decode':
      case 'from_base64': {
        const str = bytesToString(bytes).trim();
        if (typeof atob === 'function') {
          const bin = atob(str);
          const out = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
          return out;
        }
        if (typeof Buffer !== 'undefined') {
          return new Uint8Array(Buffer.from(str, 'base64'));
        }
        return bytes;
      }

      case 'base64_encode':
      case 'to_base64': {
        if (typeof btoa === 'function') {
          let bin = '';
          for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
          return new TextEncoder().encode(btoa(bin));
        }
        if (typeof Buffer !== 'undefined') {
          return new TextEncoder().encode(Buffer.from(bytes).toString('base64'));
        }
        return bytes;
      }

      case 'xor': {
        const keyRaw = String(params.key || '');
        if (!keyRaw) return bytes;

        let keyBytes;
        if (params.isHex || keyRaw.startsWith('0x')) {
          const clean = keyRaw.replace(/^0x|\s+/g, '');
          keyBytes = new Uint8Array(Math.floor(clean.length / 2));
          for (let i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = parseInt(clean.substr(i * 2, 2), 16) || 0;
          }
        } else {
          keyBytes = new TextEncoder().encode(keyRaw);
        }

        if (keyBytes.length === 0) return bytes;

        const out = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
          out[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
        }
        return out;
      }

      case 'rot13': {
        const out = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
          const c = bytes[i];
          if (c >= 65 && c <= 90) {
            out[i] = ((c - 65 + 13) % 26) + 65;
          } else if (c >= 97 && c <= 122) {
            out[i] = ((c - 97 + 13) % 26) + 97;
          } else {
            out[i] = c;
          }
        }
        return out;
      }

      case 'url_decode': {
        const str = bytesToString(bytes);
        const decoded = decodeURIComponent(str);
        return new TextEncoder().encode(decoded);
      }

      case 'url_encode': {
        const str = bytesToString(bytes);
        const encoded = encodeURIComponent(str);
        return new TextEncoder().encode(encoded);
      }

      case 'reverse': {
        const out = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
          out[i] = bytes[bytes.length - 1 - i];
        }
        return out;
      }

      default:
        // Unknown or complex operation: return unchanged for local preview
        return bytes;
    }
  }

  /**
   * Scans text for CTF flag patterns and updates detected flags list.
   * @param {string} text
   */
  scanFlags(text) {
    if (!text) {
      this.setState({ detectedFlags: [] });
      return;
    }

    let regex;
    try {
      regex = new RegExp(this.state.flagPattern || DEFAULT_FLAG_REGEX.source, 'g');
    } catch (_) {
      regex = DEFAULT_FLAG_REGEX;
    }

    const flags = new Set();
    let match;
    while ((match = regex.exec(text)) !== null) {
      flags.add(match[1] || match[0]);
    }

    const detected = Array.from(flags);
    this.setState({ detectedFlags: detected });

    if (detected.length > 0) {
      for (const cb of this.flagScannerCallbacks) {
        try {
          cb(detected);
        } catch (err) {
          console.error('[RecipeStore] Flag scan callback error:', err);
        }
      }
    }
  }

  /**
   * Executes the recipe on the backend CAS storage and persists DAG transform steps.
   * @param {string} artifactId - Input CAS artifact Blake3 ID
   * @param {string} [challengeId] - Associated challenge UUID
   * @returns {Promise<string>} Output artifact Blake3 ID
   */
  async executeAndSaveArtifact(artifactId, challengeId = null) {
    const activeOps = this.state.operations.filter(op => !op.isMuted);
    if (activeOps.length === 0) {
      throw new Error('No active operations to execute');
    }

    this.setState({ isProcessing: true, error: null });
    try {
      const opsPayload = activeOps.map(op => ({
        operation: op.operation,
        params: op.params
      }));

      const execResult = await this.ipc.executeRecipe({
        artifact_id: artifactId,
        ops: opsPayload
      });

      const outputArtifactId = execResult.output_artifact_id || execResult.hash_blake3;

      // Save steps into SQLite DAG lineage if challengeId is provided
      if (challengeId) {
        const recipeId = `recipe_${Date.now()}`;
        for (let i = 0; i < activeOps.length; i++) {
          const op = activeOps[i];
          await this.ipc.saveRecipeStep({
            challenge_id: challengeId,
            recipe_id: recipeId,
            step_order: i + 1,
            operation: op.operation,
            parameters_json: JSON.stringify(op.params || {}),
            input_artifact_id: i === 0 ? artifactId : null,
            output_artifact_id: i === activeOps.length - 1 ? outputArtifactId : null
          });
        }
      }

      this.setState({ isProcessing: false });
      return outputArtifactId;
    } catch (err) {
      this.setState({ error: err.message, isProcessing: false });
      throw err;
    }
  }
}

export const recipeStore = new RecipeStore();

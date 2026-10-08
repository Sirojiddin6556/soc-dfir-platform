/**
 * ctf_ipc.js - CTF JSON-RPC 2.0 IPC Client and Streaming Bridge
 * Extends IpcClient with CTF domain namespaces and event subscription.
 * Strictly adheres to Contract A (Role 16) and JSON-RPC 2.0 specs.
 */

import { IpcClient } from '../ipc.js';

export class CtfIpcClient extends IpcClient {
  constructor(endpointUrl = null) {
    super(endpointUrl);
    this.eventListeners = new Map();
    this.initEventBridge();
  }

  /**
   * Initializes event listener for window messages (WebView IPC bridge or worker events).
   */
  initEventBridge() {
    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('message', (event) => {
        try {
          const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
          if (data && data.jsonrpc === '2.0' && data.method && data.params) {
            this.emit(data.method, data.params);
          }
        } catch (_) {
          // Ignore unparseable window messages
        }
      });
    }
  }

  /**
   * Sends a strict JSON-RPC 2.0 request to the engine server.
   * @param {string} method - JSON-RPC method (e.g. 'competitions.list')
   * @param {Record<string, unknown>} [params={}] - Parameters object
   * @returns {Promise<any>} Result payload from JSON-RPC response
   */
  async invoke(method, params = {}) {
    const requestId = `rpc_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const token = (params && params.token) ||
      (typeof localStorage !== 'undefined' ? localStorage.getItem('soc_session_token') : null);
    const finalParams = token ? { ...params, token } : { ...params };

    const payload = {
      jsonrpc: '2.0',
      id: requestId,
      method: method,
      params: finalParams
    };

    let response;
    try {
      response = await fetch(this.endpointUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (err) {
      const netErr = new Error(`Engine unreachable at ${this.endpointUrl}: ${err.message}`);
      netErr.transport = true;
      throw netErr;
    }

    if (response.status === 401 && typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('soc:unauthorized'));
    }

    const data = await response.json();
    if (data.error) {
      const err = new Error(data.error.message || data.error.detail || data.error.title || 'RPC Failed');
      err.code = data.error.code;
      err.data = data.error.data;
      err.rpcError = data.error;
      throw err;
    }
    return data.result;
  }

  /**
   * Subscribes a listener to a streaming event (e.g. 'job.output', 'job.status_changed').
   * @param {string} event - Event name
   * @param {Function} handler - Callback taking event payload
   * @returns {() => void} Unsubscribe function
   */
  subscribe(event, handler) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, new Set());
    }
    this.eventListeners.get(event).add(handler);
    return () => {
      const set = this.eventListeners.get(event);
      if (set) {
        set.delete(handler);
        if (set.size === 0) {
          this.eventListeners.delete(event);
        }
      }
    };
  }

  /**
   * Emits an event to registered listeners.
   * @param {string} event - Event name
   * @param {unknown} payload - Event data
   */
  emit(event, payload) {
    const set = this.eventListeners.get(event);
    if (set) {
      for (const handler of set) {
        try {
          handler(payload);
        } catch (err) {
          console.error(`[CtfIpcClient] Event error (${event}):`, err);
        }
      }
    }
  }

  // --- Competitions Namespace ---
  createCompetition({ name, description, format, flag_format }) {
    return this.invoke('competitions.create', { name, description, format, flag_format });
  }

  getCompetition(id) {
    return this.invoke('competitions.get', { id });
  }

  listCompetitions(status = null) {
    return this.invoke('competitions.list', status ? { status } : {});
  }

  // --- Challenges Namespace ---
  createChallenge({ competition_id, name, category, points, target, expected_flag }) {
    return this.invoke('challenges.create', { competition_id, name, category, points, target, expected_flag });
  }

  getChallenge(id) {
    return this.invoke('challenges.get', { id });
  }

  listChallenges(competition_id, category = null) {
    const params = { competition_id };
    if (category) params.category = category;
    return this.invoke('challenges.list', params);
  }

  updateChallengeStatus(id, status, reason = null) {
    return this.invoke('challenges.update_status', { id, status, reason });
  }

  updateChallengeTarget(id, target) {
    return this.invoke('challenges.update_target', { id, target });
  }

  // --- Artifacts Namespace ---
  getArtifactSlice(artifact_id, offset, length) {
    return this.invoke('artifacts.get_slice', { artifact_id, offset, length });
  }

  verifyArtifact(hash) {
    return this.invoke('artifacts.verify', { hash });
  }

  unpackArtifact(artifact_id, target_dir) {
    return this.invoke('artifacts.unpack_archive', { artifact_id, target_dir });
  }

  ingestArtifact({ challenge_id, data_base64, filename, role }) {
    return this.invoke('artifacts.ingest', { challenge_id, data_base64, filename, role });
  }

  linkArtifactToChallenge({ challenge_id, artifact_id, role, alias }) {
    return this.invoke('artifacts.link_challenge', { challenge_id, artifact_id, role, alias });
  }

  listChallengeArtifacts(challenge_id) {
    return this.invoke('artifacts.list_for_challenge', { challenge_id });
  }

  // --- Tools Namespace ---
  listTools() {
    return this.invoke('tools.list', {});
  }

  // --- Jobs Namespace ---
  submitJob({ challenge_id, tool_id, adapter, argv, timeout_ms, limits }) {
    return this.invoke('jobs.submit', { challenge_id, tool_id, adapter, argv, timeout_ms, limits });
  }

  cancelJob(id, reason = null) {
    return this.invoke('jobs.cancel', { id, reason });
  }

  getJobState(id) {
    return this.invoke('jobs.get_state', { id });
  }

  getJobOutput(id, max_bytes = 8192) {
    return this.invoke('jobs.get_output', { id, max_bytes });
  }

  // --- Recipes Namespace ---
  previewRecipe({ input_data, input_base64, ops, flag_pattern }) {
    return this.invoke('recipes.preview', { input_data, input_base64, ops, flag_pattern });
  }

  executeRecipe({ artifact_id, ops }) {
    return this.invoke('recipes.execute', { artifact_id, ops });
  }

  saveRecipeStep({ challenge_id, recipe_id, step_order, operation, parameters_json, input_artifact_id, output_artifact_id, input_hash, output_hash }) {
    return this.invoke('recipes.save_step', {
      challenge_id,
      recipe_id,
      step_order,
      operation,
      parameters_json,
      input_artifact_id,
      output_artifact_id,
      input_hash,
      output_hash
    });
  }

  listRecipeSteps(challenge_id, recipe_id = null) {
    const params = { challenge_id };
    if (recipe_id) params.recipe_id = recipe_id;
    return this.invoke('recipes.list_steps', params);
  }

  // --- Flags Namespace ---
  registerFlagCandidate({ challenge_id, value, source_ref }) {
    return this.invoke('flags.register', { challenge_id, value, source_ref });
  }

  acceptFlag(candidate_id) {
    return this.invoke('flags.accept', { candidate_id });
  }

  rejectFlag(candidate_id, reason = null) {
    return this.invoke('flags.reject', { candidate_id, reason });
  }

  listFlags(challenge_id) {
    return this.invoke('flags.list', { challenge_id });
  }

  // --- Writeups Namespace ---
  generateWriteupDraft(challenge_id, include_timeline = true) {
    return this.invoke('writeups.generate_draft', { challenge_id, include_timeline });
  }

  exportWriteup(challenge_id, dest_path) {
    return this.invoke('writeups.export', { challenge_id, dest_path });
  }

  updateWriteupSection(challenge_id, section, content) {
    return this.invoke('writeups.update_section', { challenge_id, section, content });
  }
}

export const ctfIpc = new CtfIpcClient();

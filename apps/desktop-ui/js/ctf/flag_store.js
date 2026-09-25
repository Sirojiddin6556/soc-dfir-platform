/**
 * flag_store.js - Flag Candidates & Verification Store
 * Manages flag candidate registry, acceptance/rejection lifecycle,
 * auto-solve status propagation, and keyboard shortcuts (Ctrl+Shift+A / Ctrl+Shift+R).
 * Implements Contract A (useFlagStore) for Role 16.
 */

import { ctfIpc } from './ctf_ipc.js';
import { workspaceStore } from './workspace_store.js';

export class FlagStore {
  /**
   * @param {import('./ctf_ipc.js').CtfIpcClient} [ipc=ctfIpc]
   * @param {import('./workspace_store.js').WorkspaceStore} [wsStore=workspaceStore]
   */
  constructor(ipc = ctfIpc, wsStore = workspaceStore) {
    this.ipc = ipc;
    this.workspaceStore = wsStore;
    this.listeners = new Set();

    this.state = {
      candidates: [],               // Array of FlagCandidate objects
      filter: 'all',                // 'all' | 'candidates' | 'accepted' | 'rejected'
      activeChallengeId: null,
      selectedCandidateId: null,
      unreviewedCount: 0,
      isLoading: false,
      error: null
    };

    this.setupHotkeys();
  }

  getState = () => this.state;

  setState = (updater) => {
    const next = typeof updater === 'function' ? updater(this.state) : updater;
    const merged = { ...this.state, ...next };

    // Recompute unreviewed candidates count
    merged.unreviewedCount = merged.candidates.filter(
      (c) => c.status === 'candidate' || c.status === 'unreviewed' || !c.status
    ).length;

    this.state = merged;
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
        console.error('[FlagStore] Listener error:', err);
      }
    }
  }

  /**
   * Sets up hotkeys:
   * - Ctrl+Shift+A: Accept selected flag candidate
   * - Ctrl+Shift+R: Reject selected flag candidate
   */
  setupHotkeys() {
    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey) {
          if (e.key === 'A' || e.key === 'a') {
            e.preventDefault();
            if (this.state.selectedCandidateId) {
              this.acceptFlag(this.state.selectedCandidateId).catch((err) => {
                console.error('[FlagStore] Shortcut accept error:', err);
              });
            }
          } else if (e.key === 'R' || e.key === 'r') {
            e.preventDefault();
            if (this.state.selectedCandidateId) {
              this.rejectFlag(this.state.selectedCandidateId, 'Rejected via shortcut').catch((err) => {
                console.error('[FlagStore] Shortcut reject error:', err);
              });
            }
          }
        }
      });
    }
  }

  /**
   * Loads flag candidates for a specific challenge.
   * @param {string} challengeId
   */
  async loadFlags(challengeId) {
    if (!challengeId) return [];

    this.setState({ isLoading: true, error: null, activeChallengeId: challengeId });
    try {
      const flags = await this.ipc.listFlags(challengeId);
      const candidates = Array.isArray(flags) ? flags : [];

      this.setState({
        candidates,
        selectedCandidateId: candidates.length > 0 ? candidates[0].id : null,
        isLoading: false
      });
      return candidates;
    } catch (err) {
      this.setState({ error: err.message, isLoading: false });
      throw err;
    }
  }

  /**
   * Registers a new flag candidate with duplicate prevention.
   * @param {string} flag - Flag string value
   * @param {string} [source='manual'] - Source identifier
   * @param {string} [challengeId] - Target challenge ID
   * @returns {Promise<string>} Candidate UUID
   */
  async registerCandidate(flag, source = 'manual', challengeId = null) {
    const chalId = challengeId || this.state.activeChallengeId;
    if (!chalId) {
      throw new Error('No active challenge specified for flag registration');
    }

    const cleanFlag = String(flag || '').trim();
    if (!cleanFlag) {
      throw new Error('Flag value cannot be empty');
    }

    // Client-side duplicate check
    const existing = this.state.candidates.find(
      (c) => c.value === cleanFlag && c.challenge_id === chalId
    );
    if (existing) {
      return existing.id;
    }

    try {
      const resp = await this.ipc.registerFlagCandidate({
        challenge_id: chalId,
        value: cleanFlag,
        source_ref: source
      });

      const candidateId = resp.id || resp.candidate_id;
      const newCandidate = {
        id: candidateId,
        challenge_id: chalId,
        value: cleanFlag,
        source,
        status: 'candidate',
        timestamp: new Date().toISOString()
      };

      this.setState((prev) => ({
        candidates: [newCandidate, ...prev.candidates],
        selectedCandidateId: prev.selectedCandidateId || candidateId
      }));

      return candidateId;
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Accepts a flag candidate and triggers automatic challenge solving.
   * @param {string} candidateId
   */
  async acceptFlag(candidateId) {
    if (!candidateId) return;

    try {
      await this.ipc.acceptFlag(candidateId);

      this.setState((prev) => ({
        candidates: prev.candidates.map((c) =>
          c.id === candidateId ? { ...c, status: 'accepted' } : c
        )
      }));

      // Auto-solve trigger: update challenge status to 'Solved'
      if (this.workspaceStore && typeof this.workspaceStore.updateChallengeStatus === 'function') {
        await this.workspaceStore.updateChallengeStatus('Solved', 'Flag accepted').catch((err) => {
          console.warn('[FlagStore] Auto-solve status update warning:', err.message);
        });
      }
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Rejects a flag candidate with optional reason.
   * @param {string} candidateId
   * @param {string} [reason='Incorrect flag format or failed submission']
   */
  async rejectFlag(candidateId, reason = 'Incorrect flag format or failed submission') {
    if (!candidateId) return;

    try {
      await this.ipc.rejectFlag(candidateId, reason);

      this.setState((prev) => ({
        candidates: prev.candidates.map((c) =>
          c.id === candidateId ? { ...c, status: 'rejected', reason } : c
        )
      }));
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Selects a candidate for inspection or shortcut actions.
   * @param {string} candidateId
   */
  selectCandidate(candidateId) {
    this.setState({ selectedCandidateId: candidateId });
  }

  /**
   * Sets the candidate status filter.
   * @param {'all' | 'candidates' | 'accepted' | 'rejected'} filter
   */
  setFilter(filter) {
    this.setState({ filter });
  }

  /**
   * Returns candidates matching current active filter.
   * @returns {Array<any>}
   */
  getFilteredCandidates() {
    const { candidates, filter } = this.state;
    if (filter === 'all') return candidates;
    if (filter === 'candidates') {
      return candidates.filter((c) => c.status === 'candidate' || c.status === 'unreviewed' || !c.status);
    }
    return candidates.filter((c) => c.status === filter);
  }
}

export const flagStore = new FlagStore();

/**
 * workspace_store.js - CTF Workspace State Store
 * Manages competition context, active challenge, challenge status, and artifact tree.
 * Implements Contract A (useWorkspaceStore) for Role 16.
 */

import { ctfIpc } from './ctf_ipc.js';

export class WorkspaceStore {
  /**
   * @param {import('./ctf_ipc.js').CtfIpcClient} [ipc=ctfIpc] - IPC client instance
   */
  constructor(ipc = ctfIpc) {
    this.ipc = ipc;
    this.listeners = new Set();

    this.state = {
      competitions: [],
      activeCompetitionId: null,
      activeCompetition: null,
      challenges: {},
      activeChallengeId: null,
      activeChallenge: null,
      artifacts: {},
      artifactTree: [],
      activePanels: {
        left: true,
        bottom: true,
        rightDrawer: false
      },
      isLoading: false,
      error: null
    };
  }

  /**
   * Returns current state snapshot.
   */
  getState = () => this.state;

  /**
   * Updates state and notifies subscribers.
   * @param {Partial<typeof this.state> | ((state: typeof this.state) => Partial<typeof this.state>)} updater
   */
  setState = (updater) => {
    const next = typeof updater === 'function' ? updater(this.state) : updater;
    this.state = { ...this.state, ...next };
    this.notify();
  };

  /**
   * Subscribes a listener to state changes.
   * @param {(state: typeof this.state) => void} listener
   * @returns {() => void} Unsubscribe function
   */
  subscribe = (listener) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  notify() {
    for (const listener of this.listeners) {
      try {
        listener(this.state);
      } catch (err) {
        console.error('[WorkspaceStore] Listener error:', err);
      }
    }
  }

  /**
   * Loads all competitions, optionally filtered by status ('Active', 'Upcoming', 'Archived').
   */
  async loadCompetitions(status = null) {
    this.setState({ isLoading: true, error: null });
    try {
      const list = await this.ipc.listCompetitions(status);
      const competitions = Array.isArray(list) ? list : [];
      this.setState({ competitions, isLoading: false });
      return competitions;
    } catch (err) {
      this.setState({ error: err.message, isLoading: false });
      throw err;
    }
  }

  /**
   * Loads a competition and its associated challenges.
   * @param {string} compId - Competition UUID
   */
  async loadCompetition(compId) {
    this.setState({ isLoading: true, error: null });
    try {
      const [comp, chalList] = await Promise.all([
        this.ipc.getCompetition(compId),
        this.ipc.listChallenges(compId)
      ]);

      const challengesMap = {};
      if (Array.isArray(chalList)) {
        for (const ch of chalList) {
          challengesMap[ch.id] = ch;
        }
      }

      this.setState({
        activeCompetitionId: compId,
        activeCompetition: comp,
        challenges: challengesMap,
        isLoading: false
      });
    } catch (err) {
      this.setState({ error: err.message, isLoading: false });
      throw err;
    }
  }

  /**
   * Selects an active challenge, loading its full details and artifact hierarchy.
   * @param {string} challengeId - Challenge UUID
   */
  async selectChallenge(challengeId) {
    this.setState({ isLoading: true, error: null });
    try {
      const [challenge, rawArtifacts] = await Promise.all([
        this.ipc.getChallenge(challengeId),
        this.ipc.listChallengeArtifacts(challengeId)
      ]);

      const artifactsMap = {};
      const artifactList = Array.isArray(rawArtifacts) ? rawArtifacts : [];
      for (const a of artifactList) {
        artifactsMap[a.artifact_id || a.id] = a;
      }

      const tree = this.buildArtifactTree(artifactList);

      this.setState((prev) => ({
        activeChallengeId: challengeId,
        activeChallenge: challenge,
        challenges: {
          ...prev.challenges,
          [challengeId]: { ...prev.challenges[challengeId], ...challenge }
        },
        artifacts: artifactsMap,
        artifactTree: tree,
        isLoading: false
      }));
    } catch (err) {
      this.setState({ error: err.message, isLoading: false });
      throw err;
    }
  }

  /**
   * Groups artifacts into a structured tree (Input, Extracted, Generated, FlagCandidate).
   * @param {Array<any>} artifactList
   * @returns {Array<{ role: string, label: string, items: Array<any> }>}
   */
  buildArtifactTree(artifactList) {
    const groups = {
      Input: { role: 'Input', label: 'Source Evidence & Inputs', items: [] },
      Extracted: { role: 'Extracted', label: 'Unpacked / Extracted Assets', items: [] },
      Intermediate: { role: 'Intermediate', label: 'Intermediate Recipe Outputs', items: [] },
      Output: { role: 'Output', label: 'Transformed Artifacts', items: [] },
      Other: { role: 'Other', label: 'Miscellaneous Files', items: [] }
    };

    for (const item of artifactList) {
      const role = item.role || item.artifact_role || 'Input';
      if (groups[role]) {
        groups[role].items.push(item);
      } else {
        groups.Other.items.push(item);
      }
    }

    return Object.values(groups).filter(g => g.items.length > 0);
  }

  /**
   * Imports or ingests an artifact for the active challenge.
   * @param {{ data_base64: string, filename?: string, role?: string, filePath?: string }} params
   * @returns {Promise<string>} Created artifact blake3 ID
   */
  async importArtifact({ data_base64, filename = 'evidence.bin', role = 'Input' }) {
    if (!this.state.activeChallengeId) {
      throw new Error('No active challenge selected for artifact import');
    }

    this.setState({ isLoading: true, error: null });
    try {
      const result = await this.ipc.ingestArtifact({
        challenge_id: this.state.activeChallengeId,
        data_base64,
        filename,
        role
      });

      // Refresh challenge artifacts
      await this.selectChallenge(this.state.activeChallengeId);
      this.setState({ isLoading: false });
      return result.artifact_id || result.blake3;
    } catch (err) {
      this.setState({ error: err.message, isLoading: false });
      throw err;
    }
  }

  /**
   * Updates challenge status (e.g. 'Unsolved', 'InProgress', 'Solved', 'Blocked').
   * @param {string} status - New status string
   * @param {string} [reason] - Optional blocking reason
   */
  async updateChallengeStatus(status, reason = null) {
    const chalId = this.state.activeChallengeId;
    if (!chalId) {
      throw new Error('No active challenge selected to update status');
    }

    try {
      await this.ipc.updateChallengeStatus(chalId, status, reason);
      this.setState((prev) => {
        const updatedChal = prev.activeChallenge ? { ...prev.activeChallenge, status } : null;
        const updatedMap = { ...prev.challenges };
        if (updatedMap[chalId]) {
          updatedMap[chalId] = { ...updatedMap[chalId], status };
        }
        return {
          activeChallenge: updatedChal,
          challenges: updatedMap
        };
      });
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Updates challenge target scope.
   * @param {object} target - Target scope descriptor
   */
  async updateChallengeTarget(target) {
    const chalId = this.state.activeChallengeId;
    if (!chalId) {
      throw new Error('No active challenge selected to update target');
    }

    try {
      await this.ipc.updateChallengeTarget(chalId, target);
      this.setState((prev) => {
        const updatedChal = prev.activeChallenge ? { ...prev.activeChallenge, target } : null;
        return { activeChallenge: updatedChal };
      });
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Toggles panel visibility ('left' | 'bottom' | 'rightDrawer').
   * @param {'left' | 'bottom' | 'rightDrawer'} panel
   */
  togglePanel(panel) {
    this.setState((prev) => ({
      activePanels: {
        ...prev.activePanels,
        [panel]: !prev.activePanels[panel]
      }
    }));
  }

  /**
   * Sets exact panel visibility.
   * @param {'left' | 'bottom' | 'rightDrawer'} panel
   * @param {boolean} isOpen
   */
  setPanel(panel, isOpen) {
    this.setState((prev) => ({
      activePanels: {
        ...prev.activePanels,
        [panel]: Boolean(isOpen)
      }
    }));
  }
}

export const workspaceStore = new WorkspaceStore();

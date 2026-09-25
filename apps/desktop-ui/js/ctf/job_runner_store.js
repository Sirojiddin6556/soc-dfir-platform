/**
 * job_runner_store.js - Job Engine & Terminal Ring Buffer Store
 * Manages tool process execution, streaming ANSI/text terminal logs with 10MB ring buffer,
 * 60 FPS requestAnimationFrame throttling, backpressure monitoring, and F9 panic kill switch.
 * Implements Contract A (useJobRunnerStore) for Role 16.
 */

import { ctfIpc } from './ctf_ipc.js';

export const MAX_BUFFER_BYTES = 10 * 1024 * 1024; // 10 MB per process
export const HEAD_KEEP_BYTES = 2 * 1024 * 1024;   // 2 MB initial process header
export const TAIL_KEEP_BYTES = 8 * 1024 * 1024;   // 8 MB recent tail
export const MAX_LINES_VIEWPORT = 10000;          // Max lines stored in memory for view

/**
 * Memory-bounded terminal ring buffer.
 */
export class TerminalRingBuffer {
  constructor(jobId) {
    this.jobId = jobId;
    this.rawContent = '';
    this.lines = [];
    this.totalBytes = 0;
    this.droppedBytes = 0;
    this.isTruncated = false;
  }

  /**
   * Appends text to the buffer and enforces the 10 MB ceiling.
   * @param {string} text
   */
  append(text) {
    if (!text) return;
    this.totalBytes += text.length;
    this.rawContent += text;

    // Check 10 MB threshold
    if (this.rawContent.length > MAX_BUFFER_BYTES) {
      const head = this.rawContent.slice(0, HEAD_KEEP_BYTES);
      const tail = this.rawContent.slice(-TAIL_KEEP_BYTES);
      const droppedNow = this.rawContent.length - (HEAD_KEEP_BYTES + TAIL_KEEP_BYTES);
      this.droppedBytes += droppedNow;
      this.isTruncated = true;

      const droppedMb = (this.droppedBytes / (1024 * 1024)).toFixed(2);
      const marker = `\n\x1b[33m[... ${droppedMb} MB DROPPED TO PREVENT OOM. FULL RAW LOG IN CAS ...]\x1b[0m\n`;

      this.rawContent = head + marker + tail;
    }

    // Update lines array (capped at MAX_LINES_VIEWPORT)
    const newLines = text.split('\n');
    if (this.lines.length === 0) {
      this.lines = newLines;
    } else {
      this.lines[this.lines.length - 1] += newLines[0];
      for (let i = 1; i < newLines.length; i++) {
        this.lines.push(newLines[i]);
      }
    }

    if (this.lines.length > MAX_LINES_VIEWPORT) {
      this.lines = this.lines.slice(-MAX_LINES_VIEWPORT);
    }
  }

  clear() {
    this.rawContent = '';
    this.lines = [];
    this.totalBytes = 0;
    this.droppedBytes = 0;
    this.isTruncated = false;
  }
}

export class JobRunnerStore {
  /**
   * @param {import('./ctf_ipc.js').CtfIpcClient} [ipc=ctfIpc]
   */
  constructor(ipc = ctfIpc) {
    this.ipc = ipc;
    this.listeners = new Set();

    this.pendingChunks = new Map(); // jobId -> Array<{ stream: string, data: string }>
    this.rafScheduled = false;
    this.lastFlushTime = 0;

    this.state = {
      activeJobs: {},         // jobId -> JobRuntimeState
      tools: [],
      isLoadingTools: false,
      terminalBuffers: {},    // jobId -> TerminalRingBuffer
      isBackpressureActive: false,
      activeJobId: null,
      error: null
    };

    this.bindIpcStreaming();
    this.bindF9PanicKill();
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
        console.error('[JobRunnerStore] Listener error:', err);
      }
    }
  }

  async loadTools() {
    this.setState({ isLoadingTools: true, error: null });
    try {
      const result = await this.ipc.listTools();
      const tools = Array.isArray(result) ? result : (result?.tools || []);
      this.setState({ tools, isLoadingTools: false });
      return tools;
    } catch (err) {
      this.setState({ error: err.message, isLoadingTools: false });
      throw err;
    }
  }

  /**
   * Binds streaming event listeners from IPC client.
   */
  bindIpcStreaming() {
    // job.output notification handler
    this.ipc.subscribe('job.output', (event) => {
      if (!event || !event.job_id) return;
      this.queueLogChunk(event.job_id, {
        stream: event.stream || 'stdout',
        data: event.data || ''
      });
    });

    // job.status_changed notification handler
    this.ipc.subscribe('job.status_changed', (event) => {
      if (!event || !event.job_id) return;
      const { job_id, new_status, exit_code, elapsed_ms } = event;

      this.setState((prev) => {
        const existing = prev.activeJobs[job_id] || { id: job_id };
        const updated = {
          ...existing,
          status: new_status,
          exit_code: exit_code !== undefined ? exit_code : existing.exit_code,
          elapsed_ms: elapsed_ms || existing.elapsed_ms,
          completed_at: ['Completed', 'Failed', 'Cancelled'].includes(new_status) ? new Date().toISOString() : null
        };

        return {
          activeJobs: {
            ...prev.activeJobs,
            [job_id]: updated
          }
        };
      });
    });

    // job.progress notification handler
    this.ipc.subscribe('job.progress', (event) => {
      if (!event || !event.job_id) return;
      const { job_id, stage, percentage, bytes_processed } = event;

      this.setState((prev) => {
        const existing = prev.activeJobs[job_id];
        if (!existing) return prev;

        return {
          activeJobs: {
            ...prev.activeJobs,
            [job_id]: {
              ...existing,
              stage,
              percentage,
              bytes_processed
            }
          }
        };
      });
    });
  }

  /**
   * Registers global keyboard handler for F9 Panic Kill switch.
   */
  bindF9PanicKill() {
    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('keydown', (e) => {
        if (e.key === 'F9') {
          e.preventDefault();
          this.panicKillAll().catch((err) => {
            console.error('[JobRunnerStore] Panic kill failed:', err);
          });
        }
      });
    }
  }

  /**
   * Queues an output chunk for 60 FPS requestAnimationFrame delivery.
   * @param {string} jobId
   * @param {{ stream: string, data: string }} chunk
   */
  queueLogChunk(jobId, chunk) {
    if (!this.pendingChunks.has(jobId)) {
      this.pendingChunks.set(jobId, []);
    }
    this.pendingChunks.get(jobId).push(chunk);

    if (!this.rafScheduled) {
      this.rafScheduled = true;
      const scheduleFn = typeof requestAnimationFrame === 'function'
        ? requestAnimationFrame
        : (cb) => setTimeout(cb, 16);

      scheduleFn(() => this.flushLogs());
    }
  }

  /**
   * Flushes queued log chunks to terminal ring buffers and notifies subscribers at 60 FPS.
   */
  flushLogs() {
    this.rafScheduled = false;
    const now = Date.now();
    this.lastFlushTime = now;

    if (this.pendingChunks.size === 0) return;

    this.setState((prev) => {
      const updatedBuffers = { ...prev.terminalBuffers };

      for (const [jobId, chunks] of this.pendingChunks.entries()) {
        if (!updatedBuffers[jobId]) {
          updatedBuffers[jobId] = new TerminalRingBuffer(jobId);
        }

        const buffer = updatedBuffers[jobId];
        for (const chunk of chunks) {
          buffer.append(chunk.data);
        }
      }

      this.pendingChunks.clear();
      return { terminalBuffers: updatedBuffers };
    });
  }

  /**
   * Submits a tool process execution job.
   * @param {{ tool_id: string, argv: string[], challenge_id?: string, timeout_ms?: number, limits?: object }} params
   * @returns {Promise<string>} Created job ID
   */
  async submitJob({ tool_id, argv = [], challenge_id = null, timeout_ms = 60000, limits = null }) {
    this.setState({ error: null });
    try {
      const resp = await this.ipc.submitJob({
        tool_id,
        argv,
        challenge_id,
        timeout_ms,
        limits
      });

      const jobId = resp.id || resp.job_id;
      const initialJob = {
        id: jobId,
        tool_id,
        argv,
        challenge_id,
        status: 'Running',
        started_at: new Date().toISOString(),
        timeout_ms
      };

      this.setState((prev) => ({
        activeJobId: jobId,
        activeJobs: {
          ...prev.activeJobs,
          [jobId]: initialJob
        },
        terminalBuffers: {
          ...prev.terminalBuffers,
          [jobId]: new TerminalRingBuffer(jobId)
        }
      }));

      return jobId;
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Cancels a running job process.
   * @param {string} jobId
   * @param {string} [reason='User Cancelled']
   */
  async cancelJob(jobId, reason = 'User Cancelled') {
    try {
      await this.ipc.cancelJob(jobId, reason);
      this.setState((prev) => {
        const job = prev.activeJobs[jobId];
        if (!job) return prev;
        return {
          activeJobs: {
            ...prev.activeJobs,
            [jobId]: { ...job, status: 'Cancelled', cancel_reason: reason }
          }
        };
      });
    } catch (err) {
      this.setState({ error: err.message });
      throw err;
    }
  }

  /**
   * Emergency panic kill switch (F9). Terminates all active jobs immediately.
   */
  async panicKillAll() {
    const activeIds = Object.values(this.state.activeJobs)
      .filter((j) => j && (j.status === 'Running' || !j.status))
      .map((j) => j.id);

    if (activeIds.length === 0) return;

    await Promise.allSettled(
      activeIds.map((id) => this.cancelJob(id, 'Panic Kill Switch (F9) Triggered'))
    );
  }

  /**
   * Appends a log chunk directly (for testing or synthetic outputs).
   * @param {string} jobId
   * @param {{ stream: string, data: string }} chunk
   */
  appendLogChunk(jobId, chunk) {
    this.queueLogChunk(jobId, chunk);
  }

  /**
   * Clears terminal buffer for a specific job.
   * @param {string} jobId
   */
  clearTerminal(jobId) {
    this.setState((prev) => {
      const buffer = prev.terminalBuffers[jobId];
      if (buffer) {
        buffer.clear();
      }
      return {
        terminalBuffers: { ...prev.terminalBuffers }
      };
    });
  }

  /**
   * Sets active terminal view to a specific job ID.
   * @param {string} jobId
   */
  setActiveJob(jobId) {
    this.setState({ activeJobId: jobId });
  }

  /**
   * Sets backpressure status flag from engine.
   * @param {boolean} active
   */
  setBackpressure(active) {
    this.setState({ isBackpressureActive: Boolean(active) });
  }
}

export const jobRunnerStore = new JobRunnerStore();

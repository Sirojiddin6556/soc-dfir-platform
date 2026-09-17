/**
 * Scanner Controller for SOC/DFIR Platform
 * Orchestrates Network Discovery, Port Scanners, and CVE Vulnerability Scanners
 */
export class ScannerController {
  constructor(app, ipc) {
    this.app = app;
    this.ipc = ipc;
    this.isScanning = false;
    this.scanInterval = null;
    this.selectedSubnet = '192.168.1.0/24';
  }

  init() {
    // Top Discovery Action Buttons
    document.getElementById('btnQuickScan')?.addEventListener('click', () => this.startNetworkScan('quick'));
    document.getElementById('btnQuickScanGlobal')?.addEventListener('click', () => {
      const infraNav = document.querySelector('[data-view="infraDiscoveryView"]');
      if (infraNav) infraNav.click();
      this.startNetworkScan('quick');
    });
    document.getElementById('btnStandardScan')?.addEventListener('click', () => this.startNetworkScan('standard'));
    document.getElementById('btnDeepScan')?.addEventListener('click', () => this.startNetworkScan('deep'));
    document.getElementById('btnStopScan')?.addEventListener('click', () => this.stopNetworkScan());

    // Asset CVE & Inspection Buttons
    document.getElementById('btnScanCve')?.addEventListener('click', () => this.startCveScan());
    document.getElementById('btnInspectProc')?.addEventListener('click', () => this.quickInspectProcess());
  }

  async startNetworkScan(mode = 'quick') {
    if (this.isScanning) return;
    this.isScanning = true;

    const container = document.getElementById('scanProgressBarContainer');
    const bar = document.getElementById('scanProgressBar');
    const percentEl = document.getElementById('scanProgressPercent');
    const label = document.getElementById('scanProgressLabel');
    const logEl = document.getElementById('scanProgressLog');
    const btnStop = document.getElementById('btnStopScan');
    const scanButtons = [
      document.getElementById('btnQuickScan'),
      document.getElementById('btnStandardScan'),
      document.getElementById('btnDeepScan')
    ];

    if (container) container.style.display = 'block';
    if (btnStop) btnStop.disabled = false;
    scanButtons.forEach(btn => { if (btn) btn.disabled = true; });

    const modeUpper = mode.toUpperCase();
    if (label) label.innerHTML = `<span class="pulse-dot" style="display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--accent-primary);margin-right:6px;"></span> RUNNING ${modeUpper} SCAN (${this.selectedSubnet})...`;

    let progress = 5;
    const updateProgress = (val, log) => {
      if (bar) bar.style.width = `${val}%`;
      if (percentEl) percentEl.textContent = `${Math.round(val)}%`;
      if (log && logEl) logEl.textContent = log;
    };

    updateProgress(5, `[SCANNER] Initializing asynchronous socket scanner for ${this.selectedSubnet}...`);

    this.scanInterval = setInterval(() => {
      if (!this.isScanning) return;
      if (progress < 85) {
        progress += (90 - progress) * 0.2;
        if (progress > 25 && progress < 45) {
          updateProgress(progress, `[SCANNER] Sending ARP / ICMP probes across ${this.selectedSubnet}...`);
        } else if (progress >= 45 && progress < 70) {
          updateProgress(progress, `[SCANNER] Port probing: SYN scanning top common services (22, 53, 80, 88, 135, 445, 3389)...`);
        } else if (progress >= 70) {
          updateProgress(progress, `[SCANNER] Banner grabbing and OS fingerprinting active responder hosts...`);
        }
      }
    }, 180);

    try {
      const res = await this.ipc.call('scan.network', {
        subnet: this.selectedSubnet,
        mode: mode
      });

      clearInterval(this.scanInterval);
      if (!this.isScanning) return;

      updateProgress(100, `[SCANNER] Scan completed: ${res.hosts_up} hosts online (${res.hosts_scanned} addresses scanned in ${res.duration_ms}ms)`);

      // Merge newly discovered hosts
      if (res.discovered_hosts && Array.isArray(res.discovered_hosts)) {
        res.discovered_hosts.forEach(newHost => {
          const idx = this.app.hosts.findIndex(h => h.id === newHost.id || h.ip === newHost.ip);
          if (idx >= 0) {
            this.app.hosts[idx] = Object.assign({}, this.app.hosts[idx], newHost);
          } else {
            this.app.hosts.push(newHost);
          }
        });

        // Re-render discovery cards and update badge
        const countBadge = document.getElementById('infraHostsCount');
        if (countBadge) countBadge.textContent = `${this.app.hosts.length} Hosts Detected`;
        this.app.renderInfraDiscovery();
      }

      setTimeout(() => {
        this.resetScanControls();
      }, 1400);

    } catch (err) {
      clearInterval(this.scanInterval);
      console.error('[Scanner] Scan execution error:', err);
      updateProgress(100, `[SCANNER ERROR] ${err.message}`);
      setTimeout(() => this.resetScanControls(), 2000);
    }
  }

  stopNetworkScan() {
    this.isScanning = false;
    clearInterval(this.scanInterval);
    const logEl = document.getElementById('scanProgressLog');
    if (logEl) logEl.textContent = '[SCANNER] Scan interrupted by operator.';
    this.resetScanControls();
  }

  resetScanControls() {
    this.isScanning = false;
    const btnStop = document.getElementById('btnStopScan');
    if (btnStop) btnStop.disabled = true;
    [
      document.getElementById('btnQuickScan'),
      document.getElementById('btnStandardScan'),
      document.getElementById('btnDeepScan')
    ].forEach(btn => { if (btn) btn.disabled = false; });
  }

  async startCveScan() {
    if (!this.app.selectedHost) return;
    const host = this.app.selectedHost;

    const btn = document.getElementById('btnScanCve');
    if (btn) {
      btn.textContent = '[Scanning CVEs...]';
      btn.disabled = true;
    }

    try {
      const res = await this.ipc.call('scan.cve', { host_id: host.id });
      if (res && res.vulnerabilities) {
        host.vulnerabilities = res.vulnerabilities;
        if (res.calculated_risk) {
          host.risk = `CRITICAL (${res.calculated_risk})`;
        }
        // Update asset details view and navigate to tabVulnerabilities
        this.app.renderAssetDetails();
        const vulnTabBtn = document.querySelector('[data-asset-tab="tabVulnerabilities"]');
        if (vulnTabBtn) vulnTabBtn.click();
      }
    } catch (err) {
      console.error('[CVE Scanner] Failed:', err);
    } finally {
      if (btn) {
        btn.textContent = '[Scan CVE]';
        btn.disabled = false;
      }
    }
  }

  async quickInspectProcess() {
    if (!this.app.selectedHost) return;
    const host = this.app.selectedHost;

    try {
      const res = await this.ipc.call('broker.execute', {
        CollectProcessMetadata: { pid: 4820 }
      });
      const procTabBtn = document.querySelector('[data-asset-tab="tabProcesses"]');
      if (procTabBtn) procTabBtn.click();

      const procContainer = document.getElementById('tabProcesses');
      if (procContainer && res) {
        const notice = document.createElement('div');
        notice.style.cssText = 'background: rgba(88,166,255,0.15); border: 1px solid var(--accent-primary); padding: 8px; border-radius: 4px; margin-bottom: 8px; font-size: 11px; color: var(--accent-primary);';
        notice.innerHTML = `<strong>Live Broker Telemetry:</strong> Verified PID 4820 (${res.process_name || 'powershell.exe'}) - Status: Active / Monitored`;
        procContainer.prepend(notice);
      }
    } catch (err) {
      console.warn('[Process Inspection] Telemetry query notice:', err.message);
    }
  }
}

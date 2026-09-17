import { IpcClient } from './ipc.js';

class CyberRangeCockpitApp {
  constructor() {
    this.ipc = new IpcClient();
    this.currentView = 'infraDiscoveryView';
    this.currentAssetTab = 'tabOverview';
    this.selectedHost = null;
    this.selectedEntity = null;

    this.hosts = [
      {
        id: 'h1',
        hostname: 'DC01.CORP.LOCAL',
        ip: '192.168.1.10',
        mac: '00:1A:2B:3C:4D:5E',
        os: 'Windows Server 2022 Datacenter (Build 20348)',
        criticality: 'Tier-0 (Domain Controller)',
        status: 'Compromised / Investigating',
        risk: 'CRITICAL (9.6)',
        subnet: '192.168.1.0/24',
        ports: [53, 88, 135, 139, 389, 445, 636, 3268, 3389],
        services: ['Active Directory Domain Services', 'DNS Server', 'Kerberos Key Distribution Center', 'Netlogon'],
        persistence: ['Scheduled Task: SecurityAuditCollector (powershell -enc ...)', 'Registry Run: SysMonitor (Pending Review)'],
        software: [{ name: 'Microsoft Active Directory', ver: '10.0.20348', cpe: 'cpe:2.3:o:microsoft:windows_server_2022' }],
        vulnerabilities: [{ cve: 'CVE-2022-26923', cvss: 8.8, name: 'Active Directory Domain Services Privilege Escalation' }]
      },
      {
        id: 'h2',
        hostname: 'WS-FIN-04.CORP.LOCAL',
        ip: '192.168.1.105',
        mac: '00:1A:2B:AA:BB:CC',
        os: 'Windows 11 Enterprise (Build 22631)',
        criticality: 'Tier-2 (Workstation)',
        status: 'Patient Zero (Phishing Entry)',
        risk: 'HIGH (8.2)',
        subnet: '192.168.1.0/24',
        ports: [135, 445, 3389],
        services: ['Windows Defender Advanced Threat Protection', 'Workstation'],
        persistence: ['RunKey: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater.exe'],
        software: [{ name: 'Microsoft Office 365', ver: '16.0.17328', cpe: 'cpe:2.3:a:microsoft:office:365' }],
        vulnerabilities: [{ cve: 'CVE-2023-36884', cvss: 8.3, name: 'Office and Windows HTML RCE Vulnerability' }]
      },
      {
        id: 'h3',
        hostname: 'DMZ-WEB01',
        ip: '172.16.0.15',
        mac: '52:54:00:12:34:56',
        os: 'Ubuntu 22.04.4 LTS (Linux kernel 5.15.0-107-generic)',
        criticality: 'Tier-1 (Public Facing)',
        status: 'Normal / Monitored',
        risk: 'LOW (2.1)',
        subnet: '172.16.0.0/20',
        ports: [22, 80, 443],
        services: ['nginx.service', 'sshd.service', 'systemd-resolved.service'],
        persistence: ['Cron: /etc/cron.daily/logrotate'],
        software: [{ name: 'nginx', ver: '1.18.0-0ubuntu1.4', cpe: 'cpe:2.3:a:f5:nginx:1.18.0' }],
        vulnerabilities: []
      }
    ];

    this.selectedHost = this.hosts[0];
    this.init();
  }

  async init() {
    this.setupNavigation();
    this.setupAssetDetailsTabs();
    this.renderInfraDiscovery();
    this.renderAssetDetails();
    this.renderTimeline();
    this.renderMitreMatrix();
    this.renderEvidence();
    this.setupCanvasGraph();
    this.setupCyberRange();
    this.setupKeyboardShortcuts();
    this.setupActionButtons();
  }

  setupNavigation() {
    const navItems = document.querySelectorAll('#mainSidebar .nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const targetView = item.getAttribute('data-view');
        if (!targetView) return;

        navItems.forEach(i => i.classList.remove('active'));
        item.classList.add('active');

        document.querySelectorAll('#centerWorkspace .tab-content').forEach(view => {
          view.style.display = 'none';
        });

        const targetEl = document.getElementById(targetView);
        if (targetEl) {
          targetEl.style.display = targetView === 'infraDiscoveryView' || targetView === 'investigationGraphView' ? 'flex' : 'block';
          this.currentView = targetView;
          if (targetView === 'investigationGraphView') {
            this.drawAttackGraph();
          }
        }
      });
    });
  }

  renderInfraDiscovery() {
    const subnetListEl = document.getElementById('subnetList');
    if (subnetListEl) {
      subnetListEl.innerHTML = `
        <div class="card active" style="padding: 6px 8px; margin-bottom: 4px; font-size: 11px;">
          <strong>192.168.1.0/24</strong> (Corp LAN - 2 Hosts)
        </div>
        <div class="card" style="padding: 6px 8px; margin-bottom: 4px; font-size: 11px;">
          <strong>172.16.0.0/20</strong> (DMZ - 1 Host)
        </div>
        <div class="card" style="padding: 6px 8px; margin-bottom: 4px; font-size: 11px;">
          <strong>10.0.0.0/16</strong> (Cloud VPC - 11 Hosts)
        </div>
      `;
    }

    const hostListEl = document.getElementById('hostList');
    if (hostListEl) {
      hostListEl.innerHTML = this.hosts.map(h => `
        <div class="card ${h.id === this.selectedHost?.id ? 'active' : ''}" data-host-id="${h.id}" style="padding: 8px; margin-bottom: 6px;">
          <div style="font-weight: 600; font-size: 12px;">${h.hostname}</div>
          <div style="font-size: 11px; color: var(--text-muted);">${h.ip} | ${h.criticality.split(' ')[0]}</div>
        </div>
      `).join('');

      hostListEl.querySelectorAll('.card').forEach(card => {
        card.addEventListener('click', () => {
          const hid = card.getAttribute('data-host-id');
          this.selectedHost = this.hosts.find(h => h.id === hid) || this.hosts[0];
          this.renderInfraDiscovery();
          this.inspectEntity({
            name: this.selectedHost.hostname,
            type: 'Host Entity',
            assertion: 'Fact',
            verification: 'Confirmed',
            details: `${this.selectedHost.ip} | ${this.selectedHost.os}`
          });
        });
      });
    }

    const topoGrid = document.getElementById('topologyGrid');
    if (topoGrid) {
      topoGrid.innerHTML = this.hosts.map(h => `
        <div class="card" data-host-id="${h.id}" style="border-left: 4px solid ${h.risk.includes('CRITICAL') ? 'var(--accent-critical)' : (h.risk.includes('HIGH') ? 'var(--accent-warning)' : 'var(--accent-success)')}">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
            <div>
              <div style="font-weight: 700; font-size: 13px;">${h.hostname}</div>
              <div style="font-size: 11px; color: var(--text-secondary);">${h.ip}</div>
            </div>
            <span class="badge ${h.risk.includes('CRITICAL') ? 'badge-attack' : 'badge-host'}">${h.risk.split(' ')[0]}</span>
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px;">${h.os}</div>
          <div style="font-size: 11px; margin-bottom: 8px;"><strong>Open Ports:</strong> ${h.ports.join(', ')}</div>
          <button class="btn btn-primary btn-open-asset-details" data-host-id="${h.id}" style="width: 100%; justify-content: center;">Open Asset Details</button>
        </div>
      `).join('');

      topoGrid.querySelectorAll('.btn-open-asset-details').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const hid = btn.getAttribute('data-host-id');
          this.selectedHost = this.hosts.find(h => h.id === hid) || this.hosts[0];
          this.openAssetDetailsView();
        });
      });
    }
  }

  openAssetDetailsView() {
    document.querySelectorAll('#mainSidebar .nav-item').forEach(i => {
      if (i.getAttribute('data-view') === 'assetDetailsView') i.classList.add('active');
      else i.classList.remove('active');
    });

    document.querySelectorAll('#centerWorkspace .tab-content').forEach(view => {
      view.style.display = 'none';
    });

    const el = document.getElementById('assetDetailsView');
    if (el) el.style.display = 'flex';
    this.currentView = 'assetDetailsView';
    this.renderAssetDetails();
  }

  setupAssetDetailsTabs() {
    const subTabBtns = document.querySelectorAll('#assetSubTabs .sub-tab-btn');
    subTabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        subTabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentAssetTab = btn.getAttribute('data-asset-tab');
        this.renderAssetDetailsTabContent();
      });
    });
  }

  renderAssetDetails() {
    const h = this.selectedHost;
    if (!h) return;

    document.getElementById('assetDetailHostname').textContent = h.hostname;
    document.getElementById('assetDetailIp').textContent = h.ip;
    document.getElementById('assetDetailRisk').textContent = h.risk;
    this.renderAssetDetailsTabContent();
  }

  renderAssetDetailsTabContent() {
    const container = document.getElementById('assetTabContent');
    const h = this.selectedHost;
    if (!container || !h) return;

    switch (this.currentAssetTab) {
      case 'tabOverview':
        container.innerHTML = `
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <div class="card">
              <div class="inspector-label">Hostname & FQDN</div>
              <div class="inspector-value">${h.hostname}</div>
              <div class="inspector-label" style="margin-top: 8px;">IPv4 Address</div>
              <div class="inspector-value">${h.ip}</div>
              <div class="inspector-label" style="margin-top: 8px;">Physical MAC</div>
              <div class="inspector-value">${h.mac}</div>
            </div>
            <div class="card">
              <div class="inspector-label">Operating System</div>
              <div class="inspector-value">${h.os}</div>
              <div class="inspector-label" style="margin-top: 8px;">Criticality Level</div>
              <div class="inspector-value">${h.criticality}</div>
              <div class="inspector-label" style="margin-top: 8px;">Investigation State</div>
              <div class="inspector-value">${h.status}</div>
            </div>
          </div>
        `;
        break;
      case 'tabNetwork':
        container.innerHTML = `
          <h4 style="font-size: 12px; margin-bottom: 8px;">Listening Sockets & Open Ports</h4>
          <table class="data-table">
            <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>State</th></tr></thead>
            <tbody>
              ${h.ports.map(p => `<tr><td><strong>${p}</strong></td><td>TCP</td><td>svc-${p}</td><td><span style="color: var(--accent-success)">LISTENING</span></td></tr>`).join('')}
            </tbody>
          </table>
        `;
        break;
      case 'tabProcesses':
        container.innerHTML = `
          <h4 style="font-size: 12px; margin-bottom: 8px;">Active Process Tree (Forensic Snapshot)</h4>
          <table class="data-table">
            <thead><tr><th>PID</th><th>PPID</th><th>Image</th><th>User</th><th>CLI</th></tr></thead>
            <tbody>
              <tr><td>4</td><td>0</td><td>System</td><td>NT AUTHORITY\\SYSTEM</td><td>-</td></tr>
              <tr><td>612</td><td>4</td><td>lsass.exe</td><td>NT AUTHORITY\\SYSTEM</td><td>C:\\Windows\\system32\\lsass.exe</td></tr>
              <tr style="background: rgba(248,81,73,0.1)"><td>4820</td><td>824</td><td>powershell.exe</td><td>CORP\\Administrator</td><td>powershell.exe -NoP -enc SQBFAFgA...</td></tr>
            </tbody>
          </table>
        `;
        break;
      case 'tabPersistence':
        container.innerHTML = `
          <h4 style="font-size: 12px; margin-bottom: 8px;">Persistence & Auto-Runs</h4>
          ${h.persistence.map(p => `<div class="card" style="border-left: 3px solid var(--accent-critical)">${p}</div>`).join('')}
        `;
        break;
      case 'tabSoftware':
        container.innerHTML = `
          <h4 style="font-size: 12px; margin-bottom: 8px;">Software Inventory & CycloneDX SBOM</h4>
          <table class="data-table">
            <thead><tr><th>Component</th><th>Version</th><th>CPE Identifier</th></tr></thead>
            <tbody>
              ${h.software.map(s => `<tr><td><strong>${s.name}</strong></td><td>${s.ver}</td><td><code>${s.cpe}</code></td></tr>`).join('')}
            </tbody>
          </table>
        `;
        break;
      case 'tabVulnerabilities':
        container.innerHTML = `
          <h4 style="font-size: 12px; margin-bottom: 8px;">Correlated CVEs</h4>
          ${h.vulnerabilities.length ? h.vulnerabilities.map(v => `
            <div class="card" style="border-left: 3px solid var(--accent-critical)">
              <div style="font-weight: 700;">${v.cve} (CVSS ${v.cvss})</div>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">${v.name}</div>
            </div>
          `).join('') : '<div style="color: var(--text-muted); font-size: 12px;">No unmitigated vulnerabilities detected.</div>'}
        `;
        break;
      default:
        container.innerHTML = `<div style="color: var(--text-muted); font-size: 12px;">Tab <strong>${this.currentAssetTab}</strong> telemetry synchronized with CAS storage.</div>`;
    }
  }

  renderTimeline() {
    const lanesEl = document.getElementById('timelineLanes');
    if (!lanesEl) return;
    lanesEl.innerHTML = `
      <div class="card" style="border-left: 3px solid var(--accent-critical); margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px;">
          <span><strong>2026-09-17 14:02:18.104 UTC</strong> │ Lane: DC01 Security</span>
          <span class="badge badge-attack">CRITICAL</span>
        </div>
        <div style="font-size: 12px; margin-top: 4px;">Sysmon Event 10: Suspicious LSASS memory access from powershell.exe (PID 4820)</div>
      </div>
      <div class="card" style="border-left: 3px solid var(--accent-warning); margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px;">
          <span><strong>2026-09-17 14:01:55.002 UTC</strong> │ Lane: Network Egress</span>
          <span class="badge badge-net">SUSPICIOUS</span>
        </div>
        <div style="font-size: 12px; margin-top: 4px;">PCAP Flow: Outbound beaconing to 198.51.100.44:443 (TCP SYN/ACK 128 KB)</div>
      </div>
    `;
  }

  renderMitreMatrix() {
    const grid = document.getElementById('mitreGrid');
    if (!grid) return;
    const tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
    grid.innerHTML = tactics.map((t, idx) => `
      <div class="card" style="font-size: 11px; padding: 8px;">
        <div style="font-weight: 700; color: var(--accent-info); margin-bottom: 6px;">${idx + 1}. ${t}</div>
        <div style="background: ${t === 'Credential Access' ? 'rgba(248,81,73,0.2)' : 'var(--bg-canvas)'}; border: 1px solid var(--border-muted); padding: 4px; border-radius: 3px; font-size: 10px;">
          ${t === 'Credential Access' ? '<strong style="color: var(--accent-critical)">T1003.001 (LSASS)</strong>' : (t === 'Execution' ? 'T1059.001 (PowerShell)' : 'None detected')}
        </div>
      </div>
    `).join('');
  }

  renderEvidence() {
    const tbody = document.getElementById('evidenceTableBody');
    if (tbody) {
      tbody.innerHTML = `
        <tr><td><strong>Security_Sysmon.evtx</strong></td><td>14.2 KB</td><td>2026-09-17 14:00 UTC</td><td><code>blake3:9a12...77</code></td><td><code>sha256:d4e1...09</code></td></tr>
        <tr><td><strong>traffic_capture.pcap</strong></td><td>128.5 KB</td><td>2026-09-17 14:01 UTC</td><td><code>blake3:b834...12</code></td><td><code>sha256:88fa...ac</code></td></tr>
      `;
    }
    const custody = document.getElementById('custodyChainLog');
    if (custody) {
      custody.innerHTML = `
        <div class="card" style="font-size: 11px;">
          <strong>Block #1: ArtifactIngested</strong> │ BLAKE3 dual-hash verified at 14:00:02 UTC
        </div>
        <div class="card" style="font-size: 11px;">
          <strong>Block #2: Normalized</strong> │ Sysmon schema v1.40 mapped into SQLite repository
        </div>
      `;
    }
  }

  setupCanvasGraph() {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;
    const container = canvas.parentElement;
    canvas.width = container.clientWidth || 800;
    canvas.height = container.clientHeight || 500;
    this.drawAttackGraph();
  }

  drawAttackGraph() {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.strokeStyle = '#30363d';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(150, 150); ctx.lineTo(350, 150);
    ctx.moveTo(350, 150); ctx.lineTo(550, 150);
    ctx.stroke();

    this.drawNode(ctx, 150, 150, 'Host: DC01', '#58a6ff', 'circle');
    this.drawNode(ctx, 350, 150, 'powershell.exe:4820', '#f85149', 'diamond');
    this.drawNode(ctx, 550, 150, 'T1003.001 (LSASS)', '#d29922', 'hexagon');
  }

  drawNode(ctx, x, y, label, color, shape) {
    ctx.fillStyle = color;
    ctx.strokeStyle = '#f0f6fc';
    ctx.lineWidth = 2;
    ctx.beginPath();
    if (shape === 'circle') ctx.arc(x, y, 22, 0, Math.PI * 2);
    else if (shape === 'diamond') { ctx.moveTo(x, y - 24); ctx.lineTo(x + 24, y); ctx.lineTo(x, y + 24); ctx.lineTo(x - 24, y); ctx.closePath(); }
    else { ctx.rect(x - 20, y - 20, 40, 40); }
    ctx.fill(); ctx.stroke();
    ctx.fillStyle = '#f0f6fc'; ctx.font = '11px sans-serif'; ctx.textAlign = 'center'; ctx.fillText(label, x, y + 36);
  }

  inspectEntity(entity) {
    this.selectedEntity = entity;
    const content = document.getElementById('inspectorContent');
    const typeBadge = document.getElementById('inspectorEntityType');
    if (!content || !typeBadge) return;

    typeBadge.textContent = entity.type;
    content.innerHTML = `
      <div class="inspector-field"><div class="inspector-label">Entity Name</div><div class="inspector-value">${entity.name}</div></div>
      <div class="inspector-field"><div class="inspector-label">Epistemic Status</div><div class="inspector-value">${entity.assertion} (${entity.verification})</div></div>
      <div class="inspector-field"><div class="inspector-label">Details</div><div class="inspector-value">${entity.details}</div></div>
      <div style="display: flex; gap: 6px; margin-top: 10px;">
        <button class="btn btn-primary" style="flex: 1;">Corroborate</button>
        <button class="btn" style="flex: 1;">Disprove</button>
      </div>
    `;
  }

  setupCyberRange() {
    const btn = document.getElementById('btnVerifyHypothesis');
    const input = document.getElementById('hypothesisInput');
    const res = document.getElementById('verificationResult');
    if (!btn || !input || !res) return;

    btn.addEventListener('click', () => {
      const val = input.value.trim();
      if (val === 'T1003.001') {
        res.innerHTML = `
          <div style="background: rgba(46,160,67,0.15); border: 1px solid var(--accent-success); padding: 10px; border-radius: 4px; color: var(--accent-success); font-size: 12px;">
            <strong>SUCCESS (Score: 100/100)</strong><br>Hypothesis matched sealed Ground Truth: T1003.001 (OS Credential Dumping: LSASS Memory).
          </div>
        `;
      } else {
        res.innerHTML = `
          <div style="background: rgba(248,81,73,0.15); border: 1px solid var(--accent-critical); padding: 10px; border-radius: 4px; color: var(--accent-critical); font-size: 12px;">
            <strong>MISMATCH (Distance Score: 0/100)</strong><br>Submitted technique did not match scenario root-cause. Check memory read artifacts.
          </div>
        `;
      }
    });
  }

  setupKeyboardShortcuts() {
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const search = document.getElementById('omniSearchInput');
        if (search) search.focus();
      } else if (e.key === 'Escape') {
        this.selectedEntity = null;
        document.getElementById('inspectorContent').innerHTML = '<div style="color: var(--text-muted); font-size: 11px;">Selection cleared.</div>';
      }
    });
  }

  setupActionButtons() {
    document.getElementById('btnOpenGraphFromAsset')?.addEventListener('click', () => {
      const graphNav = document.querySelector('[data-view="investigationGraphView"]');
      if (graphNav) graphNav.click();
    });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new CyberRangeCockpitApp();
});

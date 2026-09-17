import { IpcClient } from './ipc.js';

class CyberRangeCockpitApp {
  constructor() {
    this.ipc = new IpcClient();
    this.activeTab = 'graphView';
    this.selectedEntity = null;

    this.nodes = [
      { id: 'n1', label: '192.168.1.105', type: 'Host', shape: 'circle', x: 200, y: 150, severity: 'High' },
      { id: 'n2', label: 'powershell.exe:4820', type: 'Process', shape: 'hexagon', x: 420, y: 150, severity: 'Critical' },
      { id: 'n3', label: '10.0.0.15:443', type: 'NetworkSocket', shape: 'diamond', x: 200, y: 300, severity: 'Medium' },
      { id: 'n4', label: 'T1003.001 (LSASS)', type: 'ThreatActor', shape: 'octagon', x: 620, y: 150, severity: 'Critical' }
    ];

    this.edges = [
      { source: 'n1', target: 'n2', label: 'Spawned' },
      { source: 'n1', target: 'n3', label: 'Outbound TCP' },
      { source: 'n2', target: 'n4', label: 'Access LSASS' }
    ];

    this.init();
  }

  async init() {
    this.setupTabs();
    this.setupCanvas();
    this.setupCyberRange();
    this.renderTimeline();
    this.renderMitre();
    this.renderObservations();
    this.setupEventListeners();
  }

  setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const targetTabId = btn.getAttribute('data-tab');
        document.querySelectorAll('.tab-panel').forEach(panel => {
          panel.style.display = panel.id === targetTabId ? 'block' : 'none';
        });

        this.activeTab = targetTabId;
        if (targetTabId === 'graphView') {
          this.drawGraph();
        }
      });
    });
  }

  setupCanvas() {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;
    const container = canvas.parentElement;
    canvas.width = container.clientWidth || 800;
    canvas.height = container.clientHeight || 500;

    canvas.addEventListener('click', (e) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      const clickedNode = this.nodes.find(n => {
        const dx = n.x - x;
        const dy = n.y - y;
        return Math.sqrt(dx * dx + dy * dy) <= 24;
      });

      if (clickedNode) {
        this.selectNode(clickedNode);
      }
    });

    window.addEventListener('resize', () => {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
      this.drawGraph();
    });

    this.drawGraph();
  }

  drawGraph() {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw Edges
    this.edges.forEach(edge => {
      const src = this.nodes.find(n => n.id === edge.source);
      const tgt = this.nodes.find(n => n.id === edge.target);
      if (!src || !tgt) return;

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = '#30363d';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Edge label
      const midX = (src.x + tgt.x) / 2;
      const midY = (src.y + tgt.y) / 2;
      ctx.fillStyle = '#8b949e';
      ctx.font = '11px -apple-system, sans-serif';
      ctx.fillText(edge.label, midX + 5, midY - 5);
    });

    // Draw Nodes with WCAG AA Shape Encoding (NFR-UX-002)
    this.nodes.forEach(node => {
      const isSelected = this.selectedEntity?.id === node.id;
      ctx.save();
      ctx.translate(node.x, node.y);

      let fillColor = '#58a6ff';
      let strokeColor = isSelected ? '#ffffff' : '#30363d';
      if (node.severity === 'Critical') fillColor = '#f85149';
      if (node.severity === 'High') fillColor = '#d29922';

      ctx.fillStyle = fillColor;
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = isSelected ? 3 : 1.5;

      if (node.shape === 'circle') {
        ctx.beginPath();
        ctx.arc(0, 0, 18, 0, 2 * Math.PI);
        ctx.fill();
        ctx.stroke();
      } else if (node.shape === 'hexagon') {
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const angle = (Math.PI / 3) * i;
          const hx = 20 * Math.cos(angle);
          const hy = 20 * Math.sin(angle);
          if (i === 0) ctx.moveTo(hx, hy);
          else ctx.lineTo(hx, hy);
        }
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else if (node.shape === 'diamond') {
        ctx.beginPath();
        ctx.moveTo(0, -20);
        ctx.lineTo(20, 0);
        ctx.lineTo(0, 20);
        ctx.lineTo(-20, 0);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else { // octagon
        ctx.beginPath();
        for (let i = 0; i < 8; i++) {
          const angle = (Math.PI / 4) * i + Math.PI / 8;
          const ox = 20 * Math.cos(angle);
          const oy = 20 * Math.sin(angle);
          if (i === 0) ctx.moveTo(ox, oy);
          else ctx.lineTo(ox, oy);
        }
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      }

      ctx.restore();

      // Node label
      ctx.fillStyle = '#f0f6fc';
      ctx.font = '12px -apple-system, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + 32);
    });
  }

  selectNode(node) {
    this.selectedEntity = node;
    this.drawGraph();
    this.renderInspector(node);
  }

  renderInspector(node) {
    const pane = document.getElementById('inspectorContent');
    if (!pane) return;

    let badgeClass = 'badge-host';
    let badgeText = '[HOST]';
    if (node.type === 'Process') { badgeClass = 'badge-proc'; badgeText = '[PROC]'; }
    if (node.type === 'NetworkSocket') { badgeClass = 'badge-net'; badgeText = '[NET]'; }
    if (node.type === 'ThreatActor') { badgeClass = 'badge-attack'; badgeText = '[ATT&CK]'; }

    pane.innerHTML = `
      <div style="margin-bottom: 12px;">
        <span class="badge ${badgeClass}">${badgeText}</span>
        <h4 style="margin-top: 6px;">${node.label}</h4>
      </div>

      <div class="inspector-field">
        <div class="inspector-label">Entity Type & ID</div>
        <div class="inspector-value">${node.type} (${node.id})</div>
      </div>

      <div class="inspector-field">
        <div class="inspector-label">Epistemic Status</div>
        <div class="inspector-value">Assertion: Fact | State: Confirmed</div>
      </div>

      <div class="inspector-field">
        <div class="inspector-label">Confidence & Severity</div>
        <div class="inspector-value">Confidence: 0.95 | Severity: ${node.severity}</div>
      </div>

      <div class="inspector-field">
        <div class="inspector-label">Dual Provenance Hashes</div>
        <div class="inspector-value" style="font-size: 10px;">
          BLAKE3: c47a02e6e1...<br>
          SHA256: 8a93b48f02...
        </div>
      </div>
    `;
  }

  renderTimeline() {
    const container = document.getElementById('timelineLanes');
    if (!container) return;
    const events = [
      { time: '14:22:01.104', entity: 'WORKSTATION-01', desc: 'Process Creation: powershell.exe (PID 4820)' },
      { time: '14:22:03.450', entity: 'WORKSTATION-01', desc: 'LSASS Process Access (GrantedAccess: 0x1010)' },
      { time: '14:22:05.890', entity: '10.0.0.15:443', desc: 'Outbound TLS connection initiated' }
    ];

    container.innerHTML = events.map(ev => `
      <div style="background-color: var(--bg-surface); padding: 10px; margin-bottom: 8px; border-radius: 4px; border: 1px solid var(--border-muted);">
        <div style="display: flex; justify-content: space-between; font-family: var(--font-mono); font-size: 11px; color: var(--accent-info);">
          <span>${ev.time}</span>
          <span class="badge badge-proc">[PROC]</span>
        </div>
        <div style="font-weight: 600; margin-top: 4px;">${ev.desc}</div>
      </div>
    `).join('');
  }

  renderMitre() {
    const grid = document.getElementById('mitreGrid');
    if (!grid) return;
    const tactics = [
      { id: 'TA0001', name: 'Initial Access', count: 0 },
      { id: 'TA0002', name: 'Execution', count: 1, tech: 'T1059.001 PowerShell' },
      { id: 'TA0006', name: 'Credential Access', count: 1, tech: 'T1003.001 LSASS Memory' },
      { id: 'TA0011', name: 'Command & Control', count: 1, tech: 'T1071.001 Web Protocols' }
    ];

    grid.innerHTML = tactics.map(tac => `
      <div style="background-color: var(--bg-surface); padding: 12px; border-radius: 6px; border: 1px solid ${tac.count > 0 ? 'var(--accent-critical)' : 'var(--border-muted)'};">
        <div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">${tac.id}</div>
        <div style="font-weight: 600; margin: 4px 0;">${tac.name}</div>
        ${tac.tech ? `<span class="badge badge-attack" style="margin-top: 6px;">${tac.tech}</span>` : '<span style="color: var(--text-muted); font-size: 11px;">No detections</span>'}
      </div>
    `).join('');
  }

  renderObservations() {
    const tbody = document.getElementById('obsTableBody');
    if (!tbody) return;
    const observations = [
      { type: 'Sysmon Event 1', key: 'WORKSTATION-01:4820', time: '2026-09-17T14:22:01Z', tool: 'Sysmon Normalizer' },
      { type: 'Sysmon Event 10', key: 'lsass.exe:624', time: '2026-09-17T14:22:03Z', tool: 'Sysmon Normalizer' },
      { type: 'PCAP IPv4 Flow', key: '192.168.1.105 -> 10.0.0.15', time: '2026-09-17T14:22:05Z', tool: 'PCAP Flow Analyzer' }
    ];

    tbody.innerHTML = observations.map(obs => `
      <tr style="border-bottom: 1px solid var(--border-muted);">
        <td style="padding: 6px; font-family: var(--font-mono);">${obs.type}</td>
        <td style="padding: 6px; font-family: var(--font-mono);">${obs.key}</td>
        <td style="padding: 6px; color: var(--text-muted);">${obs.time}</td>
        <td style="padding: 6px;">${obs.tool}</td>
      </tr>
    `).join('');
  }

  setupCyberRange() {
    const btn = document.getElementById('btnVerifyHypothesis');
    const input = document.getElementById('hypothesisInput');
    const resultDiv = document.getElementById('verificationResult');

    if (!btn || !input || !resultDiv) return;

    btn.addEventListener('click', () => {
      const ttp = input.value.trim();
      if (ttp === 'T1003.001' || ttp === 'T1003') {
        resultDiv.innerHTML = `
          <div style="background: rgba(46, 160, 67, 0.15); border: 1px solid var(--accent-success); color: var(--accent-success); padding: 10px; border-radius: 4px;">
            <strong>VERDICT: 100% MATCH (Confirmed)</strong><br>
            Hypothesis successfully corroborated against ground truth.<br>
            Score: +100 pts. Composite Pain Level: High (TTP).
          </div>
        `;
      } else {
        resultDiv.innerHTML = `
          <div style="background: rgba(248, 81, 73, 0.15); border: 1px solid var(--accent-critical); color: var(--accent-critical); padding: 10px; border-radius: 4px;">
            <strong>VERDICT: MISMATCH</strong><br>
            Technique ${ttp} does not match the active adversary objective in the scenario ground truth.
          </div>
        `;
      }
    });
  }

  setupEventListeners() {
    document.getElementById('btnRefreshCases')?.addEventListener('click', async () => {
      const cases = await this.ipc.call('cases.list');
      alert(`Retrieved ${cases.length} cases from engine.`);
    });
  }
}

// Instantiate on load
window.addEventListener('DOMContentLoaded', () => {
  new CyberRangeCockpitApp();
});

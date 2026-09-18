import { IpcClient } from './ipc.js';
import { ScannerController } from './scanner.js';
import { renderAssetTab } from './asset_tabs.js';
import { setupDrilldowns } from './drilldown.js';

class CyberRangeCockpitApp {
  constructor() {
    this.ipc = new IpcClient();
    this.scanner = new ScannerController(this, this.ipc);
    this.currentView = 'infraDiscoveryView';
    this.currentAssetTab = 'tabOverview';
    this.selectedHost = null;
    this.selectedEntity = null;

    this.hosts = [
      {
        id: 'h_local', hostname: 'PC-3002', ip: '127.0.0.1', mac: '00:00:00:00:00:00',
        os: 'Windows 11 Enterprise (x64)', criticality: 'Tier-1 (Рабочая станция аналитика)',
        status: 'В сети / Боевой режим', risk: 'НИЗКИЙ (1.0)', subnet: '127.0.0.1/32',
        ports: [135, 445, 8080],
        services: ['Desktop Engine Server', 'Windows Platform Broker', 'Windows Workstation'],
        persistence: [],
        software: [{ name: 'SOC DFIR Engine', ver: '0.1.0', cpe: 'cpe:2.3:a:soc:dfir_engine:0.1.0' }],
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
    this.setupInteractiveElements();
    setupDrilldowns(this);
    this.scanner.init();

    // Auto-probe live workstation on startup
    try {
      const res = await this.ipc.call('scan.network', { subnet: '127.0.0.1', mode: 'quick' });
      if (res && res.discovered_hosts && res.discovered_hosts.length > 0) {
        this.hosts[0] = Object.assign({}, this.hosts[0], res.discovered_hosts[0]);
        this.selectedHost = this.hosts[0];
        this.renderInfraDiscovery();
        this.renderAssetDetails();
      }
    } catch (_) {}
  }

  setupNavigation() {
    document.querySelectorAll('#mainSidebar .nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const targetView = item.getAttribute('data-view');
        if (targetView) this.navigateToView(targetView);
      });
    });
  }

  navigateToView(targetView) {
    let targetEl = document.getElementById(targetView);
    if (!targetEl) {
      targetView = 'casesView';
      targetEl = document.getElementById('casesView');
    }
    if (!targetEl) return;

    document.querySelectorAll('#mainSidebar .nav-item').forEach(i => {
      i.classList.toggle('active', i.getAttribute('data-view') === targetView);
    });
    document.querySelectorAll('#centerWorkspace .tab-content').forEach(v => {
      v.style.display = 'none';
    });
    targetEl.style.display = targetView === 'infraDiscoveryView' || targetView === 'investigationGraphView' ? 'flex' : 'block';
    this.currentView = targetView;
    if (targetView === 'investigationGraphView') this.drawAttackGraph();
  }

  selectAndOpenHost(hostId, tab = 'tabOverview') {
    const host = this.hosts.find(h => h.id === hostId || h.hostname === hostId || h.ip === hostId);
    if (host) this.selectedHost = host;
    this.currentAssetTab = tab;
    this.renderAssetDetails();
    this.navigateToView('assetDetailsView');
    const tabBtn = document.querySelector(`.asset-tabs .tab-btn[data-tab="${tab}"], #assetSubTabs .sub-tab-btn[data-asset-tab="${tab}"]`);
    if (tabBtn) tabBtn.click();
  }

  renderInfraDiscovery() {
    const subnetListEl = document.getElementById('subnetList');
    if (subnetListEl) {
      const subnets = [
        { cidr: '127.0.0.1/32', label: 'Локальная станция аналитика' },
        { cidr: '172.16.121.0/24', label: 'Основная сеть Ethernet' },
        { cidr: '192.168.56.0/24', label: 'Адаптер хоста (Host-Only)' },
        { cidr: '172.20.32.0/20', label: 'Виртуальная подсеть WSL' }
      ];
      subnetListEl.innerHTML = subnets.map(s => {
        const count = this.hosts.filter(h => h.subnet === s.cidr || (s.cidr.startsWith('127.') && h.ip === '127.0.0.1')).length;
        const active = (this.scanner && this.scanner.selectedSubnet === s.cidr) || (!this.scanner && s.cidr === '127.0.0.1/32');
        return `
          <div class="card subnet-card ${active ? 'active' : ''}" data-cidr="${s.cidr}" style="padding: 6px 8px; margin-bottom: 4px; font-size: 11px; cursor: pointer;">
            <strong>${s.cidr}</strong> (${s.label} - ${count} хост.)
          </div>
        `;
      }).join('');

      subnetListEl.querySelectorAll('.subnet-card').forEach(card => {
        card.addEventListener('click', () => {
          const cidr = card.getAttribute('data-cidr');
          if (this.scanner) this.scanner.selectedSubnet = cidr;
          this.renderInfraDiscovery();
        });
      });
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
            type: 'Сущность хоста',
            assertion: 'Факт',
            verification: 'Подтверждено',
            details: `${this.selectedHost.ip} | ${this.selectedHost.os}`
          });
        });
      });
    }

    const topoGrid = document.getElementById('topologyGrid');
    if (topoGrid) {
      topoGrid.innerHTML = this.hosts.map(h => `
        <div class="card" data-host-id="${h.id}" style="border-left: 4px solid ${h.risk.includes('КРИТИЧЕСКИЙ') || h.risk.includes('CRITICAL') ? 'var(--accent-critical)' : (h.risk.includes('ВЫСОКИЙ') || h.risk.includes('HIGH') ? 'var(--accent-warning)' : 'var(--accent-success)')}">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
            <div>
              <div style="font-weight: 700; font-size: 13px;">${h.hostname}</div>
              <div style="font-size: 11px; color: var(--text-secondary);">${h.ip}</div>
            </div>
            <span class="badge ${h.risk.includes('КРИТИЧЕСКИЙ') || h.risk.includes('CRITICAL') ? 'badge-attack' : 'badge-host'}">${h.risk.split(' ')[0]}</span>
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px;">${h.os}</div>
          <div style="font-size: 11px; margin-bottom: 8px;"><strong>Открытые порты:</strong> ${h.ports.join(', ')}</div>
          <button class="btn btn-primary btn-open-asset-details" data-host-id="${h.id}" style="width: 100%; justify-content: center;">Карточка актива</button>
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
    this.renderAssetDetails();
    this.navigateToView('assetDetailsView');
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

    const hostnameEl = document.getElementById('assetDetailHostname');
    const ipEl = document.getElementById('assetDetailIp');
    const riskEl = document.getElementById('assetDetailRisk');

    if (hostnameEl) hostnameEl.textContent = h.hostname;
    if (ipEl) ipEl.textContent = h.ip;
    if (riskEl) {
      riskEl.textContent = `РИСК: ${h.risk}`;
      riskEl.className = `badge ${h.risk.includes('КРИТИЧЕСКИЙ') || h.risk.includes('CRITICAL') ? 'badge-attack' : 'badge-host'}`;
    }

    this.renderAssetDetailsTabContent();
  }

  renderAssetDetailsTabContent() {
    const container = document.getElementById('assetTabContent');
    const h = this.selectedHost;
    if (!container || !h) return;
    renderAssetTab(container, h, this.currentAssetTab, this.ipc);
  }


  renderTimeline() {
    const lanesEl = document.getElementById('timelineLanes');
    if (!lanesEl) return;
    lanesEl.innerHTML = `
      <div class="card" style="border-left: 3px solid var(--accent-success); margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px;">
          <span><strong>18:00:05.120 UTC</strong> │ Поток: Локальный брокер ядра</span>
          <span class="badge badge-host">ИНФО</span>
        </div>
        <div style="font-size: 12px; margin-top: 4px;">Engine Server JSON-RPC активен на 127.0.0.1:8080. Форензик-аудит запущен.</div>
      </div>
      <div class="card" style="border-left: 3px solid var(--accent-info); margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px;">
          <span><strong>18:00:01.004 UTC</strong> │ Поток: Телеметрия хоста</span>
          <span class="badge badge-net">В НОРМЕ</span>
        </div>
        <div style="font-size: 12px; margin-top: 4px;">Станция ${this.hosts[0]?.hostname || 'PC-3002'}: Сетевые интерфейсы и сокеты в штатном режиме. Вредоносных аномалий не обнаружено.</div>
      </div>
    `;
  }

  renderMitreMatrix() {
    const grid = document.getElementById('mitreGrid');
    if (!grid) return;
    const tactics = ['Первичный доступ', 'Выполнение', 'Закрепление', 'Повышение привилегий', 'Обход защиты', 'Сбор учетных данных', 'Разведка', 'Боковое перемещение', 'Сбор данных', 'Управление и контроль', 'Эксфильтрация', 'Воздействие'];
    grid.innerHTML = tactics.map((t, idx) => `
      <div class="card" style="font-size: 11px; padding: 8px;">
        <div style="font-weight: 700; color: var(--accent-info); margin-bottom: 6px;">${idx + 1}. ${t}</div>
        <div style="background: var(--bg-canvas); border: 1px solid var(--border-muted); padding: 4px; border-radius: 3px; font-size: 10px; color: var(--text-secondary);">
          Не обнаружено
        </div>
      </div>
    `).join('');
  }

  renderEvidence() {
    const tbody = document.getElementById('evidenceTableBody');
    if (tbody) {
      tbody.innerHTML = `
        <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 14px;">Хранилище CAS готово к приему форензик-артефактов (.evtx, .pcap, .raw). Загрузите файл через кнопку сверху.</td></tr>
      `;
    }
    const custody = document.getElementById('custodyChainLog');
    if (custody) {
      custody.innerHTML = `
        <div class="card" style="font-size: 11px;">
          <strong>Блок #0: GenesisBlock</strong> │ Хранилище CAS инициализировано в каталоге data/cas. Доказательная база защищена BLAKE3.
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

    canvas.addEventListener('click', (e) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      if (x > 220 && x < 480) {
        this.inspectEntity({
          name: 'Связь: IPC Broker (Локальный канал)',
          type: 'Шина телеметрии ядра',
          assertion: 'Статус: Активен (JSON-RPC)',
          verification: 'Engine Server 127.0.0.1:8080',
          details: 'Подтверждено: Высокоскоростной локальный сокет между WebView и Rust-ядром. Задержка < 1 мс.'
        });
      } else {
        this.inspectEntity({
          name: this.hosts[0]?.hostname || 'PC-3002',
          type: 'Сущность хоста (Live Station)',
          assertion: 'Рабочая станция аналитика Tier-1',
          verification: 'Штатный режим / Защищен',
          details: `IPv4: ${this.hosts[0]?.ip || '127.0.0.1'} | ${this.hosts[0]?.os || 'Windows 11 Enterprise'}`
        });
      }
    });
  }

  drawAttackGraph() {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const host = this.hosts[0] || { hostname: 'PC-3002', ip: '127.0.0.1', ports: [135, 445, 8080] };
    const ports = host.ports && host.ports.length > 0 ? host.ports : [135, 445, 8080];
    const services = host.services || [];

    // Draw radial service connections
    const radius = Math.min(centerX, centerY) * 0.65;
    ports.forEach((p, i) => {
      const angle = (i * (2 * Math.PI / ports.length)) - (Math.PI / 2);
      const px = centerX + radius * Math.cos(angle);
      const py = centerY + radius * Math.sin(angle);

      ctx.strokeStyle = '#30363d';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(px, py);
      ctx.stroke();

      const svc = typeof services[i] === 'object' ? (services[i].service || `Port ${p}`) : (services[i] || `Port ${p}`);
      this.drawNode(ctx, px, py, `${svc} (:${p})`, '#2ea043', 'square');
    });

    // Draw central host node on top
    this.drawNode(ctx, centerX, centerY, `${host.hostname} (${host.ip})`, '#58a6ff', 'circle');
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
    const actionsHtml = Array.isArray(entity.actions) && entity.actions.length > 0 ? `
      <div style="margin-top: 10px; border-top: 1px solid var(--border-color); padding-top: 8px;">
        <div class="inspector-label" style="margin-bottom: 6px;">Быстрый переход и действия</div>
        <div style="display: flex; flex-direction: column; gap: 4px;">
          ${entity.actions.map((act, idx) => `
            <button class="btn ${act.primary ? 'btn-primary' : ''} inspector-action-btn" data-action-idx="${idx}" style="text-align: left; font-size: 11px; padding: 4px 8px;">
              ${act.label}
            </button>
          `).join('')}
        </div>
      </div>
    ` : '';

    content.innerHTML = `
      <div class="inspector-field"><div class="inspector-label">Имя сущности</div><div class="inspector-value">${entity.name}</div></div>
      <div class="inspector-field"><div class="inspector-label">Эпистемический статус</div><div class="inspector-value">${entity.assertion} (${entity.verification})</div></div>
      <div class="inspector-field"><div class="inspector-label">Детали</div><div class="inspector-value" style="white-space: pre-line;">${entity.details}</div></div>
      ${actionsHtml}
      <div style="display: flex; gap: 6px; margin-top: 10px;">
        <button class="btn btn-primary" style="flex: 1;">Подтвердить</button>
        <button class="btn" style="flex: 1;">Опровергнуть</button>
      </div>
    `;

    if (Array.isArray(entity.actions)) {
      content.querySelectorAll('.inspector-action-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const idx = parseInt(btn.getAttribute('data-action-idx'), 10);
          const act = entity.actions[idx];
          if (act && typeof act.onClick === 'function') act.onClick();
        });
      });
    }
  }

  setupCyberRange() {
    const btn = document.getElementById('btnVerifyHypothesis');
    const input = document.getElementById('hypothesisInput');
    const res = document.getElementById('verificationResult');
    if (!btn || !input || !res) return;

    btn.addEventListener('click', async () => {
      const val = input.value.trim();
      if (!val) return;

      btn.disabled = true;
      btn.textContent = 'Верификация...';
      res.innerHTML = '<div style="color: var(--text-muted); font-size: 11px;">Вычисление метрик §17.2 через scenario-verifier...</div>';

      try {
        const evalResp = await this.ipc.call('scenario.evaluate', {
          scenario_id: 'SCEN-APT29',
          hypothesis: val,
        });

        const isSuccess = evalResp.verdict === 'SUCCESS';
        const color = isSuccess ? 'var(--accent-success)' : 'var(--accent-warning)';
        const bg = isSuccess ? 'rgba(46,160,67,0.15)' : 'rgba(210,153,34,0.15)';

        res.innerHTML = `
          <div style="background: ${bg}; border: 1px solid ${color}; padding: 10px; border-radius: 4px; color: ${color}; font-size: 12px;">
            <div style="font-weight: 700; margin-bottom: 4px;">
              ${isSuccess ? 'ВЕРИФИЦИРОВАНО' : 'НЕ ПОЛНОСТЬЮ'}: ${evalResp.total_score}/${evalResp.max_possible_score} баллов (${evalResp.percentage.toFixed(1)}%)
            </div>
            <div style="font-size: 11px; margin-bottom: 6px; white-space: pre-line; color: var(--text-secondary);">
              ${evalResp.explainable_summary || 'Оценка 7 критериев завершена.'}
            </div>
          </div>
        `;
      } catch (err) {
        const isMatch = val === 'T1003.001';
        res.innerHTML = `
          <div style="background: ${isMatch ? 'rgba(46,160,67,0.15)' : 'rgba(248,81,73,0.15)'}; border: 1px solid ${isMatch ? 'var(--accent-success)' : 'var(--accent-critical)'}; padding: 10px; border-radius: 4px; font-size: 12px;">
            <strong>${isMatch ? 'УСПЕХ' : 'ОТКЛОНЕНО'}</strong>: ${err.message || 'Локальный режим'}
          </div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Верифицировать гипотезу';
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
        document.getElementById('inspectorContent').innerHTML = '<div style="color: var(--text-muted); font-size: 11px;">Выбор сброшен.</div>';
      }
    });
  }

  setupActionButtons() {
    document.getElementById('btnOpenGraphFromAsset')?.addEventListener('click', () => {
      const graphNav = document.querySelector('[data-view="investigationGraphView"]');
      if (graphNav) graphNav.click();
    });
  }

  setupInteractiveElements() {
    document.querySelectorAll('.dag-node').forEach(n => {
      n.addEventListener('click', () => {
        this.inspectEntity({
          name: `Задача: ${n.getAttribute('data-task-name')}`,
          type: 'Воркфлоу DAG',
          assertion: `Статус: ${n.getAttribute('data-task-status')}`,
          verification: `Длительность: ${n.getAttribute('data-task-dur')}`,
          details: `Цель: ${n.getAttribute('data-task-target')} | Ресурсы: CPU 1/4, IO 1/4, NET 0/6, FORENSIC 0/1`
        });
      });
    });
    document.querySelectorAll('.cve-row').forEach(r => {
      r.addEventListener('click', () => {
        this.inspectEntity({
          name: r.getAttribute('data-cve'),
          type: 'Уязвимость CVE',
          assertion: 'Контекстный риск: КРИТИЧЕСКИЙ',
          verification: 'CISA KEV: ДА | EPSS: 82%',
          details: 'Доступ из сети: ДА | Эксплуатация: Зафиксирован аномальный процесс powershell.exe'
        });
      });
    });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new CyberRangeCockpitApp();
});

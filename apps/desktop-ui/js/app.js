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
        id: 'h1', hostname: 'DC01.CORP.LOCAL', ip: '192.168.1.10', mac: '00:1A:2B:3C:4D:5E',
        os: 'Windows Server 2022 Datacenter (Сборка 20348)', criticality: 'Tier-0 (Контроллер домена)',
        status: 'Скомпрометирован / Расследование', risk: 'КРИТИЧЕСКИЙ (9.6)', subnet: '192.168.1.0/24',
        ports: [53, 88, 135, 139, 389, 445, 636, 3268, 3389],
        services: ['Active Directory Domain Services', 'DNS Server', 'Kerberos KDC', 'Netlogon'],
        persistence: ['Планировщик: SecurityAuditCollector (powershell -enc ...)', 'Реестр Run: SysMonitor (На проверке)'],
        software: [{ name: 'Microsoft Active Directory', ver: '10.0.20348', cpe: 'cpe:2.3:o:microsoft:windows_server_2022' }],
        vulnerabilities: [{ cve: 'CVE-2022-26923', cvss: 8.8, name: 'Повышение привилегий в Active Directory Domain Services' }]
      },
      {
        id: 'h2', hostname: 'WS-FIN-04.CORP.LOCAL', ip: '192.168.1.105', mac: '00:1A:2B:AA:BB:CC',
        os: 'Windows 11 Enterprise (Сборка 22631)', criticality: 'Tier-2 (Рабочая станция)',
        status: 'Нулевой пациент (Фишинг)', risk: 'ВЫСОКИЙ (8.2)', subnet: '192.168.1.0/24',
        ports: [135, 445, 3389], services: ['Windows Defender ATP', 'Workstation'],
        persistence: ['RunKey: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater.exe'],
        software: [{ name: 'Microsoft Office 365', ver: '16.0.17328', cpe: 'cpe:2.3:a:microsoft:office:365' }],
        vulnerabilities: [{ cve: 'CVE-2023-36884', cvss: 8.3, name: 'Уязвимость удаленного выполнения кода (RCE) в HTML Office/Windows' }]
      },
      {
        id: 'h3', hostname: 'DMZ-WEB01', ip: '172.16.0.15', mac: '52:54:00:12:34:56',
        os: 'Ubuntu 22.04.4 LTS (Ядро Linux 5.15.0-107-generic)', criticality: 'Tier-1 (Внешний периметр)',
        status: 'В норме / Мониторинг', risk: 'НИЗКИЙ (2.1)', subnet: '172.16.0.0/20',
        ports: [22, 80, 443], services: ['nginx.service', 'sshd.service', 'systemd-resolved.service'],
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
    this.setupInteractiveElements();
    setupDrilldowns(this);
    this.scanner.init();
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
        { cidr: '192.168.1.0/24', label: 'Корпоративная ЛВС' },
        { cidr: '172.16.0.0/20', label: 'DMZ (Периметр)' },
        { cidr: '10.0.10.0/24', label: 'Базы данных и VPC' },
        { cidr: '127.0.0.1/32', label: 'Локальный хост (Loopback)' }
      ];
      subnetListEl.innerHTML = subnets.map(s => {
        const count = this.hosts.filter(h => h.subnet === s.cidr || (s.cidr.startsWith('127.') && h.ip === '127.0.0.1')).length;
        const active = (this.scanner && this.scanner.selectedSubnet === s.cidr) || (!this.scanner && s.cidr === '192.168.1.0/24');
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
    this.navigateToView('assetDetailsView');
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
    renderAssetTab(container, h, this.currentAssetTab);
  }

  renderTimeline() {
    const lanesEl = document.getElementById('timelineLanes');
    if (!lanesEl) return;
    lanesEl.innerHTML = `
      <div class="card" style="border-left: 3px solid var(--accent-critical); margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px;">
          <span><strong>2026-09-17 14:02:18.104 UTC</strong> │ Поток: Безопасность DC01</span>
          <span class="badge badge-attack">КРИТИЧНО</span>
        </div>
        <div style="font-size: 12px; margin-top: 4px;">Событие Sysmon 10: Подозрительный доступ к памяти LSASS из powershell.exe (PID 4820)</div>
      </div>
      <div class="card" style="border-left: 3px solid var(--accent-warning); margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px;">
          <span><strong>2026-09-17 14:01:55.002 UTC</strong> │ Поток: Сетевой периметр</span>
          <span class="badge badge-net">ПОДОЗРИТЕЛЬНО</span>
        </div>
        <div style="font-size: 12px; margin-top: 4px;">Поток PCAP: Исходящий маяк (beaconing) на 198.51.100.44:443 (TCP SYN/ACK 128 КБ)</div>
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
        <div style="background: ${t === 'Сбор учетных данных' ? 'rgba(248,81,73,0.2)' : 'var(--bg-canvas)'}; border: 1px solid var(--border-muted); padding: 4px; border-radius: 3px; font-size: 10px;">
          ${t === 'Сбор учетных данных' ? '<strong style="color: var(--accent-critical)">T1003.001 (LSASS)</strong>' : (t === 'Выполнение' ? 'T1059.001 (PowerShell)' : 'Не обнаружено')}
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
          <strong>Блок #1: ArtifactIngested</strong> │ Двойной хеш BLAKE3 проверен в 14:00:02 UTC
        </div>
        <div class="card" style="font-size: 11px;">
          <strong>Блок #2: Normalized</strong> │ Схема Sysmon v1.40 смаппирована в репозиторий SQLite
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
      if (x > 200 && x < 420) {
        this.inspectEntity({
          name: 'Связь: spawned (Порождение процесса)',
          type: 'Ребро графа атак',
          assertion: 'Вероятность: 0.99 (Факт)',
          verification: 'Sysmon Event 1 & EVTX 4688',
          details: 'Подтверждено: Sysmon Event 1 (ProcessCreate), EVTX 4688, совпадение PPID: 824 -> PID: 4820. Впервые: 10:32:44 UTC'
        });
      } else if (x >= 420) {
        this.inspectEntity({
          name: 'Связь: credential_access (Доступ к памяти)',
          type: 'Ребро графа атак',
          assertion: 'Вероятность: 0.96 (Подтверждено)',
          verification: 'Sysmon Event 10',
          details: 'Подтверждено: powershell.exe запросил HANDLE к lsass.exe (0x1010 PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ).'
        });
      } else {
        this.inspectEntity({
          name: 'DC01.CORP.LOCAL',
          type: 'Сущность хоста',
          assertion: 'Контроллер домена Tier-0',
          verification: 'Скомпрометирован',
          details: 'IPv4: 192.168.1.10 | Windows Server 2022 Datacenter (Сборка 20348)'
        });
      }
    });
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

    this.drawNode(ctx, 150, 150, 'Хост: DC01', '#58a6ff', 'circle');
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
    document.querySelectorAll('.pyramid-tier').forEach(t => {
      t.addEventListener('click', () => {
        this.inspectEntity({
          name: `Пирамида боли: ${t.getAttribute('data-tier')}`,
          type: 'Индикатор IoC',
          assertion: 'Степень противодействия: ВЫСОКАЯ',
          verification: 'Скоррелировано в CAS',
          details: `Уровень ${t.getAttribute('data-tier')}: Перестройка требует смены инфраструктуры атаки.`
        });
      });
    });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new CyberRangeCockpitApp();
});

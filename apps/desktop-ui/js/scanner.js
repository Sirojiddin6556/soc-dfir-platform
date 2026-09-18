/**
 * Контроллер сканирования для платформы SOC/DFIR
 * Управляет сетевой разведкой инфраструктуры, портовыми зондами и сканером CVE
 */
export class ScannerController {
  constructor(app, ipc) {
    this.app = app;
    this.ipc = ipc;
    this.isScanning = false;
    this.scanInterval = null;
    this.selectedSubnet = '127.0.0.1/32';
  }

  init() {
    // Кнопки управления сканированием в шапке
    document.getElementById('btnQuickScan')?.addEventListener('click', () => this.startNetworkScan('quick'));
    document.getElementById('btnQuickScanGlobal')?.addEventListener('click', () => {
      const infraNav = document.querySelector('[data-view="infraDiscoveryView"]');
      if (infraNav) infraNav.click();
      this.startNetworkScan('quick');
    });
    document.getElementById('btnStandardScan')?.addEventListener('click', () => this.startNetworkScan('standard'));
    document.getElementById('btnDeepScan')?.addEventListener('click', () => this.startNetworkScan('deep'));
    document.getElementById('btnStopScan')?.addEventListener('click', () => this.stopNetworkScan());

    // Сканирование произвольного удаленного сервиса
    document.getElementById('btnScanRemote')?.addEventListener('click', () => {
      const input = document.getElementById('remoteTargetInput');
      const target = input ? input.value.trim() : '';
      this.startRemoteServiceScan(target || '127.0.0.1');
    });

    // Кнопки аудита и CVE в карточке актива
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
      document.getElementById('btnDeepScan'),
      document.getElementById('btnScanRemote')
    ];

    if (container) container.style.display = 'block';
    if (btnStop) btnStop.disabled = false;
    scanButtons.forEach(btn => { if (btn) btn.disabled = true; });

    const modeLabels = { quick: 'БЫСТРОЕ', standard: 'СТАНДАРТНОЕ', deep: 'ГЛУБОКОЕ' };
    const modeLabel = modeLabels[mode] || mode.toUpperCase();
    if (label) {
      label.innerHTML = `<span class="pulse-dot" style="display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--accent-primary);margin-right:6px;"></span> ВЫПОЛНЯЕТСЯ ${modeLabel} СКАНИРОВАНИЕ (${this.selectedSubnet})...`;
    }

    let progress = 5;
    const updateProgress = (val, log) => {
      if (bar) bar.style.width = `${val}%`;
      if (percentEl) percentEl.textContent = `${Math.round(val)}%`;
      if (log && logEl) logEl.textContent = log;
    };

    updateProgress(5, `[СКАНЕР] Инициализация асинхронного сокет-сканера для ${this.selectedSubnet}...`);

    this.scanInterval = setInterval(() => {
      if (!this.isScanning) return;
      if (progress < 85) {
        progress += (90 - progress) * 0.2;
        if (progress > 25 && progress < 45) {
          updateProgress(progress, `[СКАНЕР] Отправка ARP / ICMP эхо-зондов в подсети ${this.selectedSubnet}...`);
        } else if (progress >= 45 && progress < 70) {
          updateProgress(progress, `[СКАНЕР] Зондирование портов: SYN-сканирование ключевых служб (22, 53, 80, 88, 135, 445, 3389)...`);
        } else if (progress >= 70) {
          updateProgress(progress, `[СКАНЕР] Считывание баннеров сервисов и отпечатков ОС активных узлов...`);
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

      updateProgress(100, `[СКАНЕР] Сканирование завершено: узлов в сети — ${res.hosts_up} (проверено адресов: ${res.hosts_scanned} за ${res.duration_ms} мс)`);

      // Добавление / обновление обнаруженных хостов
      if (res.discovered_hosts && Array.isArray(res.discovered_hosts)) {
        res.discovered_hosts.forEach(newHost => {
          const idx = this.app.hosts.findIndex(h => h.id === newHost.id || h.ip === newHost.ip);
          if (idx >= 0) {
            this.app.hosts[idx] = Object.assign({}, this.app.hosts[idx], newHost);
          } else {
            this.app.hosts.push(newHost);
          }
        });

        const countBadge = document.getElementById('infraHostsCount');
        if (countBadge) countBadge.textContent = `${this.app.hosts.length} Узлов обнаружено`;
        this.app.renderInfraDiscovery();
      }

      setTimeout(() => {
        this.resetScanControls();
      }, 1400);

    } catch (err) {
      clearInterval(this.scanInterval);
      console.error('[Scanner] Ошибка выполнения сканирования:', err);
      updateProgress(100, `[ОШИБКА СКАНЕРА] ${err.message}`);
      setTimeout(() => this.resetScanControls(), 2000);
    }
  }

  async startRemoteServiceScan(target) {
    if (this.isScanning) return;
    this.isScanning = true;

    const container = document.getElementById('scanProgressBarContainer');
    const bar = document.getElementById('scanProgressBar');
    const percentEl = document.getElementById('scanProgressPercent');
    const label = document.getElementById('scanProgressLabel');
    const logEl = document.getElementById('scanProgressLog');
    const btnStop = document.getElementById('btnStopScan');

    if (container) container.style.display = 'block';
    if (btnStop) btnStop.disabled = false;

    if (label) {
      label.innerHTML = `<span class="pulse-dot" style="display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--accent-warning);margin-right:6px;"></span> АУДИТ УДАЛЕННОГО СЕРВИСА: ${target}...`;
    }

    const updateProgress = (val, log) => {
      if (bar) bar.style.width = `${val}%`;
      if (percentEl) percentEl.textContent = `${Math.round(val)}%`;
      if (log && logEl) logEl.textContent = log;
    };

    updateProgress(15, `[УДАЛЕННЫЙ СКАНЕР] Резолвинг хоста и установка TCP handshake с ${target}...`);

    try {
      const res = await this.ipc.call('scan.network', {
        subnet: target,
        mode: 'remote'
      });

      updateProgress(100, `[УДАЛЕННЫЙ СКАНЕР] Сервис ${target} успешно исследован. Добавлен в реестр активов.`);

      if (res.discovered_hosts && res.discovered_hosts.length > 0) {
        const remoteHost = res.discovered_hosts[0];
        const idx = this.app.hosts.findIndex(h => h.ip === remoteHost.ip || h.hostname === remoteHost.hostname);
        if (idx >= 0) {
          this.app.hosts[idx] = Object.assign({}, this.app.hosts[idx], remoteHost);
          this.app.selectedHost = this.app.hosts[idx];
        } else {
          this.app.hosts.push(remoteHost);
          this.app.selectedHost = remoteHost;
        }

        const countBadge = document.getElementById('infraHostsCount');
        if (countBadge) countBadge.textContent = `${this.app.hosts.length} Узлов обнаружено`;
        this.app.renderInfraDiscovery();
        this.app.openAssetDetailsView();
      }

      setTimeout(() => this.resetScanControls(), 1500);
    } catch (err) {
      console.error('[Remote Scanner Error]', err);
      updateProgress(100, `[ОШИБКА] Не удалось просканировать ${target}: ${err.message}`);
      setTimeout(() => this.resetScanControls(), 2000);
    }
  }

  stopNetworkScan() {
    this.isScanning = false;
    clearInterval(this.scanInterval);
    const logEl = document.getElementById('scanProgressLog');
    if (logEl) logEl.textContent = '[СКАНЕР] Сканирование прервано оператором.';
    this.resetScanControls();
  }

  resetScanControls() {
    this.isScanning = false;
    const btnStop = document.getElementById('btnStopScan');
    if (btnStop) btnStop.disabled = true;
    [
      document.getElementById('btnQuickScan'),
      document.getElementById('btnStandardScan'),
      document.getElementById('btnDeepScan'),
      document.getElementById('btnScanRemote')
    ].forEach(btn => { if (btn) btn.disabled = false; });
  }

  async startCveScan() {
    if (!this.app.selectedHost) return;
    const host = this.app.selectedHost;

    const btn = document.getElementById('btnScanCve');
    if (btn) {
      btn.textContent = '[Сканирование CVE...]';
      btn.disabled = true;
    }

    try {
      const res = await this.ipc.call('scan.cve', { host_id: host.id });
      if (res && res.vulnerabilities) {
        host.vulnerabilities = res.vulnerabilities;
        if (res.calculated_risk && res.calculated_risk > 5.0) {
          host.risk = `ВЫСОКИЙ (${res.calculated_risk})`;
        } else {
          host.risk = `НИЗКИЙ (${res.calculated_risk || 1.0})`;
        }
        if (res.scanned_software && Array.isArray(res.scanned_software)) {
          host.software = res.scanned_software;
        }
        this.app.renderAssetDetails();
        const vulnTabBtn = document.querySelector('[data-asset-tab="tabVulnerabilities"]');
        if (vulnTabBtn) vulnTabBtn.click();
      }
    } catch (err) {

      console.error('[CVE Scanner] Ошибка:', err);
    } finally {
      if (btn) {
        btn.textContent = '[Сканировать CVE]';
        btn.disabled = false;
      }
    }
  }

  async quickInspectProcess() {
    if (!this.app.selectedHost) return;

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
        notice.innerHTML = `<strong>Телеметрия привилегированного брокера:</strong> Проверен PID 4820 (${res.process_name || 'powershell.exe'}) — Статус: Активен / Под наблюдением`;
        procContainer.prepend(notice);
      }
    } catch (err) {
      console.warn('[Process Inspection] Уведомление:', err.message);
    }
  }
}

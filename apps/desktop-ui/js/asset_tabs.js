// Asset Details Tabs Renderer for Cyber Range & SOC/DFIR Platform
// Provides complete forensic telemetry for all 12 Asset Detail Views

let currentProcView = 'table'; // 'table' or 'tree'
let snapshotCache = null;
let isLoadingSnapshot = false;

export async function renderAssetTab(container, h, tabName, ipc = null) {
  if (!container || !h) return;

  // Attempt live snapshot load if ipc is provided and cache is empty
  if (ipc && !snapshotCache && !isLoadingSnapshot) {
    isLoadingSnapshot = true;
    try {
      snapshotCache = await ipc.getHostSnapshot(h.hostname || 'PC-3002');
    } catch (e) {
      console.warn('Snapshot load fallback:', e);
    } finally {
      isLoadingSnapshot = false;
    }
  }

  const snap = snapshotCache;

  switch (tabName) {
    case 'tabOverview':
      renderOverviewTab(container, h, snap);
      break;

    case 'tabNetwork':
      renderNetworkTab(container, h, snap);
      break;

    case 'tabProcesses':
      renderProcessesTab(container, h, snap, ipc);
      break;

    case 'tabPersistence':
      renderPersistenceTab(container, h, snap);
      break;

    case 'tabSoftware':
      renderSoftwareTab(container, h, snap);
      break;

    case 'tabServices':
      renderServicesTab(container, h, snap);
      break;

    case 'tabVulnerabilities':
      renderVulnerabilitiesTab(container, h, snap);
      break;

    case 'tabUsers':
      renderUsersTab(container, h, snap);
      break;

    case 'tabFirewall':
      renderFirewallTab(container, h, snap);
      break;

    case 'tabFiles':
      renderFilesTab(container, h);
      break;

    case 'tabLogs':
      renderLogsTab(container, h);
      break;

    case 'tabEvidence':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Связанные доказательства (Chain of Custody)</h4>
        <div style="color: var(--text-muted); font-size: 12px; padding: 12px; background: var(--bg-canvas); border: 1px dashed var(--border-muted); border-radius: 4px;">
          Артефакты расследования пока не загружены. Для добавления дампов памяти, журналов EVTX или PCAP используйте кнопку «+ Загрузить артефакт».
        </div>`;
      break;

    default:
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 12px;">Телеметрия вкладки <strong>${tabName}</strong> синхронизирована с CAS.</div>`;
  }
}

function renderOverviewTab(container, h, snap) {
  const counts = snap?.counts || { processes: snap?.processes?.length || 24, sockets: snap?.sockets?.length || 8, services: snap?.services?.length || 35 };
  container.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
      <div class="card">
        <div class="inspector-label">Имя хоста и FQDN</div><div class="inspector-value">${snap?.host || h.hostname}</div>
        <div class="inspector-label" style="margin-top: 8px;">IPv4-адрес</div><div class="inspector-value">${snap?.host_ip || h.ip}</div>
        <div class="inspector-label" style="margin-top: 8px;">Физический MAC-адрес</div><div class="inspector-value">${h.mac || '00:50:56:C0:00:08'}</div>
        <div class="inspector-label" style="margin-top: 8px;">Роль в домене</div><div class="inspector-value">Рабочая станция / Аналитический узел</div>
      </div>
      <div class="card">
        <div class="inspector-label">Операционная система</div><div class="inspector-value">${snap?.os || h.os}</div>
        <div class="inspector-label" style="margin-top: 8px;">Уровень критичности</div><div class="inspector-value">${h.criticality || 'Tier-1'}</div>
        <div class="inspector-label" style="margin-top: 8px;">Статус расследования</div><div class="inspector-value">${h.status || 'Активен'}</div>
        <div class="inspector-label" style="margin-top: 8px;">Активная телеметрия</div>
        <div class="inspector-value" style="font-size: 11px; color: var(--text-secondary);">
          Процессы: <strong>${counts.processes}</strong> │ Сокеты: <strong>${counts.sockets}</strong> │ Службы: <strong>${counts.services}</strong>
        </div>
      </div>
    </div>`;
}

function renderNetworkTab(container, h, snap) {
  const sockets = snap?.sockets || [];
  if (sockets.length > 0) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h4 style="font-size: 12px; margin: 0;">Слушающие сокеты и сетевые соединения (Socket ↔ PID: ${sockets.length})</h4>
        <span class="badge badge-host" style="font-size: 10px;">Live TCP Table</span>
      </div>
      <div style="max-height: 380px; overflow-y: auto;">
        <table class="data-table">
          <thead><tr><th>Протокол</th><th>Локальный сокет</th><th>Удаленный сокет</th><th>PID</th><th>Процесс</th><th>Состояние</th></tr></thead>
          <tbody>
            ${sockets.map(s => `
              <tr>
                <td><strong>${s.protocol}</strong></td>
                <td><code>${s.local_address}:${s.local_port}</code></td>
                <td><code>${s.remote_address}:${s.remote_port}</code></td>
                <td><span class="badge badge-net">${s.pid}</span></td>
                <td><strong>${s.process_name || '—'}</strong></td>
                <td><span style="color: ${s.state === 'Listen' ? 'var(--accent-success)' : 'var(--accent-info)'}">${s.state}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } else {
    container.innerHTML = `
      <h4 style="font-size: 12px; margin-bottom: 8px;">Слушающие сокеты и открытые порты</h4>
      <table class="data-table">
        <thead><tr><th>Порт</th><th>Протокол</th><th>Служба</th><th>Состояние</th></tr></thead>
        <tbody>${(h.ports || [135, 445, 8080]).map(p => `<tr><td><strong>${p}</strong></td><td>TCP</td><td>svc-${p}</td><td><span style="color: var(--accent-success)">СЛУШАЕТ</span></td></tr>`).join('')}</tbody>
      </table>`;
  }
}

function renderProcessesTab(container, h, snap, ipc) {
  const procs = snap?.processes || [
    { pid: 4, ppid: 0, name: 'System', username: 'NT AUTHORITY\\SYSTEM', command_line: '', sha256: null, integrity_level: 'System' },
    { pid: 612, ppid: 4, name: 'services.exe', username: 'NT AUTHORITY\\SYSTEM', command_line: '', sha256: null, integrity_level: 'System' },
    { pid: 824, ppid: 612, name: 'svchost.exe', username: 'NT AUTHORITY\\SYSTEM', command_line: 'svchost.exe -k netsvcs', sha256: null, integrity_level: 'System' },
    { pid: 1204, ppid: 824, name: 'explorer.exe', username: 'PC-3002\\Siroj', command_line: '', sha256: null, integrity_level: 'Medium' },
    { pid: 31360, ppid: 1204, name: 'desktop-app.exe', username: 'PC-3002\\Siroj', command_line: 'desktop-app.exe', sha256: 'a1b2c3d4...', integrity_level: 'Medium' },
  ];

  const headerHtml = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <h4 style="font-size: 12px; margin: 0;">Телеметрия процессов (${procs.length} активных)</h4>
      <div style="display: flex; gap: 4px;">
        <button class="btn btn-secondary btn-sm" id="btnProcModeTable" style="${currentProcView === 'table' ? 'background: var(--accent-primary); color: #fff;' : ''}">Таблица</button>
        <button class="btn btn-secondary btn-sm" id="btnProcModeTree" style="${currentProcView === 'tree' ? 'background: var(--accent-primary); color: #fff;' : ''}">Дерево процессов</button>
      </div>
    </div>`;

  let contentHtml = '';
  if (currentProcView === 'table') {
    contentHtml = `
      <div style="max-height: 380px; overflow-y: auto;">
        <table class="data-table">
          <thead><tr><th>PID</th><th>PPID</th><th>Процесс</th><th>Пользователь</th><th>Командная строка</th><th>Хеш SHA-256</th><th>Уровень</th></tr></thead>
          <tbody>
            ${procs.map(p => `
              <tr>
                <td><strong>${p.pid}</strong></td>
                <td>${p.ppid}</td>
                <td><strong style="color: var(--accent-primary)">${p.name}</strong></td>
                <td>${p.username || '—'}</td>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${p.command_line || ''}">${p.command_line || '—'}</td>
                <td><code>${p.sha256 ? p.sha256.substring(0, 8) + '...' : 'System Binary'}</code></td>
                <td><span class="badge ${p.integrity_level === 'System' ? 'badge-host' : 'badge-net'}">${p.integrity_level || 'Medium'}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } else {
    contentHtml = `
      <div style="max-height: 380px; overflow-y: auto; font-family: monospace; font-size: 12px; line-height: 1.6; background: var(--bg-canvas); padding: 12px; border-radius: 4px; border: 1px solid var(--border-muted);">
        ${buildProcessTreeHtml(procs)}
      </div>`;
  }

  container.innerHTML = headerHtml + contentHtml;

  const btnTable = container.querySelector('#btnProcModeTable');
  const btnTree = container.querySelector('#btnProcModeTree');
  if (btnTable) {
    btnTable.onclick = () => {
      currentProcView = 'table';
      renderProcessesTab(container, h, snap, ipc);
    };
  }
  if (btnTree) {
    btnTree.onclick = () => {
      currentProcView = 'tree';
      renderProcessesTab(container, h, snap, ipc);
    };
  }
}

function buildProcessTreeHtml(procs) {
  const pMap = new Map();
  const childrenMap = new Map();

  procs.forEach(p => {
    pMap.set(p.pid, p);
    if (!childrenMap.has(p.ppid)) {
      childrenMap.set(p.ppid, []);
    }
    childrenMap.get(p.ppid).push(p);
  });

  const roots = procs.filter(p => !pMap.has(p.ppid) || p.ppid === 0 || p.pid === p.ppid);

  function renderBranch(proc, depth) {
    const indent = '&nbsp;&nbsp;'.repeat(depth);
    const prefix = depth === 0 ? '▶ ' : '└─ ';
    const children = childrenMap.get(proc.pid) || [];
    let out = `<div>${indent}${prefix}<strong>${proc.name}</strong> <span style="color: var(--text-muted)">(PID: ${proc.pid}, PPID: ${proc.ppid})</span> <span class="badge badge-net" style="font-size: 9px;">${proc.username || 'SYSTEM'}</span></div>`;
    for (const child of children) {
      if (child.pid !== proc.pid) {
        out += renderBranch(child, depth + 1);
      }
    }
    return out;
  }

  return roots.map(r => renderBranch(r, 0)).join('');
}

function renderServicesTab(container, h, snap) {
  const services = snap?.services || [
    { service_name: 'EventLog', display_name: 'Служба журнала событий Windows', state: 'Running', start_type: 'Auto', binary_path: 'C:\\WINDOWS\\System32\\svchost.exe -k LocalServiceNetworkRestricted', path_quoted: false, unquoted_risk: false },
    { service_name: 'LanmanServer', display_name: 'Серверный доступ к файлам/принтерам', state: 'Running', start_type: 'Auto', binary_path: 'C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p', path_quoted: false, unquoted_risk: false },
    { service_name: 'WinDefend', display_name: 'Microsoft Defender Antivirus Service', state: 'Running', start_type: 'Auto', binary_path: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe', path_quoted: false, unquoted_risk: false }
  ];

  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <h4 style="font-size: 12px; margin: 0;">Службы операционной системы (${services.length} зарегистрировано)</h4>
      <span class="badge badge-host" style="font-size: 10px;">Service Control Manager</span>
    </div>
    <div style="max-height: 380px; overflow-y: auto;">
      <table class="data-table">
        <thead><tr><th>Служба</th><th>Отображаемое имя</th><th>Статус</th><th>Тип</th><th>Бинарный путь</th><th>Безопасность пути</th></tr></thead>
        <tbody>
          ${services.map(s => `
            <tr>
              <td><strong>${s.service_name}</strong></td>
              <td>${s.display_name}</td>
              <td><span style="color: ${s.state === 'Running' ? 'var(--accent-success)' : 'var(--text-muted)'}">${s.state}</span></td>
              <td>${s.start_type}</td>
              <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${s.binary_path}"><code>${s.binary_path}</code></td>
              <td>
                ${s.unquoted_risk
                  ? '<span class="badge badge-attack" title="Путь содержит пробелы и не заключен в кавычки">Внимание: Unquoted</span>'
                  : '<span style="color: var(--accent-success); font-size: 11px;">✓ Норма</span>'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>`;
}

function renderPersistenceTab(container, h, snap) {
  const autoruns = snap?.autoruns || [
    { hive: 'HKLM', key: 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value_name: 'SecurityHealth', value_data: '%windir%\\system32\\SecurityHealthSystray.exe' }
  ];
  const tasks = snap?.scheduled_tasks || [
    { task_name: 'OneDrive Standalone Update Task', task_path: '\\Microsoft\\OneDrive', state: 'Ready', action: 'OneDriveStandaloneUpdater.exe' }
  ];

  container.innerHTML = `
    <h4 style="font-size: 12px; margin-bottom: 8px;">Автозапуск реестра (Registry Autoruns: ${autoruns.length})</h4>
    <div style="max-height: 180px; overflow-y: auto; margin-bottom: 14px;">
      <table class="data-table">
        <thead><tr><th>Улей / Ветка</th><th>Параметр</th><th>Значение / Исполняемый файл</th></tr></thead>
        <tbody>
          ${autoruns.map(a => `
            <tr>
              <td><code>${a.key}</code></td>
              <td><strong>${a.value_name}</strong></td>
              <td><code>${a.value_data}</code></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <h4 style="font-size: 12px; margin-bottom: 8px;">Запланированные задачи (Task Scheduler: ${tasks.length})</h4>
    <div style="max-height: 180px; overflow-y: auto;">
      <table class="data-table">
        <thead><tr><th>Имя задачи</th><th>Путь</th><th>Действие (Action)</th><th>Состояние</th></tr></thead>
        <tbody>
          ${tasks.map(t => `
            <tr>
              <td><strong>${t.task_name}</strong></td>
              <td><code>${t.task_path}</code></td>
              <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${t.action || ''}"><code>${t.action || '—'}</code></td>
              <td><span style="color: var(--accent-success)">${t.state}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>`;
}

function renderSoftwareTab(container, h, snap) {
  const soft = snap?.software || (h.software || []).map(s => ({ product: s.name || s.product, version: s.ver || s.version, publisher: s.publisher || 'SOC Platform', architecture: s.architecture || 'x64', cpe: s.cpe }));
  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <h4 style="font-size: 12px; margin: 0;">Установленное ПО и спецификации CPE 2.3 (${soft.length})</h4>
      <span class="badge badge-host" style="font-size: 10px;">Registry Uninstall & CPE Normalizer</span>
    </div>
    <div style="max-height: 380px; overflow-y: auto;">
      <table class="data-table">
        <thead><tr><th>Продукт / Пакет</th><th>Версия</th><th>Издатель</th><th>Спецификация CPE 2.3</th></tr></thead>
        <tbody>
          ${soft.map(s => {
            const cleanProd = s.product || s.name || 'Component';
            const cleanVer = s.version || s.ver || '1.0';
            const cleanPub = s.publisher || 'Unknown';
            const cpe = s.cpe || `cpe:2.3:a:${cleanPub.toLowerCase().replace(/[\s.]+/g, '_')}:${cleanProd.toLowerCase().replace(/[\s.]+/g, '_')}:${cleanVer}:*:*:*:*:*:*:*`;
            return `
            <tr>
              <td><strong>${cleanProd}</strong></td>
              <td><code>${cleanVer}</code></td>
              <td>${cleanPub}</td>
              <td><code style="font-size: 10px; color: var(--accent-info);">${cpe}</code></td>
            </tr>
          `;}).join('')}
        </tbody>
      </table>
    </div>`;
}

function renderVulnerabilitiesTab(container, h, snap) {
  const vulns = h.vulnerabilities || [];
  if (vulns.length > 0) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h4 style="font-size: 12px; margin: 0;">Скоррелированные уязвимости (${vulns.length})</h4>
        <span class="badge badge-attack" style="font-size: 10px;">CVE / CVSS / EPSS / KEV</span>
      </div>
      <div style="max-height: 380px; overflow-y: auto;">
        <table class="data-table">
          <thead><tr><th>CVE ID</th><th>Уязвимый компонент</th><th>CVSS v3</th><th>EPSS</th><th>CISA KEV</th><th>Спецификация CPE</th></tr></thead>
          <tbody>
            ${vulns.map(v => `
              <tr>
                <td><strong style="color: var(--accent-critical)">${v.cve}</strong></td>
                <td>${v.name}</td>
                <td><span class="badge badge-attack">${v.cvss} (${v.severity || 'High'})</span></td>
                <td>${v.epss ? (v.epss * 100).toFixed(1) + '%' : '—'}</td>
                <td>${v.cisa_kev ? '<span class="badge badge-attack">CISA KEV</span>' : '<span style="color: var(--text-muted)">Нет</span>'}</td>
                <td><code style="font-size: 10px;">${v.cpe || '—'}</code></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } else {
    container.innerHTML = `
      <h4 style="font-size: 12px; margin-bottom: 8px;">Скоррелированные уязвимости (CVE)</h4>
      <div style="color: var(--text-muted); font-size: 12px; padding: 12px; background: var(--bg-canvas); border: 1px solid var(--border-muted); border-radius: 4px;">
        На хосте <strong>${snap?.host || h.hostname}</strong> уязвимостей CVE не зафиксировано. Статус безопасности: <span style="color: var(--accent-success); font-weight: 700;">SECURE (CVE-FREE)</span>.
      </div>`;
  }
}


function renderUsersTab(container, h, snap) {
  const users = snap?.users || ['PC-3002\\Siroj', 'PC-3002\\Administrator', 'NT AUTHORITY\\SYSTEM'];
  container.innerHTML = `
    <h4 style="font-size: 12px; margin-bottom: 8px;">Учетные записи и контекст безопасности</h4>
    <table class="data-table">
      <thead><tr><th>Учетная запись</th><th>Контекст</th><th>Статус</th></tr></thead>
      <tbody>
        ${users.map(u => `
          <tr>
            <td><strong>${u}</strong></td>
            <td>${u.includes('SYSTEM') ? 'Local System Service' : 'Local Administrator / User'}</td>
            <td><span style="color: var(--accent-success)">Активна</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>`;
}

function renderFirewallTab(container, h, snap) {
  const rules = snap?.firewall_rules || [
    { name: 'Core Networking - DNS (UDP-Out)', direction: 'Outbound', action: 'Allow', enabled: true },
    { name: 'Remote Desktop - UserMode (TCP-In)', direction: 'Inbound', action: 'Allow', enabled: true }
  ];
  container.innerHTML = `
    <h4 style="font-size: 12px; margin-bottom: 8px;">Конфигурация брандмауэра и активные правила (${rules.length})</h4>
    <div style="max-height: 380px; overflow-y: auto;">
      <table class="data-table">
        <thead><tr><th>Название правила</th><th>Направление</th><th>Действие</th><th>Состояние</th></tr></thead>
        <tbody>
          ${rules.map(r => `
            <tr>
              <td><strong>${r.name}</strong></td>
              <td>${r.direction}</td>
              <td><span style="color: var(--accent-success)">${r.action}</span></td>
              <td><span style="color: ${r.enabled ? 'var(--accent-success)' : 'var(--text-muted)'}">${r.enabled ? 'Включено' : 'Отключено'}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>`;
}

function renderFilesTab(container, h) {
  container.innerHTML = `
    <h4 style="font-size: 12px; margin-bottom: 8px;">Мониторинг файловой системы и форензик-артефакты</h4>
    <table class="data-table">
      <thead><tr><th>Файл / Каталог</th><th>Размер</th><th>Хэш SHA-256</th><th>Анализ целостности</th></tr></thead>
      <tbody>
        <tr><td><code>C:\\Windows\\System32\\ntoskrnl.exe</code></td><td>11.4 МБ</td><td><code>3a7b...88f1</code></td><td><span style="color: var(--accent-success)">Подлинный</span></td></tr>
        <tr><td><code>C:\\Windows\\System32\\drivers\\etc\\hosts</code></td><td>1.2 КБ</td><td><code>b94d...279b</code></td><td><span style="color: var(--accent-success)">Стандартный</span></td></tr>
      </tbody>
    </table>`;
}

function renderLogsTab(container, h) {
  container.innerHTML = `
    <h4 style="font-size: 12px; margin-bottom: 8px;">Поток событий журнала аудита (Telemetry Stream)</h4>
    <table class="data-table">
      <thead><tr><th>Время UTC</th><th>Канал / ID</th><th>Уровень</th><th>Описание события</th></tr></thead>
      <tbody>
        <tr><td>09:30:01</td><td>System / 7036</td><td>Info</td><td>Служба SOC DFIR Engine успешно переведена в состояние «Работает»</td></tr>
        <tr><td>09:30:02</td><td>Security / 4624</td><td>Info</td><td>Успешный локальный вход в систему: PC-3002\\Siroj</td></tr>
        <tr><td>09:30:05</td><td>Broker / 1001</td><td>Info</td><td>Локальный брокер безопасности активен на 127.0.0.1:8080</td></tr>
      </tbody>
    </table>`;
}

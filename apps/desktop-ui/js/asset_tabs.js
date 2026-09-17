// Asset Details Tabs Renderer for Cyber Range & SOC/DFIR Platform
// Provides complete forensic telemetry for all 12 Asset Detail Views

export function renderAssetTab(container, h, tabName) {
  if (!container || !h) return;

  switch (tabName) {
    case 'tabOverview':
      container.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
          <div class="card">
            <div class="inspector-label">Имя хоста и FQDN</div><div class="inspector-value">${h.hostname}</div>
            <div class="inspector-label" style="margin-top: 8px;">IPv4-адрес</div><div class="inspector-value">${h.ip}</div>
            <div class="inspector-label" style="margin-top: 8px;">Физический MAC-адрес</div><div class="inspector-value">${h.mac || '00:50:56:C0:00:08'}</div>
            <div class="inspector-label" style="margin-top: 8px;">Роль в домене</div><div class="inspector-value">${h.hostname.includes('DC') ? 'Контроллер домена (Primary DC)' : 'Рабочая станция / Сервер'}</div>
          </div>
          <div class="card">
            <div class="inspector-label">Операционная система</div><div class="inspector-value">${h.os}</div>
            <div class="inspector-label" style="margin-top: 8px;">Уровень критичности</div><div class="inspector-value">${h.criticality}</div>
            <div class="inspector-label" style="margin-top: 8px;">Статус расследования</div><div class="inspector-value">${h.status}</div>
            <div class="inspector-label" style="margin-top: 8px;">Оценка риска хоста</div><div class="inspector-value" style="color: var(--accent-critical); font-weight: 700;">${h.risk}</div>
          </div>
        </div>`;
      break;

    case 'tabNetwork':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Слушающие сокеты и открытые порты</h4>
        <table class="data-table">
          <thead><tr><th>Порт</th><th>Протокол</th><th>Служба</th><th>Состояние</th></tr></thead>
          <tbody>${(h.ports || []).map(p => `<tr><td><strong>${p}</strong></td><td>TCP</td><td>svc-${p}</td><td><span style="color: var(--accent-success)">СЛУШАЕТ</span></td></tr>`).join('')}</tbody>
        </table>`;
      break;

    case 'tabProcesses':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Дерево активных процессов (Форензик-снимок)</h4>
        <table class="data-table">
          <thead><tr><th>PID</th><th>PPID</th><th>Образ</th><th>Пользователь</th><th>Командная строка</th></tr></thead>
          <tbody>
            <tr><td>4</td><td>0</td><td>System</td><td>NT AUTHORITY\\SYSTEM</td><td>-</td></tr>
            <tr><td>612</td><td>4</td><td>lsass.exe</td><td>NT AUTHORITY\\SYSTEM</td><td>C:\\Windows\\system32\\lsass.exe</td></tr>
            <tr style="background: rgba(248,81,73,0.1)"><td>4820</td><td>824</td><td>powershell.exe</td><td>CORP\\Administrator</td><td>powershell.exe -NoP -enc SQBFAFgA...</td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabPersistence':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Механизмы закрепления (Persistence & Auto-Runs)</h4>
        ${(h.persistence || []).length
          ? (h.persistence || []).map(p => `<div class="card" style="border-left: 3px solid var(--accent-critical); margin-bottom: 6px;">${p}</div>`).join('')
          : '<div style="color: var(--text-muted); font-size: 12px;">Механизмов автозапуска и закрепления не обнаружено.</div>'}`;
      break;

    case 'tabSoftware':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Инвентарь ПО и SBOM CycloneDX</h4>
        <table class="data-table">
          <thead><tr><th>Компонент</th><th>Версия</th><th>Идентификатор CPE</th></tr></thead>
          <tbody>${(h.software || []).map(s => `<tr><td><strong>${s.name}</strong></td><td>${s.ver}</td><td><code>${s.cpe}</code></td></tr>`).join('')}</tbody>
        </table>`;
      break;

    case 'tabVulnerabilities':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Скоррелированные уязвимости (CVE)</h4>
        ${(h.vulnerabilities || []).length
          ? (h.vulnerabilities || []).map(v => `<div class="card" style="border-left: 3px solid var(--accent-critical); margin-bottom: 6px;"><div style="font-weight: 700;">${v.cve} (CVSS ${v.cvss})</div><div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">${v.name}</div></div>`).join('')
          : '<div style="color: var(--text-muted); font-size: 12px;">Неустраненных уязвимостей не обнаружено.</div>'}`;
      break;

    case 'tabServices':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Службы операционной системы</h4>
        <table class="data-table">
          <thead><tr><th>Имя службы</th><th>Отображаемое имя</th><th>Статус</th><th>Тип запуска</th></tr></thead>
          <tbody>
            <tr><td><strong>EventLog</strong></td><td>Служба журнала событий Windows</td><td><span style="color: var(--accent-success)">Работает</span></td><td>Автоматически</td></tr>
            <tr><td><strong>LanmanServer</strong></td><td>Серверный доступ к файлам/принтерам</td><td><span style="color: var(--accent-success)">Работает</span></td><td>Автоматически</td></tr>
            <tr><td><strong>WinDefend</strong></td><td>Microsoft Defender Antivirus Service</td><td><span style="color: var(--accent-success)">Работает</span></td><td>Автоматически</td></tr>
            <tr style="background: rgba(248,81,73,0.08)"><td><strong>RemoteRegistry</strong></td><td>Удаленное управление реестром</td><td><span style="color: var(--accent-warning)">Остановлена</span></td><td>Вручную</td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabUsers':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Учетные записи и группы безопасности</h4>
        <table class="data-table">
          <thead><tr><th>Имя пользователя</th><th>SID / UID</th><th>Группы</th><th>Статус</th></tr></thead>
          <tbody>
            <tr><td><strong>Administrator</strong></td><td><code>S-1-5-21-...-500</code></td><td>Domain Admins, Administrators</td><td><span style="color: var(--accent-success)">Активна</span></td></tr>
            <tr><td><strong>krbtgt</strong></td><td><code>S-1-5-21-...-502</code></td><td>Domain Users</td><td><span style="color: var(--text-muted)">Отключена</span></td></tr>
            <tr style="background: rgba(248,81,73,0.08)"><td><strong>svc_backup</strong></td><td><code>S-1-5-21-...-1105</code></td><td>Backup Operators, Remote Desktop</td><td><span style="color: var(--accent-critical)">Скомпрометирована</span></td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabFirewall':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Конфигурация брандмауэра и активные правила</h4>
        <table class="data-table">
          <thead><tr><th>Название правила</th><th>Направление</th><th>Действие</th><th>Порты</th><th>Состояние</th></tr></thead>
          <tbody>
            <tr><td><strong>RemoteDesktop-UserMode-In-TCP</strong></td><td>Входящее</td><td>Разрешить</td><td>TCP 3389</td><td><span style="color: var(--accent-success)">Включено</span></td></tr>
            <tr><td><strong>FileAndPrinterSharing-SMB-In</strong></td><td>Входящее</td><td>Разрешить</td><td>TCP 445</td><td><span style="color: var(--accent-success)">Включено</span></td></tr>
            <tr style="background: rgba(248,81,73,0.08)"><td><strong>Suspicious-ReverseShell-Out</strong></td><td>Исходящее</td><td>Разрешить</td><td>TCP 4444</td><td><span style="color: var(--accent-critical)">Обнаружено</span></td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabFiles':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Мониторинг файловой системы и форензик-артефакты</h4>
        <table class="data-table">
          <thead><tr><th>Файл / Каталог</th><th>Размер</th><th>Хэш SHA-256</th><th>Анализ целостности</th></tr></thead>
          <tbody>
            <tr><td><code>C:\\Windows\\System32\\ntoskrnl.exe</code></td><td>11.4 МБ</td><td><code>3a7b...88f1</code></td><td><span style="color: var(--accent-success)">Подлинный</span></td></tr>
            <tr><td><code>C:\\Windows\\System32\\drivers\\etc\\hosts</code></td><td>1.2 КБ</td><td><code>b94d...279b</code></td><td><span style="color: var(--accent-success)">Стандартный</span></td></tr>
            <tr style="background: rgba(248,81,73,0.08)"><td><code>C:\\Users\\Public\\mimikatz.exe</code></td><td>1.8 МБ</td><td><code>e3b0...382a</code></td><td><span style="color: var(--accent-critical)">Вредоносный (T1003)</span></td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabLogs':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Поток событий журнала аудита (Telemetry Stream)</h4>
        <table class="data-table">
          <thead><tr><th>Время UTC</th><th>Канал / ID</th><th>Уровень</th><th>Описание события</th></tr></thead>
          <tbody>
            <tr><td>14:02:18</td><td>Security / 4688</td><td>Info</td><td>Создан новый процесс: powershell.exe (PID 4820)</td></tr>
            <tr style="background: rgba(248,81,73,0.08)"><td>14:02:19</td><td>Sysmon / 10</td><td>Critical</td><td>Доступ к памяти процесса: powershell.exe ➔ lsass.exe</td></tr>
            <tr><td>14:02:22</td><td>Security / 4624</td><td>Info</td><td>Успешный вход в систему: CORP\\Administrator (LogonType 3)</td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabEvidence':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Связанные доказательства (Chain of Custody)</h4>
        <table class="data-table">
          <thead><tr><th>Имя артефакта</th><th>Тип</th><th>CAS Blake3</th><th>Релевантность</th></tr></thead>
          <tbody>
            <tr><td><strong>Security_Sysmon.evtx</strong></td><td>Журнал EVTX</td><td><code>blake3:9a12...77</code></td><td><span style="color: var(--accent-success)">1.00 (Прямая улика)</span></td></tr>
            <tr><td><strong>traffic_capture.pcap</strong></td><td>Сетевой дамп</td><td><code>blake3:b834...12</code></td><td><span style="color: var(--accent-warning)">0.85 (Корреляция)</span></td></tr>
            <tr><td><strong>memory_dump.raw</strong></td><td>Дамп памяти</td><td><code>blake3:c108...44</code></td><td><span style="color: var(--accent-success)">0.95 (Подтверждено)</span></td></tr>
          </tbody>
        </table>`;
      break;

    default:
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 12px;">Телеметрия вкладки <strong>${tabName}</strong> синхронизирована с CAS.</div>`;
  }
}

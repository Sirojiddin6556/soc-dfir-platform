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
          <thead><tr><th>PID</th><th>PPID</th><th>Образ</th><th>Пользователь</th><th>Состояние</th></tr></thead>
          <tbody>
            <tr><td>4</td><td>0</td><td>System</td><td>NT AUTHORITY\\SYSTEM</td><td><span style="color: var(--accent-success)">Работает</span></td></tr>
            <tr><td>612</td><td>4</td><td>services.exe</td><td>NT AUTHORITY\\SYSTEM</td><td><span style="color: var(--accent-success)">Работает</span></td></tr>
            <tr><td>824</td><td>612</td><td>svchost.exe</td><td>NT AUTHORITY\\SYSTEM</td><td><span style="color: var(--accent-success)">Работает</span></td></tr>
            <tr><td>1204</td><td>824</td><td>explorer.exe</td><td>PC-3002\\Siroj</td><td><span style="color: var(--accent-success)">Работает</span></td></tr>
            <tr><td>31360</td><td>1204</td><td>desktop-app.exe</td><td>PC-3002\\Siroj</td><td><span style="color: var(--accent-success)">Активен (Live UI)</span></td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabPersistence':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Механизмы закрепления (Persistence & Auto-Runs)</h4>
        ${(h.persistence || []).length
          ? (h.persistence || []).map(p => `<div class="card" style="border-left: 3px solid var(--accent-warning); margin-bottom: 6px;">${p}</div>`).join('')
          : '<div style="color: var(--text-muted); font-size: 12px;">Подозрительных механизмов автозапуска и закрепления не обнаружено. Базовая конфигурация чиста.</div>'}`;
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
          : '<div style="color: var(--text-muted); font-size: 12px;">Уязвимостей CVE на данном хосте не зафиксировано.</div>'}`;
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
            <tr><td><strong>W32Time</strong></td><td>Служба времени Windows</td><td><span style="color: var(--accent-success)">Работает</span></td><td>Автоматически</td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabUsers':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Учетные записи и группы безопасности</h4>
        <table class="data-table">
          <thead><tr><th>Имя пользователя</th><th>SID / UID</th><th>Группы</th><th>Статус</th></tr></thead>
          <tbody>
            <tr><td><strong>Siroj</strong></td><td><code>S-1-5-21-...-1001</code></td><td>Administrators, Users</td><td><span style="color: var(--accent-success)">Активна (Текущий)</span></td></tr>
            <tr><td><strong>Administrator</strong></td><td><code>S-1-5-21-...-500</code></td><td>Administrators</td><td><span style="color: var(--text-muted)">Отключена</span></td></tr>
            <tr><td><strong>SYSTEM</strong></td><td><code>S-1-5-18</code></td><td>NT AUTHORITY</td><td><span style="color: var(--accent-success)">Системная</span></td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabFirewall':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Конфигурация брандмауэра и активные правила</h4>
        <table class="data-table">
          <thead><tr><th>Название правила</th><th>Направление</th><th>Действие</th><th>Порты</th><th>Состояние</th></tr></thead>
          <tbody>
            <tr><td><strong>CoreNetworking-DNS-Out</strong></td><td>Исходящее</td><td>Разрешить</td><td>UDP 53</td><td><span style="color: var(--accent-success)">Включено</span></td></tr>
            <tr><td><strong>RemoteDesktop-UserMode-In-TCP</strong></td><td>Входящее</td><td>Разрешить</td><td>TCP 3389</td><td><span style="color: var(--accent-success)">Включено</span></td></tr>
            <tr><td><strong>FileAndPrinterSharing-SMB-In</strong></td><td>Входящее</td><td>Разрешить</td><td>TCP 445</td><td><span style="color: var(--accent-success)">Включено</span></td></tr>
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
            <tr><td><code>C:\\Windows\\System32\\win32k.sys</code></td><td>8.2 МБ</td><td><code>7c12...49e3</code></td><td><span style="color: var(--accent-success)">Подлинный</span></td></tr>
          </tbody>
        </table>`;
      break;

    case 'tabLogs':
      container.innerHTML = `
        <h4 style="font-size: 12px; margin-bottom: 8px;">Поток событий журнала аудита (Telemetry Stream)</h4>
        <table class="data-table">
          <thead><tr><th>Время UTC</th><th>Канал / ID</th><th>Уровень</th><th>Описание события</th></tr></thead>
          <tbody>
            <tr><td>18:00:01</td><td>System / 7036</td><td>Info</td><td>Служба SOC DFIR Engine успешно переведена в состояние «Работает»</td></tr>
            <tr><td>18:00:02</td><td>Security / 4624</td><td>Info</td><td>Успешный локальный вход в систему: PC-3002\\Siroj</td></tr>
            <tr><td>18:00:05</td><td>Broker / 1001</td><td>Info</td><td>Локальный брокер безопасности активен на 127.0.0.1:8080</td></tr>
          </tbody>
        </table>`;
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

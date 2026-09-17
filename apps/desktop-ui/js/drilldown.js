// Deep Dive & Drill-Down Interaction Engine for Cyber Range & SOC/DFIR Platform
// Enables seamless navigation, inspection, and pivoting across Dashboard, Cases, Graph, Timeline, and Evidence

export function setupDrilldowns(app) {
  setupDashboardDrilldowns(app);
  setupCasesDrilldowns(app);
  setupTimelineDrilldowns(app);
  setupMitreDrilldowns(app);
  setupEvidenceDrilldowns(app);
  setupHeaderDrilldowns(app);
  setupHostListDrilldowns(app);
}

function setupDashboardDrilldowns(app) {
  // 1. Metric summary cards drill-down
  const metricCards = document.querySelectorAll('#dashboardView .card[style*="text-align: center"]');
  const metricTargets = [
    { view: 'infraDiscoveryView', title: 'Реестр хостов инфраструктуры' },
    { view: 'findingsOverviewView', title: 'Находки расследования' },
    { view: 'findingsOverviewView', title: 'Критичные инциденты и тревоги', filter: 'critical' },
    { view: 'evidenceView', title: 'Хранилище улик CAS' },
    { view: 'softwareCveView', title: 'Инвентарь уязвимостей CVE' },
    { view: 'mitreView', title: 'Матрица техник MITRE ATT&CK' }
  ];

  metricCards.forEach((card, idx) => {
    card.style.cursor = 'pointer';
    card.title = `Нажмите для перехода: ${metricTargets[idx]?.title || 'Раздел'}`;
    card.addEventListener('mouseenter', () => card.style.borderColor = 'var(--accent-info)');
    card.addEventListener('mouseleave', () => card.style.borderColor = 'var(--border-muted)');
    card.addEventListener('click', () => {
      const target = metricTargets[idx];
      if (target && target.view) {
        app.navigateToView(target.view);
      }
    });
  });

  // 2. Active Incident Banner Drill-down
  const banner = document.querySelector('#dashboardView div[style*="justify-content: space-between"]');
  if (banner) {
    banner.style.cursor = 'pointer';
    banner.title = 'Нажмите для перехода в досье кейса INC-2026-001';
    banner.addEventListener('click', () => {
      app.navigateToView('casesView');
      selectCase(app, 'INC-2026-001');
    });
  }

  // 3. Recent Findings Clickable List
  const findingsContainer = document.querySelectorAll('#dashboardView .card')[2];
  if (findingsContainer) {
    const findingItems = findingsContainer.querySelectorAll('div[style*="border-left"]');
    const findingData = [
      {
        name: 'PowerShell Execution (PID 4820)',
        type: 'Находка: Обфусцированное выполнение',
        assertion: 'T1059.001 (PowerShell)',
        verification: 'Sysmon 1 & EVTX 4688',
        hostId: 'h2',
        details: 'Хост: WS-FIN-04.CORP.LOCAL (192.168.1.105)\nКоманда: powershell.exe -NoP -enc SQBFAFgA...\nРодитель: WINWORD.EXE (PID 824)\nПользователь: CORP\\Administrator',
        actions: [
          { label: '🖥️ Телеметрия хоста WS-FIN-04', primary: true, onClick: () => app.selectAndOpenHost('h2') },
          { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') },
          { label: '⏱️ Показать на Таймлайне', onClick: () => app.navigateToView('timelineView') }
        ]
      },
      {
        name: 'Scheduled Task Persistence (SecurityAuditCollector)',
        type: 'Находка: Механизм закрепления',
        assertion: 'T1053.005 (Scheduled Task)',
        verification: 'Security Event 4698',
        hostId: 'h1',
        details: 'Хост: DC01.CORP.LOCAL (192.168.1.10)\nЗадача: SecurityAuditCollector (автозапуск каждые 60 мин)\nДействие: powershell.exe -w hidden -enc ...\nПрава: NT AUTHORITY\\SYSTEM',
        actions: [
          { label: '🖥️ Вкладка «Закрепление» DC01', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabPersistence') },
          { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
        ]
      },
      {
        name: 'C2 Outbound Beaconing ➔ 198.51.100.44:443',
        type: 'Находка: Управление и контроль (C2)',
        assertion: 'T1071.001 (Web Protocols)',
        verification: 'PCAP Flow Analysis',
        hostId: 'h2',
        details: 'Хост: WS-FIN-04 (192.168.1.105:49821)\nНазначение: 198.51.100.44:443 (TCP SYN/ACK)\nОбъем: 128.5 КБ (периодический маяк с джиттером 10%)\nАртефакт: traffic_capture.pcap',
        actions: [
          { label: '⏱️ Показать поток на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') },
          { label: '📦 Открыть дамп в CAS', onClick: () => app.navigateToView('evidenceView') }
        ]
      },
      {
        name: 'Credential Access (LSASS Memory Handle)',
        type: 'Находка: Сбор учетных данных',
        assertion: 'T1003.001 (LSASS Memory)',
        verification: 'Sysmon Event 10',
        hostId: 'h1',
        details: 'Хост: DC01.CORP.LOCAL (192.168.1.10)\nИсточник: powershell.exe (PID 4820)\nЦель: lsass.exe (PID 612)\nПрава доступа: 0x1010 (VM_READ | QUERY_LIMITED_INFORMATION)',
        actions: [
          { label: '🛡️ Сверить в Киберполигоне CTF', primary: true, onClick: () => app.navigateToView('cyberRangeView') },
          { label: '🖥️ Процессы хоста DC01', onClick: () => app.selectAndOpenHost('h1', 'tabProcesses') },
          { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
        ]
      }
    ];

    findingItems.forEach((item, idx) => {
      item.style.cursor = 'pointer';
      item.style.padding = '4px 6px';
      item.style.borderRadius = '3px';
      item.title = 'Нажмите для детальной инспекции находки';
      item.addEventListener('mouseenter', () => item.style.backgroundColor = 'var(--bg-canvas)');
      item.addEventListener('mouseleave', () => item.style.backgroundColor = 'transparent');
      item.addEventListener('click', () => {
        const f = findingData[idx];
        if (f) app.inspectEntity(f);
      });
    });
  }

  // 4. Kill Chain Progression Clickable Items
  const killChainContainer = document.querySelectorAll('#dashboardView .card')[3];
  if (killChainContainer) {
    const stageItems = killChainContainer.querySelectorAll('div[style*="font-size: 11px"] > div');
    const stageTargets = [
      { view: 'mitreView', label: 'Первичный доступ (Фишинг)' },
      { view: 'investigationGraphView', label: 'Выполнение (WINWORD ➔ PowerShell)' },
      { hostId: 'h1', tab: 'tabPersistence', label: 'Закрепление (Scheduled Task)' },
      { view: 'timelineView', label: 'Управление и контроль (C2 Beaconing)' },
      { view: 'evidenceView', label: 'Эксфильтрация данных' }
    ];

    stageItems.forEach((item, idx) => {
      item.style.cursor = 'pointer';
      item.style.padding = '3px 6px';
      item.style.borderRadius = '3px';
      item.title = 'Нажмите для перехода к этапу атаки';
      item.addEventListener('mouseenter', () => item.style.backgroundColor = 'var(--bg-canvas)');
      item.addEventListener('mouseleave', () => item.style.backgroundColor = 'transparent');
      item.addEventListener('click', () => {
        const t = stageTargets[idx];
        if (t.view) {
          app.navigateToView(t.view);
        } else if (t.hostId) {
          app.selectAndOpenHost(t.hostId, t.tab);
        }
      });
    });
  }
}

function setupCasesDrilldowns(app) {
  const caseRows = document.querySelectorAll('#casesView table tbody tr');
  caseRows.forEach((row, idx) => {
    row.style.cursor = 'pointer';
    row.title = 'Нажмите для открытия досье инцидента и инструментов анализа';
    row.addEventListener('click', () => {
      caseRows.forEach(r => r.style.backgroundColor = 'transparent');
      row.style.backgroundColor = 'rgba(88,166,255,0.1)';
      const caseId = idx === 0 ? 'INC-2026-001' : 'INC-2026-002';
      selectCase(app, caseId);
    });
  });
}

function selectCase(app, caseId) {
  const selector = document.getElementById('caseSelector');
  if (selector) selector.value = caseId;

  if (caseId === 'INC-2026-001') {
    app.inspectEntity({
      name: 'INC-2026-001: Компрометация Active Directory и кража креденшалов',
      type: 'Кейс расследования (Active)',
      assertion: 'Уровень риска: КРИТИЧЕСКИЙ (8.4 / 10.0)',
      verification: 'Статус: В РАБОТЕ (76% расследовано)',
      details: 'Ведущий аналитик: SOC Tier-2 (Siroj)\nОхваченные узлы (3): DC01 (192.168.1.10), WS-FIN-04 (192.168.1.105), DMZ-WEB01 (172.16.0.15)\nПервопричина: Фишинговый документ ➔ Выполнение PowerShell (PID 4820) ➔ Доступ к памяти LSASS (T1003.001)\nУлики в CAS: Security_Sysmon.evtx, traffic_capture.pcap\nMITRE ATT&CK: T1059.001, T1003.001, T1053.005, T1071.001',
      actions: [
        { label: '📊 Открыть Граф Атаки кейса', primary: true, onClick: () => app.navigateToView('investigationGraphView') },
        { label: '⏱️ Открыть Хронологический Таймлайн', onClick: () => app.navigateToView('timelineView') },
        { label: '📦 Улики и цепочка владения (CAS)', onClick: () => app.navigateToView('evidenceView') },
        { label: '🛡️ Сверка гипотез в Киберполигоне CTF', onClick: () => app.navigateToView('cyberRangeView') },
        { label: '📑 Реестр находок инцидента', onClick: () => app.navigateToView('findingsOverviewView') }
      ]
    });
  } else {
    app.inspectEntity({
      name: 'INC-2026-002: Подозрение на сканирование периметра DMZ',
      type: 'Кейс расследования (Closed)',
      assertion: 'Уровень риска: НИЗКИЙ (2.1 / 10.0)',
      verification: 'Статус: ЗАКРЫТ (Ложное срабатывание)',
      details: 'Ведущий аналитик: AutoTriage Broker\nОхваченные узлы: DMZ-WEB01 (172.16.0.15)\nЗаключение: Регламентное сканирование портов внутренним сканером уязвимостей. Угроза нейтрализована.',
      actions: [
        { label: '🖥️ Проверить узел DMZ-WEB01', primary: true, onClick: () => app.selectAndOpenHost('h3') }
      ]
    });
  }
}

function setupTimelineDrilldowns(app) {
  const lanesEl = document.getElementById('timelineLanes');
  if (!lanesEl) return;

  const eventCards = lanesEl.querySelectorAll('.card');
  if (eventCards.length >= 2) {
    eventCards[0].style.cursor = 'pointer';
    eventCards[0].title = 'Нажмите для детальной форензик-инспекции события';
    eventCards[0].addEventListener('click', () => {
      app.inspectEntity({
        name: 'Событие Sysmon 10: Подозрительный доступ к памяти LSASS',
        type: 'Событие безопасности Windows (Sysmon)',
        assertion: 'Достоверность: 0.98 (Факт)',
        verification: 'Подтверждено в EVTX',
        details: 'Время: 2026-09-17 14:02:18.104 UTC\nИсточник: powershell.exe (PID: 4820)\nЦелевой процесс: C:\\Windows\\System32\\lsass.exe (PID: 612)\nМаска доступа: 0x1010 (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION)\nCall Trace: C:\\Windows\\SYSTEM32\\ntdll.dll+0x9fc24 | KERNELBASE.dll+0x2c140\nХэш источника SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        actions: [
          { label: '🖥️ Открыть процессы хоста DC01', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabProcesses') },
          { label: '📊 Найти узел в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') },
          { label: '🛡️ Проверить гипотезу T1003.001', onClick: () => app.navigateToView('cyberRangeView') }
        ]
      });
    });

    eventCards[1].style.cursor = 'pointer';
    eventCards[1].title = 'Нажмите для детальной форензик-инспекции сетевого маяка';
    eventCards[1].addEventListener('click', () => {
      app.inspectEntity({
        name: 'Поток PCAP: Исходящий маяк на 198.51.100.44:443',
        type: 'Сетевой поток (PCAP Telemetry)',
        assertion: 'Достоверность: 0.92 (Подтверждено)',
        verification: 'PCAP Flow Analyzer',
        details: 'Время: 2026-09-17 14:01:55.002 UTC\nИсточник: 192.168.1.105:49821 (WS-FIN-04)\nНазначение: 198.51.100.44:443 (Внешний C2 сервер)\nПротокол: TCP / TLS v1.3 (SNI: api.cloud-telemetry-sync.com)\nРазмер полезной нагрузки: 128.5 КБ\nПериодичность: 45 сек (джиттер ±4.5 сек)',
        actions: [
          { label: '📦 Открыть дамп в хранилище улик', primary: true, onClick: () => app.navigateToView('evidenceView') },
          { label: '🖥️ Открыть сеть хоста WS-FIN-04', onClick: () => app.selectAndOpenHost('h2', 'tabNetwork') }
        ]
      });
    });
  }
}

function setupMitreDrilldowns(app) {
  const grid = document.getElementById('mitreGrid');
  if (!grid) return;

  grid.querySelectorAll('.card').forEach(card => {
    card.style.cursor = 'pointer';
    card.title = 'Нажмите для инспекции техники ATT&CK и улик';
    card.addEventListener('mouseenter', () => card.style.borderColor = 'var(--accent-info)');
    card.addEventListener('mouseleave', () => card.style.borderColor = 'var(--border-muted)');
    card.addEventListener('click', () => {
      const text = card.textContent;
      if (text.includes('T1003.001')) {
        app.inspectEntity({
          name: 'MITRE ATT&CK T1003.001: OS Credential Dumping (LSASS Memory)',
          type: 'Таксономия: Сбор учетных данных',
          assertion: 'Верифицировано по эталону',
          verification: 'Corroborated (2+ улики)',
          details: 'Тактика: TA0006 Credential Access\nЗатронутый хост: DC01.CORP.LOCAL (192.168.1.10)\nПодтверждающие улики: Sysmon Event 10 (AccessMask 0x1010), память LSASS\nРекомендация: Включить Windows Defender Credential Guard (LSA Protection).',
          actions: [
            { label: '🛡️ Сверить в Киберполигоне CTF', primary: true, onClick: () => app.navigateToView('cyberRangeView') },
            { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
          ]
        });
      } else if (text.includes('T1059.001')) {
        app.inspectEntity({
          name: 'MITRE ATT&CK T1059.001: PowerShell Execution',
          type: 'Таксономия: Выполнение',
          assertion: 'Зафиксировано',
          verification: 'Sysmon Event 1',
          details: 'Тактика: TA0002 Execution\nЗатронутый хост: WS-FIN-04.CORP.LOCAL (192.168.1.105)\nКомандная строка: powershell.exe -NoP -enc SQBFAFgA...\nОбфускация: Base64 кодированный скрипт.',
          actions: [
            { label: '🖥️ Открыть хост WS-FIN-04', primary: true, onClick: () => app.selectAndOpenHost('h2') },
            { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
          ]
        });
      } else {
        const title = card.querySelector('div')?.textContent || 'Техника ATT&CK';
        app.inspectEntity({
          name: title,
          type: 'Тактика ATT&CK Enterprise',
          assertion: 'Индикатор TTP',
          verification: 'Статус: Анализируется',
          details: `Категория матрицы MITRE: ${title}.\nВ текущей сессии прямых артефактов эксплуатации на активных хостах не выявлено.`,
          actions: [
            { label: '📊 Перейти к Графу Атак', primary: true, onClick: () => app.navigateToView('investigationGraphView') }
          ]
        });
      }
    });
  });
}

function setupEvidenceDrilldowns(app) {
  const rows = document.querySelectorAll('#evidenceTableBody tr');
  const evidenceDetails = [
    {
      name: 'Security_Sysmon.evtx',
      type: 'Форензик-артефакт: Журнал событий Windows',
      assertion: 'Хранилище CAS (Неизменяемый)',
      verification: 'Хэши верифицированы',
      details: 'Размер: 14.2 КБ\nCAS BLAKE3: 9a12b88f192a3456c7890123456789abcdef0123456789abcdef0123456777\nForensic SHA-256: d4e109823456789abcdef0123456789abcdef0123456789abcdef0123456709\nИсточник: DC01.CORP.LOCAL (C:\\Windows\\System32\\Winevt\\Logs)\nНормализовано событий: 23 записи\nВыявлено ключевых фактов: 3',
      actions: [
        { label: '⏱️ Показать события на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') },
        { label: '📊 Показать связанные узлы Графа', onClick: () => app.navigateToView('investigationGraphView') }
      ]
    },
    {
      name: 'traffic_capture.pcap',
      type: 'Форензик-артефакт: Сетевой трафик',
      assertion: 'Хранилище CAS (Неизменяемый)',
      verification: 'Хэши верифицированы',
      details: 'Размер: 128.5 КБ\nCAS BLAKE3: b834ac23456789abcdef0123456789abcdef0123456789abcdef0123456712\nForensic SHA-256: 88faac123456789abcdef0123456789abcdef0123456789abcdef01234567ac\nИнтерфейс захвата: Ethernet0 (Периметр DMZ)\nПроанализировано пакетов: 842 пакета\nВыявлено аномалий C2: 1 сессия (порт 443)',
      actions: [
        { label: '⏱️ Показать сетевой маяк на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') },
        { label: '🖥️ Открыть хост источника WS-FIN-04', onClick: () => app.selectAndOpenHost('h2') }
      ]
    }
  ];

  rows.forEach((row, idx) => {
    row.style.cursor = 'pointer';
    row.title = 'Нажмите для просмотра цепочки владения и свойств артефакта';
    row.addEventListener('mouseenter', () => row.style.backgroundColor = 'rgba(88,166,255,0.08)');
    row.addEventListener('mouseleave', () => row.style.backgroundColor = 'transparent');
    row.addEventListener('click', () => {
      const ev = evidenceDetails[idx];
      if (ev) app.inspectEntity(ev);
    });
  });
}

function setupHeaderDrilldowns(app) {
  const caseSelect = document.getElementById('caseSelector');
  if (caseSelect) {
    caseSelect.addEventListener('change', () => {
      selectCase(app, caseSelect.value);
    });
  }
}

function setupHostListDrilldowns(app) {
  // Enhances host items in Infra Discovery with one-click deep dive
  const hostListEl = document.getElementById('hostList');
  if (!hostListEl) return;

  hostListEl.querySelectorAll('.host-item').forEach(item => {
    item.addEventListener('dblclick', () => {
      const hostId = item.getAttribute('data-host-id');
      if (hostId) app.selectAndOpenHost(hostId);
    });
  });
}

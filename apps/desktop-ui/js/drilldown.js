// Deep Dive & Drill-Down Interaction Engine for Cyber Range & SOC/DFIR Platform
// Enables seamless navigation, inspection, and pivoting across Dashboard, Cases, Graph, Timeline, and Evidence

export function setupDrilldowns(app) {
  setupDashboardDrilldowns(app);
  setupCasesDrilldowns(app);
  setupTimelineDrilldowns(app);
  setupMitreDrilldowns(app);
  setupEvidenceDrilldowns(app);
  setupPyramidDrilldowns(app);
  setupHeaderDrilldowns(app);
  setupHostListDrilldowns(app);
}

function setupDashboardDrilldowns(app) {
  // 1. Metric summary cards drill-down
  const metricCards = document.querySelectorAll('#dashboardView .card[style*="text-align: center"]');
  const metricTargets = [
    { view: 'infraDiscoveryView', title: 'Реестр хостов инфраструктуры' },
    { view: 'casesView', title: 'Находки расследования', filter: 'all' },
    { view: 'casesView', title: 'Критичные инциденты и тревоги', filter: 'critical' },
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
        if (target.filter) {
          applyFindingsFilter(app, target.filter);
        }
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
    const findingKeys = ['f1', 'f3', 'f4', 'f2'];
    findingItems.forEach((item, idx) => {
      item.style.cursor = 'pointer';
      item.style.padding = '4px 6px';
      item.style.borderRadius = '3px';
      item.title = 'Нажмите для детальной инспекции находки';
      item.addEventListener('mouseenter', () => item.style.backgroundColor = 'var(--bg-canvas)');
      item.addEventListener('mouseleave', () => item.style.backgroundColor = 'transparent');
      item.addEventListener('click', () => {
        const f = getFindingItem(app, findingKeys[idx]);
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
  const caseRows = document.querySelectorAll('#casesView .case-row');
  caseRows.forEach((row, idx) => {
    row.addEventListener('click', () => {
      caseRows.forEach(r => r.style.backgroundColor = 'transparent');
      row.style.backgroundColor = 'rgba(88,166,255,0.1)';
      const caseId = row.getAttribute('data-case-id') || (idx === 0 ? 'INC-2026-001' : 'INC-2026-002');
      selectCase(app, caseId);
    });
  });

  const filterBtns = document.querySelectorAll('#findingsFilterBar .btn-filter-findings');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const filter = btn.getAttribute('data-filter');
      applyFindingsFilter(app, filter);
    });
  });

  const findingRows = document.querySelectorAll('#findingsTableBody .finding-row');
  findingRows.forEach(row => {
    row.addEventListener('click', () => {
      findingRows.forEach(r => r.style.backgroundColor = 'transparent');
      row.style.backgroundColor = 'rgba(88,166,255,0.1)';
      const fid = row.getAttribute('data-finding-id');
      const item = getFindingItem(app, fid);
      if (item) app.inspectEntity(item);
    });
  });
}

function getFindingItem(app, fid) {
  const findingsMap = {
    f1: {
      name: 'PowerShell Execution (PID 4820)', type: 'Находка: Обфусцированный запуск',
      assertion: 'T1059.001 (PowerShell)', verification: 'Sysmon 1 & EVTX 4688',
      details: 'Хост: WS-FIN-04.CORP.LOCAL (192.168.1.105)\nКоманда: powershell.exe -NoP -enc SQBFAFgA...\nРодительский процесс: WINWORD.EXE (PID 824)',
      actions: [
        { label: '🖥️ Телеметрия хоста WS-FIN-04', primary: true, onClick: () => app.selectAndOpenHost('h2') },
        { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') },
        { label: '⏱️ Показать на Таймлайне', onClick: () => app.navigateToView('timelineView') }
      ]
    },
    f2: {
      name: 'Credential Access (LSASS Memory)', type: 'Находка: Сбор учетных данных',
      assertion: 'T1003.001 (LSASS Memory)', verification: 'Sysmon Event 10',
      details: 'Хост: DC01.CORP.LOCAL (192.168.1.10)\nИсточник: powershell.exe (PID 4820)\nЦель: lsass.exe (PID 612)\nДескриптор: 0x1010 (VM_READ | QUERY_LIMITED_INFORMATION)',
      actions: [
        { label: '🛡️ Сверить в Киберполигоне CTF', primary: true, onClick: () => app.navigateToView('cyberRangeView') },
        { label: '🖥️ Процессы хоста DC01', onClick: () => app.selectAndOpenHost('h1', 'tabProcesses') },
        { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
      ]
    },
    f3: {
      name: 'Scheduled Task Persistence', type: 'Находка: Механизм закрепления',
      assertion: 'T1053.005 (Scheduled Task)', verification: 'Security Event 4698',
      details: 'Хост: DC01.CORP.LOCAL (192.168.1.10)\nЗадача: SecurityAuditCollector (автозапуск каждые 60 мин)',
      actions: [
        { label: '🖥️ Вкладка «Закрепление» DC01', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabPersistence') },
        { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
      ]
    },
    f4: {
      name: 'C2 Outbound Beaconing ➔ 198.51.100.44', type: 'Находка: Канал управления C2',
      assertion: 'T1071.001 (Web Protocols)', verification: 'PCAP Flow Analysis',
      details: 'Хост: WS-FIN-04 (192.168.1.105:49821)\nНазначение: 198.51.100.44:443 (TCP SYN/ACK)\nОбъем: 128.5 КБ',
      actions: [
        { label: '⏱️ Показать поток на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') },
        { label: '📦 Открыть дамп в CAS', onClick: () => app.navigateToView('evidenceView') }
      ]
    },
    f5: {
      name: 'Suspicious File Drop (updater_payload.exe)', type: 'Находка: Внедрение файла',
      assertion: 'T1105 (Tool Transfer)', verification: 'EDR Agent SHA-256',
      details: 'Хост: WS-FIN-04 (192.168.1.105)\nПуть: C:\\Users\\Administrator\\AppData\\Local\\Temp\\updater_payload.exe',
      actions: [{ label: '🖥️ Файлы хоста WS-FIN-04', primary: true, onClick: () => app.selectAndOpenHost('h2', 'tabFilesystem') }]
    },
    f6: {
      name: 'Registry RunKey Modification', type: 'Находка: Закрепление в реестре',
      assertion: 'T1547.001 (Registry Run)', verification: 'Sysmon Event 13',
      details: 'Хост: WS-FIN-04 (192.168.1.105)\nКлюч: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater.exe',
      actions: [{ label: '🖥️ Закрепление хоста WS-FIN-04', primary: true, onClick: () => app.selectAndOpenHost('h2', 'tabPersistence') }]
    },
    f7: {
      name: 'Kerberos AS-REP Roasting Attempt', type: 'Находка: Атака на Kerberos',
      assertion: 'T1558.004 (AS-REP Roasting)', verification: 'Security Event 4768',
      details: 'Хост: DC01.CORP.LOCAL (192.168.1.10)\nЗапрошен TGT для аккаунта без pre-authentication.',
      actions: [{ label: '🖥️ Учетные записи DC01', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabAccounts') }]
    },
    f8: {
      name: 'Периметральное сканирование портов', type: 'Находка: Разведка периметра',
      assertion: 'T1046 (Network Discovery)', verification: 'Firewall Drop Logs',
      details: 'Хост: DMZ-WEB01 (172.16.0.15)\nПодсеть: 172.16.0.0/20. Внешний IP: 203.0.113.19.',
      actions: [{ label: '🖥️ Сеть DMZ-WEB01', primary: true, onClick: () => app.selectAndOpenHost('h3', 'tabNetwork') }]
    }
  };
  return findingsMap[fid];
}

export function applyFindingsFilter(app, filter) {
  const buttons = document.querySelectorAll('#findingsFilterBar .btn-filter-findings');
  buttons.forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-filter') === filter);
  });

  const rows = document.querySelectorAll('#findingsTableBody .finding-row');
  rows.forEach(r => {
    const sev = r.getAttribute('data-severity');
    r.style.display = (filter === 'all' || sev === filter) ? '' : 'none';
  });

  if (filter === 'critical') {
    app.inspectEntity({
      name: 'Критичные находки (2 активных инцидента)',
      type: 'Сводка: КРИТИЧЕСКИЙ РИСК',
      assertion: 'Статус: Активное внедрение / Доступ к креденшалам',
      verification: 'Sysmon Event 1 & Sysmon Event 10',
      details: '1. WS-FIN-04 (192.168.1.105): Обфусцированный запуск PowerShell (PID 4820) из WINWORD.EXE.\n2. DC01.CORP.LOCAL (192.168.1.10): Доступ к памяти LSASS (T1003.001) с правами VM_READ.\n\nРекомендация: Изолировать WS-FIN-04, сбросить Kerberos TGT (krbtgt) на DC01.',
      actions: [
        { label: '🖥️ Телеметрия WS-FIN-04 (PID 4820)', primary: true, onClick: () => app.selectAndOpenHost('h2', 'tabProcesses') },
        { label: '🖥️ Телеметрия DC01 (LSASS)', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabProcesses') },
        { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') },
        { label: '🛡️ Сверить гипотезу T1003.001 в CTF', onClick: () => app.navigateToView('cyberRangeView') },
        { label: '⏱️ Показать события на Таймлайне', onClick: () => app.navigateToView('timelineView') }
      ]
    });
  } else if (filter === 'all') {
    app.inspectEntity({
      name: 'Сводный реестр находок расследования (8 шт.)',
      type: 'Реестр находок расследования',
      assertion: 'Охват: 3 хоста ЛВС и периметра',
      verification: 'Скоррелировано в CAS и Графе Атаки',
      details: 'Всего обнаружено: 8 событий безопасности.\n- Критичных: 2 (PowerShell execution, LSASS memory access)\n- Высоких: 2 (Scheduled task, C2 beaconing)\n- Прочих: 4 (File drop, Registry run, Kerberos, Portscan)\n\nКликните по любой строке таблицы для детальной инспекции.',
      actions: [
        { label: '🔥 Отфильтровать только КРИТИЧНЫЕ (2)', primary: true, onClick: () => applyFindingsFilter(app, 'critical') },
        { label: '📊 Показать все узлы в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') },
        { label: '⏱️ Открыть общий Форензик-таймлайн', onClick: () => app.navigateToView('timelineView') }
      ]
    });
  }
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
        { label: '📑 Реестр находок инцидента', onClick: () => { app.navigateToView('casesView'); applyFindingsFilter(app, 'all'); } }
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
    eventCards[0].addEventListener('click', () => {
      app.inspectEntity({
        name: 'Событие Sysmon 10: Подозрительный доступ к памяти LSASS',
        type: 'Событие безопасности Windows (Sysmon)',
        assertion: 'Достоверность: 0.98 (Факт)', verification: 'Подтверждено в EVTX',
        details: 'Время: 2026-09-17 14:02:18.104 UTC\nИсточник: powershell.exe (PID: 4820) ➔ C:\\Windows\\System32\\lsass.exe (PID: 612)\nМаска доступа: 0x1010 (VM_READ | QUERY_LIMITED_INFORMATION)',
        actions: [
          { label: '🖥️ Процессы хоста DC01', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabProcesses') },
          { label: '📊 Найти узел в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') },
          { label: '🛡️ Проверить гипотезу T1003.001', onClick: () => app.navigateToView('cyberRangeView') }
        ]
      });
    });

    eventCards[1].style.cursor = 'pointer';
    eventCards[1].addEventListener('click', () => {
      app.inspectEntity({
        name: 'Поток PCAP: Исходящий маяк на 198.51.100.44:443',
        type: 'Сетевой поток (PCAP Telemetry)',
        assertion: 'Достоверность: 0.92 (Подтверждено)', verification: 'PCAP Flow Analyzer',
        details: 'Время: 2026-09-17 14:01:55.002 UTC\n192.168.1.105:49821 (WS-FIN-04) ➔ 198.51.100.44:443 (C2)\nTLS v1.3 (SNI: api.cloud-telemetry-sync.com), 128.5 КБ, джиттер 10%',
        actions: [
          { label: '📦 Открыть дамп в хранилище улик', primary: true, onClick: () => app.navigateToView('evidenceView') },
          { label: '🖥️ Сеть хоста WS-FIN-04', onClick: () => app.selectAndOpenHost('h2', 'tabNetwork') }
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
    card.addEventListener('mouseenter', () => card.style.borderColor = 'var(--accent-info)');
    card.addEventListener('mouseleave', () => card.style.borderColor = 'var(--border-muted)');
    card.addEventListener('click', () => {
      const text = card.textContent;
      if (text.includes('T1003.001')) {
        app.inspectEntity({
          name: 'MITRE ATT&CK T1003.001: OS Credential Dumping (LSASS Memory)',
          type: 'Таксономия: Сбор учетных данных', assertion: 'Верифицировано по эталону',
          verification: 'Corroborated (2+ улики)',
          details: 'Тактика: TA0006 Credential Access | Затронут: DC01.CORP.LOCAL\nУлики: Sysmon Event 10 (AccessMask 0x1010), память LSASS',
          actions: [
            { label: '🛡️ Сверить в Киберполигоне CTF', primary: true, onClick: () => app.navigateToView('cyberRangeView') },
            { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
          ]
        });
      } else if (text.includes('T1059.001')) {
        app.inspectEntity({
          name: 'MITRE ATT&CK T1059.001: PowerShell Execution',
          type: 'Таксономия: Выполнение', assertion: 'Зафиксировано', verification: 'Sysmon Event 1',
          details: 'Тактика: TA0002 Execution | Затронут: WS-FIN-04.CORP.LOCAL\nКоманда: powershell.exe -NoP -enc SQBFAFgA...',
          actions: [
            { label: '🖥️ Открыть хост WS-FIN-04', primary: true, onClick: () => app.selectAndOpenHost('h2') },
            { label: '📊 Показать в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
          ]
        });
      } else {
        const title = card.querySelector('div')?.textContent || 'Техника ATT&CK';
        app.inspectEntity({
          name: title, type: 'Тактика ATT&CK Enterprise', assertion: 'Индикатор TTP',
          verification: 'Статус: Анализируется',
          details: `Категория матрицы MITRE: ${title}.\nПрямых артефактов эксплуатации на активных хостах не выявлено.`,
          actions: [{ label: '📊 Перейти к Графу Атак', primary: true, onClick: () => app.navigateToView('investigationGraphView') }]
        });
      }
    });
  });
}

function setupEvidenceDrilldowns(app) {
  const rows = document.querySelectorAll('#evidenceTableBody tr');
  const evidenceDetails = [
    {
      name: 'Security_Sysmon.evtx', type: 'Форензик-артефакт: Журнал Windows',
      assertion: 'Хранилище CAS', verification: 'Хэши верифицированы',
      details: 'Размер: 14.2 КБ | BLAKE3: 9a12...77 | SHA-256: d4e1...09\nИсточник: DC01.CORP.LOCAL (Winevt\\Logs)',
      actions: [
        { label: '⏱️ Показать события на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') },
        { label: '📊 Связанные узлы Графа', onClick: () => app.navigateToView('investigationGraphView') }
      ]
    },
    {
      name: 'traffic_capture.pcap', type: 'Форензик-артефакт: Сетевой трафик',
      assertion: 'Хранилище CAS', verification: 'Хэши верифицированы',
      details: 'Размер: 128.5 КБ | BLAKE3: b834...12 | SHA-256: 88fa...ac\nПериметр DMZ: 842 пакета, 1 C2 сессия',
      actions: [
        { label: '⏱️ Показать сетевой маяк на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') },
        { label: '🖥️ Открыть хост WS-FIN-04', onClick: () => app.selectAndOpenHost('h2') }
      ]
    }
  ];

  rows.forEach((row, idx) => {
    row.style.cursor = 'pointer';
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
  const hostListEl = document.getElementById('hostList');
  if (!hostListEl) return;
  hostListEl.querySelectorAll('.host-item').forEach(item => {
    item.addEventListener('dblclick', () => {
      const hostId = item.getAttribute('data-host-id');
      if (hostId) app.selectAndOpenHost(hostId);
    });
  });
}

function setupPyramidDrilldowns(app) {
  const tiers = {
    TTPs: {
      name: 'Пирамида боли: TTPs (3 техники)', type: 'Индикатор TTP (Критично)',
      assertion: 'Влияние: Максимальное (Tough)', verification: 'Матрица ATT&CK',
      details: '1. T1059.001 (PowerShell) — PID 4820 на WS-FIN-04.\n2. T1003.001 (LSASS) — Чтение памяти на DC01.\n3. T1053.005 (Scheduled Task) — SecurityAuditCollector на DC01.',
      actions: [
        { label: '🎯 Матрица MITRE ATT&CK', primary: true, onClick: () => app.navigateToView('mitreView') },
        { label: '📊 Открыть Граф Атаки', onClick: () => app.navigateToView('investigationGraphView') },
        { label: '🛡️ Сверить в Киберполигоне CTF', onClick: () => app.navigateToView('cyberRangeView') }
      ]
    },
    Tools: {
      name: 'Пирамида боли: Tools (2 инструмента)', type: 'Вредоносный софт (Высокий)',
      assertion: 'Влияние: Значительное (Challenging)', verification: 'Эвристика EDR & Sysmon',
      details: '1. Mimikatz / sekurlsa — чтение паролей из памяти LSASS на DC01.\n2. Obfuscated PowerShell Loader — стейджер C2 на WS-FIN-04.',
      actions: [
        { label: '🖥️ Процессы DC01 (LSASS)', primary: true, onClick: () => app.selectAndOpenHost('h1', 'tabProcesses') },
        { label: '🖥️ Процессы WS-FIN-04', onClick: () => app.selectAndOpenHost('h2', 'tabProcesses') }
      ]
    },
    Artifacts: {
      name: 'Пирамида боли: Артефакты (9 шт.)', type: 'Артефакты расследования',
      assertion: 'Влияние: Ощутимое (Annoying)', verification: 'CAS & журналы ОС',
      details: '• EVTX: Security_Sysmon.evtx (ID 1, 10, 13)\n• Security Events: 4688, 4698, 4768\n• PCAP: traffic_capture.pcap (TCP 443)\n• Файл: C:\\Temp\\updater_payload.exe\n• Реестр: HKLM\\...\\Run\\Updater.exe',
      actions: [
        { label: '📦 Проверить улики в CAS', primary: true, onClick: () => app.navigateToView('evidenceView') },
        { label: '⏱️ События на Таймлайне', onClick: () => app.navigateToView('timelineView') }
      ]
    },
    Domains: {
      name: 'Пирамида боли: Домены C2 (4 шт.)', type: 'Сетевые домены C2',
      assertion: 'Влияние: Простое (Simple)', verification: 'DNS-кэш и сетевой перехват',
      details: '1. update.external-service-cdn.org — C2 дроппер\n2. sync.cloud-telemetry-endpoint.net — C2 маяк\n3. CORP.LOCAL — домен Active Directory\n4. defense-telemetry-check.local',
      actions: [{ label: '⏱️ Сетевые маяки на Таймлайне', primary: true, onClick: () => app.navigateToView('timelineView') }]
    },
    IPs: {
      name: 'Пирамида боли: IP-адреса (7 шт.)', type: 'Сетевые адреса',
      assertion: 'Влияние: Легкое (Easy)', verification: 'Сетевые адаптеры и сокеты',
      details: '• 192.168.1.10 (DC01)\n• 192.168.1.105 (WS-FIN-04)\n• 172.16.0.15 (DMZ-WEB01)\n• 198.51.100.44 (C2 сервер, 443)\n• 203.0.113.19 (Скан периметра)\n• 10.0.10.1 (БД), 127.0.0.1 (Loopback)',
      actions: [
        { label: '🖥️ Топология инфраструктуры', primary: true, onClick: () => app.navigateToView('infraDiscoveryView') },
        { label: '📊 Размещение в Графе Атаки', onClick: () => app.navigateToView('investigationGraphView') }
      ]
    },
    Hashes: {
      name: 'Пирамида боли: Хэши файлов (12 шт.)', type: 'Криптографические хэши',
      assertion: 'Влияние: Тривиальное (Trivial)', verification: 'Хранилище CAS',
      details: '• Security_Sysmon.evtx: blake3:9a12...77 | sha256:d4e1...09\n• traffic_capture.pcap: blake3:b834...12 | sha256:88fa...ac\n• updater_payload.exe: blake3:3f7a...bc | sha256:5e89...11\n• phishing.docx: blake3:1c2d...44 | sha256:7a9b...33',
      actions: [
        { label: '📦 Открыть Хранилище улик CAS', primary: true, onClick: () => app.navigateToView('evidenceView') },
        { label: '📑 Реестр находок расследования', onClick: () => app.navigateToView('casesView') }
      ]
    }
  };

  const tiersEls = document.querySelectorAll('.pyramid-tier');
  const boxTitle = document.getElementById('pyramidBoxTitle');
  const boxContent = document.getElementById('pyramidBoxContent');

  tiersEls.forEach(tierEl => {
    tierEl.addEventListener('click', () => {
      tiersEls.forEach(t => { t.style.outline = 'none'; });
      tierEl.style.outline = '2px solid var(--accent-info)';
      const tierKey = tierEl.getAttribute('data-tier');
      const data = tiers[tierKey];
      if (!data) return;

      if (boxTitle && boxContent) {
        boxTitle.textContent = data.name;
        boxContent.textContent = `${data.assertion} (${data.verification})\n\n${data.details}`;
      }

      app.inspectEntity({
        name: data.name,
        type: data.type,
        assertion: data.assertion,
        verification: data.verification,
        details: data.details,
        actions: data.actions
      });
    });
  });
}

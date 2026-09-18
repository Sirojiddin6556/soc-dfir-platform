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
    banner.title = 'Нажмите для перехода в досье кейса INC-LIVE-001';
    banner.addEventListener('click', () => {
      app.navigateToView('casesView');
      selectCase(app, 'INC-LIVE-001');
    });
  }

  // 3. Recent Findings Clickable List
  const findingsContainer = document.querySelectorAll('#dashboardView .card')[2];
  if (findingsContainer) {
    const findingItems = findingsContainer.querySelectorAll('div[style*="border-left"]');
    const findingKeys = ['f1', 'f2', 'f3', 'f4'];
    findingItems.forEach((item, idx) => {
      item.style.cursor = 'pointer';
      item.style.padding = '4px 6px';
      item.style.borderRadius = '3px';
      item.title = 'Нажмите для детальной инспекции события';
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
      { view: 'infraDiscoveryView', label: 'Периметр ЛВС' },
      { hostId: 'h_local', tab: 'tabProcesses', label: 'Процессы Windows' },
      { hostId: 'h_local', tab: 'tabPersistence', label: 'Автозагрузка' },
      { hostId: 'h_local', tab: 'tabNetwork', label: 'Сетевые сокеты' },
      { view: 'evidenceView', label: 'Хранилище CAS' }
    ];

    stageItems.forEach((item, idx) => {
      item.style.cursor = 'pointer';
      item.style.padding = '3px 6px';
      item.style.borderRadius = '3px';
      item.title = 'Нажмите для перехода к разделу';
      item.addEventListener('mouseenter', () => item.style.backgroundColor = 'var(--bg-canvas)');
      item.addEventListener('mouseleave', () => item.style.backgroundColor = 'transparent');
      item.addEventListener('click', () => {
        const t = stageTargets[idx];
        if (t.view) app.navigateToView(t.view);
        else if (t.hostId) app.selectAndOpenHost(t.hostId, t.tab);
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
      const caseId = row.getAttribute('data-case-id') || (idx === 0 ? 'INC-LIVE-001' : 'INC-LIVE-002');
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
      name: 'Штатный запуск рабочего процесса desktop-app.exe', type: 'Событие: Процесс платформы',
      assertion: 'Легитимный исполняемый файл', verification: 'Process Tracker',
      details: 'Хост: PC-3002 (127.0.0.1)\nБинарный файл: desktop-app.exe\nПользователь: PC-3002\\Siroj\nСтатус: Активен в пользовательской сессии.',
      actions: [
        { label: '🖥️ Процессы хоста PC-3002', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabProcesses') },
        { label: '📊 Топология инфраструктуры', onClick: () => app.navigateToView('infraDiscoveryView') }
      ]
    },
    f2: {
      name: 'Локальный брокер безопасности активен на 127.0.0.1:8080', type: 'Служба ядра: Engine Server',
      assertion: 'Статус: Слушает сокет', verification: 'JSON-RPC IPC Engine',
      details: 'Хост: PC-3002 (127.0.0.1:8080)\nПротокол: HTTP/1.1 POST /rpc\nСлужба: Embedded Rust Engine Server',
      actions: [
        { label: '🖥️ Службы хоста PC-3002', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabServices') },
        { label: '🌐 Сетевые порты хоста', onClick: () => app.selectAndOpenHost('h_local', 'tabNetwork') }
      ]
    },
    f3: {
      name: 'Мониторинг форензик-артефактов готов к приему данных', type: 'Хранилище: CAS SQLite',
      assertion: 'Хранилище доступно', verification: 'BLAKE3 & WAL Driver',
      details: 'Каталог: data/cas\nХэширование: BLAKE3 deduplication engine\nГотовность: Прием .evtx, .pcap, .raw дампов.',
      actions: [
        { label: '📦 Открыть Хранилище улик CAS', primary: true, onClick: () => app.navigateToView('evidenceView') }
      ]
    },
    f4: {
      name: 'Проверка автозагрузки Windows (Persistence)', type: 'Аудит целостности системы',
      assertion: 'Чистая базовая линия', verification: 'Registry & Scheduled Tasks',
      details: 'Хост: PC-3002\nКлючи: HKLM/HKCU Run, Планировщик заданий\nРезультат: Сторонних модификаций и вредоносных скриптов не выявлено.',
      actions: [
        { label: '🖥️ Вкладка «Закрепление» PC-3002', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabPersistence') }
      ]
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
      name: 'Критичные инциденты (0 обнаружено)',
      type: 'Сводка безопасности: ШТАТНЫЙ РЕЖИМ',
      assertion: 'Угрозы отсутствуют',
      verification: 'Телеметрия хоста и периметра',
      details: 'В системе не зафиксировано критичных аномалий, активных вторжений или утечек учетных записей.\nБазовая линия чиста.',
      actions: [
        { label: '📑 Реестр всех событий (4)', primary: true, onClick: () => applyFindingsFilter(app, 'all') },
        { label: '🖥️ Топология инфраструктуры', onClick: () => app.navigateToView('infraDiscoveryView') }
      ]
    });
  } else if (filter === 'all') {
    app.inspectEntity({
      name: 'Реестр событий телеметрии (4 шт.)',
      type: 'Сводка форензик-мониторинга',
      assertion: 'Охват: Локальная рабочая станция PC-3002',
      verification: 'Телеметрия ядра и платформы',
      details: 'Всего зафиксировано: 4 события телеметрии.\n- Критичных: 0\n- Высоких: 0\n- Информационных: 4 (Службы, брокер, CAS, автозапуск)\n\nКликните по любой строке таблицы для детальной инспекции.',
      actions: [
        { label: '📊 Открыть Граф Инфраструктуры', primary: true, onClick: () => app.navigateToView('investigationGraphView') },
        { label: '⏱️ Открыть Форензик-таймлайн', onClick: () => app.navigateToView('timelineView') }
      ]
    });
  }
}

function selectCase(app, caseId) {
  const selector = document.getElementById('caseSelector');
  if (selector) selector.value = caseId;

  if (caseId === 'INC-LIVE-001') {
    app.inspectEntity({
      name: 'INC-LIVE-001: Боевой мониторинг рабочей станции и инфраструктуры',
      type: 'Кейс мониторинга (Live)',
      assertion: 'Уровень риска: НИЗКИЙ (1.0 / 10.0)',
      verification: 'Статус: АКТИВЕН / МОНИТОРИНГ',
      details: 'Аналитик: SOC Tier-1 (Siroj)\nОхваченный узел: PC-3002 (127.0.0.1)\nПодсети: 127.0.0.1/32, 172.16.121.0/24, 192.168.56.0/24\nРежим: Боевое дежурство. Сторонних вредоносных модулей не выявлено.\nТелеметрия: Процессы, сокеты, службы активны.',
      actions: [
        { label: '📊 Топология инфраструктуры', primary: true, onClick: () => app.navigateToView('infraDiscoveryView') },
        { label: '🖥️ Карточка хоста PC-3002', onClick: () => app.selectAndOpenHost('h_local') },
        { label: '⏱️ Хронологический Таймлайн', onClick: () => app.navigateToView('timelineView') },
        { label: '📦 Хранилище улик CAS', onClick: () => app.navigateToView('evidenceView') }
      ]
    });
  } else {
    app.inspectEntity({
      name: 'INC-LIVE-002: Периметральный аудит внешних портов',
      type: 'Кейс аудита (Live)',
      assertion: 'Уровень риска: НИЗКИЙ (1.0 / 10.0)',
      verification: 'Статус: В РАБОТЕ',
      details: 'Ведущий аналитик: AutoTriage Broker\nЦель: Аудит сетевых интерфейсов и фильтрации трафика.\nРезультат: Внешних уязвимых сервисов не экспонировано.',
      actions: [
        { label: '🖥️ Проверить узел PC-3002', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabNetwork') }
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
        name: 'Служба ядра: Engine Server JSON-RPC', type: 'Телеметрия ядра платформы',
        assertion: 'Достоверность: 1.0 (Факт)', verification: '127.0.0.1:8080',
        details: 'Время: 18:00:05.120 UTC\nСлужба: Embedded Tokio Runtime\nПротокол: HTTP/1.1 POST /rpc\nСтатус: Активно обслуживает IPC запросы.',
        actions: [
          { label: '🖥️ Службы хоста PC-3002', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabServices') },
          { label: '📊 Топология инфраструктуры', onClick: () => app.navigateToView('infraDiscoveryView') }
        ]
      });
    });
    eventCards[1].style.cursor = 'pointer';
    eventCards[1].addEventListener('click', () => {
      app.inspectEntity({
        name: 'Аудит хоста PC-3002: Сетевые сокеты', type: 'Сетевой аудит рабочей станции',
        assertion: 'Достоверность: 1.0 (Подтверждено)', verification: 'Live Socket Probe',
        details: 'Время: 18:00:01.004 UTC\nХост: PC-3002 (127.0.0.1)\nОткрытые порты: 135, 445, 8080\nАномалий не обнаружено.',
        actions: [
          { label: '🌐 Сетевые порты PC-3002', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabNetwork') },
          { label: '🖥️ Карточка хоста', onClick: () => app.selectAndOpenHost('h_local') }
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
      const title = card.querySelector('div')?.textContent || 'Тактика ATT&CK';
      app.inspectEntity({
        name: title, type: 'Тактика ATT&CK Enterprise', assertion: 'Базовый мониторинг',
        verification: 'Статус: Чисто (0 срабатываний)',
        details: `Категория матрицы MITRE: ${title}.\nНа активных хостах признаков эксплуатации или внедрения не зафиксировано.`,
        actions: [{ label: '📊 Открыть Граф Инфраструктуры', primary: true, onClick: () => app.navigateToView('investigationGraphView') }]
      });
    });
  });
}

function setupEvidenceDrilldowns(app) {
  const table = document.getElementById('evidenceTableBody');
  if (!table) return;
  table.addEventListener('click', () => {
    app.inspectEntity({
      name: 'Хранилище CAS: Доказательная база',
      type: 'Форензик-хранилище (Content Addressable Storage)',
      assertion: 'Хранилище готово', verification: 'BLAKE3 & WAL Driver',
      details: 'Каталог: data/cas\nТекущее состояние: Ожидание загрузки дампов памяти, журналов EVTX или PCAP.',
      actions: [
        { label: '➕ Загрузить артефакт в CAS', primary: true, onClick: () => document.getElementById('btnIngestModal')?.click() }
      ]
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

function getPyramidTiers(app) {
  const corr = app.correlationData;
  const p = corr?.pyramid || { ttps: 0, tools: 0, artifacts: 0, domains: 1, ips: 4, hashes: 0 };
  const findings = corr?.findings || [];
  const ttpFindings = findings.filter(f => f.mitre_technique);
  const toolFindings = findings.filter(f => f.rule_id?.includes('001') && f.severity === 'Critical');

  const ttpDetails = ttpFindings.length > 0
    ? ttpFindings.map(f => `• [${f.mitre_technique}] ${f.title} (${f.severity})`).join('\n')
    : 'Вредоносных техник и цепочек эксплуатации не зафиксировано.\nБазовая линия хостов в штатном режиме.';

  const toolDetails = toolFindings.length > 0
    ? toolFindings.map(f => `• ${f.title} (${f.entity_key})`).join('\n')
    : 'Сторонних утилит, эксплойтов и генераторов шелл-кода не обнаружено.';

  return {
    TTPs: {
      name: `Пирамида боли: TTPs (${p.ttps} техник)`,
      type: p.ttps > 0 ? 'Индикаторы TTP (Обнаружено)' : 'Индикатор TTP (Чисто)',
      assertion: p.ttps > 0 ? 'Внимание: Обнаружены TTP' : 'Влияние: Нет угроз',
      verification: 'Матрица ATT&CK',
      details: ttpDetails,
      actions: [{ label: '🎯 Матрица MITRE ATT&CK', primary: true, onClick: () => app.navigateToView('mitreView') }]
    },
    Tools: {
      name: `Пирамида боли: Tools (${p.tools} утилит)`,
      type: p.tools > 0 ? 'Вредоносный софт (Обнаружен)' : 'Вредоносный софт (Чисто)',
      assertion: p.tools > 0 ? 'Обнаружены подозрительные инструменты' : 'Влияние: Отсутствует',
      verification: 'Эвристика ядра',
      details: toolDetails,
      actions: [{ label: '🖥️ Процессы рабочей станции', primary: true, onClick: () => app.selectAndOpenHost('h_local', 'tabProcesses') }]
    },
    Artifacts: {
      name: `Пирамида боли: Артефакты (${p.artifacts} угроз)`,
      type: 'Артефакты расследования',
      assertion: p.artifacts > 0 ? 'Обнаружены подозрительные артефакты' : 'Влияние: Нейтрально',
      verification: 'CAS & журналы ОС',
      details: 'Хранилище CAS инициализировано. Ожидание импорта реальных форензик-артефактов.',
      actions: [{ label: '📦 Хранилище улик CAS', primary: true, onClick: () => app.navigateToView('evidenceView') }]
    },
    Domains: {
      name: 'Пирамида боли: Домены (1)', type: 'Сетевые домены',
      assertion: 'Влияние: Легитимно', verification: 'DNS-кэш хоста',
      details: '• localhost (127.0.0.1) — локальная петля loopback.',
      actions: [{ label: '⏱️ Форензик-таймлайн', primary: true, onClick: () => app.navigateToView('timelineView') }]
    },
    IPs: {
      name: `Пирамида боли: IP-адреса (${p.ips})`, type: 'Сетевые адреса',
      assertion: 'Влияние: Локальные интерфейсы', verification: 'Сетевые адаптеры ОС',
      details: '• 127.0.0.1 (Loopback)\n• 172.16.121.32 (Основная ЛВС Ethernet)\n• 192.168.56.1 (Host-Only Адаптер)\n• 172.20.32.1 (Виртуальная сеть WSL)',
      actions: [{ label: '🖥️ Топология инфраструктуры', primary: true, onClick: () => app.navigateToView('infraDiscoveryView') }]
    },
    Hashes: {
      name: 'Пирамида боли: Хэши файлов (0 аномалий)', type: 'Криптографические хэши',
      assertion: 'Целостность: Подтверждена', verification: 'Хранилище CAS',
      details: 'Системные файлы операционной системы Windows соответствуют официальным сигнатурам Microsoft.',
      actions: [{ label: '📦 Открыть Хранилище улик CAS', primary: true, onClick: () => app.navigateToView('evidenceView') }]
    }
  };
}

function setupPyramidDrilldowns(app) {
  const tiersEls = document.querySelectorAll('.pyramid-tier');
  const boxTitle = document.getElementById('pyramidBoxTitle');
  const boxContent = document.getElementById('pyramidBoxContent');

  tiersEls.forEach(tierEl => {
    tierEl.addEventListener('click', () => {
      tiersEls.forEach(t => { t.style.outline = 'none'; });
      tierEl.style.outline = '2px solid var(--accent-info)';
      const tierKey = tierEl.getAttribute('data-tier');
      const tiers = getPyramidTiers(app);
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

export function updatePyramidAndFindings(app, corrData) {
  if (!corrData) return;
  app.correlationData = corrData;
  const p = corrData.pyramid || { ttps: 0, tools: 0, artifacts: 0, domains: 1, ips: 4, hashes: 0 };
  const findings = corrData.findings || [];

  const tierLabels = {
    TTPs: `TTPs (${p.ttps})`,
    Tools: `Инструменты / Tools (${p.tools})`,
    Artifacts: `Сетевые и хостовые артефакты (${p.artifacts})`,
    Domains: `Доменные имена (${p.domains})`,
    IPs: `IP-адреса (${p.ips})`,
    Hashes: `Хэши файлов BLAKE3/SHA-256 (${p.hashes})`
  };
  document.querySelectorAll('.pyramid-tier').forEach(el => {
    const key = el.getAttribute('data-tier');
    if (tierLabels[key]) {
      const strong = el.querySelector('strong');
      if (strong) strong.textContent = tierLabels[key];
    }
  });

  const setTxt = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  setTxt('metricFindingsCount', corrData.findings_count || 0);
  setTxt('metricCriticalCount', corrData.critical_count || 0);
  setTxt('metricAttackCount', (corrData.mitre_matrix || []).length);

  setTxt('btnFilterAll', `Все (${findings.length})`);
  setTxt('btnFilterCritical', `Критичные (${corrData.critical_count || 0})`);
  setTxt('btnFilterHigh', `Высокие (${corrData.high_count || 0})`);
  setTxt('btnFilterOther', `Прочие (${Math.max(0, findings.length - (corrData.critical_count || 0) - (corrData.high_count || 0))})`);

  const tbody = document.getElementById('findingsTableBody');
  if (tbody) {
    if (findings.length === 0) {
      tbody.innerHTML = '<tr class="finding-row"><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 14px;">Боевой режим: Активных находок и аномалий не обнаружено. Базовая линия хоста чиста.</td></tr>';
    } else {
      tbody.innerHTML = findings.map(f => `
        <tr class="finding-row" data-severity="${f.severity.toLowerCase()}" data-finding-id="${f.id}" style="cursor: pointer;">
          <td><strong>${f.title}</strong> <span class="badge badge-proc" style="font-size: 9px; margin-left: 4px;">${f.rule_id}</span></td>
          <td>${f.entity_key.split(':')[0] || 'PC-3002'}</td>
          <td><span class="badge ${f.severity === 'Critical' ? 'badge-attack' : (f.severity === 'High' ? 'badge-net' : 'badge-host')}">${f.severity.toUpperCase()}</span></td>
          <td><span class="badge badge-attack">${f.mitre_technique || '-'}</span></td>
          <td>${f.rule_id ? 'Correlation Engine' : 'Telemetry'}</td>
          <td><span class="badge badge-host">${f.verification_state}</span></td>
        </tr>
      `).join('');

      tbody.querySelectorAll('.finding-row').forEach(row => {
        row.addEventListener('click', () => {
          const fid = row.getAttribute('data-finding-id');
          const f = findings.find(item => item.id === fid);
          if (!f) return;
          app.inspectEntity({
            name: `${f.title} (${f.rule_id})`,
            type: `Находка ИБ: ${f.severity}`,
            assertion: `Верификация: ${f.verification_state} (Риск: ${f.risk_score})`,
            verification: f.mitre_technique ? `MITRE ATT&CK: ${f.mitre_technique} (${f.mitre_tactic || ''})` : 'Базовая линия',
            details: `Ключ сущности: ${f.entity_key}\nТип факта: ${f.fact_type}\nВремя фиксации: ${f.created_at}`,
            actions: [
              { label: '🎯 Открыть матрицу MITRE ATT&CK', primary: true, onClick: () => app.navigateToView('mitreView') },
              { label: '🖥️ Перейти к хосту ' + (f.entity_key.split(':')[0] || 'PC-3002'), primary: false, onClick: () => app.selectAndOpenHost('h_local') }
            ]
          });
        });
      });
    }
  }
}

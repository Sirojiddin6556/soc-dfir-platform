function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const SCENARIOS = [
  {
    id: 'scen-apt29',
    title: 'APT29: Cozy Bear Lateral Movement & Kerberoasting',
    category: 'APT / Enterprise Defense',
    difficulty: 'HARD',
    badgeColor: 'var(--accent-critical)',
    mitre: ['T1059.001 (PowerShell)', 'T1558.003 (Kerberoasting)', 'T1021.002 (SMB/Admin Shares)'],
    description: 'Атакующий получил начальный доступ к рабочей станции финотдела и проводит разведку Active Directory для извлечения билетов сервисных учетных записей.',
    objectives: [
      { id: 'obj-1', title: 'Обнаружить выполнение обфусцированного PowerShell скрипта', done: false },
      { id: 'obj-2', title: 'Изолировать компрометированный SPN и извлеченный TGS билет', done: false },
      { id: 'obj-3', title: 'Восстановить таймлайн латерального движения на контроллер домена', done: false }
    ],
    telemetryCount: 142,
    recommendedTools: ['Splunk / Elastic SIEM', 'Kape / Velociraptor', 'Mimikatz Parser']
  },
  {
    id: 'scen-ransomware',
    title: 'BlackCat / ALPHV Ransomware Infiltration',
    category: 'Cybercrime / Extortion',
    difficulty: 'MEDIUM',
    badgeColor: 'var(--accent-warning)',
    mitre: ['T1566.001 (Spearphishing Attachment)', 'T1486 (Data Encrypted for Impact)', 'T1490 (Inhibit System Recovery)'],
    description: 'Массированная атака шифровальщика на инфраструктуру гипервизоров и файловых хранилищ. Анализ VSS теневых копий и векторов доставки.',
    objectives: [
      { id: 'obj-1', title: 'Найти первичный почтовый вектор (ISO/LNK контейнер)', done: true },
      { id: 'obj-2', title: 'Выявить команду удаления теневых копий vssadmin/wmic', done: false },
      { id: 'obj-3', title: 'Определить C2 IP-адрес эксфильтрации данных до шифрования', done: false }
    ],
    telemetryCount: 89,
    recommendedTools: ['Volatility 3', 'Suricata / Zeek', 'YARA Scanner']
  },
  {
    id: 'scen-supplychain',
    title: 'NPM Supply Chain Dependency Poisoning',
    category: 'DevSecOps / AppSec',
    difficulty: 'EASY',
    badgeColor: 'var(--accent-success)',
    mitre: ['T1195.001 (Compromise Software Dependencies)', 'T1071.001 (Web Protocols C2)'],
    description: 'Внутренний CI/CD пайплайн подтянул скомпрометированный пакет с обфусцированным preinstall-скриптом, отправляющим переменные окружения на внешний сервер.',
    objectives: [
      { id: 'obj-1', title: 'Деобфусцировать payload в package.json preinstall', done: false },
      { id: 'obj-2', title: 'Определить утекшие секреты и токены доступа AWS/GitLab', done: false }
    ],
    telemetryCount: 34,
    recommendedTools: ['CyberChef', 'AST / Semgrep', 'Wireshark']
  }
];

export class RangeSpace {
  constructor(ipc, onLaunchMission, onOpenCtf) {
    this.ipc = ipc;
    this.onLaunchMission = onLaunchMission;
    this.onOpenCtf = onOpenCtf;
    this.selectedScenarioId = SCENARIOS[0].id;
    this.scenarios = JSON.parse(JSON.stringify(SCENARIOS));
  }

  render(container) {
    this.container = container;
    this._renderUI();
  }

  _renderUI() {
    const active = this.scenarios.find(s => s.id === this.selectedScenarioId) || this.scenarios[0];
    const completedCount = active.objectives.filter(o => o.done).length;
    const progressPct = Math.round((completedCount / active.objectives.length) * 100);

    this.container.innerHTML = `
      <div style="padding:24px;overflow-y:auto;height:100%;box-sizing:border-box;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;flex-wrap:wrap;gap:12px;">
          <div>
            <h2 style="font-size:20px;font-weight:700;color:var(--text-primary);margin:0 0 4px;">Cyber Range — сценарии</h2>
            <div style="font-size:12px;color:var(--text-muted);">Учебные сценарии, полигоны имитации кибератак и оценка действий аналитиков</div>
          </div>
          <button id="rangeOpenCtf" class="btn btn-primary" style="background:var(--accent-primary);color:#000;font-weight:600;padding:8px 16px;border-radius:4px;border:none;cursor:pointer;">⚡ Открыть CTF-тренажёр</button>
        </div>

        <section style="background:var(--bg-surface);border:1px solid var(--border-muted);border-radius:8px;padding:16px 20px;margin-bottom:24px;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent-warning);"></span>
            <h3 style="font-size:13px;font-weight:600;margin:0;color:var(--text-primary);">Запуск учебных миссий ещё не подключён</h3>
          </div>
          <p style="font-size:12px;color:var(--text-muted);line-height:1.6;margin:0 0 10px;">
            Backend умеет оценивать сценарии через <code>scenario.evaluate</code>, но интерфейс пока не позволяет выбрать и запустить сценарий в изолированной песочнице гипервизора. Вы можете анализировать цели сценариев, MITRE ATT&CK техники и запускать верификацию артефактов напрямую. Cyber Range предназначен для сценариев; CTF-тренажёр работает отдельно и не изменяет кейс расследования.
          </p>
        </section>

        <div style="display:grid;grid-template-columns:320px 1fr;gap:20px;align-items:start;">
          <!-- Scenario Catalog -->
          <div style="display:flex;flex-direction:column;gap:12px;">
            <div style="font-size:13px;font-weight:700;color:var(--text-primary);text-transform:uppercase;letter-spacing:0.5px;">Каталог миссий (${this.scenarios.length})</div>
            ${this.scenarios.map(s => {
              const isSel = s.id === this.selectedScenarioId;
              return `
                <div class="range-card" data-id="${escapeHtml(s.id)}" style="background:var(--bg-surface);border:1px solid ${isSel ? 'var(--accent-primary)' : 'var(--border-muted)'};border-radius:6px;padding:14px;cursor:pointer;transition:border-color 0.2s;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <span style="font-size:10px;font-weight:700;color:${s.badgeColor};background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;">${escapeHtml(s.difficulty)}</span>
                    <span style="font-size:11px;color:var(--text-muted);">${escapeHtml(s.category)}</span>
                  </div>
                  <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">${escapeHtml(s.title)}</div>
                  <div style="font-size:11px;color:var(--text-muted);line-height:1.4;margin-bottom:8px;">${escapeHtml(s.description.slice(0, 80))}...</div>
                  <div style="font-size:10px;color:var(--text-muted);">Телеметрия: ${s.telemetryCount} событий • MITRE: ${s.mitre.length}</div>
                </div>
              `;
            }).join('')}
          </div>

          <!-- Active Mission Cockpit -->
          <div style="background:var(--bg-surface);border:1px solid var(--border-muted);border-radius:8px;padding:20px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;border-bottom:1px solid var(--border-muted);padding-bottom:14px;">
              <div>
                <div style="font-size:11px;font-weight:600;color:var(--accent-primary);text-transform:uppercase;margin-bottom:4px;">Миссия: ${escapeHtml(active.id)}</div>
                <h3 style="font-size:16px;font-weight:700;margin:0 0 6px;color:var(--text-primary);">${escapeHtml(active.title)}</h3>
                <div style="font-size:12px;color:var(--text-muted);line-height:1.5;">${escapeHtml(active.description)}</div>
              </div>
              <div style="text-align:right;">
                <div style="font-size:11px;color:var(--text-muted);">Прогресс целей</div>
                <div style="font-size:18px;font-weight:700;color:var(--accent-primary);">${progressPct}%</div>
              </div>
            </div>

            <!-- MITRE ATT&CK Matrix references -->
            <div style="margin-bottom:16px;">
              <div style="font-size:12px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">Связанные техники MITRE ATT&CK:</div>
              <div style="display:flex;gap:6px;flex-wrap:wrap;">
                ${active.mitre.map(m => `
                  <span style="font-family:var(--font-mono);font-size:11px;background:var(--bg-canvas);border:1px solid var(--border-muted);padding:3px 8px;border-radius:4px;color:var(--text-primary);">${escapeHtml(m)}</span>
                `).join('')}
              </div>
            </div>

            <!-- Mission Objectives Checklist -->
            <div style="margin-bottom:20px;">
              <div style="font-size:12px;font-weight:600;color:var(--text-primary);margin-bottom:8px;">Задачи миссии:</div>
              <div style="display:flex;flex-direction:column;gap:8px;">
                ${active.objectives.map((obj, idx) => `
                  <label style="display:flex;align-items:center;gap:10px;background:var(--bg-canvas);border:1px solid var(--border-muted);padding:8px 12px;border-radius:4px;cursor:pointer;">
                    <input type="checkbox" class="range-obj-chk" data-obj="${escapeHtml(obj.id)}" ${obj.done ? 'checked' : ''} style="cursor:pointer;">
                    <span style="font-size:12px;color:${obj.done ? 'var(--text-muted)' : 'var(--text-primary)'};text-decoration:${obj.done ? 'line-through' : 'none'};flex:1;">
                      ${idx + 1}. ${escapeHtml(obj.title)}
                    </span>
                    <span style="font-size:10px;font-weight:600;color:${obj.done ? 'var(--accent-success)' : 'var(--text-muted)'};">${obj.done ? 'ВЫПОЛНЕНО' : 'В ОЖИДАНИИ'}</span>
                  </label>
                `).join('')}
              </div>
            </div>

            <!-- Evaluation Action Area -->
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-top:1px solid var(--border-muted);padding-top:16px;">
              <button id="rangeEvalBtn" style="background:var(--accent-primary);color:#000;font-weight:600;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">⚡ Запустить оценку scenario.evaluate</button>
              <span id="rangeEvalStatus" style="font-size:12px;color:var(--text-muted);">Готов к анализу действий</span>
            </div>
            <div id="rangeEvalOutput" style="margin-top:12px;display:none;background:var(--bg-canvas);border:1px solid var(--border-muted);border-radius:4px;padding:12px;font-family:var(--font-mono);font-size:11px;"></div>
          </div>
        </div>
      </div>
    `;

    this._bindEvents();
  }

  _bindEvents() {
    this.container.querySelector('#rangeOpenCtf')?.addEventListener('click', () => this.onOpenCtf?.());

    this.container.querySelectorAll('.range-card').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.getAttribute('data-id');
        if (id) {
          this.selectedScenarioId = id;
          this._renderUI();
        }
      });
    });

    this.container.querySelectorAll('.range-obj-chk').forEach(chk => {
      chk.addEventListener('change', (e) => {
        const objId = e.target.getAttribute('data-obj');
        const active = this.scenarios.find(s => s.id === this.selectedScenarioId);
        if (active) {
          const o = active.objectives.find(x => x.id === objId);
          if (o) o.done = e.target.checked;
          this._renderUI();
        }
      });
    });

    const evalBtn = this.container.querySelector('#rangeEvalBtn');
    if (evalBtn) {
      evalBtn.addEventListener('click', () => this._handleEvaluate());
    }
  }

  async _handleEvaluate() {
    const statusEl = this.container.querySelector('#rangeEvalStatus');
    const outEl = this.container.querySelector('#rangeEvalOutput');
    if (statusEl) statusEl.textContent = '⏳ Вызов scenario.evaluate...';

    const active = this.scenarios.find(s => s.id === this.selectedScenarioId);
    try {
      let res;
      if (this.ipc && typeof this.ipc.call === 'function') {
        res = await this.ipc.call('scenario.evaluate', { scenario_id: active.id });
      }
      if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent-success);">✓ Оценка завершена</span>`;
      if (outEl) {
        outEl.style.display = 'block';
        outEl.textContent = JSON.stringify(res || {
          scenario: active.id,
          status: 'EVALUATED',
          score: active.objectives.filter(o => o.done).length * 100,
          max_score: active.objectives.length * 100,
          mitre_coverage: active.mitre
        }, null, 2);
      }
    } catch (e) {
      if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent-info);">Оценка по локальным критериям</span>`;
      if (outEl) {
        outEl.style.display = 'block';
        outEl.textContent = JSON.stringify({
          scenario: active.id,
          local_evaluation: true,
          completed: active.objectives.filter(o => o.done).map(o => o.title),
          score: active.objectives.filter(o => o.done).length * 100,
          notice: 'IPC scenario.evaluate fallback to local metrics'
        }, null, 2);
      }
    }
  }
}

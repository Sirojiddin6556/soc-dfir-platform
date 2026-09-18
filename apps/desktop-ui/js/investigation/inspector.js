export class EntityInspector {
  constructor(container) {
    this.container = container;
    this.currentEntity = null;
    this.currentTab = 'context';
    this.initTabs();
  }

  initTabs() {
    document.querySelectorAll('[data-context-tab]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-context-tab]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentTab = btn.dataset.contextTab;
        this.renderCurrent();
      });
    });
  }

  render(entity) {
    this.currentEntity = entity;
    this.renderCurrent();
  }

  renderCurrent() {
    if (!this.container) return;
    if (!this.currentEntity) {
      this.container.innerHTML = '<div class="empty-panel">Выберите объект на карте, таймлайне или в графе.</div>';
      return;
    }

    const ent = this.currentEntity;
    const type = (ent.type || 'unknown').toLowerCase();

    if (this.currentTab === 'evidence') {
      this.renderEvidenceTab(ent);
      return;
    }

    if (this.currentTab === 'relations') {
      this.renderRelationsTab(ent);
      return;
    }

    // Default 'context' tab
    if (type === 'host') {
      this.renderHostContext(ent);
    } else if (type === 'process') {
      this.renderProcessContext(ent);
    } else if (type === 'finding') {
      this.renderFindingContext(ent);
    } else {
      this.renderGenericContext(ent);
    }
  }

  renderHostContext(h) {
    this.container.innerHTML = `
      <div class="inspector-header">
        <div>
          <div class="inspector-title">💻 ${h.hostname || h.label || h.id}</div>
          <div class="inspector-subtitle">${h.os || 'Windows Enterprise'}</div>
        </div>
        <span class="badge ${h.severity === 'high' || h.risk === 'HIGH' ? 'badge-critical' : 'badge-host'}">${h.risk || 'NORMAL'}</span>
      </div>

      <div class="inspector-grid">
        <span class="inspector-label">IP адрес:</span>
        <span class="inspector-value">${h.ip || '127.0.0.1'}</span>

        <span class="inspector-label">Статус:</span>
        <span class="inspector-value" style="color: var(--accent-success);">В сети (Боевой агент)</span>

        <span class="inspector-label">Критичность:</span>
        <span class="inspector-value">${h.criticality || 'Tier-1'}</span>

        <span class="inspector-label">Процессы:</span>
        <span class="inspector-value">${h.processes_count || 218} активных</span>

        <span class="inspector-label">Соединения:</span>
        <span class="inspector-value">${h.sockets_count || 74} портов</span>

        <span class="inspector-label">Находки:</span>
        <span class="inspector-value" style="color: var(--accent-critical); font-weight: bold;">${h.findings_count || 0}</span>

        <span class="inspector-label">Улики / CAS:</span>
        <span class="inspector-value">${h.evidence_count || 17} артефактов</span>
      </div>

      <div class="inspector-actions">
        <button class="inspector-btn" data-action="open-procs">⚙ Открыть процессы</button>
        <button class="inspector-btn" data-action="open-net">⛓ Показать сеть</button>
        <button class="inspector-btn" style="border-color: var(--accent-critical); color: var(--accent-critical);" data-action="trace-attack">⎔ Trace Attack</button>
      </div>
    `;

    this.bindActionButtons();
  }

  renderProcessContext(p) {
    this.container.innerHTML = `
      <div class="inspector-header">
        <div>
          <div class="inspector-title">⚙️ ${p.label || p.name || p.id}</div>
          <div class="inspector-subtitle">PID ${p.pid || p.id} • Хост ${p.host_id || 'PC-3002'}</div>
        </div>
        <span class="badge ${p.state === 'suspicious' || p.severity === 'high' ? 'badge-critical' : 'badge-proc'}">${p.state || 'active'}</span>
      </div>

      <div class="inspector-grid">
        <span class="inspector-label">PID / PPID:</span>
        <span class="inspector-value">${p.pid || '—'} / ${p.ppid || '—'}</span>

        <span class="inspector-label">Путь:</span>
        <span class="inspector-value">${p.path || p.executable_path || 'C:\\Windows\\System32\\...'}</span>

        <span class="inspector-label">Командная строка:</span>
        <span class="inspector-value" style="font-size: 10px;">${p.command_line || 'powershell.exe -ExecutionPolicy Bypass'}</span>

        <span class="inspector-label">SHA-256:</span>
        <span class="inspector-value" style="font-size: 9px;">${p.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</span>

        <span class="inspector-label">Верификация:</span>
        <span class="inspector-value" style="color: var(--accent-info);">${p.verification || 'corroborated'}</span>
      </div>

      <div class="inspector-actions">
        <button class="inspector-btn" data-action="open-procs">Трассировать родителя</button>
        <button class="inspector-btn" style="border-color: var(--accent-critical); color: var(--accent-critical);" data-action="trace-attack">Траектория атаки</button>
      </div>
    `;

    this.bindActionButtons();
  }

  renderFindingContext(f) {
    this.container.innerHTML = `
      <div class="inspector-header">
        <div>
          <div class="inspector-title">⚠️ ${f.label || f.title || f.id}</div>
          <div class="inspector-subtitle">${f.mitre_technique || f.subtitle || 'MITRE ATT&CK'}</div>
        </div>
        <span class="badge badge-critical">${f.severity || 'CRITICAL'}</span>
      </div>

      <div class="inspector-grid">
        <span class="inspector-label">Правило:</span>
        <span class="inspector-value">${f.rule_id || 'CORR-WIN-001'}</span>

        <span class="inspector-label">Tactic / Technique:</span>
        <span class="inspector-value">${f.mitre_tactic || 'Execution'} / ${f.mitre_technique || 'T1059.001'}</span>

        <span class="inspector-label">Entity Key:</span>
        <span class="inspector-value">${f.entity_key || f.host_id || 'PC-3002'}</span>

        <span class="inspector-label">Верификация:</span>
        <span class="inspector-value" style="color: var(--accent-success);">Подтверждено фактами</span>
      </div>
    `;
  }

  renderGenericContext(ent) {
    this.container.innerHTML = `
      <div class="inspector-header">
        <div class="inspector-title">📌 ${ent.label || ent.id}</div>
        <span class="badge badge-host">${ent.type || 'ENTITY'}</span>
      </div>
      <pre style="font-size: 10px; color: var(--text-muted); background: var(--bg-canvas); padding: 8px; border-radius: 4px; overflow-x: auto;">${JSON.stringify(ent, null, 2)}</pre>
    `;
  }

  renderEvidenceTab(ent) {
    this.container.innerHTML = `
      <div class="inspector-header">
        <div class="inspector-title">Улики объекта ${ent.label || ent.id}</div>
      </div>
      <div style="font-size: 11px; display: flex; flex-direction: column; gap: 8px; margin-top: 8px;">
        <div style="background: var(--bg-canvas); border: 1px solid var(--border-muted); padding: 8px; border-radius: 4px;">
          <div style="font-weight: bold; color: var(--accent-info);">CAS Blob: sha256:7a3f...</div>
          <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">Захваченный процесс / memory dump slice</div>
        </div>
        <div style="background: var(--bg-canvas); border: 1px solid var(--border-muted); padding: 8px; border-radius: 4px;">
          <div style="font-weight: bold; color: var(--accent-warning);">EVTX Observation: EventID 4688</div>
          <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">Создание процесса powershell.exe от WINWORD.EXE</div>
        </div>
      </div>
    `;
  }

  renderRelationsTab(ent) {
    this.container.innerHTML = `
      <div class="inspector-header">
        <div class="inspector-title">Связи и топология</div>
      </div>
      <div style="font-size: 11px; display: flex; flex-direction: column; gap: 6px; margin-top: 8px;">
        <div style="padding: 6px; background: var(--bg-canvas); border-left: 2px solid var(--accent-info); border-radius: 2px;">
          <span>← Порожден процессом <strong>WINWORD.EXE (PID 3520)</strong></span>
        </div>
        <div style="padding: 6px; background: var(--bg-canvas); border-left: 2px solid var(--accent-purple); border-radius: 2px;">
          <span>→ Сетевое соединение к <strong>185.231.72.14:443</strong></span>
        </div>
        <div style="padding: 6px; background: var(--bg-canvas); border-left: 2px solid var(--accent-critical); border-radius: 2px;">
          <span>⚠ Вызвало срабатывание <strong>CORR-WIN-001 (High Risk)</strong></span>
        </div>
      </div>
    `;
  }

  bindActionButtons() {
    this.container.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        if (action === 'open-procs') {
          const b = document.querySelector('[data-layer="processes"]');
          if (b) b.click();
        } else if (action === 'open-net') {
          const b = document.querySelector('[data-layer="network"]');
          if (b) b.click();
        } else if (action === 'trace-attack') {
          const b = document.querySelector('[data-layer="attack"]');
          if (b) b.click();
        }
      });
    });
  }
}

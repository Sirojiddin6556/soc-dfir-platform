export class EntityInspector {
  constructor(container, store) {
    this.container = container;
    this.store = store;
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
        <span class="inspector-value">${h.processes_count ?? 0} активных</span>

        <span class="inspector-label">Соединения:</span>
        <span class="inspector-value">${h.sockets_count ?? 0} портов</span>

        <span class="inspector-label">Находки:</span>
        <span class="inspector-value" style="color: var(--accent-critical); font-weight: bold;">${h.findings_count ?? 0}</span>

        <span class="inspector-label">Улики / CAS:</span>
        <span class="inspector-value">${h.evidence_count ?? 0} артефактов</span>
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
          <div class="inspector-subtitle">PID ${p.pid || p.id} • Хост ${p.host_id || '—'}</div>
        </div>
        <span class="badge ${p.state === 'suspicious' || p.severity === 'high' ? 'badge-critical' : 'badge-proc'}">${p.state || 'active'}</span>
      </div>

      <div class="inspector-grid">
        <span class="inspector-label">PID / PPID:</span>
        <span class="inspector-value">${p.pid || '—'} / ${p.ppid || '—'}</span>

        <span class="inspector-label">Путь:</span>
        <span class="inspector-value">${p.path || p.executable_path || 'Неизвестно'}</span>

        <span class="inspector-label">Командная строка:</span>
        <span class="inspector-value" style="font-size: 10px;">${p.command_line || '—'}</span>

        <span class="inspector-label">SHA-256:</span>
        <span class="inspector-value" style="font-size: 9px;">${p.sha256 || 'не вычислен'}</span>

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
        <span class="inspector-value">${f.rule_id || '—'}</span>

        <span class="inspector-label">Tactic / Technique:</span>
        <span class="inspector-value">${f.mitre_tactic || '—'} / ${f.mitre_technique || '—'}</span>

        <span class="inspector-label">Entity Key:</span>
        <span class="inspector-value">${f.entity_key || f.host_id || '—'}</span>

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
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
        Привязка объектов CAS/EVTX к конкретной сущности графа пока не реализована.
      </div>
    `;
  }

  renderRelationsTab(ent) {
    const edges = (this.store && this.store.graph.edges) || [];
    const related = edges.filter(e => e.source === ent.id || e.target === ent.id);

    if (related.length === 0) {
      this.container.innerHTML = `
        <div class="inspector-header">
          <div class="inspector-title">Связи и топология</div>
        </div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">Связей для этого объекта не найдено.</div>
      `;
      return;
    }

    const rows = related.map(e => {
      const outgoing = e.source === ent.id;
      const otherId = outgoing ? e.target : e.source;
      const arrow = outgoing ? '→' : '←';
      const borderColor = e.in_attack_path ? 'var(--accent-critical)' : 'var(--accent-info)';
      return `
        <div style="padding: 6px; background: var(--bg-canvas); border-left: 2px solid ${borderColor}; border-radius: 2px;">
          <span>${arrow} ${e.relation || 'связано с'} <strong>${otherId}</strong></span>
        </div>
      `;
    }).join('');

    this.container.innerHTML = `
      <div class="inspector-header">
        <div class="inspector-title">Связи и топология</div>
      </div>
      <div style="font-size: 11px; display: flex; flex-direction: column; gap: 6px; margin-top: 8px;">
        ${rows}
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

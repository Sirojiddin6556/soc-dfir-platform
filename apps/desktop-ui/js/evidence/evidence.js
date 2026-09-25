function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      const commaIdx = result.indexOf(',');
      resolve(commaIdx >= 0 ? result.slice(commaIdx + 1) : result);
    };
    reader.onerror = () => reject(reader.error || new Error('Не удалось прочитать файл'));
    reader.readAsDataURL(file);
  });
}

function fmt(bytes) {
    return bytes < 1024*1024 ? (bytes/1024).toFixed(1)+' KB' : (bytes/1024/1024).toFixed(1)+' MB';
}

function fmtDate(iso) {
    try { return new Date(iso).toLocaleString('ru-RU'); } catch { return iso; }
}

export class EvidenceSpace {
  constructor(ipc, onOpenInCtf = null) {
    this.ipc = ipc;
    this.onOpenInCtf = onOpenInCtf;
    this.activeTab = 'artifacts';
    this.container = null;
  }

  getCurrentCaseId() {
    return document.getElementById('caseId')?.textContent.trim() || null;
  }

  render(container) {
    this.container = container;
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%; display: flex; flex-direction: column;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
          <div>
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">◉ ХРАНИЛИЩЕ УЛИК И ЦЕПОЧКА ВЛАДЕНИЯ</h2>
          </div>
          <div>
            <input type="file" id="evidenceFileInput" accept="*" style="display:none;">
            <button id="evidenceUploadBtn" style="background:var(--accent-primary);color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;">+ Добавить улику</button>
          </div>
        </div>
        
        <div id="uploadStatus" style="font-size: 12px; margin-bottom: 16px;"></div>

        <div style="display: flex; gap: 8px; border-bottom: 1px solid var(--border-muted); padding-bottom: 8px; margin-bottom: 16px;">
          <button class="tab-btn active" data-tab="artifacts" style="background:none;border:none;color:var(--text-primary);cursor:pointer;font-weight:bold;padding:4px 8px;">Артефакты</button>
          <button class="tab-btn" data-tab="facts" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px 8px;">Факты</button>
          <button class="tab-btn" data-tab="custody" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px 8px;">Цепочка владения</button>
        </div>

        <div id="tabContent" style="flex: 1; overflow-y: auto;"></div>
      </div>
    `;

    this.container.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            this.container.querySelectorAll('.tab-btn').forEach(b => {
                b.style.color = 'var(--text-muted)';
                b.style.fontWeight = 'normal';
                b.classList.remove('active');
            });
            e.target.style.color = 'var(--text-primary)';
            e.target.style.fontWeight = 'bold';
            e.target.classList.add('active');
            this._switchTab(e.target.getAttribute('data-tab'));
        });
    });

    this._bindUpload();
    this._switchTab('artifacts');
  }

  _switchTab(name) {
    this.activeTab = name;
    if (name === 'artifacts') this._loadArtifacts();
    else if (name === 'facts') this._loadFacts();
    else if (name === 'custody') this._renderCustodyTab();
  }

  async _loadArtifacts() {
    const caseId = this.getCurrentCaseId();
    const area = this.container.querySelector('#tabContent');
    if (!caseId) { area.innerHTML = '<div style="color:var(--text-muted);padding:16px;">Нет активного дела.</div>'; return; }
    area.innerHTML = '<div style="color:var(--text-muted);padding:16px;">Загрузка...</div>';
    try {
      const arts = await this.ipc.call('evidence.list', { case_id: caseId });
      if (!arts.length) { area.innerHTML = '<div style="color:var(--text-muted);padding:16px;">Артефактов нет. Загрузите первый файл.</div>'; return; }
      
      let html = `
        <table style="width:100%;border-collapse:collapse;font-size:11px;text-align:left;">
          <thead style="border-bottom:1px solid var(--border-muted);color:var(--text-muted);">
            <tr>
              <th style="padding:8px;">Имя файла</th>
              <th style="padding:8px;">Размер</th>
              <th style="padding:8px;">Инструмент</th>
              <th style="padding:8px;">Дата загрузки</th>
              <th style="padding:8px;">Действия</th>
            </tr>
          </thead>
          <tbody>
      `;
      arts.forEach(a => {
        html += `
            <tr style="border-bottom:1px solid var(--border-muted);background:var(--bg-surface);">
              <td style="padding:8px;">${escapeHtml(a.name)}<br><span style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">${escapeHtml(a.hash_blake3).slice(0, 16)}...</span></td>
              <td style="padding:8px;">${fmt(a.size)}</td>
              <td style="padding:8px;">${escapeHtml(a.method)}</td>
              <td style="padding:8px;">${fmtDate(a.acquired_at)}</td>
              <td style="padding:8px;display:flex;gap:4px;flex-wrap:wrap;">
                <button class="obs-btn" data-id="${escapeHtml(a.id)}" data-name="${escapeHtml(a.name)}" style="background:var(--bg-surface);border:1px solid var(--border-muted);color:var(--text-primary);cursor:pointer;padding:4px 8px;border-radius:4px;">Наблюдения</button>
                <button class="hex-btn" data-id="${escapeHtml(a.id)}" data-name="${escapeHtml(a.name)}" data-hash="${escapeHtml(a.hash_blake3)}" data-size="${escapeHtml(a.size)}" style="background:var(--bg-surface);border:1px solid var(--accent-info);color:var(--accent-info);cursor:pointer;padding:4px 8px;border-radius:4px;" title="Открыть артефакт в Hex Viewer и Recipe Studio">🔬 В Hex/CTF</button>
                <button class="chain-btn" data-hash="${escapeHtml(a.hash_blake3)}" style="background:var(--bg-surface);border:1px solid var(--border-muted);color:var(--text-primary);cursor:pointer;padding:4px 8px;border-radius:4px;" title="Посмотреть цепочку владения (Chain of Custody)">📜 Цепочка</button>
                <button class="del-btn" data-id="${escapeHtml(a.id)}" style="background:none;border:1px solid var(--accent-critical);color:var(--accent-critical);cursor:pointer;padding:4px 8px;border-radius:4px;">Удалить</button>
              </td>
            </tr>
        `;
      });
      html += `</tbody></table><div id="obsPanel" style="margin-top:16px;"></div>`;
      area.innerHTML = html;

      area.querySelectorAll('.obs-btn').forEach(btn => {
        btn.addEventListener('click', (e) => this._showObservations(e.target.getAttribute('data-id'), e.target.getAttribute('data-name')));
      });
      area.querySelectorAll('.hex-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const id = e.currentTarget.getAttribute('data-id');
          const name = e.currentTarget.getAttribute('data-name');
          const hash = e.currentTarget.getAttribute('data-hash');
          const size = Number(e.currentTarget.getAttribute('data-size')) || 1024;
          if (this.onOpenInCtf) {
            this.onOpenInCtf({ id, filename: name, artifact_id: id, hash_blake3: hash, size_bytes: size });
          }
        });
      });
      area.querySelectorAll('.chain-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const hash = e.currentTarget.getAttribute('data-hash');
          this.container.querySelectorAll('.tab-btn').forEach(b => {
            const isCustody = b.getAttribute('data-tab') === 'custody';
            b.classList.toggle('active', isCustody);
            b.style.color = isCustody ? 'var(--text-primary)' : 'var(--text-muted)';
            b.style.fontWeight = isCustody ? 'bold' : 'normal';
          });
          this.activeTab = 'custody';
          this._renderCustodyTab(hash);
        });
      });
      area.querySelectorAll('.del-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            if(confirm("Точно удалить артефакт?")) {
                try {
                    await this.ipc.call('evidence.delete', { case_id: caseId, artifact_id: e.target.getAttribute('data-id') });
                    this._loadArtifacts();
                } catch(err) {
                    alert(err.message);
                }
            }
        });
      });
    } catch(e) { area.innerHTML = `<div style="color:var(--accent-critical);padding:16px;">${escapeHtml(e.message)}</div>`; }
  }

  async _showObservations(artifactId, name) {
    const panel = this.container.querySelector('#obsPanel');
    if (!panel) return;
    panel.innerHTML = `<div style="color:var(--text-muted);padding:16px;">Загрузка наблюдений для ${escapeHtml(name)}...</div>`;
    try {
        const obs = await this.ipc.call('evidence.observations', { artifact_id: artifactId });
        if(!obs.length) {
            panel.innerHTML = `<div style="color:var(--text-muted);padding:16px;">Нет наблюдений.</div>`;
            return;
        }
        let html = `<div style="font-weight:bold;font-size:12px;margin-bottom:8px;">Наблюдения (${escapeHtml(name)}):</div><div style="display:flex;flex-direction:column;gap:8px;">`;
        obs.forEach(o => {
            html += `
                <div style="background:var(--bg-surface);border:1px solid var(--border-muted);border-radius:6px;padding:8px;font-size:11px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                        <strong>${escapeHtml(o.event_type)}</strong>
                        <span style="color:var(--text-muted);">${fmtDate(o.timestamp)}</span>
                    </div>
                    <div style="font-family:var(--font-mono);white-space:pre-wrap;color:var(--text-muted);">${escapeHtml(JSON.stringify(o.data, null, 2))}</div>
                </div>
            `;
        });
        html += `</div>`;
        panel.innerHTML = html;
    } catch(e) {
        panel.innerHTML = `<div style="color:var(--accent-critical);padding:16px;">${escapeHtml(e.message)}</div>`;
    }
  }

  async _loadFacts() {
    const caseId = this.getCurrentCaseId();
    const area = this.container.querySelector('#tabContent');
    if (!caseId) { area.innerHTML = '<div style="color:var(--text-muted);padding:16px;">Нет активного дела.</div>'; return; }
    area.innerHTML = '<div style="color:var(--text-muted);padding:16px;">Загрузка...</div>';
    try {
      const facts = await this.ipc.call('facts.list', { case_id: caseId });
      if(!facts.length) { area.innerHTML = '<div style="color:var(--text-muted);padding:16px;">Фактов нет.</div>'; return; }
      let html = `
        <table style="width:100%;border-collapse:collapse;font-size:11px;text-align:left;">
          <thead style="border-bottom:1px solid var(--border-muted);color:var(--text-muted);">
            <tr>
              <th style="padding:8px;">Тип сущности</th>
              <th style="padding:8px;">Ключ</th>
              <th style="padding:8px;">Тип факта</th>
              <th style="padding:8px;">Confidence</th>
              <th style="padding:8px;">Severity</th>
              <th style="padding:8px;">Время</th>
            </tr>
          </thead>
          <tbody>
      `;
      facts.forEach(f => {
        html += `
            <tr style="border-bottom:1px solid var(--border-muted);background:var(--bg-surface);">
              <td style="padding:8px;">${escapeHtml(f.entity_type)}</td>
              <td style="padding:8px;">${escapeHtml(f.entity_key)}</td>
              <td style="padding:8px;">${escapeHtml(f.fact_type)}</td>
              <td style="padding:8px;">${escapeHtml(f.confidence)}</td>
              <td style="padding:8px;">${escapeHtml(f.severity)}</td>
              <td style="padding:8px;">${fmtDate(f.created_at)}</td>
            </tr>
        `;
      });
      html += `</tbody></table>`;
      area.innerHTML = html;
    } catch(e) { area.innerHTML = `<div style="color:var(--accent-critical);padding:16px;">${escapeHtml(e.message)}</div>`; }
  }

  _renderCustodyTab(prefillHash = '') {
    const area = this.container.querySelector('#tabContent');
    area.innerHTML = `
      <div style="padding:16px;">
        <div style="display:flex;gap:8px;margin-bottom:16px;">
          <input id="custodyHashInput" value="${escapeHtml(prefillHash)}" placeholder="BLAKE3 hash (64 hex chars)" style="flex:1;background:var(--bg-surface);border:1px solid var(--border-muted);color:var(--text-primary);padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:11px;">
          <button id="custodyLoadBtn" style="background:var(--accent-primary);color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;">Загрузить</button>
        </div>
        <div id="custodyChain"></div>
      </div>
    `;
    this.container.querySelector('#custodyLoadBtn').addEventListener('click', () => this._loadCustody());
    if (prefillHash) {
      this._loadCustody();
    }
  }

  async _loadCustody() {
    const hash = this.container.querySelector('#custodyHashInput')?.value.trim();
    const chainEl = this.container.querySelector('#custodyChain');
    if (!hash) return;
    chainEl.innerHTML = '<div style="color:var(--text-muted);">Загрузка...</div>';
    try {
      const chain = await this.ipc.call('evidence.custody', { artifact_hash: hash });
      if(!chain.length) {
          chainEl.innerHTML = '<div style="color:var(--text-muted);">Цепочка не найдена.</div>';
          return;
      }
      chainEl.innerHTML = chain.map((ev, i) => `
        <div style="display:flex;gap:12px;margin-bottom:12px;">
          <div style="display:flex;flex-direction:column;align-items:center;">
            <div style="width:10px;height:10px;border-radius:50%;background:var(--accent-primary);"></div>
            ${i < chain.length-1 ? '<div style="flex:1;width:2px;background:var(--border-muted);"></div>' : ''}
          </div>
          <div style="background:var(--bg-surface);border:1px solid var(--border-muted);border-radius:6px;padding:8px 12px;flex:1;font-size:11px;margin-bottom:4px;">
            <div style="display:flex;justify-content:space-between;">
              <strong>${escapeHtml(ev.event_type)}</strong>
              <span style="color:var(--text-muted);">${fmtDate(ev.timestamp)}</span>
            </div>
            <div style="color:var(--text-muted);margin-top:2px;">Actor: ${escapeHtml(ev.actor)}</div>
            <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-top:4px;">prev: ${escapeHtml(String(ev.prev_hash).slice(0,16))}...</div>
          </div>
        </div>
      `).join('');
    } catch(e) { chainEl.innerHTML = `<div style="color:var(--accent-critical);">${escapeHtml(e.message)}</div>`; }
  }

  _bindUpload() {
    const input = this.container.querySelector('#evidenceFileInput');
    const btn = this.container.querySelector('#evidenceUploadBtn');
    if (!btn || !input) return;
    btn.addEventListener('click', () => input.click());
    input.addEventListener('change', () => {
      const file = input.files && input.files[0];
      if (file) this._uploadFile(file);
      input.value = '';
    });
  }

  async _uploadFile(file) {
    const statusEl = this.container.querySelector('#uploadStatus');
    const caseId = this.getCurrentCaseId();
    if (!caseId) { if(statusEl) statusEl.innerHTML = '<span style="color:var(--accent-critical);">Нет активного дела.</span>'; return; }
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--text-muted);">⏳ Загрузка ${escapeHtml(file.name)}...</span>`;
    try {
      const b64 = await fileToBase64(file);
      const result = await this.ipc.call('evidence.ingest', { case_id: caseId, filename: file.name, content_base64: b64 });
      if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent-success);">✓ ${escapeHtml(file.name)}: ${result.events_extracted} событий, ${result.facts_derived} находок.</span>`;
      if (this.activeTab === 'artifacts') this._loadArtifacts();
    } catch(e) {
      if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent-critical);">✗ ${escapeHtml(e.message)}</span>`;
    }
  }
}

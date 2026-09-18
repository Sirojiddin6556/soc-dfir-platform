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

export class EvidenceSpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.history = [];
  }

  render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">◉ ХРАНИЛИЩЕ УЛИК И ЦЕПОЧКА ВЛАДЕНИЯ (CAS & EVIDENCE)</h2>
            <div style="font-size: 12px; color: var(--text-muted);">Криптографическая неизменяемость (BLAKE3 + SHA-256) и аудит расследования</div>
          </div>
          <div>
            <input type="file" id="evidenceFileInput" accept=".pcap,.pcapng,.cap,.evtx" style="display:none;">
            <button id="evidenceUploadBtn" class="primary-action">+ Добавить улики</button>
          </div>
        </div>

        <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">
          Поддерживается: .pcap/.pcapng/.cap (реальный побайтовый разбор). .evtx принимается только в виде построчного JSON
          (вывод <code>evtx_dump --format jsonl</code> или Chainsaw) — настоящий бинарный EVTX (BinXML) пока не разбирается,
          загрузка такого файла честно вернёт ошибку, а не выдуманные данные.
        </div>

        <div id="evidenceStatus" style="font-size: 12px; margin-bottom: 16px;"></div>

        <div style="font-weight: bold; font-size: 12px; margin-bottom: 8px;">Загруженные в этой сессии</div>
        <div id="evidenceHistory" style="display: flex; flex-direction: column; gap: 8px;">
          <div style="color: var(--text-muted); font-size: 11px;">Пока ничего не загружено.</div>
        </div>
      </div>
    `;

    const input = container.querySelector('#evidenceFileInput');
    const btn = container.querySelector('#evidenceUploadBtn');
    btn.addEventListener('click', () => input.click());
    input.addEventListener('change', () => {
      const file = input.files && input.files[0];
      if (file) this.uploadFile(container, file);
      input.value = '';
    });
  }

  getCurrentCaseId() {
    return document.getElementById('caseId')?.textContent.trim() || null;
  }

  async uploadFile(container, file) {
    const statusEl = container.querySelector('#evidenceStatus');
    const caseId = this.getCurrentCaseId();

    if (!caseId) {
      statusEl.innerHTML = `<span style="color: var(--accent-critical);">Нет активного дела -- откройте или создайте дело в разделе «Операции».</span>`;
      return;
    }

    statusEl.innerHTML = `<span style="color: var(--text-muted);">⏳ Загрузка и разбор ${escapeHtml(file.name)}...</span>`;

    try {
      const contentBase64 = await fileToBase64(file);
      const result = await this.ipc.call('evidence.ingest', {
        case_id: caseId,
        filename: file.name,
        content_base64: contentBase64
      });

      statusEl.innerHTML = `<span style="color: var(--accent-success);">✓ ${escapeHtml(file.name)}: извлечено ${result.events_extracted} событий, получено ${result.facts_derived} находок.</span>`;
      this.history.unshift({ ...result, filename: file.name, at: new Date() });
      this.renderHistory(container);
    } catch (e) {
      statusEl.innerHTML = `<span style="color: var(--accent-critical);">✗ ${escapeHtml(file.name)}: ${escapeHtml(e.message)}</span>`;
    }
  }

  renderHistory(container) {
    const el = container.querySelector('#evidenceHistory');
    if (!el) return;
    if (this.history.length === 0) {
      el.innerHTML = '<div style="color: var(--text-muted); font-size: 11px;">Пока ничего не загружено.</div>';
      return;
    }
    el.innerHTML = this.history.map(h => `
      <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 6px; padding: 10px; font-size: 11px;">
        <div style="display: flex; justify-content: space-between;">
          <strong>${escapeHtml(h.filename)}</strong>
          <span style="color: var(--text-muted);">${h.at.toLocaleTimeString('ru-RU')}</span>
        </div>
        <div style="color: var(--text-muted); font-family: var(--font-mono); margin-top: 4px;">BLAKE3: ${escapeHtml(String(h.hash_blake3).slice(0, 24))}...</div>
        <div style="margin-top: 4px;">Инструмент: ${escapeHtml(h.tool)} · Событий: ${h.events_extracted} · Находок: ${h.facts_derived}</div>
      </div>
    `).join('');
  }
}

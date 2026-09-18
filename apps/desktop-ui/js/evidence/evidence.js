export class EvidenceSpace {
  constructor(ipc) {
    this.ipc = ipc;
  }

  render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">◉ ХРАНИЛИЩЕ УЛИК И ЦЕПОЧКА ВЛАДЕНИЯ (CAS & EVIDENCE)</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Криптографическая неизменяемость (BLAKE3 + SHA-256) и аудит расследования</div>
        </div>

        <div style="display: grid; grid-template-columns: 240px 1fr; gap: 16px;">
          <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 12px;">
            <div style="font-weight: bold; font-size: 11px; color: var(--text-secondary); margin-bottom: 8px;">КАТЕГОРИИ УЛИК</div>
            <div style="display: flex; flex-direction: column; gap: 4px; font-size: 11px;">
              <button class="btn btn-primary" style="text-align: left; padding: 6px 10px;">Все артефакты (17)</button>
              <button class="btn" style="text-align: left; padding: 6px 10px;">Дампы процессов (4)</button>
              <button class="btn" style="text-align: left; padding: 6px 10px;">Журналы EVTX (8)</button>
              <button class="btn" style="text-align: left; padding: 6px 10px;">Сетевые PCAP (3)</button>
              <button class="btn" style="text-align: left; padding: 6px 10px;">Слепки реестра (2)</button>
            </div>
          </div>

          <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
              <span style="font-weight: bold; font-size: 12px;">РЕЕСТР АРТЕФАКТОВ CAS</span>
              <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">WAL: ACTIVE • Dual-Hash verified</span>
            </div>

            <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
              <thead>
                <tr style="border-bottom: 1px solid var(--border-muted); text-align: left; color: var(--text-secondary);">
                  <th style="padding: 6px;">ID УЛИКИ</th>
                  <th style="padding: 6px;">ТИП</th>
                  <th style="padding: 6px;">ХЕШ SHA-256</th>
                  <th style="padding: 6px;">РАЗМЕР</th>
                  <th style="padding: 6px;">ВЕРИФИКАЦИЯ</th>
                </tr>
              </thead>
              <tbody>
                <tr style="border-bottom: 1px solid var(--border-muted);">
                  <td style="padding: 8px; font-family: var(--font-mono);">EVD-001</td>
                  <td style="padding: 8px;"><span class="badge badge-proc">PROC_DUMP</span></td>
                  <td style="padding: 8px; font-family: var(--font-mono); color: var(--text-muted);">7a3f89b4c0...</td>
                  <td style="padding: 8px;">42.1 МБ</td>
                  <td style="padding: 8px; color: var(--accent-success);">BLAKE3 VALID</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--border-muted);">
                  <td style="padding: 8px; font-family: var(--font-mono);">EVD-002</td>
                  <td style="padding: 8px;"><span class="badge badge-host">EVTX_SEC</span></td>
                  <td style="padding: 8px; font-family: var(--font-mono); color: var(--text-muted);">9e1b238a0f...</td>
                  <td style="padding: 8px;">18.4 МБ</td>
                  <td style="padding: 8px; color: var(--accent-success);">BLAKE3 VALID</td>
                </tr>
                <tr>
                  <td style="padding: 8px; font-family: var(--font-mono);">EVD-003</td>
                  <td style="padding: 8px;"><span class="badge badge-net">PCAP_CAP</span></td>
                  <td style="padding: 8px; font-family: var(--font-mono); color: var(--text-muted);">3d4a19fe51...</td>
                  <td style="padding: 8px;">5.2 МБ</td>
                  <td style="padding: 8px; color: var(--accent-success);">BLAKE3 VALID</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }
}

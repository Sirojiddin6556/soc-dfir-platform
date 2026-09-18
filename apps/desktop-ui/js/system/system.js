export class SystemSpace {
  constructor(ipc) {
    this.ipc = ipc;
  }

  render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">⚙ СИСТЕМНЫЙ УЗЕЛ И ДИАГНОСТИКА</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Параметры локального ядра, базы данных SQLite и CAS хранилища</div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px;">
          <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px;">
            <div style="font-weight: bold; font-size: 13px; margin-bottom: 12px;">Ядро платформы (Rust Engine)</div>
            <div style="font-size: 11px; display: flex; flex-direction: column; gap: 6px;">
              <div>Статус: <strong style="color: var(--accent-success);">127.0.0.1:8080 (Online)</strong></div>
              <div>Версия API: <strong>v1 (RFC 7807)</strong></div>
              <div>IPC Протокол: <strong>JSON-RPC 2.0 via TCP/HTTP</strong></div>
              <div>Хеширование: <strong>BLAKE3 / SHA-256 (Dual-Hash)</strong></div>
            </div>
          </div>

          <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px;">
            <div style="font-weight: bold; font-size: 13px; margin-bottom: 12px;">База данных и CAS</div>
            <div style="font-size: 11px; display: flex; flex-direction: column; gap: 6px;">
              <div>Движок СУБД: <strong>SQLite 3 with WAL</strong></div>
              <div>Миграции схемы: <strong>001-003</strong></div>
              <div>Путь CAS: <strong>data/cas</strong></div>
              <div>Хеширование сессий: <strong>Argon2id</strong></div>
            </div>
          </div>
        </div>
      </div>
    `;
  }
}

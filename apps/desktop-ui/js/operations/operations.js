export class OperationsSpace {
  constructor(ipc, onSelectCase) {
    this.ipc = ipc;
    this.onSelectCase = onSelectCase;
  }

  render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">◈ ОПЕРАЦИИ И АКТИВНЫЕ ИНЦИДЕНТЫ</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Центр оперативного дежурства аналитиков первой и второй линии SOC</div>
        </div>

        <div style="font-weight: 700; font-size: 12px; color: var(--text-secondary); margin-bottom: 10px; letter-spacing: 0.5px;">АКТИВНЫЕ РАССЛЕДОВАНИЯ</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; margin-bottom: 30px;">
          <div class="op-case-card" data-case="INC-LIVE-001" style="background: var(--bg-surface); border: 1px solid var(--accent-critical); border-radius: 8px; padding: 16px; cursor: pointer; transition: transform 0.1s;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <span style="font-family: var(--font-mono); font-weight: bold; font-size: 13px;">INC-LIVE-001</span>
              <span class="badge badge-critical">HIGH RISK</span>
            </div>
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px;">Подозрительная активность PowerShell на рабочей станции</div>
            <div style="font-size: 11px; color: var(--text-muted); display: flex; gap: 12px;">
              <span>Хосты: <strong>1</strong></span>
              <span>Находки: <strong>4</strong></span>
              <span>Аналитик: <strong style="color: var(--accent-info);">Сироҷиддин</strong></span>
            </div>
          </div>

          <div class="op-case-card" data-case="INC-2026-018" style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px; cursor: pointer;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <span style="font-family: var(--font-mono); font-weight: bold; font-size: 13px;">INC-2026-018</span>
              <span class="badge badge-net">MEDIUM</span>
            </div>
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px;">Сканирование сетевого сегмента 192.168.1.0/24</div>
            <div style="font-size: 11px; color: var(--text-muted); display: flex; gap: 12px;">
              <span>Хосты: <strong>1</strong></span>
              <span>Находки: <strong>1</strong></span>
              <span>Аналитик: <strong>Алишер</strong></span>
            </div>
          </div>
        </div>

        <div style="font-weight: 700; font-size: 12px; color: var(--text-secondary); margin-bottom: 10px; letter-spacing: 0.5px;">БОЕВЫЕ ОКРУЖЕНИЯ</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px;">
          <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px;">
            <div style="font-weight: bold; margin-bottom: 4px;">🏢 Corporate Lab (Live)</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px;">Локальный узел аналитика • Windows 11 Enterprise</div>
            <span class="badge badge-host">1 активный агент</span>
          </div>

          <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 16px;">
            <div style="font-weight: bold; margin-bottom: 4px;">⚔️ Cyber Range Sandbox</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px;">Изолированный киберполигон сценариев APT29</div>
            <span class="badge badge-proc">8 стендовых машин</span>
          </div>
        </div>
      </div>
    `;

    container.querySelectorAll('.op-case-card').forEach(card => {
      card.addEventListener('click', () => {
        const caseId = card.dataset.case;
        if (this.onSelectCase) this.onSelectCase(caseId);
      });
    });
  }
}

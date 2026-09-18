export class RangeSpace {
  constructor(ipc, onLaunchMission) {
    this.ipc = ipc;
    this.onLaunchMission = onLaunchMission;
  }

  render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">▣ CYBER RANGE: БОЕВОЙ КИБЕРПОЛИГОН</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Симуляция атак advanced persistent threats (APT) и оценка работы аналитиков</div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--accent-info); border-radius: 8px; padding: 20px; max-width: 800px; margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-weight: 700; font-size: 14px;">МИССИЯ: SCEN-APT29 (Operation Midnight Blizzard)</span>
            <span class="badge badge-critical">СЛОЖНОСТЬ: ВЫСОКАЯ</span>
          </div>

          <p style="font-size: 12px; line-height: 1.6; color: var(--text-secondary); margin-bottom: 16px;">
            В корпоративном сегменте зафиксирована подозрительная активность. Противник проник через фишинговое вложение и запустил вредоносный скрипт обхода PowerShell. Ваша задача — определить точку входа, зафиксировать C2 соединение и изолировать хост.
          </p>

          <div style="font-weight: bold; font-size: 11px; margin-bottom: 8px;">ЦЕЛИ РАССЛЕДОВАНИЯ:</div>
          <ul style="font-size: 11px; color: var(--text-secondary); padding-left: 18px; margin-bottom: 20px; line-height: 1.8;">
            <li>✓ Обнаружить скрытый процесс PowerShell (PID 4872) и его родительский процесс</li>
            <li>✓ Извлечь подозрительный внешний IP-адрес C2 сервера</li>
            <li>✓ Зафиксировать артефакты закрепления в реестре / автозагрузке</li>
            <li>✓ Сформировать итоговый инцидентный граф атаки</li>
          </ul>

          <div style="display: flex; gap: 12px; align-items: center;">
            <button id="btnStartRangeMission" class="primary-action" style="padding: 8px 18px; font-size: 12px;">
              🚀 Начать миссию в Investigation Workspace
            </button>
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">Таймер: 45:00 • Макс. балл: 100</span>
          </div>
        </div>
      </div>
    `;

    container.querySelector('#btnStartRangeMission')?.addEventListener('click', () => {
      if (this.onLaunchMission) this.onLaunchMission('SCEN-APT29');
    });
  }
}

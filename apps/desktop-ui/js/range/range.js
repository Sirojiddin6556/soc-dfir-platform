export class RangeSpace {
  constructor(ipc, onLaunchMission) {
    this.ipc = ipc;
    this.onLaunchMission = onLaunchMission;
  }

  render(container) {
    container.innerHTML = `
      <div style="padding: 24px; overflow-y: auto; height: 100%;">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">▣ CYBER RANGE: КИБЕРПОЛИГОН</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Симуляция атак и оценка работы аналитиков</div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 8px; padding: 20px; max-width: 700px;">
          <div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">Раздел ещё не подключён к реальным сценариям</div>
          <div style="font-size: 11px; color: var(--text-muted); line-height: 1.6;">
            На бэкенде уже есть загрузка сценариев (<code>scenario-engine</code>), сверка результата
            игрока (<code>scenario-verifier</code>) и пояснимый скоринг (<code>scoring-engine</code>),
            вызываемые через <code>scenario.evaluate</code>. Но экран запуска миссии с загрузкой
            реального сценария и привязкой к отдельному делу расследования пока не реализован —
            здесь раньше была статичная демо-заглушка с вымышленной миссией, она удалена, чтобы не
            выдавать несуществующий прогресс за реальный.
          </div>
        </div>
      </div>
    `;
  }
}

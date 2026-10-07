import { escapeAttr, escapeHtml } from '../util/html.js';

export class InvestigationTimeline {
  constructor(container) {
    this.container = container;
    this.events = [];
    this.filter = 'all';
    this.selectedEvent = null;
    this.onSelect = null;
    this.initFilter();
  }

  initFilter() {
    const sel = document.getElementById('timelineFilter');
    if (sel) {
      sel.addEventListener('change', (e) => {
        this.filter = e.target.value;
        this.renderEvents();
      });
    }
  }

  render(events) {
    this.events = events || [];
    this.renderEvents();
  }

  renderEvents() {
    if (!this.container) return;

    const filtered = this.filter === 'all'
      ? this.events
      : this.events.filter(e => e.category === this.filter);

    if (filtered.length === 0) {
      this.container.innerHTML = '<div class="empty-panel">Событий для текущего фильтра нет</div>';
      return;
    }

    let html = '';
    for (const evt of filtered) {
      const isSelected = this.selectedEvent && this.selectedEvent.id === evt.id;
      const catClass = `timeline-cat-${evt.category || 'process'}`;
      const activeClass = isSelected ? 'active' : '';

      html += `
        <div class="timeline-event ${escapeAttr(catClass)} ${activeClass}" data-event-id="${escapeAttr(evt.id)}">
          <div class="timeline-time">${escapeHtml(evt.timestamp || '00:00:00')}</div>
          <div>
            <div class="timeline-event-header">
              <span class="timeline-event-title">${escapeHtml(evt.title)}</span>
              <span class="badge ${evt.severity === 'critical' || evt.severity === 'high' ? 'badge-critical' : 'badge-net'}" style="font-size: 8px;">${escapeHtml(evt.category || 'EVENT')}</span>
            </div>
            <div class="timeline-event-detail">${escapeHtml(evt.detail || '')}</div>
          </div>
        </div>
      `;
    }

    this.container.innerHTML = html;

    this.container.querySelectorAll('.timeline-event').forEach(el => {
      el.addEventListener('click', () => {
        const id = el.dataset.eventId;
        const evt = this.events.find(e => e.id === id);
        if (evt) {
          this.selectedEvent = evt;
          this.container.querySelectorAll('.timeline-event').forEach(item => item.classList.remove('active'));
          el.classList.add('active');
          if (this.onSelect) this.onSelect(evt);
        }
      });
    });
  }
}

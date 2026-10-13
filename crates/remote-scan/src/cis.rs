//! CIS-benchmark configuration audit over the read-only command surface.
//!
//! Every check here reaches a verdict **only from a fact actually read off the
//! host** — a directive present in `sshd_config`, a number in `login.defs`, an
//! octal mode from `stat`, an account line in `/etc/passwd`. The zero-false-
//! positive rule is structural:
//!
//! * A check is [`CheckStatus::Fail`] only when the host fact *explicitly* shows
//!   an insecure setting (a directive set to a bad value, a mode more permissive
//!   than required, an account that is definitively wrong).
//! * A check is [`CheckStatus::Pass`] only when the fact explicitly shows the
//!   secure setting.
//! * When a directive is **absent**, the effective value is a compiled default
//!   we cannot observe from the file, so the check is [`CheckStatus::NotConfigured`]
//!   (reported, with the applicable default noted) — never a fail.
//! * When the evidence could **not be read** (the file needs privileges we were
//!   not given, or is empty), the check is [`CheckStatus::NeedsPrivileges`] —
//!   never a fail.
//! * A setting that is only a problem in a site-specific context is
//!   [`CheckStatus::Manual`].
//!
//! So a fail is always backed by the exact evidence printed alongside it, and a
//! gap in what we could read never masquerades as a finding.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};

use crate::command::{CommandRunner, ReadCommand};

/// The verdict of a single check. See the module docs for the certainty policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Fail,
    /// Setting not explicitly configured; relying on a default we cannot see.
    NotConfigured,
    /// Evidence could not be read (privileges, missing file). Never a fail.
    NeedsPrivileges,
    /// Needs human judgement for this host (site-specific).
    Manual,
}

impl CheckStatus {
    fn label(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Fail => "FAIL",
            CheckStatus::NotConfigured => "NOT_CONFIGURED",
            CheckStatus::NeedsPrivileges => "NEEDS_PRIVILEGES",
            CheckStatus::Manual => "MANUAL",
        }
    }
}

/// How much a failed check matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    High,
    Medium,
    Low,
}

/// A compliance framework a check maps to, for the per-standard rollup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    Cis,
    PciDss4,
    Iso27001,
}

impl Framework {
    pub fn label(self) -> &'static str {
        match self {
            Framework::Cis => "CIS",
            Framework::PciDss4 => "PCI DSS 4.0",
            Framework::Iso27001 => "ISO 27001:2022",
        }
    }
}

impl Serialize for Framework {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.label())
    }
}

/// A reference from a check to a control in a compliance framework.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ComplianceRef {
    pub framework: Framework,
    /// The control / requirement identifier within that framework.
    pub control: &'static str,
}

const fn cref(framework: Framework, control: &'static str) -> ComplianceRef {
    ComplianceRef { framework, control }
}

/// One audited control.
#[derive(Debug, Clone, Serialize)]
pub struct CisCheck {
    /// A stable identifier for this check, e.g. `SSH-PERMIT-ROOT-LOGIN`.
    pub id: &'static str,
    /// Human title (Russian, matching the UI).
    pub title: &'static str,
    #[serde(serialize_with = "ser_status")]
    pub status: CheckStatus,
    pub severity: Severity,
    /// The exact host fact the verdict rests on.
    pub evidence: String,
    /// What to change to make a failed check pass.
    pub remediation: &'static str,
    pub references: Vec<ComplianceRef>,
}

fn ser_status<S: Serializer>(status: &CheckStatus, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(status.label())
}

/// Count of checks by verdict, plus a per-framework compliance rollup.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CisSummary {
    pub pass: usize,
    pub fail: usize,
    pub not_configured: usize,
    pub needs_privileges: usize,
    pub manual: usize,
    /// For each framework, how many mapped checks passed out of those that
    /// reached a definite pass/fail verdict (the only ones a percentage can
    /// honestly be computed from).
    pub compliance: Vec<FrameworkScore>,
}

/// Compliance against one framework, computed only from checks that reached a
/// definite pass or fail (NotConfigured/NeedsPrivileges/Manual are excluded, so
/// a percentage never counts something we did not actually determine).
#[derive(Debug, Clone, Serialize)]
pub struct FrameworkScore {
    #[serde(serialize_with = "ser_framework")]
    pub framework: Framework,
    pub passed: usize,
    pub evaluated: usize,
    /// Checks mapped to this framework that could not be evaluated definitely.
    pub undetermined: usize,
    /// passed / evaluated as a percentage, or `None` when nothing was evaluated.
    pub percent: Option<u8>,
}

fn ser_framework<S: Serializer>(framework: &Framework, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(framework.label())
}

/// The full configuration-audit result.
#[derive(Debug, Clone, Serialize)]
pub struct CisReport {
    pub checks: Vec<CisCheck>,
    pub summary: CisSummary,
}

impl CisReport {
    fn from_checks(checks: Vec<CisCheck>) -> Self {
        let mut summary = CisSummary::default();
        for c in &checks {
            match c.status {
                CheckStatus::Pass => summary.pass += 1,
                CheckStatus::Fail => summary.fail += 1,
                CheckStatus::NotConfigured => summary.not_configured += 1,
                CheckStatus::NeedsPrivileges => summary.needs_privileges += 1,
                CheckStatus::Manual => summary.manual += 1,
            }
        }
        summary.compliance = compliance_rollup(&checks);
        Self { checks, summary }
    }
}

fn compliance_rollup(checks: &[CisCheck]) -> Vec<FrameworkScore> {
    [Framework::Cis, Framework::PciDss4, Framework::Iso27001]
        .into_iter()
        .map(|framework| {
            let mut passed = 0usize;
            let mut evaluated = 0usize;
            let mut undetermined = 0usize;
            for c in checks {
                if !c.references.iter().any(|r| r.framework == framework) {
                    continue;
                }
                match c.status {
                    CheckStatus::Pass => {
                        passed += 1;
                        evaluated += 1;
                    }
                    CheckStatus::Fail => evaluated += 1,
                    _ => undetermined += 1,
                }
            }
            let percent = (passed * 100).checked_div(evaluated).map(|p| p as u8);
            FrameworkScore {
                framework,
                passed,
                evaluated,
                undetermined,
                percent,
            }
        })
        .collect()
}

// --- Parsers over the read command output --------------------------------

/// sshd keywords are case-insensitive; a keyword may legitimately appear more
/// than once (and across drop-in files), so we keep every value seen.
#[derive(Default)]
struct SshdConfig {
    /// lowercased keyword -> values, in the order read.
    values: BTreeMap<String, Vec<String>>,
    readable: bool,
}

impl SshdConfig {
    fn parse(text: &str) -> Self {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut any = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            any = true;
            // `Keyword value...` — the keyword is the first token; the rest is
            // the value (sshd allows `=` or whitespace separators).
            let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
            let Some(key) = parts.next() else { continue };
            let value = parts.next().unwrap_or("").trim().to_string();
            values
                .entry(key.to_ascii_lowercase())
                .or_default()
                .push(value);
        }
        SshdConfig {
            values,
            readable: any,
        }
    }

    fn get(&self, key: &str) -> &[String] {
        self.values.get(key).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// `KEY value` pairs from login.defs (comments and blanks skipped).
fn parse_login_defs(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let Some(key) = parts.next() {
            let value = parts.next().unwrap_or("").to_string();
            map.insert(key.to_string(), value);
        }
    }
    map
}

struct PasswdEntry {
    name: String,
    /// The password *field* (the `x`/`*` placeholder or, in the legacy case, an
    /// empty string). Never a hash.
    password_field: String,
    uid: Option<u32>,
}

fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            // Keep legacy NIS markers (`+`/`-`) so a check can flag them.
            entries.push(PasswdEntry {
                name: line.to_string(),
                password_field: String::new(),
                uid: None,
            });
            continue;
        }
        entries.push(PasswdEntry {
            name: fields[0].to_string(),
            password_field: fields[1].to_string(),
            uid: fields[2].parse().ok(),
        });
    }
    entries
}

struct FileMode {
    /// Octal permission bits, e.g. 0o644.
    mode: u32,
    owner: String,
    group: String,
}

/// Parses `stat -c '%n %a %U %G'` lines into path -> mode/owner/group.
fn parse_file_modes(text: &str) -> BTreeMap<String, FileMode> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            continue;
        }
        let Ok(mode) = u32::from_str_radix(parts[1], 8) else {
            continue;
        };
        map.insert(
            parts[0].to_string(),
            FileMode {
                mode,
                owner: parts[2].to_string(),
                group: parts[3].to_string(),
            },
        );
    }
    map
}

// --- Check helpers --------------------------------------------------------

fn parse_uint(values: &[String]) -> Option<u64> {
    values.first().and_then(|v| v.trim().parse().ok())
}

/// Builds a check whose verdict comes from a single sshd keyword that must *not*
/// be set to a given insecure value. `secure` lists the acceptable values.
#[allow(clippy::too_many_arguments)]
fn sshd_enum_check(
    cfg: &SshdConfig,
    id: &'static str,
    title: &'static str,
    severity: Severity,
    keyword: &str,
    secure: &[&str],
    insecure: &[&str],
    default_note: &str,
    remediation: &'static str,
    references: Vec<ComplianceRef>,
) -> CisCheck {
    let (status, evidence) = if !cfg.readable {
        (
            CheckStatus::NeedsPrivileges,
            "файл sshd_config недоступен для чтения".to_string(),
        )
    } else {
        let values = cfg.get(keyword);
        let has_secure = values
            .iter()
            .any(|v| secure.iter().any(|s| v.eq_ignore_ascii_case(s)));
        let has_insecure = values
            .iter()
            .any(|v| insecure.iter().any(|s| v.eq_ignore_ascii_case(s)));
        match (has_secure, has_insecure) {
            // Set insecure and nowhere secure: the only configured value is
            // insecure, so it is effective regardless of file precedence.
            (false, true) => (
                CheckStatus::Fail,
                format!("{keyword} {}", values.join(", ")),
            ),
            (true, false) => (
                CheckStatus::Pass,
                format!("{keyword} {}", values.join(", ")),
            ),
            // Set to conflicting values across files: precedence needs
            // `sshd -T`, which we do not run, so we do not guess.
            (true, true) => (
                CheckStatus::Manual,
                format!(
                    "{keyword} задан в нескольких местах с разными значениями: {}",
                    values.join(", ")
                ),
            ),
            (false, false) if values.is_empty() => (
                CheckStatus::NotConfigured,
                format!("{keyword} не задан; {default_note}"),
            ),
            // Present but an unrecognised value: report, don't guess.
            (false, false) => (
                CheckStatus::Manual,
                format!(
                    "{keyword} {} (значение требует проверки)",
                    values.join(", ")
                ),
            ),
        }
    };
    CisCheck {
        id,
        title,
        status,
        severity,
        evidence,
        remediation,
        references,
    }
}

// --- The checks -----------------------------------------------------------

fn ssh_checks(cfg: &SshdConfig) -> Vec<CisCheck> {
    let ssh_refs = || {
        vec![
            cref(Framework::Cis, "5.1 SSH Server Configuration"),
            cref(Framework::PciDss4, "2.2 Secure configuration"),
            cref(Framework::Iso27001, "A.8.9 Configuration management"),
        ]
    };
    let mut out = vec![
        sshd_enum_check(
            cfg,
            "SSH-PERMIT-ROOT-LOGIN",
            "SSH: вход root запрещён",
            Severity::High,
            "permitrootlogin",
            &["no", "prohibit-password", "without-password"],
            &["yes"],
            "по умолчанию в современном OpenSSH — prohibit-password",
            "Задайте PermitRootLogin no в /etc/ssh/sshd_config и перезапустите sshd.",
            ssh_refs(),
        ),
        sshd_enum_check(
            cfg,
            "SSH-PERMIT-EMPTY-PASSWORDS",
            "SSH: пустые пароли запрещены",
            Severity::High,
            "permitemptypasswords",
            &["no"],
            &["yes"],
            "по умолчанию — no",
            "Задайте PermitEmptyPasswords no в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_enum_check(
            cfg,
            "SSH-HOSTBASED-AUTH",
            "SSH: host-based аутентификация выключена",
            Severity::Medium,
            "hostbasedauthentication",
            &["no"],
            &["yes"],
            "по умолчанию — no",
            "Задайте HostbasedAuthentication no в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_enum_check(
            cfg,
            "SSH-IGNORE-RHOSTS",
            "SSH: .rhosts игнорируются",
            Severity::Medium,
            "ignorerhosts",
            &["yes"],
            &["no"],
            "по умолчанию — yes",
            "Задайте IgnoreRhosts yes в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_enum_check(
            cfg,
            "SSH-X11-FORWARDING",
            "SSH: проброс X11 выключен",
            Severity::Low,
            "x11forwarding",
            &["no"],
            &["yes"],
            "по умолчанию — no",
            "Задайте X11Forwarding no, если графический проброс не нужен.",
            ssh_refs(),
        ),
    ];

    // MaxAuthTries <= 4.
    out.push({
        let values = cfg.get("maxauthtries");
        let (status, evidence) = if !cfg.readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл sshd_config недоступен для чтения".to_string(),
            )
        } else if values.is_empty() {
            (
                CheckStatus::NotConfigured,
                "MaxAuthTries не задан; по умолчанию — 6".to_string(),
            )
        } else if let Some(n) = parse_uint(values) {
            if n <= 4 {
                (CheckStatus::Pass, format!("MaxAuthTries {n}"))
            } else {
                (CheckStatus::Fail, format!("MaxAuthTries {n}"))
            }
        } else {
            (
                CheckStatus::Manual,
                format!("MaxAuthTries {} (не число)", values.join(", ")),
            )
        };
        CisCheck {
            id: "SSH-MAX-AUTH-TRIES",
            title: "SSH: не более 4 попыток входа",
            status,
            severity: Severity::Medium,
            evidence,
            remediation: "Задайте MaxAuthTries 4 (или меньше) в /etc/ssh/sshd_config.",
            references: ssh_refs(),
        }
    });

    // LoginGraceTime <= 60 and > 0.
    out.push({
        let values = cfg.get("logingracetime");
        let (status, evidence) = if !cfg.readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл sshd_config недоступен для чтения".to_string(),
            )
        } else if values.is_empty() {
            (
                CheckStatus::NotConfigured,
                "LoginGraceTime не задан; по умолчанию — 120 секунд".to_string(),
            )
        } else if let Some(n) = parse_uint(values) {
            if (1..=60).contains(&n) {
                (CheckStatus::Pass, format!("LoginGraceTime {n}"))
            } else {
                (CheckStatus::Fail, format!("LoginGraceTime {n}"))
            }
        } else {
            (
                CheckStatus::Manual,
                format!("LoginGraceTime {} (не число)", values.join(", ")),
            )
        };
        CisCheck {
            id: "SSH-LOGIN-GRACE-TIME",
            title: "SSH: окно входа не больше 60 секунд",
            status,
            severity: Severity::Low,
            evidence,
            remediation: "Задайте LoginGraceTime 60 (или меньше) в /etc/ssh/sshd_config.",
            references: ssh_refs(),
        }
    });

    out
}

fn password_policy_checks(defs: &BTreeMap<String, String>, readable: bool) -> Vec<CisCheck> {
    let pw_refs = || {
        vec![
            cref(Framework::Cis, "5.4 User Accounts and Environment"),
            cref(Framework::PciDss4, "8.3.9 Password policy"),
            cref(Framework::Iso27001, "A.5.17 Authentication information"),
        ]
    };

    let numeric_check = |id: &'static str,
                         title: &'static str,
                         severity: Severity,
                         key: &str,
                         ok: &dyn Fn(i64) -> bool,
                         default_note: &str,
                         remediation: &'static str|
     -> CisCheck {
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл /etc/login.defs недоступен".to_string(),
            )
        } else {
            match defs.get(key) {
                None => (
                    CheckStatus::NotConfigured,
                    format!("{key} не задан; {default_note}"),
                ),
                Some(v) => match v.parse::<i64>() {
                    Ok(n) if ok(n) => (CheckStatus::Pass, format!("{key} {n}")),
                    Ok(n) => (CheckStatus::Fail, format!("{key} {n}")),
                    Err(_) => (CheckStatus::Manual, format!("{key} {v} (не число)")),
                },
            }
        };
        CisCheck {
            id,
            title,
            status,
            severity,
            evidence,
            remediation,
            references: pw_refs(),
        }
    };

    let mut out = vec![
        numeric_check(
            "PW-MAX-DAYS",
            "Пароли: максимальный срок не больше 365 дней",
            Severity::Low,
            "PASS_MAX_DAYS",
            &|n| (0..=365).contains(&n),
            "по умолчанию в большинстве систем — 99999 (бессрочно)",
            "Задайте PASS_MAX_DAYS 365 (или меньше) в /etc/login.defs.",
        ),
        numeric_check(
            "PW-MIN-DAYS",
            "Пароли: минимальный срок не меньше 1 дня",
            Severity::Low,
            "PASS_MIN_DAYS",
            &|n| n >= 1,
            "по умолчанию — 0",
            "Задайте PASS_MIN_DAYS 1 (или больше) в /etc/login.defs.",
        ),
        numeric_check(
            "PW-WARN-AGE",
            "Пароли: предупреждение об истечении не меньше 7 дней",
            Severity::Low,
            "PASS_WARN_AGE",
            &|n| n >= 7,
            "по умолчанию — 7",
            "Задайте PASS_WARN_AGE 7 (или больше) в /etc/login.defs.",
        ),
    ];

    // ENCRYPT_METHOD must be a strong hash.
    out.push({
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл /etc/login.defs недоступен".to_string(),
            )
        } else {
            match defs.get("ENCRYPT_METHOD") {
                None => (
                    CheckStatus::NotConfigured,
                    "ENCRYPT_METHOD не задан; хэш определяется PAM".to_string(),
                ),
                Some(v)
                    if v.eq_ignore_ascii_case("SHA512") || v.eq_ignore_ascii_case("YESCRYPT") =>
                {
                    (CheckStatus::Pass, format!("ENCRYPT_METHOD {v}"))
                }
                Some(v) => (CheckStatus::Fail, format!("ENCRYPT_METHOD {v}")),
            }
        };
        CisCheck {
            id: "PW-ENCRYPT-METHOD",
            title: "Пароли: стойкий алгоритм хэширования (SHA512/yescrypt)",
            status,
            severity: Severity::Medium,
            evidence,
            remediation: "Задайте ENCRYPT_METHOD SHA512 (или YESCRYPT) в /etc/login.defs.",
            references: pw_refs(),
        }
    });

    out
}

fn file_mode_checks(modes: &BTreeMap<String, FileMode>, readable: bool) -> Vec<CisCheck> {
    let perm_refs = || {
        vec![
            cref(Framework::Cis, "6.1 System File Permissions"),
            cref(Framework::PciDss4, "7.2 Access control"),
            cref(Framework::Iso27001, "A.8.3 Information access restriction"),
        ]
    };

    // `allowed` is the loosest acceptable mode; any bit outside it fails.
    // `groups` lists acceptable owning groups (owner must be root).
    let perm_check = |id: &'static str,
                      title: &'static str,
                      severity: Severity,
                      path: &str,
                      allowed: u32,
                      groups: &[&str],
                      remediation: &'static str|
     -> CisCheck {
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "не удалось прочитать метаданные (stat)".to_string(),
            )
        } else {
            match modes.get(path) {
                None => (
                    CheckStatus::NeedsPrivileges,
                    format!("{path}: stat не вернул данные (файл отсутствует или недоступен)"),
                ),
                Some(fm) => {
                    let mode_str = format!("{:o}", fm.mode);
                    let extra = fm.mode & !allowed;
                    let owner_ok = fm.owner == "root";
                    let group_ok = groups.contains(&fm.group.as_str());
                    if extra == 0 && owner_ok && group_ok {
                        (
                            CheckStatus::Pass,
                            format!("{path} = {mode_str} {}:{}", fm.owner, fm.group),
                        )
                    } else {
                        (
                            CheckStatus::Fail,
                            format!(
                                "{path} = {mode_str} {}:{} (требуется ≤ {:o}, root:{})",
                                fm.owner,
                                fm.group,
                                allowed,
                                groups.join("/")
                            ),
                        )
                    }
                }
            }
        };
        CisCheck {
            id,
            title,
            status,
            severity,
            evidence,
            remediation,
            references: perm_refs(),
        }
    };

    vec![
        perm_check(
            "PERM-PASSWD",
            "Права /etc/passwd не слабее 644 root:root",
            Severity::Medium,
            "/etc/passwd",
            0o644,
            &["root"],
            "Выполните: chown root:root /etc/passwd && chmod 644 /etc/passwd.",
        ),
        perm_check(
            "PERM-SHADOW",
            "Права /etc/shadow не слабее 640 root:(root|shadow)",
            Severity::High,
            "/etc/shadow",
            0o640,
            &["root", "shadow"],
            "Выполните: chown root:shadow /etc/shadow && chmod 640 /etc/shadow.",
        ),
        perm_check(
            "PERM-GROUP",
            "Права /etc/group не слабее 644 root:root",
            Severity::Low,
            "/etc/group",
            0o644,
            &["root"],
            "Выполните: chown root:root /etc/group && chmod 644 /etc/group.",
        ),
        perm_check(
            "PERM-GSHADOW",
            "Права /etc/gshadow не слабее 640 root:(root|shadow)",
            Severity::Medium,
            "/etc/gshadow",
            0o640,
            &["root", "shadow"],
            "Выполните: chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow.",
        ),
        perm_check(
            "PERM-SSHD-CONFIG",
            "Права /etc/ssh/sshd_config не слабее 600 root:root",
            Severity::Medium,
            "/etc/ssh/sshd_config",
            0o600,
            &["root"],
            "Выполните: chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config.",
        ),
    ]
}

fn account_checks(entries: &[PasswdEntry], readable: bool) -> Vec<CisCheck> {
    let acct_refs = || {
        vec![
            cref(Framework::Cis, "6.2 User and Group Settings"),
            cref(Framework::PciDss4, "8.2 User identification"),
            cref(Framework::Iso27001, "A.8.2 Privileged access rights"),
        ]
    };

    // Exactly one UID-0 account, and it is root.
    let uid0 = {
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл /etc/passwd недоступен".to_string(),
            )
        } else {
            let holders: Vec<&str> = entries
                .iter()
                .filter(|e| e.uid == Some(0))
                .map(|e| e.name.as_str())
                .collect();
            if holders == ["root"] {
                (CheckStatus::Pass, "UID 0 только у root".to_string())
            } else if holders.is_empty() {
                // No parseable UID-0 line at all is unusual; report for review.
                (
                    CheckStatus::Manual,
                    "в /etc/passwd не найден аккаунт с UID 0".to_string(),
                )
            } else {
                (
                    CheckStatus::Fail,
                    format!("UID 0 у нескольких аккаунтов: {}", holders.join(", ")),
                )
            }
        };
        CisCheck {
            id: "ACCT-SINGLE-UID0",
            title: "Аккаунты: UID 0 только у root",
            status,
            severity: Severity::High,
            evidence,
            remediation: "Уберите UID 0 у всех аккаунтов, кроме root, или удалите лишний аккаунт.",
            references: acct_refs(),
        }
    };

    // No account with an empty password *field* in /etc/passwd (legacy
    // no-password accounts). This is a true fact from passwd — no shadow needed.
    let empty_pw = {
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл /etc/passwd недоступен".to_string(),
            )
        } else {
            let bad: Vec<&str> = entries
                .iter()
                .filter(|e| e.uid.is_some() && e.password_field.is_empty())
                .map(|e| e.name.as_str())
                .collect();
            if bad.is_empty() {
                (
                    CheckStatus::Pass,
                    "нет аккаунтов с пустым полем пароля в /etc/passwd".to_string(),
                )
            } else {
                (
                    CheckStatus::Fail,
                    format!("пустое поле пароля в /etc/passwd у: {}", bad.join(", ")),
                )
            }
        };
        CisCheck {
            id: "ACCT-EMPTY-PASSWD-FIELD",
            title: "Аккаунты: нет пустого поля пароля в /etc/passwd",
            status,
            severity: Severity::High,
            evidence,
            remediation:
                "Заблокируйте такие аккаунты (passwd -l) или задайте пароль; поле должно быть x.",
            references: acct_refs(),
        }
    };

    // No legacy NIS `+`/`-` entries.
    let legacy = {
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "файл /etc/passwd недоступен".to_string(),
            )
        } else {
            let bad: Vec<&str> = entries
                .iter()
                .filter(|e| e.name.starts_with('+') || e.name.starts_with('-'))
                .map(|e| e.name.as_str())
                .collect();
            if bad.is_empty() {
                (
                    CheckStatus::Pass,
                    "устаревших записей NIS (+/-) нет".to_string(),
                )
            } else {
                (
                    CheckStatus::Fail,
                    format!("устаревшие записи NIS в /etc/passwd: {}", bad.join(", ")),
                )
            }
        };
        CisCheck {
            id: "ACCT-LEGACY-NIS",
            title: "Аккаунты: нет устаревших записей NIS (+/-)",
            status,
            severity: Severity::Low,
            evidence,
            remediation: "Удалите строки, начинающиеся с + или - из /etc/passwd.",
            references: acct_refs(),
        }
    };

    vec![uid0, empty_pw, legacy]
}

/// Runs the whole CIS configuration audit over `runner`. Each command whose
/// output cannot be read leaves its checks at [`CheckStatus::NeedsPrivileges`],
/// never at a fail.
pub fn audit_cis(runner: &mut dyn CommandRunner) -> CisReport {
    let sshd_text = runner
        .run(ReadCommand::SshdConfig)
        .map(|o| o.stdout)
        .unwrap_or_default();
    let sshd = SshdConfig::parse(&sshd_text);

    let login_text = runner
        .run(ReadCommand::LoginDefs)
        .map(|o| o.stdout)
        .unwrap_or_default();
    let login_readable = login_text.lines().any(|l| !l.trim().is_empty());
    let defs = parse_login_defs(&login_text);

    let passwd_text = runner
        .run(ReadCommand::Passwd)
        .map(|o| o.stdout)
        .unwrap_or_default();
    let passwd_readable = passwd_text.lines().any(|l| !l.trim().is_empty());
    let entries = parse_passwd(&passwd_text);

    let stat_text = runner
        .run(ReadCommand::FileModes)
        .map(|o| o.stdout)
        .unwrap_or_default();
    let stat_readable = stat_text.lines().any(|l| !l.trim().is_empty());
    let modes = parse_file_modes(&stat_text);

    let mut checks = Vec::new();
    checks.extend(ssh_checks(&sshd));
    checks.extend(password_policy_checks(&defs, login_readable));
    checks.extend(file_mode_checks(&modes, stat_readable));
    checks.extend(account_checks(&entries, passwd_readable));

    CisReport::from_checks(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::MapRunner;

    fn find<'a>(report: &'a CisReport, id: &str) -> &'a CisCheck {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("check {id} missing"))
    }

    const HARDENED_SSHD: &str = "\
PermitRootLogin no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 60
";

    const WEAK_SSHD: &str = "\
# a comment
PermitRootLogin yes
PermitEmptyPasswords yes
MaxAuthTries 10
LoginGraceTime 120
X11Forwarding yes
";

    const HARDENED_LOGIN_DEFS: &str = "\
PASS_MAX_DAYS 365
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
ENCRYPT_METHOD SHA512
";

    const GOOD_STAT: &str = "\
/etc/passwd 644 root root
/etc/shadow 640 root shadow
/etc/group 644 root root
/etc/gshadow 640 root shadow
/etc/ssh/sshd_config 600 root root
";

    const GOOD_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
";

    fn runner(sshd: &str, defs: &str, stat: &str, passwd: &str) -> MapRunner {
        MapRunner::new()
            .with(ReadCommand::SshdConfig, sshd)
            .with(ReadCommand::LoginDefs, defs)
            .with(ReadCommand::FileModes, stat)
            .with(ReadCommand::Passwd, passwd)
    }

    #[test]
    fn a_fully_hardened_host_passes_everything_definite() {
        let mut r = runner(HARDENED_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        let report = audit_cis(&mut r);
        // Nothing may fail on a hardened host — the core zero-FP guarantee.
        assert_eq!(report.summary.fail, 0, "hardened host produced a FAIL");
        assert_eq!(
            find(&report, "SSH-PERMIT-ROOT-LOGIN").status,
            CheckStatus::Pass
        );
        assert_eq!(find(&report, "PW-MAX-DAYS").status, CheckStatus::Pass);
        assert_eq!(find(&report, "PERM-SHADOW").status, CheckStatus::Pass);
        assert_eq!(find(&report, "ACCT-SINGLE-UID0").status, CheckStatus::Pass);
    }

    #[test]
    fn explicit_weak_settings_fail_with_evidence() {
        let mut r = runner(WEAK_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        let report = audit_cis(&mut r);

        let root = find(&report, "SSH-PERMIT-ROOT-LOGIN");
        assert_eq!(root.status, CheckStatus::Fail);
        assert!(root.evidence.contains("yes"), "evidence: {}", root.evidence);

        assert_eq!(
            find(&report, "SSH-PERMIT-EMPTY-PASSWORDS").status,
            CheckStatus::Fail
        );
        assert_eq!(
            find(&report, "SSH-MAX-AUTH-TRIES").status,
            CheckStatus::Fail
        );
        assert!(find(&report, "SSH-MAX-AUTH-TRIES").evidence.contains("10"));
        assert_eq!(
            find(&report, "SSH-LOGIN-GRACE-TIME").status,
            CheckStatus::Fail
        );
    }

    #[test]
    fn absent_sshd_directive_is_not_configured_never_fail() {
        // Only PermitRootLogin is set; everything else is absent and must be
        // NOT_CONFIGURED, never a fabricated FAIL.
        let mut r = runner(
            "PermitRootLogin no\n",
            HARDENED_LOGIN_DEFS,
            GOOD_STAT,
            GOOD_PASSWD,
        );
        let report = audit_cis(&mut r);
        assert_eq!(
            find(&report, "SSH-X11-FORWARDING").status,
            CheckStatus::NotConfigured
        );
        assert_eq!(
            find(&report, "SSH-MAX-AUTH-TRIES").status,
            CheckStatus::NotConfigured
        );
        assert_eq!(report.summary.fail, 0);
    }

    #[test]
    fn unreadable_files_need_privileges_never_fail() {
        // sshd/login.defs/stat/passwd all empty (e.g. permission denied): every
        // check must be NEEDS_PRIVILEGES, and nothing may fail.
        let mut r = runner("", "", "", "");
        let report = audit_cis(&mut r);
        assert_eq!(report.summary.fail, 0);
        assert!(report.summary.needs_privileges >= 10);
        assert_eq!(
            find(&report, "PERM-SHADOW").status,
            CheckStatus::NeedsPrivileges
        );
        assert_eq!(
            find(&report, "ACCT-SINGLE-UID0").status,
            CheckStatus::NeedsPrivileges
        );
    }

    #[test]
    fn extra_uid0_account_fails_and_names_it() {
        let passwd = format!("{GOOD_PASSWD}backdoor:x:0:0::/root:/bin/bash\n");
        let mut r = runner(HARDENED_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, &passwd);
        let report = audit_cis(&mut r);
        let c = find(&report, "ACCT-SINGLE-UID0");
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.evidence.contains("backdoor"), "evidence: {}", c.evidence);
    }

    #[test]
    fn world_readable_shadow_fails() {
        let stat = GOOD_STAT.replace("/etc/shadow 640 root shadow", "/etc/shadow 644 root shadow");
        let mut r = runner(HARDENED_SSHD, HARDENED_LOGIN_DEFS, &stat, GOOD_PASSWD);
        let report = audit_cis(&mut r);
        let c = find(&report, "PERM-SHADOW");
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.evidence.contains("644"));
    }

    #[test]
    fn conflicting_sshd_values_are_manual_not_guessed() {
        // PermitRootLogin set both yes and no across files: precedence needs
        // sshd -T, so we must not guess — Manual, not Pass or Fail.
        let mut r = runner(
            "PermitRootLogin yes\nPermitRootLogin no\n",
            HARDENED_LOGIN_DEFS,
            GOOD_STAT,
            GOOD_PASSWD,
        );
        let report = audit_cis(&mut r);
        assert_eq!(
            find(&report, "SSH-PERMIT-ROOT-LOGIN").status,
            CheckStatus::Manual
        );
    }

    #[test]
    fn compliance_percent_only_counts_definite_checks() {
        let mut r = runner(WEAK_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        let report = audit_cis(&mut r);
        let cis = report
            .summary
            .compliance
            .iter()
            .find(|f| f.framework == Framework::Cis)
            .unwrap();
        // Every check maps to CIS, so CIS's evaluated set is exactly the
        // pass+fail checks — NOT_CONFIGURED/NEEDS_PRIVILEGES/MANUAL are excluded.
        assert_eq!(cis.passed, report.summary.pass);
        assert_eq!(cis.evaluated, report.summary.pass + report.summary.fail);
        // Some SSH checks fail, so compliance is below 100.
        assert!(report.summary.fail > 0);
        assert!(cis.percent.unwrap() < 100);
    }
}

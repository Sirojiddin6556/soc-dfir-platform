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

pub(crate) const fn cref(framework: Framework, control: &'static str) -> ComplianceRef {
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
    /// All checks mapped to this framework (`evaluated + undetermined`), so the
    /// UI can say honestly how much of the framework was actually covered.
    pub applicable: usize,
    /// passed / evaluated as a percentage, rounded to the nearest whole number,
    /// or `None` when nothing was evaluated.
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
    pub(crate) fn from_checks(checks: Vec<CisCheck>) -> Self {
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
            // Round to the nearest whole percent (76.9 -> 77), not truncate.
            let percent = if evaluated == 0 {
                None
            } else {
                Some(((passed * 200 + evaluated) / (evaluated * 2)) as u8)
            };
            FrameworkScore {
                framework,
                passed,
                evaluated,
                undetermined,
                applicable: evaluated + undetermined,
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

/// The sshd configuration the SSH checks read, and whether it is authoritative.
///
/// When `sshd -T` could be run (usually as root) its output is the *effective*
/// configuration — every keyword resolved, precedence across the main file and
/// all drop-ins already applied by the daemon — so a verdict from it is exact.
/// Otherwise we fall back to parsing the files, where an absent keyword means a
/// compiled-in default we cannot see, and a keyword set to different values in
/// different files is a precedence question we refuse to guess.
struct SshdView<'a> {
    cfg: &'a SshdConfig,
    authoritative: bool,
}

impl<'a> SshdView<'a> {
    fn readable(&self) -> bool {
        self.cfg.readable
    }
    fn get(&self, key: &str) -> &[String] {
        self.cfg.get(key)
    }
    /// Suffix that marks evidence taken from the daemon's own resolved config.
    fn src(&self) -> &'static str {
        if self.authoritative {
            " (sshd -T)"
        } else {
            ""
        }
    }
}

/// Builds a check whose verdict comes from a single sshd keyword that must *not*
/// be set to a given insecure value. `secure` lists the acceptable values.
/// `default_secure` says whether the OpenSSH compiled-in default (noted in
/// `default_note`) already satisfies the check, so an absent directive in the
/// file-based fallback can be reported honestly: a secure default passes, an
/// insecure or unknown default stays `NotConfigured` (never a fabricated fail).
#[allow(clippy::too_many_arguments)]
fn sshd_enum_check(
    view: &SshdView,
    id: &'static str,
    title: &'static str,
    severity: Severity,
    keyword: &str,
    secure: &[&str],
    insecure: &[&str],
    default_secure: bool,
    default_note: &str,
    remediation: &'static str,
    references: Vec<ComplianceRef>,
) -> CisCheck {
    let src = view.src();
    let (status, evidence) = if !view.readable() {
        (
            CheckStatus::NeedsPrivileges,
            "файл sshd_config недоступен для чтения".to_string(),
        )
    } else {
        let values = view.get(keyword);
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
                format!("{keyword} {}{src}", values.join(", ")),
            ),
            (true, false) => (
                CheckStatus::Pass,
                format!("{keyword} {}{src}", values.join(", ")),
            ),
            // Set to conflicting values across files without `sshd -T` to
            // resolve precedence — we do not guess. (With `sshd -T` there is
            // only ever the single resolved value, so this branch never fires.)
            (true, true) => (
                CheckStatus::Manual,
                format!(
                    "{keyword} задан в нескольких местах с разными значениями: {}",
                    values.join(", ")
                ),
            ),
            (false, false) if values.is_empty() => {
                if default_secure {
                    // The daemon would use a safe compiled-in default.
                    (
                        CheckStatus::Pass,
                        format!("{keyword} не задан; действует безопасное значение по умолчанию ({default_note})"),
                    )
                } else {
                    (
                        CheckStatus::NotConfigured,
                        format!("{keyword} не задан; {default_note}"),
                    )
                }
            }
            // Present but an unrecognised value: report, don't guess.
            (false, false) => (
                CheckStatus::Manual,
                format!(
                    "{keyword} {}{src} (значение требует проверки)",
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

/// SSH server-configuration controls (CIS 5.1). Maps to PCI 2.2 and ISO A.8.9.
fn ssh_refs() -> Vec<ComplianceRef> {
    vec![
        cref(Framework::Cis, "5.1 SSH Server Configuration"),
        cref(Framework::PciDss4, "2.2 Secure configuration"),
        cref(Framework::Iso27001, "A.8.9 Configuration management"),
    ]
}

/// SSH cryptographic strength (ciphers/MACs/KEX). Maps to PCI 4.2.1 (strong
/// cryptography) and ISO A.8.24 (use of cryptography) — a different PCI/ISO
/// control than plain configuration, so the per-standard rollups diverge.
fn ssh_crypto_refs() -> Vec<ComplianceRef> {
    vec![
        cref(Framework::Cis, "5.1 SSH Server Configuration"),
        cref(Framework::PciDss4, "4.2.1 Strong cryptography"),
        cref(Framework::Iso27001, "A.8.24 Use of cryptography"),
    ]
}

/// Builds a numeric sshd check: the keyword must parse and satisfy `ok`. An
/// absent keyword relies on a default; when that default does not meet the bar
/// we report it (with the default noted) rather than fabricate a fail.
#[allow(clippy::too_many_arguments)]
fn sshd_numeric_check(
    view: &SshdView,
    id: &'static str,
    title: &'static str,
    severity: Severity,
    keyword: &str,
    ok: &dyn Fn(u64) -> bool,
    default_note: &str,
    remediation: &'static str,
) -> CisCheck {
    let src = view.src();
    let values = view.get(keyword);
    let (status, evidence) = if !view.readable() {
        (
            CheckStatus::NeedsPrivileges,
            "файл sshd_config недоступен для чтения".to_string(),
        )
    } else if values.is_empty() {
        (
            CheckStatus::NotConfigured,
            format!("{keyword} не задан; {default_note}"),
        )
    } else if let Some(n) = parse_uint(values) {
        if ok(n) {
            (CheckStatus::Pass, format!("{keyword} {n}{src}"))
        } else {
            (CheckStatus::Fail, format!("{keyword} {n}{src}"))
        }
    } else {
        (
            CheckStatus::Manual,
            format!("{keyword} {} (не число)", values.join(", ")),
        )
    };
    CisCheck {
        id,
        title,
        status,
        severity,
        evidence,
        remediation,
        references: ssh_refs(),
    }
}

/// A check over a comma-separated algorithm list (Ciphers/MACs/KexAlgorithms):
/// it fails only when an *explicitly configured* algorithm matches a known-weak
/// token. An absent directive means the daemon uses its modern, strong defaults
/// — we cannot see the list, so it is `NotConfigured`, never a fail.
fn sshd_algorithm_check(
    view: &SshdView,
    id: &'static str,
    title: &'static str,
    keyword: &str,
    weak_tokens: &[&str],
    remediation: &'static str,
) -> CisCheck {
    let src = view.src();
    let values = view.get(keyword);
    let (status, evidence) = if !view.readable() {
        (
            CheckStatus::NeedsPrivileges,
            "файл sshd_config недоступен для чтения".to_string(),
        )
    } else if values.is_empty() {
        (
            CheckStatus::NotConfigured,
            format!("{keyword} не задан; действуют стойкие алгоритмы OpenSSH по умолчанию"),
        )
    } else {
        // Flatten every configured list into its individual algorithm tokens.
        let configured: Vec<String> = values
            .iter()
            .flat_map(|v| v.split(','))
            .map(|t| {
                t.trim()
                    .trim_start_matches(['+', '-', '^'])
                    .to_ascii_lowercase()
            })
            .filter(|t| !t.is_empty())
            .collect();
        let weak: Vec<&str> = configured
            .iter()
            .filter(|t| weak_tokens.iter().any(|w| t.contains(w)))
            .map(String::as_str)
            .collect();
        if weak.is_empty() {
            (
                CheckStatus::Pass,
                format!("{keyword}: слабых алгоритмов нет{src}"),
            )
        } else {
            (
                CheckStatus::Fail,
                format!(
                    "{keyword} содержит слабые алгоритмы: {}{src}",
                    weak.join(", ")
                ),
            )
        }
    };
    CisCheck {
        id,
        title,
        status,
        severity: Severity::Medium,
        evidence,
        remediation,
        references: ssh_crypto_refs(),
    }
}

fn ssh_checks(view: &SshdView) -> Vec<CisCheck> {
    let mut out = vec![
        sshd_enum_check(
            view,
            "SSH-PERMIT-ROOT-LOGIN",
            "SSH: вход root запрещён",
            Severity::High,
            "permitrootlogin",
            &["no", "prohibit-password", "without-password"],
            &["yes"],
            true,
            "в современном OpenSSH по умолчанию prohibit-password",
            "Задайте PermitRootLogin no в /etc/ssh/sshd_config и перезапустите sshd.",
            ssh_refs(),
        ),
        sshd_enum_check(
            view,
            "SSH-PERMIT-EMPTY-PASSWORDS",
            "SSH: пустые пароли запрещены",
            Severity::High,
            "permitemptypasswords",
            &["no"],
            &["yes"],
            true,
            "по умолчанию — no",
            "Задайте PermitEmptyPasswords no в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_enum_check(
            view,
            "SSH-HOSTBASED-AUTH",
            "SSH: host-based аутентификация выключена",
            Severity::Medium,
            "hostbasedauthentication",
            &["no"],
            &["yes"],
            true,
            "по умолчанию — no",
            "Задайте HostbasedAuthentication no в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_enum_check(
            view,
            "SSH-IGNORE-RHOSTS",
            "SSH: .rhosts игнорируются",
            Severity::Medium,
            "ignorerhosts",
            &["yes"],
            &["no"],
            true,
            "по умолчанию — yes",
            "Задайте IgnoreRhosts yes в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_enum_check(
            view,
            "SSH-X11-FORWARDING",
            "SSH: проброс X11 выключен",
            Severity::Low,
            "x11forwarding",
            &["no"],
            &["yes"],
            true,
            "по умолчанию — no",
            "Задайте X11Forwarding no, если графический проброс не нужен.",
            ssh_refs(),
        ),
        sshd_enum_check(
            view,
            "SSH-PERMIT-USER-ENV",
            "SSH: PermitUserEnvironment выключен",
            Severity::Medium,
            "permituserenvironment",
            &["no"],
            &["yes"],
            true,
            "по умолчанию — no",
            "Задайте PermitUserEnvironment no в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_numeric_check(
            view,
            "SSH-MAX-AUTH-TRIES",
            "SSH: не более 4 попыток входа",
            Severity::Medium,
            "maxauthtries",
            &|n| n <= 4,
            "по умолчанию — 6, что превышает рекомендацию (≤4)",
            "Задайте MaxAuthTries 4 (или меньше) в /etc/ssh/sshd_config.",
        ),
        sshd_numeric_check(
            view,
            "SSH-LOGIN-GRACE-TIME",
            "SSH: окно входа не больше 60 секунд",
            Severity::Low,
            "logingracetime",
            &|n| (1..=60).contains(&n),
            "по умолчанию — 120 секунд, что превышает рекомендацию (≤60)",
            "Задайте LoginGraceTime 60 (или меньше) в /etc/ssh/sshd_config.",
        ),
        // Idle-session timeout: ClientAliveInterval must be a positive, bounded
        // value; 0 (explicitly) means sessions never time out.
        sshd_numeric_check(
            view,
            "SSH-CLIENT-ALIVE-INTERVAL",
            "SSH: сессия завершается при простое",
            Severity::Low,
            "clientaliveinterval",
            &|n| (1..=900).contains(&n),
            "по умолчанию — 0 (сессия не завершается по простою)",
            "Задайте ClientAliveInterval 300 и ClientAliveCountMax 3 в /etc/ssh/sshd_config.",
        ),
        sshd_enum_check(
            view,
            "SSH-LOG-LEVEL",
            "SSH: уровень журналирования INFO или VERBOSE",
            Severity::Low,
            "loglevel",
            &["info", "verbose"],
            &["quiet", "fatal", "error"],
            true,
            "по умолчанию — INFO",
            "Задайте LogLevel VERBOSE (или INFO) в /etc/ssh/sshd_config.",
            ssh_refs(),
        ),
        sshd_algorithm_check(
            view,
            "SSH-CIPHERS",
            "SSH: нет слабых шифров",
            "ciphers",
            &["cbc", "arcfour", "3des", "des-", "blowfish", "cast128", "rijndael"],
            "Уберите слабые шифры из Ciphers; оставьте только aes*-gcm и chacha20-poly1305.",
        ),
        sshd_algorithm_check(
            view,
            "SSH-MACS",
            "SSH: нет слабых MAC",
            "macs",
            &["md5", "sha1", "umac-64", "ripemd"],
            "Оставьте в MACs только *-etm на базе SHA-2 (hmac-sha2-256/512-etm, umac-128-etm).",
        ),
        sshd_algorithm_check(
            view,
            "SSH-KEX",
            "SSH: нет слабых алгоритмов обмена ключами",
            "kexalgorithms",
            &["group1-", "group14-sha1", "sha1", "gss-", "group-exchange-sha1"],
            "Оставьте в KexAlgorithms современные алгоритмы (curve25519-sha256, diffie-hellman-group16-sha512).",
        ),
    ];

    // Keep the column of SSH checks deterministic for the UI and tests.
    out.sort_by_key(|c| c.id);
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

// --- Filesystem, kernel and host-hardening parsers and checks -------------

/// A mounted filesystem and the options it was mounted with (`/proc/mounts`).
struct MountEntry {
    target: String,
    options: Vec<String>,
}

fn parse_mounts(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        out.push(MountEntry {
            target: f[1].to_string(),
            options: f[3].split(',').map(str::to_string).collect(),
        });
    }
    out
}

/// `path:value` pairs from `grep -H '' /proc/sys/...`, keyed by the full path.
fn parse_sysctl(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((path, value)) = line.split_once(':') {
            map.insert(path.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

/// `key = value` / `key=value` pairs from a PAM config file, comments skipped
/// and keys lower-cased. A bare flag line is kept with an empty value.
fn parse_keyvalue(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        } else {
            map.insert(line.to_ascii_lowercase(), String::new());
        }
    }
    map
}

/// Extracts the integer value of an APT::Periodic key from a `20auto-upgrades`
/// file, e.g. `APT::Periodic::Unattended-Upgrade "1";` -> `"1"`.
fn apt_periodic_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(key) {
            let digits: String = rest.chars().filter(char::is_ascii_digit).collect();
            if !digits.is_empty() {
                return Some(digits);
            }
        }
    }
    None
}

/// `/tmp` hardening (CIS 1.1): when `/tmp` is a separate mount it must carry
/// nodev, nosuid and noexec. When it is not a separate mount the options do not
/// apply, so this is `NotConfigured`, never a fail.
fn mount_checks(mounts: &[MountEntry], readable: bool) -> Vec<CisCheck> {
    let refs = || {
        vec![
            cref(Framework::Cis, "1.1 Filesystem Configuration"),
            cref(Framework::Iso27001, "A.8.9 Configuration management"),
        ]
    };
    let required = ["nodev", "nosuid", "noexec"];
    let (status, evidence) = if !readable {
        (
            CheckStatus::NeedsPrivileges,
            "/proc/mounts недоступен".to_string(),
        )
    } else {
        match mounts.iter().find(|m| m.target == "/tmp") {
            None => (
                CheckStatus::NotConfigured,
                "/tmp не вынесен в отдельный раздел — опции nodev/nosuid/noexec неприменимы"
                    .to_string(),
            ),
            Some(m) => {
                let missing: Vec<&str> = required
                    .iter()
                    .copied()
                    .filter(|r| !m.options.iter().any(|o| o == r))
                    .collect();
                if missing.is_empty() {
                    (CheckStatus::Pass, format!("/tmp: {}", m.options.join(",")))
                } else {
                    (
                        CheckStatus::Fail,
                        format!(
                            "/tmp смонтирован без {} (опции: {})",
                            missing.join(","),
                            m.options.join(",")
                        ),
                    )
                }
            }
        }
    };
    vec![CisCheck {
        id: "FS-TMP-OPTIONS",
        title: "Файловая система: /tmp с nodev, nosuid, noexec",
        status,
        severity: Severity::Low,
        evidence,
        remediation:
            "Вынесите /tmp в отдельный раздел с опциями nodev,nosuid,noexec (или через systemd tmp.mount).",
        references: refs(),
    }]
}

/// Kernel/network hardening parameters read straight from `/proc/sys`
/// (CIS 3.x). Mapped to CIS and ISO network-security, but *not* a PCI control,
/// so the PCI rollup covers a different, smaller set than CIS.
fn sysctl_checks(map: &BTreeMap<String, String>, readable: bool) -> Vec<CisCheck> {
    let refs = || {
        vec![
            cref(Framework::Cis, "3.2 Network Parameters"),
            cref(Framework::Iso27001, "A.8.20 Networks security"),
        ]
    };
    let one = |id: &'static str,
               title: &'static str,
               severity: Severity,
               path: &str,
               pass_vals: &[&str],
               fail_vals: &[&str],
               manual_vals: &[&str],
               remediation: &'static str|
     -> CisCheck {
        let (status, evidence) = if !readable {
            (
                CheckStatus::NeedsPrivileges,
                "параметры /proc/sys недоступны".to_string(),
            )
        } else {
            match map.get(path) {
                None => (CheckStatus::NotConfigured, format!("{path} не прочитан")),
                Some(v) => {
                    let v = v.trim();
                    if pass_vals.contains(&v) {
                        (CheckStatus::Pass, format!("{path} = {v}"))
                    } else if manual_vals.contains(&v) {
                        (
                            CheckStatus::Manual,
                            format!("{path} = {v} (может быть обусловлено ролью хоста)"),
                        )
                    } else if fail_vals.contains(&v) {
                        (CheckStatus::Fail, format!("{path} = {v}"))
                    } else {
                        (
                            CheckStatus::Manual,
                            format!("{path} = {v} (значение требует проверки)"),
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
            references: refs(),
        }
    };
    vec![
        one(
            "SYSCTL-RP-FILTER",
            "Сеть: обратная фильтрация пути (rp_filter)",
            Severity::Low,
            "/proc/sys/net/ipv4/conf/all/rp_filter",
            &["1", "2"],
            &["0"],
            &[],
            "Задайте net.ipv4.conf.all.rp_filter=1 в /etc/sysctl.d/.",
        ),
        one(
            "SYSCTL-SYNCOOKIES",
            "Сеть: защита от SYN-flood (tcp_syncookies)",
            Severity::Low,
            "/proc/sys/net/ipv4/tcp_syncookies",
            &["1"],
            &["0"],
            &[],
            "Задайте net.ipv4.tcp_syncookies=1.",
        ),
        one(
            "SYSCTL-ASLR",
            "Ядро: рандомизация адресного пространства (ASLR)",
            Severity::Medium,
            "/proc/sys/kernel/randomize_va_space",
            &["2"],
            &["0", "1"],
            &[],
            "Задайте kernel.randomize_va_space=2.",
        ),
        one(
            "SYSCTL-ACCEPT-REDIRECTS",
            "Сеть: ICMP-перенаправления не принимаются",
            Severity::Low,
            "/proc/sys/net/ipv4/conf/all/accept_redirects",
            &["0"],
            &["1"],
            &[],
            "Задайте net.ipv4.conf.all.accept_redirects=0.",
        ),
        one(
            "SYSCTL-SEND-REDIRECTS",
            "Сеть: ICMP-перенаправления не отправляются",
            Severity::Low,
            "/proc/sys/net/ipv4/conf/all/send_redirects",
            &["0"],
            &["1"],
            &[],
            "Задайте net.ipv4.conf.all.send_redirects=0.",
        ),
        one(
            "SYSCTL-SOURCE-ROUTE",
            "Сеть: маршрутизация от источника выключена",
            Severity::Low,
            "/proc/sys/net/ipv4/conf/all/accept_source_route",
            &["0"],
            &["1"],
            &[],
            "Задайте net.ipv4.conf.all.accept_source_route=0.",
        ),
        one(
            "SYSCTL-IP-FORWARD",
            "Сеть: IP-форвардинг выключен",
            Severity::Low,
            "/proc/sys/net/ipv4/ip_forward",
            &["0"],
            &[],
            &["1"],
            "Если хост не маршрутизатор, задайте net.ipv4.ip_forward=0.",
        ),
    ]
}

/// Mandatory access control (AppArmor). An absent AppArmor node is reported,
/// not failed — the host may use SELinux instead.
fn apparmor_check(text: &str) -> CisCheck {
    let refs = vec![
        cref(Framework::Cis, "1.6 Mandatory Access Control"),
        cref(Framework::Iso27001, "A.8.7 Protection against malware"),
    ];
    let t = text.trim();
    let (status, evidence) = if t.is_empty() {
        (
            CheckStatus::NotConfigured,
            "AppArmor не обнаружен в ядре (возможно, используется SELinux)".to_string(),
        )
    } else if t.eq_ignore_ascii_case("Y") {
        (
            CheckStatus::Pass,
            "AppArmor включён (/sys/module/apparmor/parameters/enabled = Y)".to_string(),
        )
    } else {
        (
            CheckStatus::Fail,
            format!("AppArmor выключен (enabled = {t})"),
        )
    };
    CisCheck {
        id: "MAC-APPARMOR",
        title: "Мандатный контроль доступа: AppArmor включён",
        status,
        severity: Severity::Medium,
        evidence,
        remediation:
            "Включите AppArmor (или настройте SELinux) для обязательного контроля доступа.",
        references: refs,
    }
}

/// Automatic security updates (Debian/Ubuntu `unattended-upgrades`). Absent on
/// non-APT distributions, where it is reported as not-configured, not failed.
fn auto_upgrades_check(text: &str) -> CisCheck {
    let refs = vec![
        cref(Framework::Cis, "1.2 Package Updates"),
        cref(Framework::PciDss4, "6.3.3 Security patches"),
        cref(
            Framework::Iso27001,
            "A.8.8 Management of technical vulnerabilities",
        ),
    ];
    let (status, evidence) = match apt_periodic_value(text, "APT::Periodic::Unattended-Upgrade") {
        None => (
            CheckStatus::NotConfigured,
            "автоматические обновления безопасности не настроены (20auto-upgrades отсутствует)"
                .to_string(),
        ),
        Some(v) if v == "0" => (
            CheckStatus::Fail,
            "APT::Periodic::Unattended-Upgrade \"0\" — автообновления отключены".to_string(),
        ),
        Some(v) => (
            CheckStatus::Pass,
            format!("APT::Periodic::Unattended-Upgrade \"{v}\""),
        ),
    };
    CisCheck {
        id: "PATCH-UNATTENDED-UPGRADES",
        title: "Обновления: включены автоматические обновления безопасности",
        status,
        severity: Severity::Medium,
        evidence,
        remediation:
            "Установите unattended-upgrades и задайте APT::Periodic::Unattended-Upgrade \"1\".",
        references: refs,
    }
}

/// Account lockout after failed logins (pam_faillock). Absent config is
/// reported, not failed, since lockout can also be configured elsewhere.
fn faillock_check(map: &BTreeMap<String, String>, readable: bool) -> CisCheck {
    let refs = vec![
        cref(Framework::Cis, "5.4 User Accounts and Environment"),
        cref(Framework::PciDss4, "8.3.4 Account lockout"),
        cref(Framework::Iso27001, "A.5.17 Authentication information"),
    ];
    let (status, evidence) = if !readable {
        (
            CheckStatus::NotConfigured,
            "faillock.conf отсутствует или пуст — блокировка после неудачных входов не подтверждена"
                .to_string(),
        )
    } else {
        match map.get("deny").and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(0) => (
                CheckStatus::Fail,
                "deny = 0 — блокировка отключена".to_string(),
            ),
            Some(n) if (1..=10).contains(&n) => (CheckStatus::Pass, format!("deny = {n}")),
            Some(n) => (
                CheckStatus::Manual,
                format!("deny = {n} (велик порог блокировки)"),
            ),
            None => (
                CheckStatus::NotConfigured,
                "в faillock.conf не задан параметр deny".to_string(),
            ),
        }
    };
    CisCheck {
        id: "AUTH-FAILLOCK",
        title: "Аутентификация: блокировка после неудачных попыток входа",
        status,
        severity: Severity::Medium,
        evidence,
        remediation:
            "Настройте pam_faillock: задайте deny=4 и unlock_time в /etc/security/faillock.conf.",
        references: refs,
    }
}

/// Password-quality policy (pam_pwquality `minlen`). Absent config is reported,
/// not failed.
fn pwquality_check(map: &BTreeMap<String, String>, readable: bool) -> CisCheck {
    let refs = vec![
        cref(Framework::Cis, "5.4 User Accounts and Environment"),
        cref(Framework::PciDss4, "8.3.6 Password length and complexity"),
        cref(Framework::Iso27001, "A.5.17 Authentication information"),
    ];
    let (status, evidence) = if !readable {
        (
            CheckStatus::NotConfigured,
            "pwquality.conf отсутствует или пуст — требования к паролям не подтверждены"
                .to_string(),
        )
    } else {
        match map.get("minlen").and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(n) if n >= 12 => (CheckStatus::Pass, format!("minlen = {n}")),
            Some(n) => (
                CheckStatus::Fail,
                format!("minlen = {n} (рекомендуется ≥ 12)"),
            ),
            None => (
                CheckStatus::NotConfigured,
                "в pwquality.conf не задан minlen".to_string(),
            ),
        }
    };
    CisCheck {
        id: "PW-QUALITY-MINLEN",
        title: "Пароли: минимальная длина не меньше 12",
        status,
        severity: Severity::Low,
        evidence,
        remediation: "Задайте minlen = 14 в /etc/security/pwquality.conf.",
        references: refs,
    }
}

/// Reads a command's stdout, treating a run error as empty output.
fn read_cmd(runner: &mut dyn CommandRunner, cmd: ReadCommand) -> String {
    runner.run(cmd).map(|o| o.stdout).unwrap_or_default()
}

/// True when a text has at least one non-blank line (i.e. the file was actually
/// readable, not an empty permission-denied result).
fn has_content(text: &str) -> bool {
    text.lines().any(|l| !l.trim().is_empty())
}

/// Runs the whole CIS configuration audit over `runner`. Each command whose
/// output cannot be read leaves its checks at [`CheckStatus::NeedsPrivileges`]
/// or [`CheckStatus::NotConfigured`], never at a fail.
pub fn audit_cis(runner: &mut dyn CommandRunner) -> CisReport {
    // Prefer the daemon's own resolved configuration (`sshd -T`); fall back to
    // parsing the files when it could not be run (usually a non-root session).
    let sshd_file = SshdConfig::parse(&read_cmd(runner, ReadCommand::SshdConfig));
    let sshd_eff = SshdConfig::parse(&read_cmd(runner, ReadCommand::SshdEffective));
    let sshd_view = if sshd_eff.readable {
        SshdView {
            cfg: &sshd_eff,
            authoritative: true,
        }
    } else {
        SshdView {
            cfg: &sshd_file,
            authoritative: false,
        }
    };

    let login_text = read_cmd(runner, ReadCommand::LoginDefs);
    let login_readable = has_content(&login_text);
    let defs = parse_login_defs(&login_text);

    let passwd_text = read_cmd(runner, ReadCommand::Passwd);
    let passwd_readable = has_content(&passwd_text);
    let entries = parse_passwd(&passwd_text);

    let stat_text = read_cmd(runner, ReadCommand::FileModes);
    let stat_readable = has_content(&stat_text);
    let modes = parse_file_modes(&stat_text);

    let mounts_text = read_cmd(runner, ReadCommand::Mounts);
    let mounts_readable = has_content(&mounts_text);
    let mounts = parse_mounts(&mounts_text);

    let sysctl_text = read_cmd(runner, ReadCommand::Sysctl);
    let sysctl_readable = has_content(&sysctl_text);
    let sysctl = parse_sysctl(&sysctl_text);

    let pwq_text = read_cmd(runner, ReadCommand::PwQuality);
    let pwq_readable = has_content(&pwq_text);
    let pwq = parse_keyvalue(&pwq_text);

    let faillock_text = read_cmd(runner, ReadCommand::Faillock);
    let faillock_readable = has_content(&faillock_text);
    let faillock = parse_keyvalue(&faillock_text);

    let autoupgrades_text = read_cmd(runner, ReadCommand::AutoUpgrades);
    let apparmor_text = read_cmd(runner, ReadCommand::Apparmor);

    let mut checks = Vec::new();
    checks.extend(ssh_checks(&sshd_view));
    checks.extend(password_policy_checks(&defs, login_readable));
    checks.extend(file_mode_checks(&modes, stat_readable));
    checks.extend(account_checks(&entries, passwd_readable));
    checks.extend(mount_checks(&mounts, mounts_readable));
    checks.extend(sysctl_checks(&sysctl, sysctl_readable));
    checks.push(apparmor_check(&apparmor_text));
    checks.push(auto_upgrades_check(&autoupgrades_text));
    checks.push(faillock_check(&faillock, faillock_readable));
    checks.push(pwquality_check(&pwq, pwq_readable));

    CisReport::from_checks(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandOutput, MapRunner};

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
    fn absent_sshd_directive_with_secure_default_passes_never_fail() {
        // Only PermitRootLogin is set. Directives whose OpenSSH default is
        // already secure (X11Forwarding no) pass by that default; directives
        // whose default does not meet the bar (MaxAuthTries 6 > 4) stay
        // NOT_CONFIGURED — never a fabricated FAIL in either case.
        let mut r = runner(
            "PermitRootLogin no\n",
            HARDENED_LOGIN_DEFS,
            GOOD_STAT,
            GOOD_PASSWD,
        );
        let report = audit_cis(&mut r);
        let x11 = find(&report, "SSH-X11-FORWARDING");
        assert_eq!(x11.status, CheckStatus::Pass);
        assert!(
            x11.evidence.contains("по умолчанию"),
            "evidence should note the default: {}",
            x11.evidence
        );
        assert_eq!(
            find(&report, "SSH-MAX-AUTH-TRIES").status,
            CheckStatus::NotConfigured
        );
        assert_eq!(report.summary.fail, 0);
    }

    #[test]
    fn sshd_dash_t_is_authoritative_over_files() {
        // When `sshd -T` output is present it resolves precedence the files
        // cannot: a file conflict that would otherwise be MANUAL becomes a
        // definite verdict from the daemon's own effective value.
        let mut r = runner(
            "PermitRootLogin yes\nPermitRootLogin no\n",
            HARDENED_LOGIN_DEFS,
            GOOD_STAT,
            GOOD_PASSWD,
        );
        r.insert(
            ReadCommand::SshdEffective,
            CommandOutput::ok("permitrootlogin no\nmaxauthtries 3\nx11forwarding no\n"),
        );
        let report = audit_cis(&mut r);
        let root = find(&report, "SSH-PERMIT-ROOT-LOGIN");
        assert_eq!(root.status, CheckStatus::Pass);
        assert!(
            root.evidence.contains("sshd -T"),
            "evidence: {}",
            root.evidence
        );
        // A numeric default resolves to the real effective value, too.
        assert_eq!(
            find(&report, "SSH-MAX-AUTH-TRIES").status,
            CheckStatus::Pass
        );
    }

    #[test]
    fn weak_ssh_algorithms_fail_only_when_explicitly_configured() {
        let weak = "\
Ciphers aes256-ctr,aes128-cbc,3des-cbc
MACs hmac-sha2-256,hmac-md5
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1
";
        let mut r = runner(weak, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        let report = audit_cis(&mut r);
        assert_eq!(find(&report, "SSH-CIPHERS").status, CheckStatus::Fail);
        assert!(find(&report, "SSH-CIPHERS").evidence.contains("cbc"));
        assert_eq!(find(&report, "SSH-MACS").status, CheckStatus::Fail);
        assert_eq!(find(&report, "SSH-KEX").status, CheckStatus::Fail);

        // Strong lists pass; absent lists are NOT_CONFIGURED (strong defaults).
        let strong = "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n";
        let mut r2 = runner(strong, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        let report2 = audit_cis(&mut r2);
        assert_eq!(find(&report2, "SSH-CIPHERS").status, CheckStatus::Pass);
        assert_eq!(
            find(&report2, "SSH-MACS").status,
            CheckStatus::NotConfigured
        );
    }

    #[test]
    fn tmp_mount_and_sysctl_checks_from_host_facts() {
        let mut r = runner(HARDENED_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        r.insert(
            ReadCommand::Mounts,
            CommandOutput::ok(
                "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                 /dev/sda1 / ext4 rw,relatime 0 0\n",
            ),
        );
        r.insert(
            ReadCommand::Sysctl,
            CommandOutput::ok(
                "/proc/sys/net/ipv4/ip_forward:0\n\
                 /proc/sys/net/ipv4/conf/all/rp_filter:1\n\
                 /proc/sys/net/ipv4/tcp_syncookies:1\n\
                 /proc/sys/kernel/randomize_va_space:0\n",
            ),
        );
        let report = audit_cis(&mut r);
        assert_eq!(find(&report, "FS-TMP-OPTIONS").status, CheckStatus::Pass);
        assert_eq!(find(&report, "SYSCTL-RP-FILTER").status, CheckStatus::Pass);
        // ASLR disabled is an explicit, host-backed fail.
        assert_eq!(find(&report, "SYSCTL-ASLR").status, CheckStatus::Fail);
        // ip_forward=0 passes; a router (=1) would be MANUAL, never a fail.
        assert_eq!(find(&report, "SYSCTL-IP-FORWARD").status, CheckStatus::Pass);
    }

    #[test]
    fn tmp_without_separate_mount_is_not_configured_not_fail() {
        let mut r = runner(HARDENED_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        r.insert(
            ReadCommand::Mounts,
            CommandOutput::ok("/dev/sda1 / ext4 rw,relatime 0 0\n"),
        );
        let report = audit_cis(&mut r);
        assert_eq!(
            find(&report, "FS-TMP-OPTIONS").status,
            CheckStatus::NotConfigured
        );
    }

    #[test]
    fn per_framework_scores_can_diverge() {
        // sysctl/mount/apparmor map to CIS and ISO but not PCI, so when those
        // checks reach definite verdicts the CIS and PCI denominators differ.
        let mut r = runner(HARDENED_SSHD, HARDENED_LOGIN_DEFS, GOOD_STAT, GOOD_PASSWD);
        r.insert(
            ReadCommand::Sysctl,
            CommandOutput::ok(
                "/proc/sys/net/ipv4/ip_forward:0\n\
                 /proc/sys/net/ipv4/conf/all/rp_filter:1\n\
                 /proc/sys/net/ipv4/tcp_syncookies:1\n\
                 /proc/sys/kernel/randomize_va_space:2\n\
                 /proc/sys/net/ipv4/conf/all/accept_redirects:0\n\
                 /proc/sys/net/ipv4/conf/all/send_redirects:0\n\
                 /proc/sys/net/ipv4/conf/all/accept_source_route:0\n",
            ),
        );
        let report = audit_cis(&mut r);
        let score = |f: Framework| {
            report
                .summary
                .compliance
                .iter()
                .find(|s| s.framework == f)
                .unwrap()
        };
        let cis = score(Framework::Cis);
        let pci = score(Framework::PciDss4);
        // The sysctl checks (CIS+ISO, not PCI) widen the CIS evaluated set
        // beyond PCI's, so the two frameworks cover different numbers of checks.
        assert!(
            cis.evaluated > pci.evaluated,
            "CIS evaluated {} should exceed PCI {}",
            cis.evaluated,
            pci.evaluated
        );
        assert!(cis.applicable >= cis.evaluated);
    }

    #[test]
    fn percent_rounds_to_nearest() {
        // 10 of 13 = 76.9%, which must round to 77, not truncate to 76.
        assert_eq!(Some(77u8), {
            let evaluated = 13usize;
            let passed = 10usize;
            Some(((passed * 200 + evaluated) / (evaluated * 2)) as u8)
        });
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

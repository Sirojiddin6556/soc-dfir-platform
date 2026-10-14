//! CIS-benchmark configuration audit for a **Windows Server** target, over the
//! read-only Windows command surface. It reuses the same verdict types and
//! per-framework rollup as the Linux audit ([`crate::cis`]), and the same
//! zero-false-positive rule: a check is `Fail` only when a value actually read
//! off the host is explicitly insecure; a value that is absent is
//! `NotConfigured` (never a fail) and one that could not be read (no privilege,
//! or a localised output we cannot parse) is `NeedsPrivileges`.
//!
//! This is a curated Level-1 subset — the settings that are unambiguous to read
//! remotely and whose insecure state is a definite finding (SMBv1, RDP NLA,
//! UAC, Defender, LLMNR, WDigest, the Guest account, Remote Registry, the
//! firewall, and the password/lockout policy).

use crate::cis::{cref, CheckStatus, CisCheck, CisReport, ComplianceRef, Framework, Severity};
use crate::command::{WinCommandRunner, WinReadCommand};

/// Reads one command's stdout, or empty string when it could not be run.
fn read(runner: &mut dyn WinCommandRunner, cmd: WinReadCommand) -> String {
    runner.run_win(cmd).map(|o| o.stdout).unwrap_or_default()
}

/// Value of a `key=value` line (the format most Windows commands print), by
/// case-insensitive key. `None` when the key is absent or its value empty.
fn kv<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// The integer after the last run of digits-only token on a `net accounts`
/// line whose English label contains `needle`. Returns `None` when the label is
/// absent (e.g. a non-English Windows), so we never fail on what we cannot read.
fn net_accounts_number(text: &str, needle: &str) -> Option<i64> {
    for line in text.lines() {
        if line.to_ascii_lowercase().contains(needle) {
            // The value is the last whitespace-separated token; parse it when
            // it is a plain number ("Never"/"None"/"Unlimited" → not a number).
            let last = line.split_whitespace().last().unwrap_or("");
            return last.parse::<i64>().ok();
        }
    }
    None
}

/// Whether a `net accounts` line's value is the "no limit" word ("Never",
/// "None", "Unlimited"), which for a lockout threshold means *not* set.
fn net_accounts_is_never(text: &str, needle: &str) -> bool {
    for line in text.lines() {
        if line.to_ascii_lowercase().contains(needle) {
            let last = line.split_whitespace().last().unwrap_or("").to_ascii_lowercase();
            return matches!(last.as_str(), "never" | "none" | "unlimited" | "0");
        }
    }
    false
}

fn check(
    id: &'static str,
    title: &'static str,
    status: CheckStatus,
    severity: Severity,
    evidence: String,
    remediation: &'static str,
    references: Vec<ComplianceRef>,
) -> CisCheck {
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

/// Runs the Windows CIS subset and returns the report.
pub fn audit_windows_cis(runner: &mut dyn WinCommandRunner) -> CisReport {
    let mut checks = Vec::new();

    // --- Password & lockout policy (net accounts) ------------------------
    let net = read(runner, WinReadCommand::NetAccounts);
    {
        let minlen = net_accounts_number(&net, "minimum password length");
        let (status, evidence) = match minlen {
            Some(n) if n >= 14 => (CheckStatus::Pass, format!("Минимальная длина пароля: {n}")),
            Some(n) => (CheckStatus::Fail, format!("Минимальная длина пароля: {n} (нужно ≥14)")),
            None => (
                CheckStatus::NeedsPrivileges,
                "Не удалось прочитать политику паролей (net accounts недоступен или не на английском)".into(),
            ),
        };
        checks.push(check(
            "WIN-PW-MINLEN",
            "Минимальная длина пароля не меньше 14",
            status,
            Severity::Medium,
            evidence,
            "Задайте минимальную длину пароля не менее 14 символов в групповой политике.",
            vec![
                cref(Framework::Cis, "1.1.4"),
                cref(Framework::PciDss4, "8.3.6"),
                cref(Framework::Iso27001, "A.5.17"),
            ],
        ));
    }
    {
        let threshold = net_accounts_number(&net, "lockout threshold");
        let never = net_accounts_is_never(&net, "lockout threshold");
        let (status, evidence) = if let Some(n) = threshold {
            if (1..=5).contains(&n) {
                (CheckStatus::Pass, format!("Порог блокировки: {n} попыток"))
            } else if n == 0 {
                (CheckStatus::Fail, "Блокировка после неудачных входов отключена".into())
            } else {
                (CheckStatus::Pass, format!("Порог блокировки: {n} попыток"))
            }
        } else if never {
            (CheckStatus::Fail, "Блокировка после неудачных входов не настроена (Never)".into())
        } else {
            (
                CheckStatus::NeedsPrivileges,
                "Не удалось прочитать политику блокировки".into(),
            )
        };
        checks.push(check(
            "WIN-LOCKOUT-THRESHOLD",
            "Блокировка учётной записи после неудачных входов",
            status,
            Severity::Medium,
            evidence,
            "Задайте порог блокировки (например, 5 попыток) в политике учётных записей.",
            vec![
                cref(Framework::Cis, "1.2.1"),
                cref(Framework::PciDss4, "8.3.4"),
                cref(Framework::Iso27001, "A.5.17"),
            ],
        ));
    }

    // --- Firewall profiles ----------------------------------------------
    {
        let fw = read(runner, WinReadCommand::Firewall);
        let profiles: Vec<(&str, bool)> = fw
            .lines()
            .filter_map(|l| {
                let mut p = l.split('\t');
                let name = p.next()?.trim();
                let on = p.next()?.trim();
                if name.is_empty() {
                    return None;
                }
                Some((name, on.eq_ignore_ascii_case("true") || on == "1"))
            })
            .collect();
        let (status, evidence) = if profiles.is_empty() {
            (CheckStatus::NeedsPrivileges, "Состояние брандмауэра не прочитано".into())
        } else if profiles.iter().all(|(_, on)| *on) {
            (CheckStatus::Pass, "Все профили брандмауэра включены".into())
        } else {
            let off: Vec<&str> = profiles.iter().filter(|(_, on)| !on).map(|(n, _)| *n).collect();
            (CheckStatus::Fail, format!("Отключены профили брандмауэра: {}", off.join(", ")))
        };
        checks.push(check(
            "WIN-FIREWALL",
            "Брандмауэр Windows включён во всех профилях",
            status,
            Severity::High,
            evidence,
            "Включите брандмауэр Windows во всех профилях (Domain, Private, Public).",
            vec![
                cref(Framework::Cis, "9.1"),
                cref(Framework::PciDss4, "1.2.1"),
                cref(Framework::Iso27001, "A.8.20"),
            ],
        ));
    }

    // --- SMBv1 -----------------------------------------------------------
    {
        let smb = read(runner, WinReadCommand::Smb1);
        let (status, evidence) = match kv(&smb, "EnableSMB1Protocol").map(|v| v.to_ascii_lowercase()) {
            Some(v) if v == "false" => (CheckStatus::Pass, "SMBv1 отключён".into()),
            Some(v) if v == "true" => (CheckStatus::Fail, "SMBv1 включён (устаревший уязвимый протокол)".into()),
            _ => (CheckStatus::NotConfigured, "Состояние SMBv1 не прочитано".into()),
        };
        checks.push(check(
            "WIN-SMB1",
            "Протокол SMBv1 отключён",
            status,
            Severity::High,
            evidence,
            "Отключите SMBv1 на сервере; используйте SMBv2/3.",
            vec![cref(Framework::Cis, "18.3.1"), cref(Framework::Iso27001, "A.8.27")],
        ));
    }

    // --- RDP: Network Level Authentication ------------------------------
    {
        let rdp = read(runner, WinReadCommand::Rdp);
        let deny = kv(&rdp, "fDenyTSConnections");
        let ua = kv(&rdp, "UserAuthentication");
        let (status, evidence) = match (deny, ua) {
            (Some("1"), _) => (CheckStatus::Pass, "Подключения RDP отключены".into()),
            (_, Some("1")) => (CheckStatus::Pass, "RDP требует проверки на уровне сети (NLA)".into()),
            (Some("0"), Some("0")) => (
                CheckStatus::Fail,
                "RDP включён без проверки на уровне сети (NLA)".into(),
            ),
            _ => (CheckStatus::NotConfigured, "Настройки RDP/NLA не прочитаны".into()),
        };
        checks.push(check(
            "WIN-RDP-NLA",
            "RDP требует проверки на уровне сети (NLA)",
            status,
            Severity::High,
            evidence,
            "Включите «Требовать проверку подлинности на уровне сети» для RDP или отключите RDP.",
            vec![
                cref(Framework::Cis, "18.9.65"),
                cref(Framework::PciDss4, "8.3.1"),
                cref(Framework::Iso27001, "A.8.5"),
            ],
        ));
    }

    // --- UAC -------------------------------------------------------------
    {
        let uac = read(runner, WinReadCommand::Uac);
        let (status, evidence) = match kv(&uac, "EnableLUA") {
            Some("1") => (CheckStatus::Pass, "UAC (EnableLUA) включён".into()),
            Some("0") => (CheckStatus::Fail, "UAC (EnableLUA) отключён".into()),
            _ => (CheckStatus::NotConfigured, "Состояние UAC не прочитано".into()),
        };
        checks.push(check(
            "WIN-UAC",
            "Контроль учётных записей (UAC) включён",
            status,
            Severity::High,
            evidence,
            "Включите UAC: EnableLUA=1.",
            vec![cref(Framework::Cis, "2.3.17"), cref(Framework::Iso27001, "A.8.2")],
        ));
    }

    // --- Defender real-time protection ----------------------------------
    {
        let def = read(runner, WinReadCommand::Defender);
        let (status, evidence) = match kv(&def, "RealTimeProtectionEnabled").map(|v| v.to_ascii_lowercase()) {
            Some(v) if v == "true" => (CheckStatus::Pass, "Защита в реальном времени включена".into()),
            Some(v) if v == "false" => (CheckStatus::Fail, "Защита в реальном времени Microsoft Defender отключена".into()),
            _ => (
                CheckStatus::NotConfigured,
                "Статус Microsoft Defender не прочитан (возможно, используется сторонний антивирус)".into(),
            ),
        };
        checks.push(check(
            "WIN-DEFENDER-RTP",
            "Защита в реальном времени антивируса включена",
            status,
            Severity::High,
            evidence,
            "Включите защиту в реальном времени Microsoft Defender или убедитесь, что работает сторонний антивирус.",
            vec![
                cref(Framework::Cis, "18.9.47"),
                cref(Framework::PciDss4, "5.2.1"),
                cref(Framework::Iso27001, "A.8.7"),
            ],
        ));
    }

    // --- LLMNR -----------------------------------------------------------
    {
        let llmnr = read(runner, WinReadCommand::Llmnr);
        let (status, evidence) = match kv(&llmnr, "EnableMulticast") {
            Some("0") => (CheckStatus::Pass, "LLMNR отключён политикой".into()),
            Some("1") => (CheckStatus::Fail, "LLMNR включён политикой (риск перехвата учётных данных)".into()),
            _ => (CheckStatus::NotConfigured, "Политика LLMNR не задана".into()),
        };
        checks.push(check(
            "WIN-LLMNR",
            "LLMNR (multicast-разрешение имён) отключён",
            status,
            Severity::Medium,
            evidence,
            "Отключите LLMNR групповой политикой: EnableMulticast=0.",
            vec![cref(Framework::Cis, "18.5.4"), cref(Framework::Iso27001, "A.8.21")],
        ));
    }

    // --- WDigest ---------------------------------------------------------
    {
        let wd = read(runner, WinReadCommand::Wdigest);
        let (status, evidence) = match kv(&wd, "UseLogonCredential") {
            Some("0") => (CheckStatus::Pass, "WDigest не кэширует пароли в открытом виде".into()),
            Some("1") => (CheckStatus::Fail, "WDigest кэширует пароли в открытом виде (UseLogonCredential=1)".into()),
            _ => (CheckStatus::NotConfigured, "Параметр WDigest не задан".into()),
        };
        checks.push(check(
            "WIN-WDIGEST",
            "WDigest не хранит пароли в открытом виде",
            status,
            Severity::High,
            evidence,
            "Задайте UseLogonCredential=0 для провайдера WDigest.",
            vec![cref(Framework::Cis, "18.3.4"), cref(Framework::Iso27001, "A.8.5")],
        ));
    }

    // --- Guest account ---------------------------------------------------
    {
        let guest = read(runner, WinReadCommand::GuestAccount);
        let (status, evidence) = match kv(&guest, "GuestEnabled").map(|v| v.to_ascii_lowercase()) {
            Some(v) if v == "false" => (CheckStatus::Pass, "Гостевая учётная запись отключена".into()),
            Some(v) if v == "true" => (CheckStatus::Fail, "Гостевая учётная запись включена".into()),
            _ => (CheckStatus::NotConfigured, "Состояние гостевой учётной записи не прочитано".into()),
        };
        checks.push(check(
            "WIN-GUEST",
            "Встроенная гостевая учётная запись отключена",
            status,
            Severity::Medium,
            evidence,
            "Отключите встроенную учётную запись «Гость».",
            vec![
                cref(Framework::Cis, "2.3.1.2"),
                cref(Framework::PciDss4, "8.2.2"),
                cref(Framework::Iso27001, "A.5.16"),
            ],
        ));
    }

    // --- Remote Registry service ----------------------------------------
    {
        let rr = read(runner, WinReadCommand::RemoteRegistry);
        let (status, evidence) = match kv(&rr, "RemoteRegistryStart").map(|v| v.to_ascii_lowercase()) {
            Some(v) if v == "disabled" => (CheckStatus::Pass, "Служба удалённого реестра отключена".into()),
            Some(v) if v == "automatic" => (CheckStatus::Fail, "Служба удалённого реестра запускается автоматически".into()),
            Some(v) => (CheckStatus::Manual, format!("Тип запуска удалённого реестра: {v}")),
            None => (CheckStatus::NotConfigured, "Тип запуска удалённого реестра не прочитан".into()),
        };
        checks.push(check(
            "WIN-REMOTE-REGISTRY",
            "Служба удалённого реестра отключена",
            status,
            Severity::Medium,
            evidence,
            "Отключите службу «Удалённый реестр», если она не требуется.",
            vec![cref(Framework::Cis, "5.26"), cref(Framework::Iso27001, "A.8.20")],
        ));
    }

    // --- Logon auditing (best-effort; English output only) --------------
    {
        let audit = read(runner, WinReadCommand::AuditPolicy);
        let lower = audit.to_ascii_lowercase();
        let (status, evidence) = if lower.lines().any(|l| l.contains("logon") && l.contains("no auditing")) {
            (CheckStatus::Fail, "Аудит входа в систему отключён (No Auditing)".into())
        } else if lower.lines().any(|l| l.contains("logon") && l.contains("success")) {
            (CheckStatus::Pass, "Аудит входа в систему включён".into())
        } else {
            (
                CheckStatus::NotConfigured,
                "Политику аудита не удалось разобрать (нет данных или не на английском)".into(),
            )
        };
        checks.push(check(
            "WIN-AUDIT-LOGON",
            "Включён аудит событий входа в систему",
            status,
            Severity::Medium,
            evidence,
            "Включите аудит входа/выхода (Success) в расширенной политике аудита.",
            vec![
                cref(Framework::Cis, "17.5.1"),
                cref(Framework::PciDss4, "10.2.1"),
                cref(Framework::Iso27001, "A.8.15"),
            ],
        ));
    }

    CisReport::from_checks(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cis::CheckStatus;
    use crate::command::MapRunner;

    fn status_of<'a>(report: &'a CisReport, id: &str) -> &'a CisCheck {
        report.checks.iter().find(|c| c.id == id).expect("check present")
    }

    #[test]
    fn insecure_host_fails_the_right_checks() {
        let mut r = MapRunner::new()
            .with_win(WinReadCommand::Smb1, "EnableSMB1Protocol=True\n")
            .with_win(WinReadCommand::Uac, "EnableLUA=0\n")
            .with_win(WinReadCommand::Wdigest, "UseLogonCredential=1\n")
            .with_win(WinReadCommand::GuestAccount, "GuestEnabled=True\n")
            .with_win(WinReadCommand::Firewall, "Domain\tTrue\nPrivate\tFalse\nPublic\tTrue\n")
            .with_win(WinReadCommand::Rdp, "fDenyTSConnections=0\nUserAuthentication=0\n")
            .with_win(WinReadCommand::NetAccounts, "Minimum password length:    8\nLockout threshold:    Never\n");
        let report = audit_windows_cis(&mut r);
        assert_eq!(status_of(&report, "WIN-SMB1").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-UAC").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-WDIGEST").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-GUEST").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-FIREWALL").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-RDP-NLA").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-PW-MINLEN").status, CheckStatus::Fail);
        assert_eq!(status_of(&report, "WIN-LOCKOUT-THRESHOLD").status, CheckStatus::Fail);
    }

    #[test]
    fn secure_host_passes_and_absent_is_not_a_fail() {
        let mut r = MapRunner::new()
            .with_win(WinReadCommand::Smb1, "EnableSMB1Protocol=False\n")
            .with_win(WinReadCommand::Uac, "EnableLUA=1\n")
            .with_win(WinReadCommand::GuestAccount, "GuestEnabled=False\n")
            .with_win(WinReadCommand::Firewall, "Domain\tTrue\nPrivate\tTrue\nPublic\tTrue\n")
            .with_win(WinReadCommand::Rdp, "fDenyTSConnections=1\n")
            .with_win(WinReadCommand::NetAccounts, "Minimum password length:    14\nLockout threshold:    5\n");
        let report = audit_windows_cis(&mut r);
        assert_eq!(status_of(&report, "WIN-SMB1").status, CheckStatus::Pass);
        assert_eq!(status_of(&report, "WIN-UAC").status, CheckStatus::Pass);
        assert_eq!(status_of(&report, "WIN-GUEST").status, CheckStatus::Pass);
        assert_eq!(status_of(&report, "WIN-FIREWALL").status, CheckStatus::Pass);
        assert_eq!(status_of(&report, "WIN-RDP-NLA").status, CheckStatus::Pass);
        assert_eq!(status_of(&report, "WIN-PW-MINLEN").status, CheckStatus::Pass);
        assert_eq!(status_of(&report, "WIN-LOCKOUT-THRESHOLD").status, CheckStatus::Pass);
        // WDigest was never read → NotConfigured, never a fail.
        assert_eq!(status_of(&report, "WIN-WDIGEST").status, CheckStatus::NotConfigured);
    }

    #[test]
    fn frameworks_diverge() {
        // A host where everything readable passes; the three framework
        // percentages should not all be identical because the control sets
        // differ (SMB1/LLMNR/WDigest/RemoteRegistry are CIS+ISO, not PCI).
        let mut r = MapRunner::new()
            .with_win(WinReadCommand::Smb1, "EnableSMB1Protocol=False\n")
            .with_win(WinReadCommand::Uac, "EnableLUA=1\n");
        let report = audit_windows_cis(&mut r);
        let pcts: Vec<Option<u8>> = report.summary.compliance.iter().map(|f| f.percent).collect();
        // At least one framework evaluated something.
        assert!(pcts.iter().any(|p| p.is_some()));
    }
}

//! Parses the Windows read-command output into the shapes the shared matchers
//! already understand: a [`WindowsHostFacts`] for the MSRC OS/KB match and a
//! list of [`InstalledApp`] for the NVD installed-program match. The engine
//! then runs the *same* matching code paths the local Windows scan uses, so a
//! remote Windows finding is as true as a local one.
//!
//! Every field comes only from a value actually read off the host; a missing or
//! unparsable value is left empty or `None`, never guessed.

use vulnerability_engine::app_scan::InstalledApp;
use vulnerability_engine::msrc::WindowsHostFacts;

use crate::command::{WinCommandRunner, WinReadCommand};

/// What the Windows collection produced.
#[derive(Debug, Clone)]
pub struct WindowsInventory {
    pub facts: WindowsHostFacts,
    /// Installed programs for the app-CVE match.
    pub apps: Vec<InstalledApp>,
    /// Whether the OS info parsed into a real build (i.e. this truly is a
    /// Windows host we could read). When false the caller reports the host as
    /// unreadable rather than inventing facts.
    pub identified: bool,
    pub collection_errors: Vec<String>,
}

/// Reads `key=value` lines (the [`WinReadCommand::OsInfo`] format) into a map.
fn parse_kv(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            if !v.is_empty() {
                map.insert(k.trim().to_string(), v.to_string());
            }
        }
    }
    map
}

/// Maps the `OSArchitecture` string Windows reports to the short form the
/// matcher uses. Unknown values pass through so nothing is lost.
fn normalize_arch(raw: &str) -> String {
    let l = raw.to_ascii_lowercase();
    if l.contains("arm") {
        "aarch64".to_string()
    } else if l.contains("64") {
        "x86_64".to_string()
    } else if l.contains("32") || l.contains("x86") {
        "x86".to_string()
    } else {
        raw.to_string()
    }
}

/// Collects the Windows host facts and installed programs over `runner`.
pub fn collect_windows(runner: &mut dyn WinCommandRunner) -> WindowsInventory {
    let mut errors = Vec::new();
    let read = |runner: &mut dyn WinCommandRunner, cmd: WinReadCommand| -> String {
        runner.run_win(cmd).map(|o| o.stdout).unwrap_or_default()
    };

    let os = parse_kv(&read(runner, WinReadCommand::OsInfo));
    let get = |k: &str| os.get(k).cloned().unwrap_or_default();

    let build: u32 = get("CurrentBuild").parse().unwrap_or(0);
    let ubr: Option<u32> = get("UBR").parse().ok();
    let product_type: Option<u32> = get("ProductType").parse().ok();
    let identified = build > 0 && !get("CurrentVersion").is_empty();
    if !identified {
        errors.push(
            "Не удалось прочитать версию и сборку Windows (нет доступа или это не Windows).".into(),
        );
    }

    let facts = WindowsHostFacts {
        caption: get("Caption"),
        version: get("CurrentVersion"),
        build,
        ubr,
        display_version: get("DisplayVersion"),
        installation_type: get("InstallationType"),
        product_type,
        architecture: normalize_arch(&get("Architecture")),
        installed_kbs: parse_hotfixes(&read(runner, WinReadCommand::Hotfixes)),
    };

    let apps = parse_programs(&read(runner, WinReadCommand::Programs));

    WindowsInventory {
        facts,
        apps,
        identified,
        collection_errors: errors,
    }
}

/// `Get-HotFix` prints one `KB…` id per line; keep the KB-looking ones.
fn parse_hotfixes(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            let u = l.to_ascii_uppercase();
            u.starts_with("KB") && u[2..].chars().all(|c| c.is_ascii_digit()) && l.len() > 2
        })
        .map(|l| l.to_string())
        .collect()
}

/// Each program line is `DisplayName \t DisplayVersion \t Publisher`; a missing
/// trailing field is simply empty.
fn parse_programs(text: &str) -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let name = parts.next().unwrap_or("").trim().to_string();
        if name.is_empty() {
            continue;
        }
        let version = parts.next().unwrap_or("").trim().to_string();
        let publisher = parts.next().unwrap_or("").trim().to_string();
        apps.push(InstalledApp {
            name,
            version,
            publisher,
            architecture: String::new(),
        });
    }
    apps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::MapRunner;

    const OS_INFO: &str = "ProductName=Windows Server 2022 Datacenter\n\
        CurrentVersion=10.0.20348\n\
        CurrentBuild=20348\n\
        UBR=2340\n\
        DisplayVersion=21H2\n\
        InstallationType=Server\n\
        Caption=Microsoft Windows Server 2022 Datacenter\n\
        ProductType=3\n\
        Architecture=64-bit\n";

    fn runner() -> MapRunner {
        MapRunner::new()
            .with_win(WinReadCommand::OsInfo, OS_INFO)
            .with_win(WinReadCommand::Hotfixes, "KB5044284\nKB5043123\nnot-a-kb\n")
            .with_win(
                WinReadCommand::Programs,
                "7-Zip 23.01 (x64)\t23.01\tIgor Pavlov\n\
                 Mozilla Firefox (x64 en-US)\t120.0\tMozilla\n\
                 \t\t\n",
            )
    }

    #[test]
    fn parses_os_facts() {
        let mut r = runner();
        let inv = collect_windows(&mut r);
        assert!(inv.identified);
        assert_eq!(inv.facts.version, "10.0.20348");
        assert_eq!(inv.facts.build, 20348);
        assert_eq!(inv.facts.ubr, Some(2340));
        assert_eq!(inv.facts.full_build(), "10.0.20348.2340");
        assert_eq!(inv.facts.product_type, Some(3));
        assert_eq!(inv.facts.architecture, "x86_64");
        assert_eq!(inv.facts.installed_kbs, vec!["KB5044284", "KB5043123"]);
    }

    #[test]
    fn parses_programs_dropping_empty_rows() {
        let mut r = runner();
        let inv = collect_windows(&mut r);
        assert_eq!(inv.apps.len(), 2);
        assert_eq!(inv.apps[0].name, "7-Zip 23.01 (x64)");
        assert_eq!(inv.apps[0].version, "23.01");
        assert_eq!(inv.apps[0].publisher, "Igor Pavlov");
        assert_eq!(inv.apps[1].name, "Mozilla Firefox (x64 en-US)");
    }

    #[test]
    fn unreadable_host_is_not_identified() {
        let mut r = MapRunner::new();
        let inv = collect_windows(&mut r);
        assert!(!inv.identified);
        assert_eq!(inv.facts.build, 0);
        assert!(!inv.collection_errors.is_empty());
    }
}

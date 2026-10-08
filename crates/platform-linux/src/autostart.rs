#![forbid(unsafe_code)]

//! Boot/logon autostart locations other than systemd units and cron:
//! /etc/rc.local, XDG autostart `.desktop` entries and /etc/ld.so.preload.

/// Commands in an rc.local script (comments, blank lines, the shebang and
/// the conventional trailing `exit 0` are skipped).
pub fn parse_rc_local(content: &str) -> Vec<(usize, String)> {
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, raw)| {
            let line = raw.trim();
            (!line.is_empty() && !line.starts_with('#') && line != "exit 0")
                .then(|| (idx + 1, line.to_string()))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopEntry {
    pub name: Option<String>,
    pub exec: Option<String>,
    pub hidden: bool,
}

/// Parses the `[Desktop Entry]` group of an XDG `.desktop` file. Entries
/// with `Hidden=true` or `X-GNOME-Autostart-enabled=false` are disabled.
pub fn parse_desktop_entry(content: &str) -> DesktopEntry {
    let mut entry = DesktopEntry {
        name: None,
        exec: None,
        hidden: false,
    };
    let mut in_main = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_main = line == "[Desktop Entry]";
            continue;
        }
        if !in_main || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Name" => entry.name = Some(value.to_string()),
            "Exec" => entry.exec = Some(value.to_string()),
            "Hidden" if value.eq_ignore_ascii_case("true") => entry.hidden = true,
            "X-GNOME-Autostart-enabled" if value.eq_ignore_ascii_case("false") => {
                entry.hidden = true
            }
            _ => {}
        }
    }
    entry
}

/// Libraries listed in /etc/ld.so.preload (whitespace or newline separated).
pub fn parse_ld_so_preload(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .flat_map(|l| l.split_whitespace())
        .map(str::to_string)
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;
    use crate::systemd::command_executable;
    use crate::util::{file_mtime_rfc3339, root_path};
    use host_snapshot::AutorunObservation;
    use std::path::Path;

    fn autorun(
        hive: &str,
        key: &Path,
        value_name: String,
        command: String,
        owner: Option<String>,
        mechanism: &str,
        now: &str,
    ) -> AutorunObservation {
        AutorunObservation {
            hive: hive.to_string(),
            key: key.to_string_lossy().into_owned(),
            value_name,
            resolved_executable: command_executable(&command),
            value_data: command,
            hash: None,
            owner,
            timestamp: file_mtime_rfc3339(key).unwrap_or_else(|| now.to_string()),
            mechanism: mechanism.to_string(),
        }
    }

    /// `home_dirs`: (user, home directory) pairs.
    pub fn collect(
        root: &Path,
        home_dirs: &[(String, String)],
        now: &str,
    ) -> Vec<AutorunObservation> {
        let mut out = Vec::new();

        for rc in ["etc/rc.local", "etc/rc.d/rc.local"] {
            let path = root.join(rc);
            if let Ok(content) = std::fs::read_to_string(&path) {
                for (line_no, command) in parse_rc_local(&content) {
                    out.push(autorun(
                        "rc.local",
                        &path,
                        format!("line {}", line_no),
                        command,
                        Some("root".to_string()),
                        "rc_local",
                        now,
                    ));
                }
            }
        }

        let mut xdg_dirs = vec![(root.join("etc/xdg/autostart"), None)];
        for (user, home) in home_dirs {
            xdg_dirs.push((
                root_path(root, home).join(".config/autostart"),
                Some(user.clone()),
            ));
        }
        for (dir, owner) in xdg_dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut paths: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "desktop"))
                .collect();
            paths.sort();
            for path in paths {
                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let entry = parse_desktop_entry(&content);
                let (Some(exec), false) = (entry.exec, entry.hidden) else {
                    continue;
                };
                let name = entry.name.unwrap_or_else(|| {
                    path.file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default()
                });
                out.push(autorun(
                    "xdg-autostart",
                    &path,
                    name,
                    exec,
                    owner.clone().or_else(|| Some("all users".to_string())),
                    "xdg_autostart",
                    now,
                ));
            }
        }

        let preload = root.join("etc/ld.so.preload");
        if let Ok(content) = std::fs::read_to_string(&preload) {
            for lib in parse_ld_so_preload(&content) {
                out.push(autorun(
                    "ld.so.preload",
                    &preload,
                    lib.clone(),
                    lib,
                    Some("all processes".to_string()),
                    "ld_preload",
                    now,
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rc_local() {
        let content = "#!/bin/sh -e\n#\n# rc.local\n\n/usr/local/bin/firewall-up\nnohup /dev/shm/.x/agent &\nexit 0\n";
        assert_eq!(
            parse_rc_local(content),
            vec![
                (5, "/usr/local/bin/firewall-up".to_string()),
                (6, "nohup /dev/shm/.x/agent &".to_string())
            ]
        );
    }

    #[test]
    fn parses_desktop_entries() {
        let entry = parse_desktop_entry(
            "[Desktop Entry]\nType=Application\nName=Updater\nExec=/tmp/.u/update --silent\n\n[Desktop Action New]\nExec=ignored\n",
        );
        assert_eq!(entry.name.as_deref(), Some("Updater"));
        assert_eq!(entry.exec.as_deref(), Some("/tmp/.u/update --silent"));
        assert!(!entry.hidden);

        let hidden = parse_desktop_entry("[Desktop Entry]\nExec=/usr/bin/x\nHidden=true\n");
        assert!(hidden.hidden);
        let gnome_off = parse_desktop_entry(
            "[Desktop Entry]\nExec=/usr/bin/x\nX-GNOME-Autostart-enabled=false\n",
        );
        assert!(gnome_off.hidden);
    }

    #[test]
    fn parses_ld_so_preload() {
        assert_eq!(
            parse_ld_so_preload("/usr/lib/libprocesshider.so\n# comment\n/lib/a.so /lib/b.so\n"),
            vec!["/usr/lib/libprocesshider.so", "/lib/a.so", "/lib/b.so"]
        );
        assert!(parse_ld_so_preload("\n").is_empty());
    }
}

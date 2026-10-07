#![forbid(unsafe_code)]

//! systemd unit files and `systemctl list-units` output.

use std::collections::BTreeMap;

/// A parsed unit file: section name -> ordered (key, value) pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitFile {
    pub sections: BTreeMap<String, Vec<(String, String)>>,
}

impl UnitFile {
    /// First value of `key` in `section`.
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .get(section)?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// All values of `key` in `section`, in file order.
    pub fn get_all(&self, section: &str, key: &str) -> Vec<&str> {
        self.sections
            .get(section)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
                    .filter(|v| !v.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn description(&self) -> Option<&str> {
        self.get("Unit", "Description")
    }

    /// The command line of the first `ExecStart=` with systemd's special
    /// executable prefixes (`@`, `-`, `:`, `+`, `!`, `!!`) removed.
    pub fn exec_start(&self) -> Option<String> {
        self.get("Service", "ExecStart")
            .map(|v| v.trim_start_matches(['@', '-', ':', '+', '!']).to_string())
    }

    pub fn user(&self) -> Option<&str> {
        self.get("Service", "User")
    }

    /// Whether the unit can be enabled (has an [Install] section with an
    /// installation target). Units without one are "static".
    pub fn installable(&self) -> bool {
        ["WantedBy", "RequiredBy", "Alias", "Also", "UpheldBy"]
            .iter()
            .any(|k| self.get("Install", k).is_some())
    }

    /// Human readable timer schedule (`OnCalendar=`, `OnBootSec=`, ...).
    pub fn timer_schedule(&self) -> Option<String> {
        let keys = [
            "OnCalendar",
            "OnBootSec",
            "OnStartupSec",
            "OnUnitActiveSec",
            "OnUnitInactiveSec",
            "OnActiveSec",
        ];
        let parts: Vec<String> = keys
            .iter()
            .flat_map(|k| {
                self.get_all("Timer", k)
                    .into_iter()
                    .map(move |v| format!("{}={}", k, v))
            })
            .collect();
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// Parses a systemd unit file (INI-like, `#`/`;` comments, trailing
/// backslash line continuation).
pub fn parse_unit_file(content: &str) -> UnitFile {
    let mut unit = UnitFile::default();
    let mut section = String::new();
    let mut pending = String::new();
    for raw in content.lines() {
        let line = raw.trim_end();
        if pending.is_empty() {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                section = trimmed[1..trimmed.len() - 1].to_string();
                continue;
            }
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            pending.push_str(stripped.trim());
            pending.push(' ');
            continue;
        }
        pending.push_str(line.trim_start());
        let full = std::mem::take(&mut pending);
        if let Some((key, value)) = full.split_once('=') {
            unit.sections
                .entry(section.clone())
                .or_default()
                .push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    unit
}

/// One row of `systemctl list-units --type=service --all --no-legend --plain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedUnit {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

pub fn parse_list_units(output: &str) -> Vec<ListedUnit> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_start_matches(['●', '*', ' ']).trim();
            let (fields, description) = crate::util::split_fields(line, 4)?;
            if !fields[0].contains('.') {
                return None;
            }
            Some(ListedUnit {
                unit: fields[0].to_string(),
                load: fields[1].to_string(),
                active: fields[2].to_string(),
                sub: fields[3].to_string(),
                description: description.to_string(),
            })
        })
        .collect()
}

/// For a template instance `getty@tty1.service` returns `getty@.service`.
pub fn template_name(unit: &str) -> Option<String> {
    let (prefix, rest) = unit.split_once('@')?;
    let ext = rest.rsplit_once('.').map(|(_, ext)| ext)?;
    Some(format!("{}@.{}", prefix, ext))
}

/// First token of a command line, with surrounding quotes removed.
pub fn command_executable(command: &str) -> String {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    if let Some(rest) = command.strip_prefix('\'') {
        return rest.split('\'').next().unwrap_or("").to_string();
    }
    command.split_whitespace().next().unwrap_or("").to_string()
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;
    use crate::util::{file_mtime_rfc3339, root_path};
    use host_snapshot::{AutorunObservation, ScheduledTaskObservation, ServiceObservation};
    use std::collections::{BTreeSet, HashMap};
    use std::path::{Path, PathBuf};

    /// System unit search path, highest precedence first.
    const SYSTEM_UNIT_DIRS: [&str; 5] = [
        "etc/systemd/system",
        "run/systemd/system",
        "usr/local/lib/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ];

    pub struct LoadedUnit {
        pub name: String,
        pub path: PathBuf,
        pub masked: bool,
        pub unit: UnitFile,
    }

    pub struct SystemdScan {
        pub services: Vec<ServiceObservation>,
        pub autoruns: Vec<AutorunObservation>,
        pub timers: Vec<ScheduledTaskObservation>,
        pub errors: Vec<String>,
    }

    /// Like `sd_booted()`: systemd is the running init system.
    pub fn systemd_running() -> bool {
        Path::new("/run/systemd/system").is_dir()
    }

    pub fn list_units() -> Result<Vec<ListedUnit>, String> {
        let out = std::process::Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--plain",
                "--no-pager",
            ])
            .output()
            .map_err(|e| format!("systemctl недоступен: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "systemctl list-units завершился с ошибкой: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_list_units(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Loads every unit file with extension `ext` from `dirs` (first
    /// directory wins on name collisions, mirroring systemd precedence).
    pub fn load_units(root: &Path, dirs: &[PathBuf], ext: &str) -> BTreeMap<String, LoadedUnit> {
        let mut units = BTreeMap::new();
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.ends_with(ext) || units.contains_key(&name) {
                    continue;
                }
                let path = entry.path();
                let masked = std::fs::read_link(&path)
                    .map(|t| t == Path::new("/dev/null"))
                    .unwrap_or(false);
                let unit = if masked {
                    UnitFile::default()
                } else {
                    match std::fs::read_to_string(&path) {
                        Ok(content) => parse_unit_file(&content),
                        // Dangling symlink / unreadable: skip.
                        Err(_) => continue,
                    }
                };
                units.insert(
                    name.clone(),
                    LoadedUnit {
                        name,
                        path,
                        masked,
                        unit,
                    },
                );
            }
        }
        units
    }

    /// Unit names linked from `<dir>/*.wants/` and `*.requires/` -- the
    /// symlinks `systemctl enable` creates.
    pub fn enabled_links(dir: &Path) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.ends_with(".wants") || name.ends_with(".requires")) {
                continue;
            }
            if let Ok(links) = std::fs::read_dir(entry.path()) {
                for link in links.flatten() {
                    out.insert(link.file_name().to_string_lossy().into_owned());
                }
            }
        }
        out
    }

    fn resolve<'a>(units: &'a BTreeMap<String, LoadedUnit>, name: &str) -> Option<&'a LoadedUnit> {
        units
            .get(name)
            .or_else(|| template_name(name).and_then(|t| units.get(&t)))
    }

    fn start_type(loaded: &LoadedUnit, enabled: &BTreeSet<String>) -> &'static str {
        if loaded.masked {
            "masked"
        } else if enabled.contains(&loaded.name) {
            "enabled"
        } else if loaded.unit.installable() {
            "disabled"
        } else {
            "static"
        }
    }

    /// `home_dirs`: (user, home directory) pairs whose per-user systemd
    /// units should be inspected.
    pub fn scan(
        root: &Path,
        unit_pids: &HashMap<String, Vec<u32>>,
        home_dirs: &[(String, String)],
        now: &str,
    ) -> SystemdScan {
        let mut errors = Vec::new();
        let dirs: Vec<PathBuf> = SYSTEM_UNIT_DIRS.iter().map(PathBuf::from).collect();
        let services = load_units(root, &dirs, ".service");
        let timers = load_units(root, &dirs, ".timer");
        let enabled = enabled_links(&root.join("etc/systemd/system"));

        let running = root == Path::new("/") && systemd_running();
        let listed: BTreeMap<String, ListedUnit> = if running {
            match list_units() {
                Ok(list) => list.into_iter().map(|u| (u.unit.clone(), u)).collect(),
                Err(e) => {
                    errors.push(e);
                    BTreeMap::new()
                }
            }
        } else {
            errors.push(
                "systemd не является init-системой (нет /run/systemd/system): состояние служб \
                 неизвестно, перечислены unit-файлы с диска"
                    .to_string(),
            );
            BTreeMap::new()
        };

        let mut out_services = Vec::new();
        let mut seen = BTreeSet::new();
        let mut push_service =
            |name: &str, loaded: Option<&LoadedUnit>, listed: Option<&ListedUnit>| {
                if !seen.insert(name.to_string()) {
                    return;
                }
                let pid = unit_pids
                    .get(name)
                    .and_then(|pids| pids.iter().min().copied());
                let state = match listed {
                    Some(l) => format!("{}/{}", l.active, l.sub),
                    None if running => "inactive/dead".to_string(),
                    None => "unknown".to_string(),
                };
                let display = listed
                    .map(|l| l.description.clone())
                    .filter(|d| !d.is_empty())
                    .or_else(|| loaded.and_then(|l| l.unit.description().map(str::to_string)))
                    .unwrap_or_else(|| name.to_string());
                out_services.push(ServiceObservation {
                    service_name: name.to_string(),
                    display_name: display,
                    state,
                    start_type: loaded
                        .map(|l| start_type(l, &enabled))
                        .unwrap_or(if listed.is_some() {
                            "generated"
                        } else {
                            "unknown"
                        })
                        .to_string(),
                    binary_path: loaded.and_then(|l| l.unit.exec_start()).unwrap_or_default(),
                    account: loaded
                        .and_then(|l| l.unit.user().map(str::to_string))
                        .unwrap_or_else(|| "root".to_string()),
                    pid,
                    executable_hash: None,
                    path_quoted: false,
                    unquoted_risk: false,
                    collected_at: now.to_string(),
                    source: "systemd".to_string(),
                    unit_file: loaded.map(|l| l.path.to_string_lossy().into_owned()),
                });
            };

        for (name, loaded) in &services {
            // Templates ("foo@.service") are not services until instantiated.
            if name.contains("@.") {
                continue;
            }
            push_service(name, Some(loaded), listed.get(name));
        }
        // Instances and generated units only systemd knows about.
        for (name, l) in &listed {
            push_service(name, resolve(&services, name), Some(l));
        }
        // Enabled template instances (e.g. getty@tty1.service).
        for name in enabled.iter().filter(|n| n.ends_with(".service")) {
            if let Some(loaded) = resolve(&services, name) {
                push_service(name, Some(loaded), listed.get(name));
            }
        }

        // Persistence: every enabled system service.
        let mut autoruns = Vec::new();
        for name in enabled.iter().filter(|n| n.ends_with(".service")) {
            let Some(loaded) = resolve(&services, name) else {
                continue;
            };
            let exec = loaded.unit.exec_start().unwrap_or_default();
            autoruns.push(AutorunObservation {
                hive: "systemd".to_string(),
                key: loaded.path.to_string_lossy().into_owned(),
                value_name: name.clone(),
                resolved_executable: command_executable(&exec),
                value_data: exec,
                hash: None,
                owner: Some(loaded.unit.user().unwrap_or("root").to_string()),
                timestamp: file_mtime_rfc3339(&loaded.path).unwrap_or_else(|| now.to_string()),
                mechanism: "systemd_service".to_string(),
            });
        }

        // Per-user units enabled with `systemctl --user enable`.
        let user_vendor_dirs = [
            PathBuf::from("usr/lib/systemd/user"),
            PathBuf::from("etc/systemd/user"),
        ];
        for (user, home) in home_dirs {
            let user_dir = root_path(root, home).join(".config/systemd/user");
            let user_enabled = enabled_links(&user_dir);
            if user_enabled.is_empty() {
                continue;
            }
            let mut dirs = vec![user_dir
                .strip_prefix(root)
                .unwrap_or(&user_dir)
                .to_path_buf()];
            dirs.extend(user_vendor_dirs.iter().cloned());
            let user_units = load_units(root, &dirs, ".service");
            for name in user_enabled.iter().filter(|n| n.ends_with(".service")) {
                let Some(loaded) = resolve(&user_units, name) else {
                    continue;
                };
                let exec = loaded.unit.exec_start().unwrap_or_default();
                autoruns.push(AutorunObservation {
                    hive: "systemd-user".to_string(),
                    key: loaded.path.to_string_lossy().into_owned(),
                    value_name: name.clone(),
                    resolved_executable: command_executable(&exec),
                    value_data: exec,
                    hash: None,
                    owner: Some(user.clone()),
                    timestamp: file_mtime_rfc3339(&loaded.path).unwrap_or_else(|| now.to_string()),
                    mechanism: "systemd_user_service".to_string(),
                });
            }
        }

        // Enabled timers are scheduled tasks.
        let mut timer_tasks = Vec::new();
        for name in enabled.iter().filter(|n| n.ends_with(".timer")) {
            let Some(timer) = resolve(&timers, name) else {
                continue;
            };
            let service_name = timer
                .unit
                .get("Timer", "Unit")
                .map(str::to_string)
                .unwrap_or_else(|| name.trim_end_matches(".timer").to_string() + ".service");
            let service = resolve(&services, &service_name);
            let exec = service.and_then(|s| s.unit.exec_start());
            let user = service
                .and_then(|s| s.unit.user().map(str::to_string))
                .unwrap_or_else(|| "root".to_string());
            timer_tasks.push(ScheduledTaskObservation {
                task_name: name.clone(),
                task_path: timer.path.to_string_lossy().into_owned(),
                state: "enabled".to_string(),
                action: exec,
                arguments: None,
                run_level: user.clone(),
                collected_at: now.to_string(),
                mechanism: "systemd_timer".to_string(),
                schedule: timer.unit.timer_schedule(),
                user: Some(user),
            });
        }

        SystemdScan {
            services: out_services,
            autoruns,
            timers: timer_tasks,
            errors,
        }
    }

    /// SysV init scripts in /etc/init.d that have no systemd unit.
    pub fn sysv_services(
        root: &Path,
        known: &BTreeSet<String>,
        now: &str,
    ) -> Vec<ServiceObservation> {
        use std::os::unix::fs::PermissionsExt;
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(root.join("etc/init.d")) else {
            return out;
        };
        let mut names: Vec<(String, PathBuf)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = e.metadata().ok()?;
                let executable = meta.is_file() && meta.permissions().mode() & 0o111 != 0;
                (executable
                    && !matches!(
                        name.as_str(),
                        "README" | "skeleton" | "rc" | "rcS" | "functions"
                    ))
                .then_some((name, e.path()))
            })
            .collect();
        names.sort();
        for (name, path) in names {
            if known.contains(&format!("{}.service", name)) {
                continue;
            }
            let enabled = (2..=5).any(|level| {
                std::fs::read_dir(root.join(format!("etc/rc{}.d", level)))
                    .map(|links| {
                        links.flatten().any(|l| {
                            let link = l.file_name().to_string_lossy().into_owned();
                            link.starts_with('S') && link.get(3..) == Some(name.as_str())
                        })
                    })
                    .unwrap_or(false)
            });
            out.push(ServiceObservation {
                service_name: name.clone(),
                display_name: name.clone(),
                state: "unknown".to_string(),
                start_type: if enabled { "enabled" } else { "disabled" }.to_string(),
                binary_path: path.to_string_lossy().into_owned(),
                account: "root".to_string(),
                pid: None,
                executable_hash: None,
                path_quoted: false,
                unquoted_risk: false,
                collected_at: now.to_string(),
                source: "sysv".to_string(),
                unit_file: Some(path.to_string_lossy().into_owned()),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIS_UNIT: &str = r#"[Unit]
Description=Advanced key-value store
After=network.target
Documentation=http://redis.io/documentation,
              man:redis-server(1)

[Service]
Type=notify
ExecStart=/usr/bin/redis-server /etc/redis/redis.conf --supervised systemd --daemonize no
PIDFile=/run/redis/redis-server.pid
TimeoutStopSec=0
Restart=always
User=redis
Group=redis
# comment line
; another comment
ExecStartPre=-/bin/mkdir -p \
    /run/redis

[Install]
WantedBy=multi-user.target
Alias=redis.service
"#;

    #[test]
    fn parses_service_unit() {
        let unit = parse_unit_file(REDIS_UNIT);
        assert_eq!(unit.description(), Some("Advanced key-value store"));
        assert_eq!(
            unit.exec_start().as_deref(),
            Some("/usr/bin/redis-server /etc/redis/redis.conf --supervised systemd --daemonize no")
        );
        assert_eq!(unit.user(), Some("redis"));
        assert!(unit.installable());
        assert_eq!(
            unit.get("Service", "ExecStartPre"),
            Some("-/bin/mkdir -p /run/redis")
        );
    }

    #[test]
    fn strips_exec_prefixes_and_detects_static_units() {
        let unit = parse_unit_file("[Service]\nExecStart=-!/usr/sbin/sshd -D\n");
        assert_eq!(unit.exec_start().as_deref(), Some("/usr/sbin/sshd -D"));
        assert!(!unit.installable());
        assert_eq!(unit.user(), None);
    }

    #[test]
    fn parses_timer_schedule() {
        let unit = parse_unit_file(
            "[Timer]\nOnCalendar=daily\nOnCalendar=*-*-* 06:00\nOnBootSec=15min\nUnit=backup.service\n",
        );
        assert_eq!(
            unit.timer_schedule().as_deref(),
            Some("OnCalendar=daily; OnCalendar=*-*-* 06:00; OnBootSec=15min")
        );
        assert_eq!(unit.get("Timer", "Unit"), Some("backup.service"));
    }

    #[test]
    fn parses_systemctl_list_units() {
        let output = "cron.service                 loaded    active   running Regular background program processing daemon
● nonexistent.service        not-found inactive dead    nonexistent.service
redis-server.service         loaded    active   running Advanced key-value store
systemd-fsck@dev-vda.service loaded    active   exited  File System Check on /dev/vda
";
        let units = parse_list_units(output);
        assert_eq!(units.len(), 4);
        assert_eq!(units[0].unit, "cron.service");
        assert_eq!(units[0].active, "active");
        assert_eq!(units[0].sub, "running");
        assert_eq!(
            units[0].description,
            "Regular background program processing daemon"
        );
        assert_eq!(units[1].unit, "nonexistent.service");
        assert_eq!(units[1].load, "not-found");
        assert_eq!(units[3].sub, "exited");
    }

    #[test]
    fn resolves_template_names_and_executables() {
        assert_eq!(
            template_name("getty@tty1.service").as_deref(),
            Some("getty@.service")
        );
        assert_eq!(template_name("cron.service"), None);
        assert_eq!(
            command_executable("/usr/bin/redis-server /etc/redis.conf"),
            "/usr/bin/redis-server"
        );
        assert_eq!(
            command_executable("\"/opt/my app/run\" --x"),
            "/opt/my app/run"
        );
        assert_eq!(command_executable(""), "");
    }
}

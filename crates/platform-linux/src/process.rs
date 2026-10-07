#![forbid(unsafe_code)]

//! Process enumeration from `/proc`.

/// Selected fields of `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub session: u32,
    /// Start time in clock ticks since boot (field 22).
    pub start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. The command name is enclosed in parentheses
/// and may itself contain spaces and parentheses, so the fixed fields are
/// located after the *last* ')'.
pub fn parse_proc_stat(content: &str) -> Option<ProcStat> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = content[..open].trim().parse().ok()?;
    let comm = content[open + 1..close].to_string();
    let rest: Vec<&str> = content[close + 1..].split_whitespace().collect();
    // rest[0] is field 3 (state); field N is rest[N - 3].
    if rest.len() < 20 {
        return None;
    }
    Some(ProcStat {
        pid,
        comm,
        state: rest[0].chars().next().unwrap_or('?'),
        ppid: rest[1].parse().ok()?,
        session: rest[3].parse().ok()?,
        start_ticks: rest[19].parse().ok()?,
    })
}

/// Selected fields of `/proc/<pid>/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcStatus {
    pub name: String,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub vm_rss_kb: u64,
}

pub fn parse_status_fields(status: &str) -> ProcStatus {
    let mut out = ProcStatus::default();
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            out.name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Uid:") {
            let ids: Vec<u32> = v
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            out.uid = ids.first().copied();
            out.euid = ids.get(1).copied();
        } else if let Some(v) = line.strip_prefix("VmRSS:") {
            out.vm_rss_kb = v.replace("kB", "").trim().parse().unwrap_or(0);
        }
    }
    out
}

/// Parses `/proc/[pid]/status` extracting Name and VmRSS (kB).
pub fn parse_proc_status(status_str: &str) -> (String, u64) {
    let status = parse_status_fields(status_str);
    (status.name, status.vm_rss_kb)
}

/// Splits the target of `/proc/<pid>/exe` into the path and whether the
/// image was deleted after the process started.
pub fn parse_exe_link(target: &str) -> (String, bool) {
    match target.strip_suffix(" (deleted)") {
        Some(path) => (path.to_string(), true),
        None => (target.to_string(), false),
    }
}

/// `/proc/<pid>/cmdline` is NUL separated; renders it as a space separated
/// command line. Kernel threads have an empty cmdline -> `None`.
pub fn cmdline_to_string(raw: &[u8]) -> Option<String> {
    let parts: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let mut parts = parts;
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    let joined = parts.join(" ");
    let trimmed = joined.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Architecture of an ELF image from its first 20 bytes.
pub fn elf_architecture(header: &[u8]) -> Option<&'static str> {
    if header.len() < 20 || &header[..4] != b"\x7fELF" {
        return None;
    }
    let class64 = header[4] == 2;
    let machine = match header[5] {
        2 => u16::from_be_bytes([header[18], header[19]]),
        _ => u16::from_le_bytes([header[18], header[19]]),
    };
    Some(match machine {
        3 => "i386",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        22 => "s390x",
        40 => "arm",
        62 => "x86_64",
        183 => "aarch64",
        243 if class64 => "riscv64",
        243 => "riscv32",
        258 => "loongarch64",
        _ => "unknown",
    })
}

/// The systemd system service a process belongs to, from
/// `/proc/<pid>/cgroup` (e.g. `0::/system.slice/nginx.service` -> "nginx.service").
pub fn parse_cgroup_unit(content: &str) -> Option<String> {
    for line in content.lines() {
        let path = line.splitn(3, ':').nth(2).unwrap_or("");
        if !path.contains("/system.slice/") {
            continue;
        }
        if let Some(unit) = path
            .split('/')
            .rev()
            .find(|segment| segment.ends_with(".service"))
        {
            return Some(unit.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;
    use chrono::{TimeZone, Utc};
    use host_snapshot::{FileHashCache, ProcessObservation, COLLECTOR_VERSION, MAX_HASH_BYTES};
    use std::collections::HashMap;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    static EXE_HASHES: FileHashCache = FileHashCache::new();

    pub struct LiveProcess {
        pub obs: ProcessObservation,
        pub systemd_unit: Option<String>,
        pub vm_rss_kb: u64,
    }

    pub struct ProcessScan {
        pub processes: Vec<LiveProcess>,
        pub unreadable_exe: usize,
        pub too_large_to_hash: usize,
    }

    pub fn boot_time() -> Option<i64> {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        stat.lines()
            .find_map(|l| l.strip_prefix("btime "))
            .and_then(|v| v.trim().parse().ok())
    }

    /// USER_HZ. Fixed at 100 on every mainstream architecture, but asked of
    /// the system when `getconf` is available.
    pub fn clock_ticks() -> u64 {
        std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .filter(|v: &u64| *v > 0)
            .unwrap_or(100)
    }

    fn read_head(path: &Path, n: usize) -> Option<Vec<u8>> {
        let mut f = std::fs::File::open(path).ok()?;
        let mut buf = vec![0u8; n];
        let mut read = 0;
        while read < n {
            match f.read(&mut buf[read..]) {
                Ok(0) => break,
                Ok(k) => read += k,
                Err(_) => return None,
            }
        }
        buf.truncate(read);
        Some(buf)
    }

    pub fn collect_processes(host: &str, uid_names: &HashMap<u32, String>) -> ProcessScan {
        let now = Utc::now().to_rfc3339();
        let btime = boot_time();
        let ticks = clock_ticks();
        let mut processes = Vec::new();
        let mut unreadable_exe = 0usize;
        let mut too_large_to_hash = 0usize;

        let Ok(dir) = std::fs::read_dir("/proc") else {
            return ProcessScan {
                processes,
                unreadable_exe,
                too_large_to_hash,
            };
        };
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let base = entry.path();
            // The process may exit while we read it; skip it if so.
            let Some(stat) = std::fs::read_to_string(base.join("stat"))
                .ok()
                .and_then(|s| parse_proc_stat(&s))
            else {
                continue;
            };
            let status = std::fs::read_to_string(base.join("status"))
                .map(|s| parse_status_fields(&s))
                .unwrap_or_default();
            let command_line = std::fs::read(base.join("cmdline"))
                .ok()
                .and_then(|raw| cmdline_to_string(&raw));
            let is_kernel_thread = command_line.is_none() && (stat.ppid == 2 || pid == 2);

            let exe_link = base.join("exe");
            let (executable_path, exe_deleted) = match std::fs::read_link(&exe_link) {
                Ok(target) => {
                    let (path, deleted) = parse_exe_link(&target.to_string_lossy());
                    (Some(path), deleted)
                }
                Err(_) => {
                    if !is_kernel_thread {
                        unreadable_exe += 1;
                    }
                    (None, false)
                }
            };

            let mut architecture = "unknown".to_string();
            let mut sha256 = None;
            if executable_path.is_some() {
                if let Some(arch) = read_head(&exe_link, 20)
                    .as_deref()
                    .and_then(elf_architecture)
                {
                    architecture = arch.to_string();
                }
                if let Ok(meta) = std::fs::metadata(&exe_link) {
                    if meta.len() > MAX_HASH_BYTES {
                        too_large_to_hash += 1;
                    } else {
                        // Hash through /proc/<pid>/exe so the bytes are the
                        // ones actually mapped -- this also works for deleted
                        // and memfd-backed images.
                        let key = format!(
                            "{}:{}:{}:{}",
                            meta.dev(),
                            meta.ino(),
                            meta.len(),
                            meta.mtime()
                        );
                        sha256 = EXE_HASHES.get_or_compute(&key, &exe_link, MAX_HASH_BYTES);
                    }
                }
            }

            let started_at = btime.and_then(|bt| {
                let secs = bt + (stat.start_ticks / ticks) as i64;
                let nanos = ((stat.start_ticks % ticks) * (1_000_000_000 / ticks)) as u32;
                Utc.timestamp_opt(secs, nanos)
                    .single()
                    .map(|t| t.to_rfc3339())
            });

            let username = status.uid.map(|uid| {
                uid_names
                    .get(&uid)
                    .cloned()
                    .unwrap_or_else(|| uid.to_string())
            });
            let integrity_level = match status.euid {
                Some(0) => "root",
                Some(_) => "user",
                None => "unknown",
            }
            .to_string();

            let systemd_unit = std::fs::read_to_string(base.join("cgroup"))
                .ok()
                .and_then(|c| parse_cgroup_unit(&c));

            let name = if status.name.is_empty() {
                stat.comm.clone()
            } else {
                status.name.clone()
            };

            processes.push(LiveProcess {
                obs: ProcessObservation {
                    host_id: host.to_string(),
                    pid,
                    ppid: stat.ppid,
                    name,
                    executable_path,
                    command_line,
                    username,
                    session_id: stat.session,
                    started_at,
                    sha256,
                    signer: None,
                    architecture,
                    integrity_level,
                    collected_at: now.clone(),
                    collector_version: COLLECTOR_VERSION.to_string(),
                    source: "LinuxProcfsCollector".to_string(),
                    uid: status.uid,
                    exe_deleted,
                },
                systemd_unit,
                vm_rss_kb: status.vm_rss_kb,
            });
        }
        processes.sort_by_key(|p| p.obs.pid);
        ProcessScan {
            processes,
            unreadable_exe,
            too_large_to_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_spaces_and_parens_in_comm() {
        let sample = "11556 (cat) R 11551 11556 11551 0 -1 4194304 85 0 0 0 0 0 0 0 20 0 1 0 70067 2928640 365 18446744073709551615 94836578521088 94836578538673 140734035227136 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0";
        let stat = parse_proc_stat(sample).unwrap();
        assert_eq!(stat.pid, 11556);
        assert_eq!(stat.comm, "cat");
        assert_eq!(stat.state, 'R');
        assert_eq!(stat.ppid, 11551);
        assert_eq!(stat.session, 11551);
        assert_eq!(stat.start_ticks, 70067);

        let tricky = "42 (evil) (x y)) S 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0";
        let stat = parse_proc_stat(tricky).unwrap();
        assert_eq!(stat.comm, "evil) (x y)");
        assert_eq!(stat.ppid, 1);
        assert_eq!(stat.start_ticks, 999);

        assert!(parse_proc_stat("garbage").is_none());
    }

    #[test]
    fn parses_status_uid_and_rss() {
        let sample = "Name:\tsoc-engine\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t42\nPPid:\t1\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\nVmRSS:\t   18450 kB\n";
        let status = parse_status_fields(sample);
        assert_eq!(status.name, "soc-engine");
        assert_eq!(status.uid, Some(1000));
        assert_eq!(status.euid, Some(0));
        assert_eq!(status.vm_rss_kb, 18450);
        assert_eq!(parse_proc_status(sample), ("soc-engine".to_string(), 18450));
    }

    #[test]
    fn detects_deleted_and_memfd_executables() {
        assert_eq!(
            parse_exe_link("/usr/bin/bash"),
            ("/usr/bin/bash".to_string(), false)
        );
        assert_eq!(
            parse_exe_link("/tmp/.x/payload (deleted)"),
            ("/tmp/.x/payload".to_string(), true)
        );
        assert_eq!(
            parse_exe_link("/memfd:sbx-telemetry-collector (deleted)"),
            ("/memfd:sbx-telemetry-collector".to_string(), true)
        );
    }

    #[test]
    fn renders_cmdline() {
        assert_eq!(
            cmdline_to_string(b"/bin/bash\0-c\0echo hi\0"),
            Some("/bin/bash -c echo hi".to_string())
        );
        assert_eq!(cmdline_to_string(b""), None);
        assert_eq!(cmdline_to_string(b"\0"), None);
    }

    #[test]
    fn reads_elf_machine() {
        let mut x86_64 = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        x86_64.extend_from_slice(&[0; 10]);
        x86_64.extend_from_slice(&62u16.to_le_bytes());
        assert_eq!(elf_architecture(&x86_64), Some("x86_64"));

        let mut arm64 = x86_64.clone();
        arm64[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert_eq!(elf_architecture(&arm64), Some("aarch64"));

        assert_eq!(elf_architecture(b"#!/bin/sh\nexec foo bar"), None);
    }

    #[test]
    fn extracts_systemd_unit_from_cgroup() {
        assert_eq!(
            parse_cgroup_unit("0::/system.slice/nginx.service\n"),
            Some("nginx.service".to_string())
        );
        assert_eq!(
            parse_cgroup_unit(
                "12:pids:/system.slice/ssh.service\n1:name=systemd:/system.slice/ssh.service\n"
            ),
            Some("ssh.service".to_string())
        );
        assert_eq!(
            parse_cgroup_unit("0::/user.slice/user-1000.slice/session-2.scope\n"),
            None
        );
        assert_eq!(parse_cgroup_unit("0::/\n"), None);
    }
}

//! DFIR stage 3 — cross-host correlation («связи»).
//!
//! The stage-2 detectors look at one host's events in isolation. This module
//! links the *same* indicator seen across more than one host, so a spray
//! across the fleet or lateral movement with a shared account stands out:
//!
//! * a source IP that attempted logons on several hosts, and
//! * an account that successfully logged in on several hosts.
//!
//! Both span Linux (`auth.log`/`secure` SSH) and Windows (`.evtx` logon events
//! 4624/4625/4771), so an address or account reused across a Windows server and
//! a Linux box links the two.
//!
//! Like the detections these are leads, not verdicts: every link carries the
//! concrete log lines it rests on (grouped per host), a UTC range and the
//! relevant MITRE ATT&CK technique. The analyst decides whether the shared
//! access is legitimate.
//!
//! A host is attributed per event by [`event_host`]: logs collected into a
//! per-host folder (`web01/auth.log`) are grouped by that folder; a flat
//! syslog carrying real hostnames is grouped by the hostname in the frame.
//! When neither is available an event cannot be tied to a host and is left out
//! of correlation (never guessed).

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::detect::{EvidenceRef, Finding, Severity};
use crate::{LogEvent, LogSource, Outcome};

/// Evidence lines kept per host within one link.
const MAX_EVIDENCE_PER_HOST: usize = 4;
/// Hosts whose evidence is included before the rest are summarized by count.
const MAX_HOSTS_EVIDENCE: usize = 8;

/// Whether a source address is on the local/internal network rather than the
/// public internet: private (RFC1918), loopback, link-local, unspecified and
/// carrier-grade-NAT v4, plus unique-local and link-local v6. Documentation
/// ranges (`198.51.100.x` etc.) are treated as external — they stand in for
/// public addresses. An unparseable value is not internal.
///
/// Why it matters: a *shared internal* IP or account spanning several hosts is
/// everyday operations — a jump host, a config-management box, an admin's
/// workstation, a service account. Flagging those as cross-host "links" buries
/// the real signal. A cross-host indicator is a lead worth raising when the
/// access came from *outside*: an external address spraying the fleet, or a
/// shared account broken into from the internet (lateral movement / valid-
/// accounts reuse). So correlation links are gated on an external source.
fn is_internal_ip(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || {
                // 100.64.0.0/10 — carrier-grade NAT, not a specific host.
                let o = a.octets();
                o[0] == 100 && (64..=127).contains(&o[1])
            }
        }
        Ok(IpAddr::V6(a)) => {
            a.is_loopback()
                || a.is_unspecified()
                || (a.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (a.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
        }
        Err(_) => false,
    }
}

/// A source address on the public internet: it parses and is not internal.
fn is_external_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() && !is_internal_ip(s)
}

/// Which host an event belongs to: the first path segment of its
/// `source_file` (the per-host folder a collection uses), else the syslog
/// hostname when the line carried a real one. `None` when the event cannot be
/// tied to a host — such events are never invented onto a host.
pub(crate) fn event_host(e: &LogEvent) -> Option<String> {
    if let Some((dir, _)) = e.source_file.split_once(['/', '\\']) {
        let dir = dir.trim();
        if !dir.is_empty() && dir != "." {
            return Some(dir.to_string());
        }
    }
    // `e.host` is the syslog hostname when present, but auth parsing falls back
    // to the program name (e.g. `sshd`) when a line has no hostname — reject
    // that so a daemon name is never treated as a host.
    let prog = e.fields.get("program").map(String::as_str);
    match &e.host {
        Some(h) if !h.is_empty() && Some(h.as_str()) != prog => Some(h.clone()),
        _ => None,
    }
}

/// A logon event we correlate across hosts: any Linux auth line, or a Windows
/// logon record (success 4624, failure 4625, Kerberos pre-auth 4771). Other
/// Windows events (process creation, service install …) are not logons and do
/// not participate in these links.
fn is_logon_event(e: &LogEvent) -> bool {
    match e.source {
        LogSource::Auth => true,
        LogSource::WindowsEvent => matches!(
            e.fields.get("event_id").and_then(|s| s.parse::<i64>().ok()),
            Some(4624) | Some(4625) | Some(4771)
        ),
        _ => false,
    }
}

/// Source IP of a logon event: Linux auth stores it in `src_ip`, the Windows
/// `.evtx` parser in `ip`.
fn source_ip(e: &LogEvent) -> Option<&str> {
    e.fields
        .get("src_ip")
        .or_else(|| e.fields.get("ip"))
        .map(String::as_str)
        .filter(|s| !s.is_empty())
}

/// Account of a logon event: Linux auth stores it in `fields["user"]`, the
/// Windows parser in `actor` (the target account).
fn logon_user(e: &LogEvent) -> Option<&str> {
    match e.source {
        LogSource::WindowsEvent => e.actor.as_deref(),
        _ => e.fields.get("user").map(String::as_str),
    }
    .filter(|s| !s.is_empty())
}

/// Run every correlation over the timeline and return the links, worst first.
pub fn correlate(events: &[LogEvent]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(cross_host_ip(events));
    out.extend(cross_host_account(events));
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.first_time.cmp(&b.first_time))
    });
    out
}

/// Chronological, origin-stable order for evidence gathered across hosts.
fn chrono(a: &&LogEvent, b: &&LogEvent) -> std::cmp::Ordering {
    a.timestamp
        .cmp(&b.timestamp)
        .then_with(|| a.source_file.cmp(&b.source_file))
        .then_with(|| a.line_no.cmp(&b.line_no))
}

/// Build the per-host evidence list (a few lines per host, bounded) and the
/// overall first/last time, from events already grouped by host.
fn evidence_and_range(
    by_host: &BTreeMap<String, Vec<&LogEvent>>,
) -> (Vec<EvidenceRef>, String, String) {
    let mut all: Vec<&LogEvent> = by_host.values().flatten().copied().collect();
    all.sort_by(chrono);
    let first_time = all.first().map(|e| e.timestamp.clone()).unwrap_or_default();
    let last_time = all.last().map(|e| e.timestamp.clone()).unwrap_or_default();

    let mut evidence = Vec::new();
    for host_events in by_host.values().take(MAX_HOSTS_EVIDENCE) {
        let mut sorted = host_events.clone();
        sorted.sort_by(chrono);
        for e in sorted.into_iter().take(MAX_EVIDENCE_PER_HOST) {
            evidence.push(EvidenceRef::of(e));
        }
    }
    (evidence, first_time, last_time)
}

// ---------------------------------------------------------------------------
// One source IP, several hosts
// ---------------------------------------------------------------------------

fn cross_host_ip(events: &[LogEvent]) -> Vec<Finding> {
    struct PerIp<'a> {
        by_host: BTreeMap<String, Vec<&'a LogEvent>>,
        any_success: bool,
    }
    let mut by_ip: BTreeMap<String, PerIp> = BTreeMap::new();

    for e in events {
        if !is_logon_event(e) {
            continue;
        }
        let Some(ip) = source_ip(e) else {
            continue;
        };
        let Some(host) = event_host(e) else {
            continue;
        };
        let entry = by_ip.entry(ip.to_string()).or_insert_with(|| PerIp {
            by_host: BTreeMap::new(),
            any_success: false,
        });
        entry.by_host.entry(host).or_default().push(e);
        if e.outcome == Some(Outcome::Success) {
            entry.any_success = true;
        }
    }

    let mut findings = Vec::new();
    for (ip, per) in by_ip {
        if per.by_host.len() < 2 {
            continue;
        }
        // An internal address reaching several hosts is normal operations
        // (jump host, admin box); only an external source is a lead.
        if !is_external_ip(&ip) {
            continue;
        }
        let hosts: Vec<String> = per.by_host.keys().cloned().collect();
        let (evidence, first_time, last_time) = evidence_and_range(&per.by_host);
        let (severity, mitre) = if per.any_success {
            (
                Severity::High,
                vec!["T1021".into(), "T1078".into(), "T1110".into()],
            )
        } else {
            (Severity::Medium, vec!["T1110".into(), "T1021".into()])
        };
        let summary = format!(
            "Адрес {ip} обращался к {} хостам ({}).{}",
            hosts.len(),
            hosts.join(", "),
            if per.any_success {
                " Есть успешный вход — возможно продвижение по сети."
            } else {
                " Везде только неудачные попытки — похоже на перебор по всему парку."
            }
        );
        findings.push(Finding {
            rule: "link-ip-multi-host".into(),
            title: "Один адрес — несколько хостов".into(),
            severity,
            mitre,
            summary,
            actor: Some(ip),
            first_time,
            last_time,
            evidence,
            hosts,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// One account, successful logins on several hosts
// ---------------------------------------------------------------------------

fn cross_host_account(events: &[LogEvent]) -> Vec<Finding> {
    struct PerUser<'a> {
        by_host: BTreeMap<String, Vec<&'a LogEvent>>,
        any_external: bool,
    }
    let mut by_user: BTreeMap<String, PerUser> = BTreeMap::new();

    for e in events {
        if !is_logon_event(e) || e.outcome != Some(Outcome::Success) {
            continue;
        }
        let Some(user) = logon_user(e) else {
            continue;
        };
        let Some(host) = event_host(e) else {
            continue;
        };
        let entry = by_user.entry(user.to_string()).or_insert_with(|| PerUser {
            by_host: BTreeMap::new(),
            any_external: false,
        });
        entry.by_host.entry(host).or_default().push(e);
        if source_ip(e).is_some_and(is_external_ip) {
            entry.any_external = true;
        }
    }

    let mut findings = Vec::new();
    for (user, per) in by_user {
        let by_host = per.by_host;
        if by_host.len() < 2 {
            continue;
        }
        // A shared account used across hosts only from inside the network is
        // ordinary (ops/service accounts); raise it when at least one of those
        // logins came from the public internet — the valid-accounts-reuse lead.
        if !per.any_external {
            continue;
        }
        let hosts: Vec<String> = by_host.keys().cloned().collect();
        let (evidence, first_time, last_time) = evidence_and_range(&by_host);
        let summary = format!(
            "Учётная запись {user} успешно входила на {} хостов ({}). Проверьте, легитимен ли такой доступ ко всем этим машинам.",
            hosts.len(),
            hosts.join(", ")
        );
        findings.push(Finding {
            rule: "link-account-multi-host".into(),
            title: "Учётная запись входит на несколько хостов".into(),
            severity: Severity::High,
            mitre: vec!["T1078".into()],
            summary,
            actor: Some(user),
            first_time,
            last_time,
            evidence,
            hosts,
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
                "incident-corr-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        /// Write `body` to `<host>/auth.log`, creating the per-host folder.
        fn write_host(&self, host: &str, name: &str, body: &str) {
            let dir = self.0.join(host);
            std::fs::create_dir_all(&dir).unwrap();
            let mut f = std::fs::File::create(dir.join(name)).unwrap();
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
            .unwrap_or_else(|| panic!("no link {rule} in {f:#?}"))
    }

    #[test]
    fn same_ip_hitting_two_hosts_is_linked() {
        let d = TempDir::new("ip");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n",
        );
        d.write_host(
            "db01",
            "auth.log",
            "Oct 10 10:05:00 db01 sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let link = find(&t.links, "link-ip-multi-host");
        assert_eq!(link.severity, Severity::Medium);
        assert_eq!(link.actor.as_deref(), Some("203.0.113.9"));
        assert_eq!(link.hosts, vec!["db01".to_string(), "web01".to_string()]);
        // Evidence spans both hosts.
        assert!(link
            .evidence
            .iter()
            .any(|e| e.source_file.contains("web01")));
        assert!(link.evidence.iter().any(|e| e.source_file.contains("db01")));
    }

    #[test]
    fn a_success_on_any_host_raises_severity_to_high() {
        let d = TempDir::new("ipok");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n",
        );
        d.write_host(
            "db01",
            "auth.log",
            "Oct 10 10:05:00 db01 sshd[1]: Accepted password for deploy from 203.0.113.9 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let link = find(&t.links, "link-ip-multi-host");
        assert_eq!(link.severity, Severity::High);
        assert!(link.mitre.iter().any(|m| m == "T1078"));
    }

    #[test]
    fn an_ip_on_one_host_is_not_a_link() {
        let d = TempDir::new("oneip");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n\
             Oct 10 10:01:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(t.links.iter().all(|l| l.rule != "link-ip-multi-host"));
    }

    #[test]
    fn account_logging_into_two_hosts_is_linked() {
        let d = TempDir::new("acct");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Accepted password for deploy from 198.51.100.4 port 1 ssh2\n",
        );
        d.write_host(
            "db01",
            "auth.log",
            "Oct 10 10:05:00 db01 sshd[1]: Accepted publickey for deploy from 198.51.100.5 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let link = find(&t.links, "link-account-multi-host");
        assert_eq!(link.severity, Severity::High);
        assert_eq!(link.actor.as_deref(), Some("deploy"));
        assert!(link.mitre.iter().any(|m| m == "T1078"));
        assert_eq!(link.hosts.len(), 2);
    }

    #[test]
    fn only_failed_logins_do_not_link_an_account() {
        let d = TempDir::new("acctfail");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Failed password for deploy from 198.51.100.4 port 1 ssh2\n",
        );
        d.write_host(
            "db01",
            "auth.log",
            "Oct 10 10:05:00 db01 sshd[1]: Failed password for deploy from 198.51.100.5 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(t.links.iter().all(|l| l.rule != "link-account-multi-host"));
    }

    #[test]
    fn an_internal_ip_across_hosts_is_not_a_link() {
        // A private address reaching two hosts (a jump host / admin box) is
        // normal operations, not a cross-host lead.
        let d = TempDir::new("intip");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Accepted publickey for ubuntu from 10.0.3.11 port 1 ssh2\n",
        );
        d.write_host(
            "db01",
            "auth.log",
            "Oct 10 10:05:00 db01 sshd[1]: Accepted publickey for ubuntu from 10.0.3.11 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(
            t.links.iter().all(|l| l.rule != "link-ip-multi-host"),
            "{:#?}",
            t.links
        );
    }

    #[test]
    fn an_account_only_from_internal_ips_is_not_linked() {
        // The same admin account on two hosts, but every login from the LAN —
        // ordinary shared access, suppressed.
        let d = TempDir::new("intacct");
        d.write_host(
            "web01",
            "auth.log",
            "Oct 10 10:00:00 web01 sshd[1]: Accepted publickey for ubuntu from 10.0.3.11 port 1 ssh2\n",
        );
        d.write_host(
            "db01",
            "auth.log",
            "Oct 10 10:05:00 db01 sshd[1]: Accepted publickey for ubuntu from 192.168.1.50 port 2 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert!(
            t.links.iter().all(|l| l.rule != "link-account-multi-host"),
            "{:#?}",
            t.links
        );
    }

    #[test]
    fn classifies_internal_and_external_addresses() {
        for ip in [
            "10.0.3.11",
            "192.168.1.50",
            "172.16.5.9",
            "127.0.0.1",
            "100.100.1.1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(is_internal_ip(ip), "{ip} should be internal");
            assert!(!is_external_ip(ip), "{ip} should not be external");
        }
        for ip in [
            "45.137.21.134",
            "203.0.113.9",
            "198.51.100.4",
            "8.8.8.8",
            "2606:4700::1111",
        ] {
            assert!(!is_internal_ip(ip), "{ip} should not be internal");
            assert!(is_external_ip(ip), "{ip} should be external");
        }
        assert!(!is_external_ip("not-an-ip"));
        assert!(!is_internal_ip("not-an-ip"));
    }

    #[test]
    fn a_single_host_corpus_produces_no_links() {
        let d = TempDir::new("single");
        // Flat file, one host in the frame — nothing to correlate across.
        let dir = &d.0;
        let mut f = std::fs::File::create(dir.join("auth.log")).unwrap();
        f.write_all(
            b"Oct 10 10:00:00 web01 sshd[1]: Accepted password for deploy from 198.51.100.4 port 1 ssh2\n",
        )
        .unwrap();
        drop(f);
        let t = analyze_path(dir, &opts()).unwrap();
        assert!(t.links.is_empty(), "{:#?}", t.links);
    }

    // ---- Cross-host links spanning Windows (.evtx) events ------------------

    /// A Windows logon `LogEvent` as the `.evtx` parser produces it, on a named
    /// host, with a source IP.
    fn win_logon(
        id: i64,
        secs: i64,
        user: &str,
        host: &str,
        ip: &str,
        outcome: Outcome,
    ) -> LogEvent {
        let mut fields = BTreeMap::new();
        fields.insert("event_id".to_string(), id.to_string());
        fields.insert("ip".to_string(), ip.to_string());
        LogEvent {
            timestamp: format!("2026-10-10T10:00:{secs:02}Z"),
            source: LogSource::WindowsEvent,
            source_file: format!("{host}/Security.evtx"),
            line_no: secs as usize,
            host: Some(host.to_string()),
            actor: Some(user.to_string()),
            summary: format!("EID {id}"),
            outcome: Some(outcome),
            fields,
            raw: format!("EID {id}"),
        }
    }

    /// A Linux sshd `LogEvent` (as the auth parser produces it): account in
    /// `fields["user"]`, source IP in `fields["src_ip"]`.
    fn linux_logon(secs: i64, user: &str, host: &str, ip: &str, ok: bool) -> LogEvent {
        let mut fields = BTreeMap::new();
        fields.insert("user".to_string(), user.to_string());
        fields.insert("src_ip".to_string(), ip.to_string());
        LogEvent {
            timestamp: format!("2026-10-10T10:00:{secs:02}Z"),
            source: LogSource::Auth,
            source_file: format!("{host}/auth.log"),
            line_no: secs as usize,
            host: Some(host.to_string()),
            actor: Some(ip.to_string()),
            summary: "ssh".into(),
            outcome: Some(if ok {
                Outcome::Success
            } else {
                Outcome::Failure
            }),
            fields,
            raw: "ssh".into(),
        }
    }

    #[test]
    fn an_external_ip_hitting_a_windows_and_a_linux_host_links_them() {
        let events = vec![
            win_logon(
                4625,
                1,
                "administrator",
                "WIN-DC01",
                "203.0.113.9",
                Outcome::Failure,
            ),
            linux_logon(2, "root", "web01", "203.0.113.9", false),
        ];
        let links = correlate(&events);
        let link = find(&links, "link-ip-multi-host");
        assert_eq!(link.actor.as_deref(), Some("203.0.113.9"));
        assert_eq!(
            link.hosts,
            vec!["WIN-DC01".to_string(), "web01".to_string()]
        );
    }

    #[test]
    fn an_account_logging_into_a_windows_and_a_linux_host_from_outside_links() {
        let events = vec![
            win_logon(
                4624,
                1,
                "deploy",
                "WIN-APP",
                "203.0.113.9",
                Outcome::Success,
            ),
            linux_logon(2, "deploy", "web01", "198.51.100.4", true),
        ];
        let links = correlate(&events);
        let link = find(&links, "link-account-multi-host");
        assert_eq!(link.severity, Severity::High);
        assert_eq!(link.actor.as_deref(), Some("deploy"));
        assert_eq!(link.hosts.len(), 2);
    }

    #[test]
    fn two_windows_hosts_from_one_external_ip_link() {
        let events = vec![
            win_logon(4625, 1, "admin", "WIN-A", "45.137.21.134", Outcome::Failure),
            win_logon(4624, 2, "admin", "WIN-B", "45.137.21.134", Outcome::Success),
        ];
        let links = correlate(&events);
        let link = find(&links, "link-ip-multi-host");
        // A success somewhere raises it to High.
        assert_eq!(link.severity, Severity::High);
        assert_eq!(link.hosts, vec!["WIN-A".to_string(), "WIN-B".to_string()]);
    }

    #[test]
    fn an_internal_rdp_ip_across_two_windows_hosts_is_not_a_link() {
        let events = vec![
            win_logon(4624, 1, "helpdesk", "WIN-A", "10.0.0.5", Outcome::Success),
            win_logon(4624, 2, "helpdesk", "WIN-B", "10.0.0.5", Outcome::Success),
        ];
        let links = correlate(&events);
        assert!(
            links.iter().all(|l| l.rule != "link-ip-multi-host"),
            "{links:#?}"
        );
    }
}

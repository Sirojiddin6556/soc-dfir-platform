//! Per-line parsing: detect a file's log type, read each line's UTC time, and
//! pull out the fields that matter for an investigation.
//!
//! Everything here is conservative: a line becomes an event only when its
//! timestamp parses. A recognized-but-unusual message still becomes a generic
//! event (so it stays on the timeline) rather than being dropped.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use crate::{LogEvent, LogSource, Outcome};

/// Canonical fixed-width UTC rendering, so lexicographic order equals
/// chronological order when events are sorted as strings.
fn render(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn event(ts: DateTime<Utc>, source: LogSource, summary: String, raw: &str) -> LogEvent {
    LogEvent {
        timestamp: render(ts),
        source,
        source_file: String::new(),
        line_no: 0,
        host: None,
        actor: None,
        summary,
        outcome: None,
        fields: BTreeMap::new(),
        raw: raw.to_string(),
    }
}

/// Decide a file's log type from its name and first readable lines.
pub fn detect_source(name: &str, lines: &[String]) -> LogSource {
    let lower = name.to_ascii_lowercase();
    if lower.contains("access") {
        return LogSource::WebAccess;
    }
    if lower.contains("error")
        && (lower.contains("nginx") || lower.contains("apache") || lower.contains("httpd"))
    {
        return LogSource::WebError;
    }
    if lower.contains("auth") || lower.contains("secure") {
        return LogSource::Auth;
    }
    // Fall back to content sniffing on the first non-empty lines.
    for line in lines.iter().filter(|l| !l.trim().is_empty()).take(20) {
        if clf_re().is_match(line) {
            return LogSource::WebAccess;
        }
        if line.contains("sshd[") || line.contains("sudo:") || line.contains("pam_unix") {
            return LogSource::Auth;
        }
    }
    LogSource::Syslog
}

/// Parse one line. Returns `None` when no timestamp can be read.
pub fn parse_line(source: LogSource, line: &str, year: i32) -> Option<LogEvent> {
    match source {
        LogSource::WebAccess => parse_web_access(line),
        LogSource::WebError => parse_web_error(line),
        LogSource::Auth => parse_auth(line, year),
        LogSource::Syslog => parse_syslog(line, year),
    }
}

// ---------------------------------------------------------------------------
// Web access logs (Common / Combined Log Format)
// ---------------------------------------------------------------------------

fn clf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // host - user [time] "request" status bytes ["referer" "ua"]?
        Regex::new(
            r#"^(?P<host>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?"#,
        )
        .unwrap()
    })
}

fn parse_web_access(line: &str) -> Option<LogEvent> {
    let c = clf_re().captures(line)?;
    let time = c.name("time")?.as_str();
    let ts = parse_clf_time(time)?;

    let req = c.name("req").map(|m| m.as_str()).unwrap_or_default();
    let (method, path, proto) = split_request(req);
    let status = c.name("status").map(|m| m.as_str()).unwrap_or_default();
    let client = c.name("host").map(|m| m.as_str()).unwrap_or_default();

    let mut ev = event(
        ts,
        LogSource::WebAccess,
        format!("{method} {path} → {status}"),
        line,
    );
    ev.actor = Some(client.to_string());
    if let Ok(code) = status.parse::<u16>() {
        ev.outcome = Some(if code < 400 {
            Outcome::Success
        } else {
            Outcome::Failure
        });
    }
    let f = &mut ev.fields;
    if !method.is_empty() {
        f.insert("method".into(), method.to_string());
    }
    if !path.is_empty() {
        f.insert("path".into(), path.to_string());
    }
    if !proto.is_empty() {
        f.insert("protocol".into(), proto.to_string());
    }
    f.insert("status".into(), status.to_string());
    if let Some(b) = c.name("bytes") {
        f.insert("bytes".into(), b.as_str().to_string());
    }
    if let Some(u) = c.name("user") {
        if u.as_str() != "-" {
            f.insert("auth_user".into(), u.as_str().to_string());
        }
    }
    if let Some(r) = c.name("ref") {
        if !r.as_str().is_empty() && r.as_str() != "-" {
            f.insert("referer".into(), r.as_str().to_string());
        }
    }
    if let Some(ua) = c.name("ua") {
        if !ua.as_str().is_empty() && ua.as_str() != "-" {
            f.insert("user_agent".into(), ua.as_str().to_string());
        }
    }
    Some(ev)
}

fn split_request(req: &str) -> (&str, &str, &str) {
    let mut it = req.splitn(3, ' ');
    let method = it.next().unwrap_or("");
    let path = it.next().unwrap_or("");
    let proto = it.next().unwrap_or("");
    (method, path, proto)
}

/// `10/Oct/2026:13:55:36 +0000` → UTC.
fn parse_clf_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

// ---------------------------------------------------------------------------
// Web error logs (nginx and Apache)
// ---------------------------------------------------------------------------

fn parse_web_error(line: &str) -> Option<LogEvent> {
    // nginx: 2026/10/10 13:55:36 [error] 123#0: *45 message, client: 1.2.3.4
    if let Some(ts_str) = line.get(0..19) {
        if let Ok(naive) = NaiveDateTime::parse_from_str(ts_str, "%Y/%m/%d %H:%M:%S") {
            let ts = Utc.from_utc_datetime(&naive);
            let rest = line[19..].trim_start();
            let mut ev = event(ts, LogSource::WebError, summarize(rest, 160), line);
            if let Some(level) = bracket_token(rest) {
                ev.fields.insert("level".into(), level);
            }
            if let Some(ip) = after_label(line, "client:") {
                ev.actor = Some(ip);
            }
            return Some(ev);
        }
    }
    // Apache: [Fri Oct 10 13:55:36.123456 2026] [core:error] [client 1.2.3.4] msg
    let ap = apache_err_re().captures(line)?;
    let naive = NaiveDateTime::parse_from_str(
        &format!(
            "{} {} {} {}",
            ap.name("mon")?.as_str(),
            ap.name("day")?.as_str(),
            ap.name("time")?.as_str(),
            ap.name("year")?.as_str()
        ),
        "%b %e %H:%M:%S %Y",
    )
    .ok()?;
    let ts = Utc.from_utc_datetime(&naive);
    let rest = &line[ap.get(0)?.end()..];
    let mut ev = event(ts, LogSource::WebError, summarize(rest.trim(), 160), line);
    if let Some(ip) = after_label(line, "[client") {
        ev.actor = Some(ip.trim_end_matches(']').to_string());
    }
    Some(ev)
}

fn apache_err_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\[\w{3} (?P<mon>\w{3}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)? (?P<year>\d{4})\]",
        )
        .unwrap()
    })
}

// ---------------------------------------------------------------------------
// Auth logs (sshd / sudo / su / PAM)
// ---------------------------------------------------------------------------

fn parse_auth(line: &str, year: i32) -> Option<LogEvent> {
    let (ts, host, program, pid, msg) = parse_syslog_frame(line, year)?;
    let mut ev = event(ts, LogSource::Auth, String::new(), line);
    ev.host = host.or_else(|| program.clone());
    if let Some(p) = &program {
        ev.fields.insert("program".into(), p.clone());
    }
    if let Some(p) = pid {
        ev.fields.insert("pid".into(), p.to_string());
    }

    let prog = program.as_deref().unwrap_or("");
    if prog.starts_with("sshd") {
        if let Some(c) = ssh_accepted_re().captures(msg) {
            ev.outcome = Some(Outcome::Success);
            let user = c.name("user").map(|m| m.as_str()).unwrap_or("");
            let method = c.name("method").map(|m| m.as_str()).unwrap_or("");
            let ip = c.name("ip").map(|m| m.as_str()).unwrap_or("");
            ev.actor = Some(user.to_string());
            ev.summary = format!("SSH вход: {user} с {ip} ({method})");
            ev.fields.insert("user".into(), user.to_string());
            ev.fields.insert("src_ip".into(), ip.to_string());
            ev.fields.insert("method".into(), method.to_string());
            return Some(ev);
        }
        if let Some(c) = ssh_failed_re().captures(msg) {
            ev.outcome = Some(Outcome::Failure);
            let invalid = c.name("invalid").is_some();
            let user = c.name("user").map(|m| m.as_str()).unwrap_or("");
            let ip = c.name("ip").map(|m| m.as_str()).unwrap_or("");
            ev.actor = Some(ip.to_string());
            ev.summary = if invalid {
                format!("SSH: неверный пароль для несуществующего пользователя {user} с {ip}")
            } else {
                format!("SSH: неверный пароль для {user} с {ip}")
            };
            ev.fields.insert("user".into(), user.to_string());
            ev.fields.insert("src_ip".into(), ip.to_string());
            if invalid {
                ev.fields.insert("invalid_user".into(), "true".into());
            }
            return Some(ev);
        }
    }

    if prog.starts_with("sudo") {
        if let Some(c) = sudo_re().captures(msg) {
            let user = c.name("user").map(|m| m.as_str()).unwrap_or("");
            let cmd = c.name("cmd").map(|m| m.as_str()).unwrap_or("");
            ev.actor = Some(user.to_string());
            ev.summary = format!("sudo: {user} выполнил {cmd}");
            ev.fields.insert("user".into(), user.to_string());
            ev.fields.insert("command".into(), cmd.to_string());
            return Some(ev);
        }
    }

    // Recognized auth line without a specific rule: keep it on the timeline.
    ev.summary = format!("{}: {}", prog.trim_end_matches(':'), summarize(msg, 140));
    Some(ev)
}

fn ssh_accepted_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)").unwrap()
    })
}

fn ssh_failed_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
            .unwrap()
    })
}

fn sudo_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$").unwrap())
}

// ---------------------------------------------------------------------------
// Generic syslog
// ---------------------------------------------------------------------------

fn parse_syslog(line: &str, year: i32) -> Option<LogEvent> {
    let (ts, host, program, pid, msg) = parse_syslog_frame(line, year)?;
    let mut ev = event(ts, LogSource::Syslog, String::new(), line);
    ev.host = host;
    let prog = program.clone().unwrap_or_default();
    if let Some(p) = program {
        ev.fields.insert("program".into(), p);
    }
    if let Some(p) = pid {
        ev.fields.insert("pid".into(), p.to_string());
    }
    ev.summary = if prog.is_empty() {
        summarize(msg, 160)
    } else {
        format!("{}: {}", prog.trim_end_matches(':'), summarize(msg, 150))
    };
    Some(ev)
}

/// Parse the common syslog line frame, returning `(utc, host, program, pid,
/// message)`. Handles both BSD (`Oct 10 13:55:36 host prog[pid]: msg`) and
/// ISO-timestamp (`2026-10-10T13:55:36+00:00 host prog[pid]: msg`) front
/// matter.
#[allow(clippy::type_complexity)]
fn parse_syslog_frame(
    line: &str,
    year: i32,
) -> Option<(
    DateTime<Utc>,
    Option<String>,
    Option<String>,
    Option<u32>,
    &str,
)> {
    let (ts, rest) = parse_syslog_time(line, year)?;
    let rest = rest.trim_start();

    // Next token is the hostname (syslog) — but journald `short` export also
    // begins with the host. A token containing no `[` and not ending `:` is a
    // host; the token after it is `program[pid]:`.
    let mut words = rest.splitn(2, ' ');
    let first = words.next().unwrap_or("");
    let after_first = words.next().unwrap_or("");

    let (host, tail) = if first.ends_with(':') || first.contains('[') {
        // No hostname field; `first` is already the program token.
        (None, rest)
    } else {
        (Some(first.to_string()), after_first)
    };

    // tail starts with `program[pid]:` or `program:`.
    let (program, pid, msg) = split_program(tail);
    Some((ts, host, program, pid, msg))
}

/// Read the leading timestamp. Returns `(utc, remainder_after_timestamp)`.
fn parse_syslog_time(line: &str, year: i32) -> Option<(DateTime<Utc>, &str)> {
    // ISO 8601 with offset: 2026-10-10T13:55:36+03:00 / ...Z / with fraction.
    if let Some(end) = iso_ts_end(line) {
        let token = &line[..end];
        if let Ok(dt) = DateTime::parse_from_rfc3339(token) {
            return Some((dt.with_timezone(&Utc), &line[end..]));
        }
        // No offset (naive ISO, e.g. `2026-10-10T13:55:36`): treat as UTC.
        if let Ok(naive) = NaiveDateTime::parse_from_str(token, "%Y-%m-%dT%H:%M:%S") {
            return Some((Utc.from_utc_datetime(&naive), &line[end..]));
        }
        if let Ok(naive) = NaiveDateTime::parse_from_str(token, "%Y-%m-%d %H:%M:%S") {
            return Some((Utc.from_utc_datetime(&naive), &line[end..]));
        }
    }
    // BSD syslog: `Oct 10 13:55:36` or `Oct  1 13:55:36` (15 chars).
    if line.len() >= 15 {
        let token = &line[..15];
        let with_year = format!("{year} {token}");
        if let Ok(naive) = NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S") {
            return Some((Utc.from_utc_datetime(&naive), &line[15..]));
        }
    }
    None
}

/// Length of a leading ISO-8601-ish timestamp token (up to the first space),
/// when the line looks like it starts with one.
fn iso_ts_end(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    // YYYY-MM-DD
    let digit = |i: usize| bytes.get(i).is_some_and(|b| b.is_ascii_digit());
    if !(digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && bytes[4] == b'-'
        && digit(5)
        && digit(6)
        && bytes[7] == b'-'
        && digit(8)
        && digit(9))
    {
        return None;
    }
    let sep = bytes[10];
    if sep != b'T' && sep != b' ' {
        return None;
    }
    // Token runs until the first space that is not inside the timestamp. For
    // the `YYYY-MM-DD HH:MM:SS` space-separated form, take a fixed 19 chars;
    // otherwise run to the next space.
    if sep == b' ' {
        return Some(19);
    }
    let end = line[11..].find(' ').map(|i| 11 + i).unwrap_or(line.len());
    Some(end)
}

/// Split `program[pid]: message` (or `program: message`) into parts.
fn split_program(tail: &str) -> (Option<String>, Option<u32>, &str) {
    let colon = match tail.find(':') {
        Some(i) => i,
        None => return (None, None, tail.trim_start()),
    };
    let head = &tail[..colon];
    let msg = tail[colon + 1..].trim_start();
    if let Some(open) = head.find('[') {
        let name = head[..open].to_string();
        let pid = head
            .get(open + 1..head.len().saturating_sub(1))
            .and_then(|s| s.trim_end_matches(']').parse::<u32>().ok());
        (Some(name), pid, msg)
    } else {
        (Some(head.to_string()), None, msg)
    }
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

/// First `[token]` in a string, without the brackets.
fn bracket_token(s: &str) -> Option<String> {
    let open = s.find('[')?;
    let close = s[open..].find(']')? + open;
    Some(s[open + 1..close].to_string())
}

/// The whitespace token right after `label`, if present.
fn after_label(line: &str, label: &str) -> Option<String> {
    let at = line.find(label)? + label.len();
    line[at..]
        .split_whitespace()
        .next()
        .map(|s| s.trim_end_matches(',').to_string())
        .filter(|s| !s.is_empty())
}

/// Collapse internal whitespace and cap the length for a summary field.
fn summarize(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max + 1));
    let mut last_space = false;
    for ch in s.trim().chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
        if out.chars().count() >= max {
            out.push('…');
            break;
        }
    }
    out
}

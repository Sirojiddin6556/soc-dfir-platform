//! DFIR incident investigation — stage 1: log ingest and a unified UTC
//! timeline.
//!
//! The analyst points the engine at a folder (or a single file) of logs
//! collected from a host or web server. This crate discovers the log files,
//! parses each line into a normalized [`LogEvent`] with a UTC timestamp, and
//! merges every source into one chronological [`Timeline`].
//!
//! Two rules hold throughout, both from the project's DFIR requirements:
//!
//! * **No invention.** A line is turned into an event only when its timestamp
//!   and shape are actually recognized. An unparseable line is counted and,
//!   for the first few per file, surfaced as a warning — never dropped
//!   silently and never given a made-up time.
//! * **Every event carries its evidence.** [`LogEvent::raw`] is the exact
//!   source line, and [`LogEvent::source_file`]/[`LogEvent::line_no`] point at
//!   where it came from, so every later finding can be traced to a concrete
//!   log line.

#![forbid(unsafe_code)]

mod ingest;
mod parse;

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use ingest::IngestError;

/// What kind of log a line came from. Detected per file from its name and
/// its first readable lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    /// An nginx or Apache access log (Common or Combined Log Format).
    WebAccess,
    /// An nginx or Apache error log.
    WebError,
    /// Linux authentication log (`auth.log`, `secure`): sshd, sudo, su, PAM.
    Auth,
    /// General syslog / messages, or a `journalctl` short/`short-iso` export.
    Syslog,
}

impl LogSource {
    /// A stable identifier for the UI and for grouping.
    pub fn as_str(self) -> &'static str {
        match self {
            LogSource::WebAccess => "web_access",
            LogSource::WebError => "web_error",
            LogSource::Auth => "auth",
            LogSource::Syslog => "syslog",
        }
    }
}

/// Whether a security-relevant action succeeded, as read from the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

/// One parsed log line on the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Event time, normalized to UTC. Serialized as RFC 3339.
    pub timestamp: String,
    /// The log this came from.
    pub source: LogSource,
    /// Path of the file, relative to the analyzed root (or the file name when
    /// a single file was analyzed).
    pub source_file: String,
    /// 1-based line number within that file (after decompression).
    pub line_no: usize,
    /// The host or service that emitted the line, when the line names one
    /// (syslog hostname, or the daemon such as `sshd`).
    pub host: Option<String>,
    /// Who or what the line is about: a client IP for web access, a user name
    /// or source IP for auth events.
    pub actor: Option<String>,
    /// A short, normalized description of what happened, in the analyst's
    /// language. Never contains the raw line verbatim.
    pub summary: String,
    /// Whether the action succeeded, when the line expresses it.
    pub outcome: Option<Outcome>,
    /// Extra parsed fields (HTTP status, method, request path, PID ...), kept
    /// as strings so the UI can show them without guessing types.
    pub fields: BTreeMap<String, String>,
    /// The exact source line, trimmed of its trailing newline only.
    pub raw: String,
}

/// What was found in one ingested file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: String,
    pub source: LogSource,
    /// Lines read (after decompression).
    pub lines: usize,
    /// Lines turned into timeline events.
    pub parsed: usize,
    /// Whether the file was gzip-compressed.
    pub compressed: bool,
    /// SHA-256 of the file as stored on disk (hex), so the evidence it
    /// supplies can be shown to be unaltered.
    pub sha256: String,
    /// Size of the file on disk, in bytes.
    pub bytes: u64,
}

/// The result of an investigation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timeline {
    /// All events, sorted by UTC timestamp ascending, ties broken by file and
    /// line so the order is stable.
    pub events: Vec<LogEvent>,
    /// One entry per ingested log file.
    pub files: Vec<FileSummary>,
    /// Earliest and latest event time (RFC 3339), when any event was parsed.
    pub first_event: Option<String>,
    pub last_event: Option<String>,
    /// Non-fatal problems: unrecognized lines (sampled), skipped files, a
    /// guessed year, etc. Information for the analyst, not an error.
    pub warnings: Vec<String>,
}

/// Options for a run.
#[derive(Debug, Clone)]
pub struct Options {
    /// BSD-syslog lines (`Oct 10 13:55:36 ...`) carry no year. When set, this
    /// year is used; otherwise the file's modification year is used, and a
    /// warning records the choice.
    pub assume_year: Option<i32>,
    /// Stop after this many events, so a huge log set cannot exhaust memory.
    pub max_events: usize,
    /// Visit at most this many files.
    pub max_files: usize,
    /// Skip any single file larger than this many bytes (uncompressed read is
    /// still bounded by `max_events`). Guards against a runaway file.
    pub max_file_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            assume_year: None,
            max_events: 200_000,
            max_files: 2_000,
            max_file_bytes: 512 * 1024 * 1024,
        }
    }
}

/// How many unrecognized lines to report per file before summarizing the rest
/// as a count.
const WARN_SAMPLE_PER_FILE: usize = 3;

/// Discover, parse and merge the logs under `root` (a folder or a single
/// file) into one UTC timeline.
pub fn analyze_path(root: &Path, opts: &Options) -> Result<Timeline, IngestError> {
    let files = ingest::discover(root, opts)?;
    let mut timeline = Timeline::default();

    for file in files {
        if timeline.events.len() >= opts.max_events {
            timeline
                .warnings
                .push(format!("Достигнут предел в {} событий", opts.max_events));
            break;
        }
        let rel = ingest::relative_name(root, &file.path);
        let read = match ingest::read_lines(&file, opts.max_file_bytes) {
            Ok(lines) => lines,
            Err(e) => {
                timeline.warnings.push(format!("Файл {rel} пропущен: {e}"));
                continue;
            }
        };

        let source = parse::detect_source(&rel, &read.lines);
        let year = opts.assume_year.unwrap_or(read.mtime_year);
        if opts.assume_year.is_none() {
            // Only matters for year-less BSD syslog lines; noted once per run
            // lazily below when such a line is actually parsed.
        }

        let mut parsed = 0usize;
        let mut unrecognized = 0usize;
        for (idx, line) in read.lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if timeline.events.len() >= opts.max_events {
                break;
            }
            match parse::parse_line(source, line, year) {
                Some(mut ev) => {
                    ev.source_file = rel.clone();
                    ev.line_no = idx + 1;
                    timeline.events.push(ev);
                    parsed += 1;
                }
                None => {
                    unrecognized += 1;
                    if unrecognized <= WARN_SAMPLE_PER_FILE {
                        timeline
                            .warnings
                            .push(format!("{rel}:{}: строка не распознана", idx + 1));
                    }
                }
            }
        }
        if unrecognized > WARN_SAMPLE_PER_FILE {
            timeline.warnings.push(format!(
                "{rel}: ещё {} нераспознанных строк",
                unrecognized - WARN_SAMPLE_PER_FILE
            ));
        }
        if parsed > 0 && source == LogSource::Syslog && opts.assume_year.is_none() {
            timeline.warnings.push(format!(
                "{rel}: год взят из даты файла ({year}) — уточните, если лог за другой год",
                year = year
            ));
        }

        timeline.files.push(FileSummary {
            path: rel,
            source,
            lines: read.lines.len(),
            parsed,
            compressed: file.compressed,
            sha256: read.sha256,
            bytes: read.bytes,
        });
    }

    // Stable chronological order: time, then origin.
    timeline.events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.source_file.cmp(&b.source_file))
            .then_with(|| a.line_no.cmp(&b.line_no))
    });
    timeline.first_event = timeline.events.first().map(|e| e.timestamp.clone());
    timeline.last_event = timeline.events.last().map(|e| e.timestamp.clone());
    Ok(timeline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A throwaway directory under the OS temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "incident-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            p.push(uniq);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn write(&self, name: &str, body: &str) {
            let mut f = std::fs::File::create(self.0.join(name)).unwrap();
            f.write_all(body.as_bytes()).unwrap();
        }
        fn write_gz(&self, name: &str, body: &str) {
            let f = std::fs::File::create(self.0.join(name)).unwrap();
            let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            enc.write_all(body.as_bytes()).unwrap();
            enc.finish().unwrap();
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

    fn find<'a>(t: &'a Timeline, needle: &str) -> &'a LogEvent {
        t.events
            .iter()
            .find(|e| e.summary.contains(needle))
            .unwrap_or_else(|| panic!("no event matching {needle:?} in {:#?}", t.events))
    }

    #[test]
    fn merges_web_and_auth_into_one_utc_timeline() {
        let d = TempDir::new("merge");
        d.write(
            "access.log",
            "192.0.2.50 - - [10/Oct/2026:13:55:36 +0000] \"GET /admin HTTP/1.1\" 403 512 \"-\" \"curl/8.0\"\n",
        );
        d.write(
            "auth.log",
            "Oct 10 13:55:38 web01 sshd[2210]: Failed password for invalid user admin from 192.0.2.50 port 50420 ssh2\n\
             Oct 10 13:55:40 web01 sshd[2211]: Accepted password for deploy from 192.0.2.50 port 50422 ssh2\n",
        );
        d.write(
            "syslog",
            "2026-10-10T13:55:30+00:00 web01 systemd[1]: Started Daily apt upgrade.\n",
        );

        let t = analyze_path(&d.0, &opts()).unwrap();
        assert_eq!(t.events.len(), 4, "{:#?}", t.events);
        // Sorted ascending: systemd 13:55:30, access 13:55:36, failed :38, ok :40.
        let times: Vec<&str> = t.events.iter().map(|e| e.timestamp.as_str()).collect();
        assert_eq!(
            times,
            vec![
                "2026-10-10T13:55:30Z",
                "2026-10-10T13:55:36Z",
                "2026-10-10T13:55:38Z",
                "2026-10-10T13:55:40Z"
            ]
        );
        assert_eq!(t.first_event.as_deref(), Some("2026-10-10T13:55:30Z"));
        assert_eq!(t.last_event.as_deref(), Some("2026-10-10T13:55:40Z"));
    }

    #[test]
    fn web_access_fields_and_outcome() {
        let d = TempDir::new("web");
        d.write(
            "access.log",
            "192.0.2.50 - alice [10/Oct/2026:13:55:36 +0000] \"POST /login HTTP/1.1\" 200 12 \"http://x/\" \"Mozilla/5.0\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let e = &t.events[0];
        assert_eq!(e.source, LogSource::WebAccess);
        assert_eq!(e.actor.as_deref(), Some("192.0.2.50"));
        assert_eq!(e.outcome, Some(Outcome::Success));
        assert_eq!(e.fields.get("method").map(String::as_str), Some("POST"));
        assert_eq!(e.fields.get("path").map(String::as_str), Some("/login"));
        assert_eq!(e.fields.get("status").map(String::as_str), Some("200"));
        assert_eq!(e.fields.get("auth_user").map(String::as_str), Some("alice"));
        assert_eq!(
            e.fields.get("user_agent").map(String::as_str),
            Some("Mozilla/5.0")
        );
        // The exact line is kept as evidence.
        assert!(e.raw.contains("POST /login HTTP/1.1"));
    }

    #[test]
    fn ssh_accepted_and_failed_are_distinguished() {
        let d = TempDir::new("ssh");
        d.write(
            "auth.log",
            "Oct 10 13:55:38 web01 sshd[2210]: Failed password for invalid user admin from 192.0.2.50 port 50420 ssh2\n\
             Oct 10 13:55:40 web01 sshd[2211]: Accepted password for deploy from 192.0.2.50 port 50422 ssh2\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let fail = find(&t, "неверный пароль");
        assert_eq!(fail.outcome, Some(Outcome::Failure));
        assert_eq!(fail.actor.as_deref(), Some("192.0.2.50"));
        assert_eq!(
            fail.fields.get("invalid_user").map(String::as_str),
            Some("true")
        );
        assert_eq!(fail.fields.get("user").map(String::as_str), Some("admin"));

        let ok = find(&t, "SSH вход");
        assert_eq!(ok.outcome, Some(Outcome::Success));
        assert_eq!(ok.actor.as_deref(), Some("deploy"));
        assert_eq!(
            ok.fields.get("src_ip").map(String::as_str),
            Some("192.0.2.50")
        );
    }

    #[test]
    fn sudo_command_is_captured() {
        let d = TempDir::new("sudo");
        d.write(
            "auth.log",
            "Oct 10 14:00:01 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        let e = &t.events[0];
        assert_eq!(e.fields.get("user").map(String::as_str), Some("deploy"));
        assert_eq!(
            e.fields.get("command").map(String::as_str),
            Some("/usr/bin/cat /etc/shadow")
        );
    }

    #[test]
    fn reads_gzip_rotated_logs() {
        let d = TempDir::new("gz");
        d.write_gz(
            "access.log.1.gz",
            "203.0.113.7 - - [09/Oct/2026:01:02:03 +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"-\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert_eq!(t.events.len(), 1);
        assert!(t.files[0].compressed);
        assert_eq!(t.events[0].timestamp, "2026-10-09T01:02:03Z");
    }

    #[test]
    fn each_file_is_hashed_for_chain_of_custody() {
        let d = TempDir::new("hash");
        // Known content → known SHA-256 of exactly those bytes.
        d.write("access.log", "hello\n");
        let t = analyze_path(&d.0, &opts()).unwrap();
        let f = &t.files[0];
        assert_eq!(
            f.sha256,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        assert_eq!(f.bytes, 6);
    }

    #[test]
    fn unrecognized_lines_are_warned_not_invented() {
        let d = TempDir::new("junk");
        d.write(
            "access.log",
            "this is not a log line at all\n192.0.2.50 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"-\"\n",
        );
        let t = analyze_path(&d.0, &opts()).unwrap();
        assert_eq!(t.events.len(), 1, "only the real line becomes an event");
        assert!(t.warnings.iter().any(|w| w.contains("не распознана")));
    }

    #[test]
    fn missing_path_is_an_error() {
        let p = std::path::Path::new("/no/such/incident/path/xyz");
        assert!(matches!(
            analyze_path(p, &opts()),
            Err(IngestError::Missing(_))
        ));
    }
}

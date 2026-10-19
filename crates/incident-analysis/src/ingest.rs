//! Finding log files under a path and reading them into lines, including
//! rotated (`.1`) and gzip-compressed (`.gz`) files.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{Datelike, Utc};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

use crate::Options;

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("путь {0} недоступен: {1}")]
    Unreadable(String, String),
    #[error("путь {0} не существует")]
    Missing(String),
    #[error("под {0} не найдено файлов журналов")]
    NoLogs(String),
}

/// A log file discovered for ingestion.
#[derive(Debug, Clone)]
pub struct LogFile {
    pub path: PathBuf,
    pub compressed: bool,
    /// A Windows event log (`.evtx`): binary, parsed by record rather than by
    /// text line.
    pub is_evtx: bool,
}

/// Lines read from a file, plus the file's modification year (used as the
/// year for year-less BSD syslog timestamps).
pub struct ReadResult {
    pub lines: Vec<String>,
    pub mtime_year: i32,
    /// SHA-256 of the file exactly as stored on disk (for a `.gz` this is the
    /// compressed bytes). Chain-of-custody proof the artifact is unaltered.
    pub sha256: String,
    /// Size of the file on disk, in bytes.
    pub bytes: u64,
    /// The decompressed content looks binary (a NUL byte near the start), so it
    /// is not a text log and must not be parsed line by line.
    pub looks_binary: bool,
}

/// Walk `root` (a folder or a single file) and return the candidate log files.
pub fn discover(root: &Path, opts: &Options) -> Result<Vec<LogFile>, IngestError> {
    let meta = fs::metadata(root).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            IngestError::Missing(root.display().to_string())
        } else {
            IngestError::Unreadable(root.display().to_string(), e.to_string())
        }
    })?;

    if meta.is_file() {
        // A file named explicitly is always read, whatever its name.
        return Ok(vec![LogFile {
            path: root.to_path_buf(),
            compressed: is_gz(root),
            is_evtx: is_evtx(root),
        }]);
    }

    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if out.len() >= opts.max_files {
            break;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue, // unreadable subdir: skip, not fatal
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue; // never follow symlinks
            }
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() && looks_like_log(&path) {
                out.push(LogFile {
                    path: path.clone(),
                    compressed: is_gz(&path),
                    is_evtx: is_evtx(&path),
                });
                if out.len() >= opts.max_files {
                    break;
                }
            }
        }
    }

    if out.is_empty() {
        return Err(IngestError::NoLogs(root.display().to_string()));
    }
    // Deterministic order so line numbering and the timeline are reproducible.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Read a file into lines (decompressing gzip), bounded by `max_bytes`.
pub fn read_lines(file: &LogFile, max_bytes: u64) -> Result<ReadResult, String> {
    let meta = fs::metadata(&file.path).map_err(|e| e.to_string())?;
    if !file.compressed && meta.len() > max_bytes {
        return Err(format!(
            "размер {} превышает предел {} МБ",
            meta.len(),
            max_bytes / (1024 * 1024)
        ));
    }
    let mtime_year = file_year(&meta);

    let raw = fs::read(&file.path).map_err(|e| e.to_string())?;
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        hex::encode(hasher.finalize())
    };
    let bytes = raw.len() as u64;
    let text = if file.compressed {
        let mut buf = Vec::new();
        let mut dec = GzDecoder::new(&raw[..]);
        // Bound the decompressed size too, so a small bomb cannot blow memory.
        let limit = max_bytes;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match dec.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() as u64 > limit {
                        return Err(format!(
                            "распакованный размер превышает предел {} МБ",
                            limit / (1024 * 1024)
                        ));
                    }
                }
                Err(e) => return Err(format!("ошибка распаковки: {e}")),
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        String::from_utf8_lossy(&raw).into_owned()
    };

    // A text log never contains a NUL byte; a binary file (a .evtx read as
    // lossy UTF-8, an image, an archive) does, near the start.
    let looks_binary = text.as_bytes().iter().take(8192).any(|&b| b == 0);
    let lines = text.lines().map(|l| l.to_string()).collect();
    Ok(ReadResult {
        lines,
        mtime_year,
        sha256,
        bytes,
        looks_binary,
    })
}

/// Path relative to `root`, or the file name when `root` is that file.
pub fn relative_name(root: &Path, path: &Path) -> String {
    if path == root {
        return path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
    }
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.display().to_string())
}

fn is_gz(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
}

fn is_evtx(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
}

fn file_year(meta: &fs::Metadata) -> i32 {
    meta.modified()
        .ok()
        .map(|t| chrono::DateTime::<Utc>::from(t).year())
        .unwrap_or_else(|| Utc::now().year())
}

/// Whether a file under a scanned folder is worth reading as a log. Keeps the
/// walk from slurping databases, archives and binaries that happen to sit
/// beside the logs.
fn looks_like_log(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    // Compressed rotation: foo.log.2.gz, auth.log.gz ...
    let base = name.strip_suffix(".gz").unwrap_or(&name);

    // Windows event logs are binary but supported: route them to the .evtx
    // parser rather than rejecting them as not-a-text-log.
    if base.ends_with(".evtx") {
        return true;
    }

    // Configuration, code and keys are never logs, whatever they are called
    // (`daemon.service`, `mail-warning.sh`). A collected case folder holds
    // such files beside the logs.
    const NOT_LOG_EXT: &[&str] = &[
        "service", "timer", "socket", "target", "conf", "cfg", "ini", "sh", "py", "pl", "json",
        "yaml", "yml", "toml", "xml", "html", "pem", "key", "pub", "crt", "defs",
        // Binary formats that may sit in a collected case folder and are not
        // parsed here: legacy event logs, packet captures, databases, archives,
        // images, executables. (`.evtx` is handled above.)
        "evt", "etl", "pcap", "pcapng", "cap", "db", "sqlite", "sqlite3", "zip", "7z", "rar", "tar",
        "xz", "bz2", "zst", "png", "jpg", "jpeg", "gif", "bmp", "ico", "pdf", "exe", "dll", "so",
        "bin",
    ];
    if let Some((_, ext)) = base.rsplit_once('.') {
        if NOT_LOG_EXT.contains(&ext) {
            return false;
        }
    }

    // Binary login records and journald files are not text logs.
    let stem = base.split(['.', '-', '_']).next().unwrap_or(base);
    if matches!(stem, "wtmp" | "btmp" | "lastlog" | "faillog" | "tallylog")
        || base.ends_with(".journal")
        || base.ends_with(".journal~")
    {
        return false;
    }

    // Common explicit log names, matched on the name's first word so that
    // `authorized_keys` is not mistaken for an auth log.
    const NAMES: &[&str] = &[
        "access", "error", "auth", "authlog", "secure", "syslog", "messages", "journal", "kern",
        "mail", "maillog", "daemon", "cron", "dmesg", "nginx", "apache", "httpd",
    ];
    if NAMES.contains(&stem) {
        return true;
    }
    // foo.log / foo.log.1 (rotated).
    if base.ends_with(".log") {
        return true;
    }
    if let Some((stem, suffix)) = base.rsplit_once('.') {
        if suffix.chars().all(|c| c.is_ascii_digit()) && stem.ends_with(".log") {
            return true;
        }
    }
    false
}

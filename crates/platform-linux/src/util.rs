#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

/// Splits off the first `n` whitespace separated fields of `line` and
/// returns them together with the untouched remainder (trimmed). Returns
/// `None` when the line has fewer than `n` fields.
pub fn split_fields(line: &str, n: usize) -> Option<(Vec<&str>, &str)> {
    let mut fields = Vec::with_capacity(n);
    let mut rest = line.trim_start();
    for _ in 0..n {
        if rest.is_empty() {
            return None;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    Some((fields, rest.trim_end()))
}

/// `root` + absolute path (used so collectors can be pointed at a fixture
/// tree in tests; `root` is `/` in production).
pub fn root_path(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

/// Modification time of `path` as RFC 3339.
pub fn file_mtime_rfc3339(path: &Path) -> Option<String> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(chrono::DateTime::<chrono::Utc>::from(modified).to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_fields_and_keeps_remainder() {
        let (f, rest) = split_fields("*/5  *  * * *   root  /usr/bin/run --x  'a b'", 6).unwrap();
        assert_eq!(f, vec!["*/5", "*", "*", "*", "*", "root"]);
        assert_eq!(rest, "/usr/bin/run --x  'a b'");
        assert!(split_fields("a b", 3).is_none());
        let (f, rest) = split_fields("a b c", 3).unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(rest, "");
    }

    #[test]
    fn joins_root_paths() {
        assert_eq!(
            root_path(Path::new("/tmp/fixture"), "/etc/crontab"),
            PathBuf::from("/tmp/fixture/etc/crontab")
        );
        assert_eq!(
            root_path(Path::new("/"), "/etc/crontab"),
            PathBuf::from("/etc/crontab")
        );
    }
}

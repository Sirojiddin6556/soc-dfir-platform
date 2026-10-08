#![forbid(unsafe_code)]

//! PowerShell plumbing shared by the Windows collectors.
//!
//! Every script is a `&'static str` compiled into the binary: callers cannot
//! pass runtime (potentially attacker controlled) text into a command line.

use serde_json::Value;

/// Prepended to every script: emit UTF-8 so non-ASCII account names and
/// paths (e.g. Cyrillic user names) survive the pipe, and silence progress
/// records that would otherwise corrupt stdout.
pub const PRELUDE: &str =
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; ";

/// Runs a static script and returns its stdout.
#[cfg(target_os = "windows")]
pub fn run(script: &'static str) -> Result<String, String> {
    let full = format!("{}{}", PRELUDE, script);
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &full])
        .output()
        .map_err(|e| format!("powershell.exe недоступен: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "PowerShell завершился с кодом {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Error returned by every live collector on non-Windows builds.
pub fn unsupported(what: &str) -> String {
    format!("{}: доступно только на Windows", what)
}

pub fn get_str(item: &Value, key: &str) -> Option<String> {
    match item.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn get_u64(item: &Value, key: &str) -> Option<u64> {
    match item.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Items of a JSON value that may be an array or a single object.
pub fn value_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items.clone(),
        Some(obj @ Value::Object(_)) => vec![obj.clone()],
        _ => Vec::new(),
    }
}

/// Converts the `/Date(1700000000000)/` form produced by Windows
/// PowerShell 5.1 for `DateTime` values, or an ISO 8601 string, to RFC 3339.
pub fn ps_datetime(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if let Some(ms) = raw
        .strip_prefix("/Date(")
        .and_then(|r| r.strip_suffix(")/"))
    {
        let digits: String = ms
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        let ms: i64 = digits.parse().ok()?;
        return chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).map(|t| t.to_rfc3339());
    }
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc).to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_powershell_dates() {
        assert_eq!(
            ps_datetime("/Date(1704067200000)/").as_deref(),
            Some("2024-01-01T00:00:00+00:00")
        );
        assert_eq!(
            ps_datetime("2024-01-01T03:00:00.0000000+03:00").as_deref(),
            Some("2024-01-01T00:00:00+00:00")
        );
        assert_eq!(ps_datetime("garbage"), None);
    }

    #[test]
    fn reads_scalars_leniently() {
        let v: Value = serde_json::json!({"a": "x", "b": 5, "c": " ", "d": "7"});
        assert_eq!(get_str(&v, "a").as_deref(), Some("x"));
        assert_eq!(get_str(&v, "b").as_deref(), Some("5"));
        assert_eq!(get_str(&v, "c"), None);
        assert_eq!(get_u64(&v, "d"), Some(7));
        assert_eq!(value_items(v.get("missing")).len(), 0);
        assert_eq!(value_items(Some(&v)).len(), 1);
    }
}

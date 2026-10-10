//! OS command injection, surfaced by the parameter controlling the response
//! time.
//!
//! A value that reaches a shell can be made to run `sleep` (or, on Windows,
//! `ping` against loopback), which does nothing but wait. The check sends such
//! a payload through one parameter and times the round trip. To avoid blaming
//! a slow endpoint it compares the delayed request against the same payload
//! with a zero-second wait (a control) and confirms the delay a second time:
//! only a response consistently slower than its own control by about the
//! requested delay is reported. This mirrors the time-based SQL-injection
//! check and, like it, almost never fires falsely. These checks are for
//! authorized testing of systems the operator controls.

use crate::http::{Client, RequestRecord, Response};
use crate::{Finding, InjectionPoint, Severity};
use std::time::Instant;

/// Seconds the probe asks the shell to wait.
const DELAY: u64 = 3;
/// A delayed response must take at least this long to be a candidate.
const THRESHOLD: f64 = DELAY as f64 * 0.6;
/// A candidate is confirmed only if it beats its own zero-second control by at
/// least this much, which cancels a uniformly slow endpoint.
const MARGIN: f64 = DELAY as f64 * 0.5;
/// Requests needed free to confirm one payload (delayed, control, delayed).
const CONFIRM_BUDGET: u32 = 3;

/// (label, slow payload, zero-wait control) triples, one per shell context.
/// The slow and control payloads are identical except for the wait, so the
/// control isolates the wait as the only variable. The baseline value leads
/// each payload so the original command still parses before the injection.
fn wait_pairs(base: &str) -> Vec<(&'static str, String, String)> {
    let d = DELAY;
    vec![
        (
            "Unix ;",
            format!("{base}; sleep {d}"),
            format!("{base}; sleep 0"),
        ),
        (
            "Unix |",
            format!("{base}| sleep {d}"),
            format!("{base}| sleep 0"),
        ),
        (
            "Unix &&",
            format!("{base} && sleep {d}"),
            format!("{base} && sleep 0"),
        ),
        (
            "Unix $()",
            format!("{base}$(sleep {d})"),
            format!("{base}$(sleep 0)"),
        ),
        (
            "Unix ``",
            format!("{base}`sleep {d}`"),
            format!("{base}`sleep 0`"),
        ),
        (
            "Windows &",
            // ping sends one packet per second; -n (d+1) waits ~d seconds,
            // -n 1 returns at once.
            format!("{base}& ping -n {} 127.0.0.1", d + 1),
            format!("{base}& ping -n 1 127.0.0.1"),
        ),
    ]
}

/// Sends one payload and times the whole round trip, body included. `None` on
/// a transport error so the caller moves on.
fn timed(
    client: &Client,
    point: &InjectionPoint,
    index: usize,
    payload: &str,
) -> Option<(Response, RequestRecord, f64)> {
    let start = Instant::now();
    let (resp, record) = point.send(client, Some(index), payload).ok()?;
    Some((resp, record, start.elapsed().as_secs_f64()))
}

pub fn check(client: &Client, point: &InjectionPoint, index: usize, findings: &mut Vec<Finding>) {
    let base = point.params[index].1.clone();
    for (shell, slow, control) in wait_pairs(&base) {
        if client.remaining() < CONFIRM_BUDGET {
            return;
        }
        // One cheap probe first: a parameter that does not reach a shell
        // answers fast, so most points cost a single request here.
        let Some((_, _, first)) = timed(client, point, index, &slow) else {
            continue;
        };
        if first < THRESHOLD {
            continue;
        }
        // Candidate. Prove the delay is the wait, not a slow page: the same
        // payload asking for no wait must come back quickly, and a second
        // delayed request must be slow again.
        let Some((_, _, control_time)) = timed(client, point, index, &control) else {
            continue;
        };
        let Some((_, record, confirm)) = timed(client, point, index, &slow) else {
            continue;
        };
        let delayed = first.min(confirm);
        if delayed - control_time >= MARGIN && confirm >= THRESHOLD {
            let name = point.params[index].0.clone();
            findings.push(Finding {
                rule: "command-injection".into(),
                cwe: 78,
                severity: Severity::Critical,
                title: "Внедрение команд ОС".into(),
                message: format!(
                    "Параметр «{name}» управляет временем ответа через команду ожидания ({shell}): значение попадает в системную команду и выполняется оболочкой. Так можно выполнить любую команду на сервере. Не передавайте ввод в оболочку: вызывайте программы без shell и со списком аргументов, а значения проверяйте по белому списку."
                ),
                url: record.url.clone(),
                method: point.method.as_str().into(),
                param: Some(name),
                evidence: format!(
                    "Задержка по времени ({shell}): с паузой {DELAY}с ответ {delayed:.1}с, без паузы {control_time:.1}с."
                ),
                request: record.as_curl(),
                request_detail: record,
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_payload_requests_no_wait() {
        let pairs = wait_pairs("1");
        // Every slow payload has a matching control that waits zero seconds.
        assert!(pairs.iter().any(|(_, s, _)| s.contains("sleep 3")));
        assert!(pairs
            .iter()
            .all(|(_, _, c)| c.contains("sleep 0") || c.contains("ping -n 1")));
        // The Windows probe waits ~DELAY seconds via ping.
        assert!(pairs.iter().any(|(_, s, _)| s.contains("ping -n 4")));
    }

    #[test]
    fn payloads_keep_the_original_value_in_front() {
        let pairs = wait_pairs("report.txt");
        assert!(pairs.iter().all(|(_, s, _)| s.starts_with("report.txt")));
    }
}

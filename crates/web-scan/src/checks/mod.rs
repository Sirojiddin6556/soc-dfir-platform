//! The individual weakness checks and how a scan runs them.
//!
//! Active checks put a payload into one parameter at a time and read the
//! response back. Passive checks judge a response the scan already has. Each
//! check appends [`Finding`]s and respects the client's request budget.

pub mod cmdi;
pub mod csrf;
pub mod passive;
pub mod redirect;
pub mod sqli;
pub mod ssti;
pub mod stored;
pub mod traversal;
pub mod xss;

use crate::http::{Client, Response};
use crate::{Confirmation, Finding, InjectionPoint, ResponseRecord};

/// Runs every active check against each parameter of one injection point.
pub fn run_active(client: &Client, point: &InjectionPoint, findings: &mut Vec<Finding>) {
    for index in 0..point.params.len() {
        if client.remaining() == 0 {
            return;
        }
        xss::check(client, point, index, findings);
        sqli::check(client, point, index, findings);
        traversal::check(client, point, index, findings);
        redirect::check(client, point, index, findings);
        ssti::check(client, point, index, findings);
        cmdi::check(client, point, index, findings);
    }
}

/// Whether a response is HTML, so a reflection check is meaningful.
pub(crate) fn is_html(resp: &crate::http::Response) -> bool {
    resp.header("content-type")
        .map(|c| c.to_lowercase().contains("html"))
        .unwrap_or(true)
}

/// Confirms an active finding is caused by the injected `payload`: re-sends
/// the payload (the `signal` must reappear) and sends the parameter's own
/// original value (the signal must be gone). Returns the exchange, or `None`
/// when the request budget is too low to run it (the finding is then reported
/// unconfirmed). The two requests are spent from the same budget as the scan.
pub(crate) fn confirm(
    client: &Client,
    point: &InjectionPoint,
    index: usize,
    payload: &str,
    signal: impl Fn(&Response) -> bool,
) -> Option<Confirmation> {
    if client.remaining() < 2 {
        return None;
    }
    let (repeat_resp, repeat) = point.send(client, Some(index), payload).ok()?;
    let reproduced = signal(&repeat_resp);
    let original = point.params[index].1.clone();
    let (control_resp, control) = point.send(client, Some(index), &original).ok()?;
    let control_clean = !signal(&control_resp);
    Some(Confirmation {
        reproduced,
        control_clean,
        repeat,
        repeat_status: repeat_resp.status,
        control,
        control_status: control_resp.status,
    })
}

/// Whether a confirmation (if any ran) proved the finding.
pub(crate) fn confirmed(confirmation: &Option<Confirmation>) -> bool {
    confirmation
        .as_ref()
        .map(Confirmation::is_confirmed)
        .unwrap_or(false)
}

/// A short window of `body` around `needle` for the response excerpt, with
/// newlines flattened. When the needle is not found, a head of the body.
pub(crate) fn excerpt(body: &str, needle: &str) -> String {
    // Snaps a byte offset down to the nearest char boundary, so slicing a
    // UTF-8 body never splits a multi-byte character.
    let floor = |mut i: usize| {
        i = i.min(body.len());
        while i > 0 && !body.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let around = |pos: usize, len: usize| {
        let start = floor(pos.saturating_sub(40));
        let end = floor(pos + len + 30);
        body[start..end].replace(['\n', '\r'], " ")
    };
    match body.find(needle) {
        Some(pos) => around(pos, needle.len()),
        None => {
            let head: String = body.chars().take(160).collect();
            head.replace(['\n', '\r'], " ")
        }
    }
}

/// The response record for a finding: status plus an excerpt around `needle`.
pub(crate) fn response_record(resp: &Response, needle: &str) -> ResponseRecord {
    ResponseRecord {
        status: resp.status,
        excerpt: excerpt(&resp.body, needle),
    }
}

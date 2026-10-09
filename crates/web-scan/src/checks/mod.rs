//! The individual weakness checks and how a scan runs them.
//!
//! Active checks put a payload into one parameter at a time and read the
//! response back. Passive checks judge a response the scan already has. Each
//! check appends [`Finding`]s and respects the client's request budget.

pub mod passive;
pub mod redirect;
pub mod sqli;
pub mod traversal;
pub mod xss;

use crate::http::Client;
use crate::{Finding, InjectionPoint};

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
    }
}

/// Whether a response is HTML, so a reflection check is meaningful.
pub(crate) fn is_html(resp: &crate::http::Response) -> bool {
    resp.header("content-type")
        .map(|c| c.to_lowercase().contains("html"))
        .unwrap_or(true)
}

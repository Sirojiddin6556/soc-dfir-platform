#![forbid(unsafe_code)]

pub mod issues;
pub mod json_export;
pub mod model;
pub mod normalizer;
pub mod parser;

pub use issues::{ParseIssue, ParseQuality};
pub use json_export::{EvtxJsonExportAdapter, JSON_EXPORT_PARSER_VERSION};
pub use model::{EvtxParseResult, EvtxParseSummary, EvtxRecord, ParsedEvtxRecord};
pub use normalizer::{extract_data_field, parse_sysmon_hashes, EvtxNormalizer};
pub use parser::{EvtxParser, PARSER_VERSION};

use std::path::Path;

/// Parses binary EVTX file directly using streaming BinXML engine
pub fn parse_evtx_file(path: &Path) -> Result<EvtxParseResult, String> {
    EvtxParser::parse_file(path)
}

/// Backwards compatible function for parsing EVTX bytes into ParsedEvtxRecord list.
/// Dispatches to native streaming parser.
pub fn parse_evtx_bytes(bytes: &[u8]) -> Result<Vec<ParsedEvtxRecord>, String> {
    let result = EvtxParser::parse_bytes(bytes)?;
    Ok(result.records.iter().map(ParsedEvtxRecord::from).collect())
}

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};
use std::path::Path;

/// One normalized CVE record ready for upsert into cve_entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedCve {
    pub cve_id: String,
    pub cpe_vendor: String,
    pub cpe_product: String,
    pub cvss_v3: f64,
    pub epss_score: f64,
    pub cisa_kev: bool,
    pub severity: String,
    pub cwe_ids: Vec<String>,
    pub description: String,
    pub source: String,
    pub published_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug)]
pub enum ImportError {
    Io(io::Error),
    Json(serde_json::Error),
    MissingField(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Io(e) => write!(f, "IO error: {}", e),
            ImportError::Json(e) => write!(f, "JSON parse error: {}", e),
            ImportError::MissingField(s) => write!(f, "Missing field: {}", s),
        }
    }
}

impl From<io::Error> for ImportError {
    fn from(e: io::Error) -> Self {
        ImportError::Io(e)
    }
}
impl From<serde_json::Error> for ImportError {
    fn from(e: serde_json::Error) -> Self {
        ImportError::Json(e)
    }
}

pub fn parse_nvd_json(path: &Path) -> Result<Vec<ImportedCve>, ImportError> {
    let content = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&content)?;
    let items = root
        .get("CVE_Items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ImportError::MissingField("CVE_Items".to_string()))?;

    let mut out = Vec::new();
    for item in items {
        let cve_obj = match item.get("cve") {
            Some(v) => v,
            None => continue,
        };
        let cve_id = cve_obj
            .pointer("/CVE_data_meta/ID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if cve_id.is_empty() {
            continue;
        }

        let description = cve_obj
            .pointer("/description/description_data/0/value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // CWEs
        let cwe_ids: Vec<String> = cve_obj
            .pointer("/problemtype/problemtype_data")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .flat_map(|pt| {
                        pt.get("description")
                            .and_then(|d| d.as_array())
                            .into_iter()
                            .flatten()
                    })
                    .filter_map(|d| {
                        d.get("value")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .filter(|s| s.starts_with("CWE-"))
                    .collect()
            })
            .unwrap_or_default();

        let cvss_v3 = item
            .pointer("/impact/baseMetricV3/cvssV3/baseScore")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let severity = item
            .pointer("/impact/baseMetricV3/cvssV3/baseSeverity")
            .and_then(|v| v.as_str())
            .map(|s| capitalize(s))
            .unwrap_or_else(|| "Unknown".to_string());

        // CPE: extract vendor + product from first cpe23Uri
        let (cpe_vendor, cpe_product) = item
            .pointer("/configurations/nodes/0/cpe_match/0/cpe23Uri")
            .and_then(|v| v.as_str())
            .map(extract_cpe_vendor_product)
            .unwrap_or_default();

        let published_at = item
            .get("publishedDate")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let updated_at = item
            .get("lastModifiedDate")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        out.push(ImportedCve {
            cve_id,
            cpe_vendor,
            cpe_product,
            cvss_v3,
            epss_score: 0.0,
            cisa_kev: false,
            severity,
            cwe_ids,
            description,
            source: "nvd".to_string(),
            published_at,
            updated_at,
        });
    }
    Ok(out)
}

pub fn parse_kev_json(path: &Path) -> Result<Vec<ImportedCve>, ImportError> {
    let content = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&content)?;
    let vulns = root
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ImportError::MissingField("vulnerabilities".to_string()))?;

    let mut out = Vec::new();
    for v in vulns {
        let cve_id = v
            .get("cveID")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if cve_id.is_empty() {
            continue;
        }
        let cpe_vendor = v
            .get("vendorProject")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_lowercase();
        let cpe_product = v
            .get("product")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_lowercase();
        let description = v
            .get("shortDescription")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let date_added = v
            .get("dateAdded")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        out.push(ImportedCve {
            cve_id,
            cpe_vendor,
            cpe_product,
            cvss_v3: 0.0,
            epss_score: 0.0,
            cisa_kev: true,
            severity: "Unknown".to_string(),
            cwe_ids: vec![],
            description,
            source: "kev".to_string(),
            published_at: None,
            updated_at: date_added,
        });
    }
    Ok(out)
}

pub fn parse_epss_csv(path: &Path) -> Result<Vec<(String, f64)>, ImportError> {
    let file = std::fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut out = Vec::new();
    let mut first = true;
    for line in reader.lines() {
        let line = line?;
        if first {
            first = false;
            continue;
        } // skip header
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ',');
        let cve_id = parts.next().unwrap_or("").trim().to_string();
        let epss: f64 = parts.next().unwrap_or("0").trim().parse().unwrap_or(0.0);
        if !cve_id.is_empty() {
            out.push((cve_id, epss));
        }
    }
    Ok(out)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + &c.as_str().to_lowercase(),
    }
}

/// Extracts (vendor, product) from CPE 2.3 URI.
/// cpe:2.3:a:vendor:product:version:... -> ("vendor", "product")
fn extract_cpe_vendor_product(cpe: &str) -> (String, String) {
    let parts: Vec<&str> = cpe.split(':').collect();
    // parts[0]=cpe, [1]=2.3, [2]=type, [3]=vendor, [4]=product
    if parts.len() >= 5 {
        (parts[3].to_string(), parts[4].to_string())
    } else {
        (String::new(), String::new())
    }
}

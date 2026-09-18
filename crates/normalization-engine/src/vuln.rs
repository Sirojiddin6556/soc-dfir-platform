#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityRecord {
    pub cve_id: String,
    pub product_pattern: String,
    pub affected_versions: Vec<String>,
    pub cvss_v3: f32,
    pub severity: String,
    pub epss_score: f32, // 0.0 .. 1.0
    pub cisa_kev: bool,  // Listed in CISA Known Exploited Vulnerabilities Catalog
    pub cwes: Vec<String>,
    pub description: String,
}

pub struct VulnerabilityDatabase {
    pub records: Vec<VulnerabilityRecord>,
}

impl VulnerabilityDatabase {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn load_records(&mut self, records: Vec<VulnerabilityRecord>) {
        self.records = records;
    }

    /// Matches software against the vulnerability index
    pub fn match_vulnerabilities(&self, product: &str, version: &str) -> Vec<VulnerabilityRecord> {
        let prod_lower = product.to_lowercase();
        let mut matches = Vec::new();

        for rec in &self.records {
            if prod_lower.contains(&rec.product_pattern)
                && rec.affected_versions.iter().any(|v| version.contains(v))
            {
                matches.push(rec.clone());
            }
        }

        matches
    }
}

impl Default for VulnerabilityDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn fixture_records() -> Vec<VulnerabilityRecord> {
        vec![
            VulnerabilityRecord {
                cve_id: "CVE-2023-38606".to_string(),
                product_pattern: "kernel".to_string(),
                affected_versions: vec!["16.0".to_string(), "16.5".to_string()],
                cvss_v3: 8.8,
                severity: "High".to_string(),
                epss_score: 0.82,
                cisa_kev: true,
                cwes: vec!["CWE-284".to_string()],
                description: "Improper state handling leading to privilege escalation.".to_string(),
            },
            VulnerabilityRecord {
                cve_id: "CVE-2023-4863".to_string(),
                product_pattern: "webp".to_string(),
                affected_versions: vec!["1.0.0".to_string(), "1.0.1".to_string()],
                cvss_v3: 8.8,
                severity: "High".to_string(),
                epss_score: 0.94,
                cisa_kev: true,
                cwes: vec!["CWE-787".to_string()],
                description: "Heap buffer overflow in libwebp in Huffman coding.".to_string(),
            },
            VulnerabilityRecord {
                cve_id: "CVE-2024-21413".to_string(),
                product_pattern: "outlook".to_string(),
                affected_versions: vec!["16.0.14326".to_string()],
                cvss_v3: 9.8,
                severity: "Critical".to_string(),
                epss_score: 0.89,
                cisa_kev: true,
                cwes: vec!["CWE-94".to_string()],
                description:
                    "Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link)."
                        .to_string(),
            },
        ]
    }

    #[test]
    fn test_vulnerability_matching() {
        let mut db = VulnerabilityDatabase::new();
        db.records = fixture_records();
        // clean product -> zero matches
        let clean = db.match_vulnerabilities("7-Zip", "26.00");
        assert!(clean.is_empty());
        // known affected version -> match
        let matched = db.match_vulnerabilities("libwebp image viewer", "1.0.0");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].cve_id, "CVE-2023-4863");
    }

    #[test]
    fn test_empty_database_returns_no_matches() {
        let db = VulnerabilityDatabase::new();
        assert!(db.match_vulnerabilities("outlook", "16.0.14326").is_empty());
        assert!(db.match_vulnerabilities("libwebp", "1.0.0").is_empty());
    }
}

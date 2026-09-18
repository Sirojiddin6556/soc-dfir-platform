#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSoftwareId {
    pub product: String,
    pub vendor: String,
    pub version: String,
    pub cpe23: String,
    pub purl: String,
    pub confidence: u8, // 0..100
}

fn sanitize_cpe_field(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == ' ' {
            out.push('_');
        }
    }
    if out.is_empty() {
        "*".to_string()
    } else {
        out
    }
}

/// Normalizes raw product, publisher and version into structured CPE 2.3 and PURL
pub fn resolve_cpe_and_purl(
    product_raw: &str,
    publisher_raw: &str,
    version_raw: &str,
) -> NormalizedSoftwareId {
    let mut clean_product = product_raw.trim().to_string();

    // Strip architecture suffixes like (x64), 64-bit from product name
    for suffix in &[" (x64)", " (x86)", " 64-bit", " 32-bit"] {
        if let Some(idx) = clean_product.to_lowercase().find(&suffix.to_lowercase()) {
            clean_product = clean_product[..idx].trim().to_string();
        }
    }

    // Strip trailing version from product name if embedded (e.g. "draw.io 31.4.5" -> "draw.io")
    let prod_words: Vec<&str> = clean_product.split_whitespace().collect();
    if prod_words.len() > 1 {
        let last = prod_words.last().unwrap();
        if last
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
            && last.contains('.')
        {
            clean_product = prod_words[..prod_words.len() - 1].join(" ");
        }
    }

    let vendor = if publisher_raw.trim().is_empty() || publisher_raw.eq_ignore_ascii_case("Unknown")
    {
        if clean_product.to_lowercase().contains("microsoft") {
            "microsoft".to_string()
        } else {
            sanitize_cpe_field(&clean_product)
        }
    } else {
        sanitize_cpe_field(publisher_raw)
    };

    let product = sanitize_cpe_field(&clean_product);
    let version = sanitize_cpe_field(version_raw);

    let cpe23 = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, version);
    let purl = format!("pkg:generic/{}/{}@{}", vendor, product, version);

    NormalizedSoftwareId {
        product: clean_product,
        vendor: publisher_raw.to_string(),
        version: version_raw.to_string(),
        cpe23,
        purl,
        confidence: 95,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpe_and_purl_generation() {
        let res = resolve_cpe_and_purl("7-Zip 26.00 (x64)", "Igor Pavlov", "26.00");
        assert_eq!(res.product, "7-Zip");
        assert_eq!(res.cpe23, "cpe:2.3:a:igor_pavlov:7-zip:26.00:*:*:*:*:*:*:*");
        assert_eq!(res.purl, "pkg:generic/igor_pavlov/7-zip@26.00");

        let docker = resolve_cpe_and_purl("Docker Desktop", "Docker Inc.", "4.85.0");
        assert_eq!(
            docker.cpe23,
            "cpe:2.3:a:docker_inc.:docker_desktop:4.85.0:*:*:*:*:*:*:*"
        );
        assert_eq!(docker.purl, "pkg:generic/docker_inc./docker_desktop@4.85.0");
    }
}

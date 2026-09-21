#![forbid(unsafe_code)]

use crate::types::RawAssetObservation;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalAsset {
    pub asset_id: String,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub ip: Option<std::net::Ipv4Addr>,
    pub mac: Option<String>,
    pub cert_names: Vec<String>,
    pub smb_hostname: Option<String>,
    pub confidence: f32,
    pub sources: Vec<String>,
}

pub struct AssetResolver;

impl AssetResolver {
    pub fn resolve(&self, observations: &[RawAssetObservation]) -> Vec<CanonicalAsset> {
        let mut map = std::collections::HashMap::new();

        for obs in observations {
            let key = if let Some(ip) = obs.ip {
                format!("ip_{}", ip)
            } else if let Some(mac) = &obs.mac {
                format!("mac_{}", mac)
            } else if let Some(hostname) = &obs.hostname {
                format!("host_{}", hostname)
            } else {
                continue;
            };

            let entry = map.entry(key).or_insert_with(|| CanonicalAsset {
                asset_id: uuid::Uuid::now_v7().to_string(),
                hostname: None,
                fqdn: None,
                ip: None,
                mac: None,
                cert_names: vec![],
                smb_hostname: None,
                confidence: 0.0,
                sources: vec![],
            });
            Self::merge(entry, obs);
        }

        map.into_values()
            .map(|mut a| {
                a.confidence = Self::compute_confidence(&a);
                a
            })
            .collect()
    }

    fn merge(existing: &mut CanonicalAsset, obs: &RawAssetObservation) {
        if existing.ip.is_none() {
            existing.ip = obs.ip;
        }
        if existing.mac.is_none() {
            existing.mac = obs.mac.clone();
        }
        if existing.hostname.is_none() {
            existing.hostname = obs.hostname.clone();
        }
        if existing.fqdn.is_none() {
            existing.fqdn = obs.fqdn.clone();
        }
        if existing.smb_hostname.is_none() {
            existing.smb_hostname = obs.smb_hostname.clone();
        }
        for cert in &obs.cert_names {
            if !existing.cert_names.contains(cert) {
                existing.cert_names.push(cert.clone());
            }
        }
        if !existing.sources.contains(&obs.source) {
            existing.sources.push(obs.source.clone());
        }
    }

    fn compute_confidence(asset: &CanonicalAsset) -> f32 {
        let mut score = 0.0;
        if asset.ip.is_some() {
            score += 0.3;
        }
        if asset.mac.is_some() {
            score += 0.4;
        }
        if asset.hostname.is_some() {
            score += 0.3;
        }
        score
    }
}

#![forbid(unsafe_code)]

#[cfg(test)]
mod scan_tests {
    use crate::asset_resolver::*;
    use crate::coverage::*;
    use crate::nmap_adapter::*;
    use crate::orchestrator::*;
    use crate::port_scan::*;
    use crate::target::*;
    use crate::types::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_target_cidr() {
        let t = parse_target("192.168.1.0/24").unwrap();
        match t {
            ScanTarget::Cidr { base, prefix_len } => {
                assert_eq!(base, Ipv4Addr::new(192, 168, 1, 0));
                assert_eq!(prefix_len, 24);
            }
            _ => panic!("Wrong type"),
        }
    }

    #[test]
    fn test_expand_cidr_24() {
        let t = ScanTarget::Cidr {
            base: Ipv4Addr::new(192, 168, 1, 0),
            prefix_len: 24,
        };
        let ips = expand_target_to_ips(&t).unwrap();
        assert_eq!(ips.len(), 254);
    }

    #[test]
    fn test_expand_cidr_too_large() {
        let t = ScanTarget::Cidr {
            base: Ipv4Addr::new(10, 0, 0, 0),
            prefix_len: 15,
        };
        let err = expand_target_to_ips(&t).unwrap_err();
        match err {
            TargetParseError::CidrTooLarge(m) => assert_eq!(m, 15),
            _ => panic!("Wrong error"),
        }
    }

    #[test]
    fn test_port_state_timeout_ne_closed() {
        let e = std::io::Error::from(std::io::ErrorKind::TimedOut);
        let s = classify_error(&e);
        assert_eq!(s, PortState::Timeout);
        assert_ne!(s, PortState::Closed);
    }

    #[test]
    fn test_asset_resolver_deduplication() {
        let ip = Some(Ipv4Addr::new(10, 0, 0, 1));
        let obs1 = RawAssetObservation {
            ip,
            mac: None,
            hostname: None,
            fqdn: None,
            cert_names: vec![],
            smb_hostname: None,
            source: "s1".into(),
        };
        let obs2 = RawAssetObservation {
            ip,
            mac: Some("AA".into()),
            hostname: None,
            fqdn: None,
            cert_names: vec![],
            smb_hostname: None,
            source: "s2".into(),
        };
        let obs3 = RawAssetObservation {
            ip,
            mac: None,
            hostname: Some("host".into()),
            fqdn: None,
            cert_names: vec![],
            smb_hostname: None,
            source: "s3".into(),
        };
        let resolver = AssetResolver;
        let assets = resolver.resolve(&[obs1, obs2, obs3]);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].mac.as_deref(), Some("AA"));
        assert_eq!(assets[0].hostname.as_deref(), Some("host"));
    }

    #[test]
    fn test_coverage_report_fields() {
        let job = ScanJob {
            id: ScanJobId("j1".into()),
            target: ScanTarget::SingleIp(Ipv4Addr::new(127, 0, 0, 1)),
            profile: ScanProfile::Quick,
            created_at: chrono::Utc::now(),
            status: ScanJobStatus::Pending,
        };
        let res = ScanResult {
            job_id: "j1".into(),
            hosts: vec![],
            port_results: std::collections::HashMap::new(),
            coverage: ScanCoverage {
                targets_total: 1,
                targets_responsive: 0,
                tcp_ports_attempted: 0,
                tcp_ports_open: 0,
                tcp_ports_filtered: 0,
                tcp_ports_timeout: 0,
                tcp_ports_closed: 0,
                tcp_ports_error: 0,
                udp_ports_attempted: 0,
                services_identified: 0,
                services_unknown: 0,
                os_identified: 0,
                errors: 0,
                quality: CoverageQuality::Full,
                confidence: 1.0,
                scan_duration_ms: 0,
                privilege_level: "n".into(),
                nmap_available: false,
                note: None,
            },
            observations: vec![],
            errors: vec![],
            duration_ms: 0,
        };
        let cov = compute_coverage(&job, &res, 1, false);
        assert_eq!(cov.targets_total, 1);
    }

    #[test]
    fn test_nmap_xml_parse() {
        let res = NmapAdapter::parse_xml("").unwrap();
        assert!(res.hosts.is_empty());
    }
}

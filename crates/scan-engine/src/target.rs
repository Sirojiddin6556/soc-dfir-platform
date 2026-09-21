#![forbid(unsafe_code)]

use crate::types::ScanTarget;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum TargetParseError {
    #[error("Invalid IP: {0}")]
    InvalidIp(String),
    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("Invalid range: {0}")]
    InvalidRange(String),
    #[error("CIDR too large: /{0} exceeds max 65536 hosts")]
    CidrTooLarge(u8),
}

pub fn parse_target(input: &str) -> Result<ScanTarget, TargetParseError> {
    if let Ok(ip) = Ipv4Addr::from_str(input) {
        return Ok(ScanTarget::SingleIp(ip));
    }

    if let Some((ip_str, mask_str)) = input.split_once('/') {
        if let (Ok(ip), Ok(mask)) = (Ipv4Addr::from_str(ip_str), u8::from_str(mask_str)) {
            if mask < 16 {
                return Err(TargetParseError::CidrTooLarge(mask));
            }
            if mask > 32 {
                return Err(TargetParseError::InvalidCidr(input.to_string()));
            }
            let ip_u32 = u32::from(ip);
            let mask_u32 = !((1 << (32 - mask)) - 1);
            let base = Ipv4Addr::from(ip_u32 & mask_u32);
            return Ok(ScanTarget::Cidr {
                base,
                prefix_len: mask,
            });
        }
    }

    if let Some((start_str, end_str)) = input.split_once('-') {
        if let (Ok(start), Ok(end)) = (Ipv4Addr::from_str(start_str), Ipv4Addr::from_str(end_str)) {
            if u32::from(start) > u32::from(end) {
                return Err(TargetParseError::InvalidRange(input.to_string()));
            }
            if u32::from(end) - u32::from(start) > 65536 {
                return Err(TargetParseError::InvalidRange(
                    "Range exceeds 65536 hosts".to_string(),
                ));
            }
            return Ok(ScanTarget::Range { start, end });
        }
    }

    Ok(ScanTarget::Hostname(input.to_string()))
}

pub fn expand_target_to_ips(target: &ScanTarget) -> Result<Vec<Ipv4Addr>, TargetParseError> {
    match target {
        ScanTarget::SingleIp(ip) => Ok(vec![*ip]),
        ScanTarget::Cidr { base, prefix_len } => {
            if *prefix_len < 16 {
                return Err(TargetParseError::CidrTooLarge(*prefix_len));
            }
            if *prefix_len == 32 {
                return Ok(vec![*base]);
            }
            let base_u32 = u32::from(*base);
            let hosts = 1u32 << (32 - prefix_len);
            let mut ips = Vec::with_capacity(hosts as usize);
            let start = base_u32 + 1;
            let end = base_u32 + hosts - 2;
            for i in start..=end {
                ips.push(Ipv4Addr::from(i));
            }
            Ok(ips)
        }
        ScanTarget::Range { start, end } => {
            let start_u32 = u32::from(*start);
            let end_u32 = u32::from(*end);
            if end_u32 < start_u32 {
                return Err(TargetParseError::InvalidRange("End before start".into()));
            }
            if end_u32 - start_u32 > 65536 {
                return Err(TargetParseError::InvalidRange(
                    "Range exceeds 65536 hosts".to_string(),
                ));
            }
            let mut ips = Vec::with_capacity((end_u32 - start_u32 + 1) as usize);
            for i in start_u32..=end_u32 {
                ips.push(Ipv4Addr::from(i));
            }
            Ok(ips)
        }
        ScanTarget::Hostname(_) => Ok(vec![]),
    }
}

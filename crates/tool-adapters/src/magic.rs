#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ForensicArtifactFormat {
    Evtx,
    PcapMicrosecondLe,
    PcapMicrosecondBe,
    PcapNanosecondLe,
    PcapNanosecondBe,
    PcapNg,
    Unknown,
}

impl ForensicArtifactFormat {
    pub fn is_supported(&self) -> bool {
        !matches!(self, ForensicArtifactFormat::Unknown)
    }

    pub fn default_extension(&self) -> &'static str {
        match self {
            ForensicArtifactFormat::Evtx => "evtx",
            ForensicArtifactFormat::PcapMicrosecondLe
            | ForensicArtifactFormat::PcapMicrosecondBe
            | ForensicArtifactFormat::PcapNanosecondLe
            | ForensicArtifactFormat::PcapNanosecondBe => "pcap",
            ForensicArtifactFormat::PcapNg => "pcapng",
            ForensicArtifactFormat::Unknown => "bin",
        }
    }

    pub fn mime_type(&self) -> &'static str {
        match self {
            ForensicArtifactFormat::Evtx => "application/vnd.ms-windows.eventlog",
            ForensicArtifactFormat::PcapMicrosecondLe
            | ForensicArtifactFormat::PcapMicrosecondBe
            | ForensicArtifactFormat::PcapNanosecondLe
            | ForensicArtifactFormat::PcapNanosecondBe => "application/vnd.tcpdump.pcap",
            ForensicArtifactFormat::PcapNg => "application/x-pcapng",
            ForensicArtifactFormat::Unknown => "application/octet-stream",
        }
    }
}

/// Detects forensic artifact format by reading the ground-truth magic bytes
/// from the start of a buffer.
pub fn detect_artifact_format(header_bytes: &[u8]) -> ForensicArtifactFormat {
    if header_bytes.len() >= 8 && &header_bytes[0..8] == b"ElfFile\0" {
        return ForensicArtifactFormat::Evtx;
    }

    if header_bytes.len() >= 4 {
        let magic = [
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ];

        match magic {
            [0xa1, 0xb2, 0xc3, 0xd4] => ForensicArtifactFormat::PcapMicrosecondBe,
            [0xd4, 0xc3, 0xb2, 0xa1] => ForensicArtifactFormat::PcapMicrosecondLe,
            [0xa1, 0xb2, 0x3c, 0x4d] => ForensicArtifactFormat::PcapNanosecondBe,
            [0x4d, 0x3c, 0xb2, 0xa1] => ForensicArtifactFormat::PcapNanosecondLe,
            [0x0a, 0x0d, 0x0d, 0x0a] => ForensicArtifactFormat::PcapNg,
            _ => ForensicArtifactFormat::Unknown,
        }
    } else {
        ForensicArtifactFormat::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_detection_all_types() {
        assert_eq!(
            detect_artifact_format(b"ElfFile\0extra_bytes_here"),
            ForensicArtifactFormat::Evtx
        );
        assert_eq!(
            detect_artifact_format(&[0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00]),
            ForensicArtifactFormat::PcapMicrosecondLe
        );
        assert_eq!(
            detect_artifact_format(&[0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02]),
            ForensicArtifactFormat::PcapMicrosecondBe
        );
        assert_eq!(
            detect_artifact_format(&[0x4d, 0x3c, 0xb2, 0xa1, 0x02, 0x00]),
            ForensicArtifactFormat::PcapNanosecondLe
        );
        assert_eq!(
            detect_artifact_format(&[0xa1, 0xb2, 0x3c, 0x4d, 0x00, 0x02]),
            ForensicArtifactFormat::PcapNanosecondBe
        );
        assert_eq!(
            detect_artifact_format(&[0x0a, 0x0d, 0x0d, 0x0a, 0x00, 0x00]),
            ForensicArtifactFormat::PcapNg
        );
        assert_eq!(
            detect_artifact_format(b"GARBAGE_BYTES"),
            ForensicArtifactFormat::Unknown
        );
        assert_eq!(detect_artifact_format(&[]), ForensicArtifactFormat::Unknown);
    }
}

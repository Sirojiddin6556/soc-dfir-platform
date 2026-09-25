#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

pub mod phase3;

#[derive(Debug, PartialEq, Eq)]
pub enum PcapEndianness {
    Little,
    Big,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedPacket {
    pub packet_index: usize,
    pub timestamp_epoch_sec: u32,
    pub timestamp_epoch_usec: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub ether_type: u16,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub protocol: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<String>,
    pub payload_len: usize,
    pub timestamp_epoch_nanos: u32,
    pub src_ipv6: Option<String>,
    pub dst_ipv6: Option<String>,
    pub vlan_id: Option<u16>,
    pub tcp_sequence: Option<u32>,
    pub tcp_acknowledgment: Option<u32>,
    pub payload: Vec<u8>,
    pub interface_id: Option<u32>,
    pub physical_offset: Option<u64>,
    pub packet_hash: String,
    pub parse_quality: String,
    pub packet_locator: String,
    pub section_index: Option<u32>,
    pub capture_timestamp: Option<crate::pcap::phase3::CaptureTimestamp>,
}

pub fn parse_binary_pcap(bytes: &[u8]) -> Result<Vec<ParsedPacket>, String> {
    if bytes.len() < 24 {
        return Err("File too small for PCAP global header (min 24 bytes)".to_string());
    }

    let (endianness, nanos) = match &bytes[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (PcapEndianness::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (PcapEndianness::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (PcapEndianness::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (PcapEndianness::Big, true),
        _ => return Err("Invalid PCAP magic number".to_string()),
    };

    let read_u16 = |buf: &[u8], offset: usize| -> u16 {
        let raw = [buf[offset], buf[offset + 1]];
        match endianness {
            PcapEndianness::Little => u16::from_le_bytes(raw),
            PcapEndianness::Big => u16::from_be_bytes(raw),
        }
    };

    let read_u32 = |buf: &[u8], offset: usize| -> u32 {
        let raw = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        match endianness {
            PcapEndianness::Little => u32::from_le_bytes(raw),
            PcapEndianness::Big => u32::from_be_bytes(raw),
        }
    };

    let _ver_major = read_u16(bytes, 4);
    let _ver_minor = read_u16(bytes, 6);
    let snaplen = read_u32(bytes, 16);
    let linktype = read_u32(bytes, 20);

    let mut cursor = 24;
    let mut packet_idx = 0;
    let mut packets = Vec::new();

    while cursor + 16 <= bytes.len() {
        let packet_offset = cursor as u64;
        let ts_sec = read_u32(bytes, cursor);
        let ts_usec = read_u32(bytes, cursor + 4);
        let incl_len_raw = read_u32(bytes, cursor + 8);
        let incl_len = usize::try_from(incl_len_raw)
            .map_err(|_| format!("packet #{packet_idx} captured length does not fit usize"))?;
        let orig_len = read_u32(bytes, cursor + 12);
        cursor += 16;

        if incl_len > 16 * 1024 * 1024 {
            return Err(format!(
                "packet #{packet_idx} captured length exceeds configured limit"
            ));
        }
        if incl_len_raw > snaplen {
            return Err(format!(
                "packet #{packet_idx} captured length exceeds snaplen"
            ));
        }
        if orig_len < incl_len_raw {
            return Err(format!(
                "packet #{packet_idx} original length is smaller than captured length"
            ));
        }
        let packet_end = cursor
            .checked_add(incl_len)
            .ok_or_else(|| format!("packet #{packet_idx} length arithmetic overflow"))?;
        if packet_end > bytes.len() {
            return Err(format!(
                "Truncated packet #{}: expected {} bytes, only {} remaining",
                packet_idx,
                incl_len,
                bytes.len() - cursor
            ));
        }

        let pkt_data = &bytes[cursor..packet_end];
        cursor = packet_end;
        packet_idx += 1;

        let mut ether_type = 0u16;
        let mut src_ip = None;
        let mut dst_ip = None;
        let mut protocol = None;
        let mut src_port = None;
        let mut dst_port = None;
        let mut tcp_flags = None;
        let mut payload_len = 0;
        let mut src_ipv6 = None;
        let mut dst_ipv6 = None;
        let mut vlan_id = None;
        let mut tcp_sequence = None;
        let mut tcp_acknowledgment = None;
        let mut payload = Vec::new();

        // Ethernet frame decoding (LINKTYPE_ETHERNET = 1)
        if linktype == 1 && pkt_data.len() >= 14 {
            ether_type = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
            let mut network_offset = 14usize;
            if ether_type == 0x8100 && pkt_data.len() >= 18 {
                vlan_id = Some(u16::from_be_bytes([pkt_data[14], pkt_data[15]]) & 0x0fff);
                ether_type = u16::from_be_bytes([pkt_data[16], pkt_data[17]]);
                network_offset = 18;
            }
            if ether_type == 0x0800 && pkt_data.len() >= 34 {
                // IPv4
                let ip_hdr = &pkt_data[network_offset..];
                let ihl = ((ip_hdr[0] & 0x0f) * 4) as usize;
                let proto_num = ip_hdr[9];
                let s_ip = Ipv4Addr::new(ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);
                let d_ip = Ipv4Addr::new(ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]);
                src_ip = Some(s_ip.to_string());
                dst_ip = Some(d_ip.to_string());

                if ip_hdr.len() >= ihl {
                    let trans_data = &ip_hdr[ihl..];
                    match proto_num {
                        6 => {
                            // TCP
                            protocol = Some("TCP".to_string());
                            if trans_data.len() >= 20 {
                                src_port = Some(u16::from_be_bytes([trans_data[0], trans_data[1]]));
                                dst_port = Some(u16::from_be_bytes([trans_data[2], trans_data[3]]));
                                let flags_byte = trans_data[13];
                                let mut f_names = Vec::new();
                                if flags_byte & 0x02 != 0 {
                                    f_names.push("SYN");
                                }
                                if flags_byte & 0x10 != 0 {
                                    f_names.push("ACK");
                                }
                                if flags_byte & 0x01 != 0 {
                                    f_names.push("FIN");
                                }
                                if flags_byte & 0x04 != 0 {
                                    f_names.push("RST");
                                }
                                if flags_byte & 0x08 != 0 {
                                    f_names.push("PSH");
                                }
                                tcp_flags = Some(f_names.join("|"));
                                let tcp_offset = ((trans_data[12] >> 4) * 4) as usize;
                                if trans_data.len() >= tcp_offset {
                                    payload_len = trans_data.len() - tcp_offset;
                                    tcp_sequence = Some(u32::from_be_bytes([
                                        trans_data[4],
                                        trans_data[5],
                                        trans_data[6],
                                        trans_data[7],
                                    ]));
                                    tcp_acknowledgment = Some(u32::from_be_bytes([
                                        trans_data[8],
                                        trans_data[9],
                                        trans_data[10],
                                        trans_data[11],
                                    ]));
                                    payload.extend_from_slice(&trans_data[tcp_offset..]);
                                }
                            }
                        }
                        17 => {
                            // UDP
                            protocol = Some("UDP".to_string());
                            if trans_data.len() >= 8 {
                                src_port = Some(u16::from_be_bytes([trans_data[0], trans_data[1]]));
                                dst_port = Some(u16::from_be_bytes([trans_data[2], trans_data[3]]));
                                payload_len = trans_data.len() - 8;
                                payload.extend_from_slice(&trans_data[8..]);
                            }
                        }
                        1 => protocol = Some("ICMP".to_string()),
                        _ => protocol = Some(format!("IP-Proto-{}", proto_num)),
                    }
                }
            } else if ether_type == 0x86dd && pkt_data.len() >= network_offset + 40 {
                let ip = &pkt_data[network_offset..];
                let next = ip[6];
                src_ipv6 = Some(
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()).to_string(),
                );
                dst_ipv6 = Some(
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap())
                        .to_string(),
                );
                let trans = &ip[40..];
                match next {
                    6 if trans.len() >= 20 => {
                        protocol = Some("TCP".to_string());
                        src_port = Some(u16::from_be_bytes([trans[0], trans[1]]));
                        dst_port = Some(u16::from_be_bytes([trans[2], trans[3]]));
                        tcp_sequence =
                            Some(u32::from_be_bytes([trans[4], trans[5], trans[6], trans[7]]));
                        tcp_acknowledgment = Some(u32::from_be_bytes([
                            trans[8], trans[9], trans[10], trans[11],
                        ]));
                        let off = ((trans[12] >> 4) as usize) * 4;
                        if trans.len() >= off {
                            payload.extend_from_slice(&trans[off..]);
                            payload_len = trans.len() - off;
                        }
                    }
                    17 if trans.len() >= 8 => {
                        protocol = Some("UDP".to_string());
                        src_port = Some(u16::from_be_bytes([trans[0], trans[1]]));
                        dst_port = Some(u16::from_be_bytes([trans[2], trans[3]]));
                        payload.extend_from_slice(&trans[8..]);
                        payload_len = trans.len() - 8;
                    }
                    58 => protocol = Some("ICMPv6".to_string()),
                    _ => protocol = Some(format!("IP-Proto-{next}")),
                }
            }
        }

        let valid_fraction = if nanos {
            ts_usec < 1_000_000_000
        } else {
            ts_usec < 1_000_000
        };
        let timestamp_epoch_nanos = if valid_fraction {
            if nanos {
                ts_usec
            } else {
                ts_usec * 1000
            }
        } else {
            0
        };
        let capture_timestamp = if valid_fraction {
            phase3::TimestampResolution::Decimal(if nanos { 9 } else { 6 })
                .capture_timestamp(
                    (ts_sec as u64)
                        .checked_mul(if nanos { 1_000_000_000 } else { 1_000_000 })
                        .and_then(|value| value.checked_add(ts_usec as u64))
                        .ok_or_else(|| format!("packet #{packet_idx} timestamp overflow"))?,
                    0,
                )
                .ok()
        } else {
            None
        };

        packets.push(ParsedPacket {
            packet_index: packet_idx,
            timestamp_epoch_sec: ts_sec,
            timestamp_epoch_usec: ts_usec,
            captured_len: incl_len as u32,
            original_len: orig_len,
            ether_type,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            tcp_flags,
            payload_len,
            timestamp_epoch_nanos,
            src_ipv6,
            dst_ipv6,
            vlan_id,
            tcp_sequence,
            tcp_acknowledgment,
            payload,
            interface_id: None,
            physical_offset: Some(packet_offset),
            packet_hash: blake3::hash(pkt_data).to_hex().to_string(),
            parse_quality: "COMPLETE".to_string(),
            packet_locator: format!("pcap://offset/0x{packet_offset:08X}/packet/{packet_idx}"),
            section_index: None,
            capture_timestamp,
        });
    }

    Ok(packets)
}

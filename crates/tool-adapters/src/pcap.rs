#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

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
}

pub fn parse_binary_pcap(bytes: &[u8]) -> Result<Vec<ParsedPacket>, String> {
    if bytes.len() < 24 {
        return Err("File too small for PCAP global header (min 24 bytes)".to_string());
    }

    let magic = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let endianness = match magic {
        0xa1b2c3d4 => PcapEndianness::Little,
        0xd4c3b2a1 => PcapEndianness::Big,
        0xa1b23c4d => PcapEndianness::Little, // Nanosecond resolution
        0x4d3cb2a1 => PcapEndianness::Big,
        _ => return Err(format!("Invalid PCAP magic number: {:#010x}", magic)),
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
    let _snaplen = read_u32(bytes, 16);
    let linktype = read_u32(bytes, 20);

    let mut cursor = 24;
    let mut packet_idx = 0;
    let mut packets = Vec::new();

    while cursor + 16 <= bytes.len() {
        let ts_sec = read_u32(bytes, cursor);
        let ts_usec = read_u32(bytes, cursor + 4);
        let incl_len = read_u32(bytes, cursor + 8) as usize;
        let orig_len = read_u32(bytes, cursor + 12);
        cursor += 16;

        if cursor + incl_len > bytes.len() {
            return Err(format!(
                "Truncated packet #{}: expected {} bytes, only {} remaining",
                packet_idx,
                incl_len,
                bytes.len() - cursor
            ));
        }

        let pkt_data = &bytes[cursor..cursor + incl_len];
        cursor += incl_len;
        packet_idx += 1;

        let mut ether_type = 0u16;
        let mut src_ip = None;
        let mut dst_ip = None;
        let mut protocol = None;
        let mut src_port = None;
        let mut dst_port = None;
        let mut tcp_flags = None;
        let mut payload_len = 0;

        // Ethernet frame decoding (LINKTYPE_ETHERNET = 1)
        if linktype == 1 && pkt_data.len() >= 14 {
            ether_type = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
            if ether_type == 0x0800 && pkt_data.len() >= 34 {
                // IPv4
                let ip_hdr = &pkt_data[14..];
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
                            }
                        }
                        1 => protocol = Some("ICMP".to_string()),
                        _ => protocol = Some(format!("IP-Proto-{}", proto_num)),
                    }
                }
            }
        }

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
        });
    }

    Ok(packets)
}

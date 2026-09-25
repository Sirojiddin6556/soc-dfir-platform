use std::net::Ipv4Addr;

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
        sum = sum.wrapping_add(word);
        while sum > u16::MAX as u32 {
            sum = (sum & u16::MAX as u32) + (sum >> 16);
        }
    }
    !(sum as u16)
}

fn checksum_with_ipv4_pseudo_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    internet_checksum(&pseudo)
}

fn set_ipv4_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let checksum = internet_checksum(header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
}

#[derive(Debug, Clone)]
pub struct UdpFixture {
    pub payload: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl UdpFixture {
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            src_port: 53000,
            dst_port: 53,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
        }
    }

    pub fn ethernet_frame(&self) -> Vec<u8> {
        let udp_len = 8 + self.payload.len();
        let ip_len = 20 + udp_len;
        assert!(udp_len <= u16::MAX as usize);
        assert!(ip_len <= u16::MAX as usize);

        let mut udp = Vec::with_capacity(udp_len);
        udp.extend_from_slice(&self.src_port.to_be_bytes());
        udp.extend_from_slice(&self.dst_port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&self.payload);
        let checksum = checksum_with_ipv4_pseudo_header(self.src_ip, self.dst_ip, 17, &udp);
        let wire_checksum = if checksum == 0 { u16::MAX } else { checksum };
        udp[6..8].copy_from_slice(&wire_checksum.to_be_bytes());

        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&(ip_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&self.src_ip.octets());
        ip.extend_from_slice(&self.dst_ip.octets());
        set_ipv4_checksum(&mut ip);

        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        self.validate_geometry(&frame)
            .expect("valid UDP fixture geometry");
        frame
    }

    pub fn validate_geometry(&self, frame: &[u8]) -> Result<(), String> {
        if frame.len() < 42 {
            return Err("Ethernet/IPv4/UDP frame is truncated".into());
        }
        if frame[12..14] != [0x08, 0x00] {
            return Err("fixture is not IPv4 Ethernet".into());
        }
        let ip = &frame[14..34];
        if ip[0] >> 4 != 4 || (ip[0] & 0x0f) != 5 {
            return Err("invalid IPv4 version or IHL".into());
        }
        let ip_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if ip_len != frame.len() - 14 || internet_checksum(ip) != 0 {
            return Err("invalid IPv4 length or checksum".into());
        }
        let udp = &frame[34..];
        if udp[0..2] != self.src_port.to_be_bytes() || udp[2..4] != self.dst_port.to_be_bytes() {
            return Err("unexpected UDP endpoints".into());
        }
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        let stored_checksum = u16::from_be_bytes([udp[6], udp[7]]);
        let mut checksum_input = udp.to_vec();
        checksum_input[6..8].fill(0);
        let calculated_checksum =
            checksum_with_ipv4_pseudo_header(self.src_ip, self.dst_ip, 17, &checksum_input);
        let expected_wire_checksum = if calculated_checksum == 0 {
            u16::MAX
        } else {
            calculated_checksum
        };
        if udp_len != udp.len() || stored_checksum != expected_wire_checksum {
            return Err("invalid UDP length or checksum".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TcpFixture {
    pub payload: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u16,
}

impl TcpFixture {
    pub fn new(payload: Vec<u8>, sequence: u32) -> Self {
        Self {
            payload,
            src_port: 53000,
            dst_port: 53,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            sequence,
            acknowledgement: 0,
            flags: 0x018,
        }
    }

    pub fn next_sequence(&self) -> u32 {
        self.sequence
            .wrapping_add(u32::try_from(self.payload.len()).expect("fixture payload fits u32"))
    }

    pub fn ethernet_frame(&self) -> Vec<u8> {
        let tcp_len = 20 + self.payload.len();
        let ip_len = 20 + tcp_len;
        assert!(tcp_len <= u16::MAX as usize);
        assert!(ip_len <= u16::MAX as usize);

        let mut tcp = Vec::with_capacity(tcp_len);
        tcp.extend_from_slice(&self.src_port.to_be_bytes());
        tcp.extend_from_slice(&self.dst_port.to_be_bytes());
        tcp.extend_from_slice(&self.sequence.to_be_bytes());
        tcp.extend_from_slice(&self.acknowledgement.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(self.flags as u8);
        tcp.extend_from_slice(&65_535u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(&self.payload);
        let checksum = checksum_with_ipv4_pseudo_header(self.src_ip, self.dst_ip, 6, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&(ip_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&self.src_ip.octets());
        ip.extend_from_slice(&self.dst_ip.octets());
        set_ipv4_checksum(&mut ip);

        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        self.validate_geometry(&frame)
            .expect("valid TCP fixture geometry");
        frame
    }

    pub fn validate_geometry(&self, frame: &[u8]) -> Result<(), String> {
        if frame.len() < 54 {
            return Err("Ethernet/IPv4/TCP frame is truncated".into());
        }
        if frame[12..14] != [0x08, 0x00] {
            return Err("fixture is not IPv4 Ethernet".into());
        }
        let ip = &frame[14..34];
        if ip[0] >> 4 != 4 || (ip[0] & 0x0f) != 5 {
            return Err("invalid IPv4 version or IHL".into());
        }
        let ip_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if ip_len != frame.len() - 14 || internet_checksum(ip) != 0 {
            return Err("invalid IPv4 length or checksum".into());
        }
        let tcp = &frame[34..];
        if tcp[0..2] != self.src_port.to_be_bytes() || tcp[2..4] != self.dst_port.to_be_bytes() {
            return Err("unexpected TCP endpoints".into());
        }
        let header_len = ((tcp[12] >> 4) as usize) * 4;
        if header_len < 20 || header_len > tcp.len() {
            return Err("invalid TCP data offset".into());
        }
        if checksum_with_ipv4_pseudo_header(self.src_ip, self.dst_ip, 6, tcp) != 0 {
            return Err("invalid TCP checksum".into());
        }
        Ok(())
    }
}

pub fn classic_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    capture.extend_from_slice(&65_535u32.to_le_bytes());
    capture.extend_from_slice(&1u32.to_le_bytes());
    for frame in frames {
        let len = u32::try_from(frame.len()).expect("fixture frame fits PCAP length");
        capture.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        capture.extend_from_slice(&len.to_le_bytes());
        capture.extend_from_slice(&len.to_le_bytes());
        capture.extend_from_slice(frame);
    }
    let mut cursor = 24;
    for frame in frames {
        let len = frame.len();
        assert_eq!(
            u32::from_le_bytes(capture[cursor + 8..cursor + 12].try_into().unwrap()) as usize,
            len
        );
        cursor += 16 + len;
    }
    assert_eq!(cursor, capture.len());
    capture
}

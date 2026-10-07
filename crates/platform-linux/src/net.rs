#![forbid(unsafe_code)]

//! TCP/UDP sockets from `/proc/net/{tcp,tcp6,udp,udp6}` and local addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// One row of a `/proc/net/{tcp,udp}{,6}` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetSocket {
    pub transport: Transport,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub state_code: u8,
    pub uid: u32,
    pub inode: u64,
}

impl ProcNetSocket {
    pub fn protocol(&self) -> &'static str {
        match self.transport {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
        }
    }

    /// State name normalized to the same vocabulary the Windows collector
    /// uses (`Get-NetTCPConnection`).
    pub fn state(&self) -> &'static str {
        match self.transport {
            Transport::Tcp => tcp_state_name(self.state_code),
            Transport::Udp => match self.state_code {
                0x01 => "Established",
                _ => "Bound",
            },
        }
    }
}

/// Linux TCP states (include/net/tcp_states.h).
pub fn tcp_state_name(code: u8) -> &'static str {
    match code {
        0x01 => "Established",
        0x02 => "SynSent",
        0x03 => "SynReceived",
        0x04 => "FinWait1",
        0x05 => "FinWait2",
        0x06 => "TimeWait",
        0x07 => "Closed",
        0x08 => "CloseWait",
        0x09 => "LastAck",
        0x0A => "Listen",
        0x0B => "Closing",
        0x0C => "NewSynRecv",
        _ => "Unknown",
    }
}

/// Decodes `0100007F:0035` (IPv4) or a 32 hex digit IPv6 address with port.
///
/// The kernel prints each 32-bit word of the address with `%08X` of its
/// in-memory (native endian) value, so converting each word back with
/// native byte order restores the network-order bytes.
pub fn decode_proc_net_addr(raw: &str) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = raw.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match ip_hex.len() {
        8 => {
            let word = u32::from_str_radix(ip_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&ip_hex[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Parses a `/proc/net/{tcp,tcp6,udp,udp6}` table. The header line and
/// malformed rows are skipped.
pub fn parse_proc_net(content: &str, transport: Transport) -> Vec<ProcNetSocket> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                return None;
            }
            let (local_ip, local_port) = decode_proc_net_addr(parts[1])?;
            let (remote_ip, remote_port) = decode_proc_net_addr(parts[2])?;
            Some(ProcNetSocket {
                transport,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state_code: u8::from_str_radix(parts[3], 16).ok()?,
                uid: parts[7].parse().ok()?,
                inode: parts[9].parse().ok()?,
            })
        })
        .collect()
}

/// Inode of a `/proc/<pid>/fd/<n>` link target such as `socket:[12345]`.
pub fn parse_socket_link(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Local (host-owned) IPv4 addresses from `/proc/net/fib_trie`: an address
/// line `|-- a.b.c.d` followed by a `/32 host LOCAL` line.
pub fn parse_fib_trie_local(content: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut last_addr: Option<Ipv4Addr> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(addr) = trimmed.strip_prefix("|-- ") {
            last_addr = addr.trim().parse().ok();
        } else if trimmed.starts_with("/32 host LOCAL") {
            if let Some(addr) = last_addr {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    out
}

/// Addresses from `/proc/net/if_inet6` (32 hex digits, index, prefix,
/// scope, flags, interface name).
pub fn parse_if_inet6(content: &str) -> Vec<(Ipv6Addr, String)> {
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 || parts[0].len() != 32 {
                return None;
            }
            let value = u128::from_str_radix(parts[0], 16).ok()?;
            Some((Ipv6Addr::from(value), parts[5].to_string()))
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) mod live {
    use super::*;
    use host_snapshot::SocketObservation;
    use std::collections::HashMap;

    /// Maps socket inodes to the lowest pid holding them open (a listening
    /// socket inherited by worker processes maps to the parent).
    pub fn socket_inode_owners() -> HashMap<u64, u32> {
        let mut owners: HashMap<u64, u32> = HashMap::new();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return owners;
        };
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let Ok(target) = std::fs::read_link(fd.path()) else {
                    continue;
                };
                if let Some(inode) = parse_socket_link(&target.to_string_lossy()) {
                    owners
                        .entry(inode)
                        .and_modify(|p| *p = (*p).min(pid))
                        .or_insert(pid);
                }
            }
        }
        owners
    }

    pub fn collect_sockets(pid_names: &HashMap<u32, String>) -> Vec<SocketObservation> {
        let now = chrono::Utc::now().to_rfc3339();
        let owners = socket_inode_owners();
        let tables = [
            ("/proc/net/tcp", Transport::Tcp),
            ("/proc/net/tcp6", Transport::Tcp),
            ("/proc/net/udp", Transport::Udp),
            ("/proc/net/udp6", Transport::Udp),
        ];
        let mut out = Vec::new();
        for (path, transport) in tables {
            // tcp6/udp6 are absent when IPv6 is disabled: not an error.
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            for s in parse_proc_net(&content, transport) {
                let pid = if s.inode == 0 {
                    0
                } else {
                    owners.get(&s.inode).copied().unwrap_or(0)
                };
                out.push(SocketObservation {
                    protocol: s.protocol().to_string(),
                    local_address: s.local_ip.to_string(),
                    local_port: s.local_port,
                    remote_address: s.remote_ip.to_string(),
                    remote_port: s.remote_port,
                    state: s.state().to_string(),
                    pid,
                    process_name: pid_names.get(&pid).cloned(),
                    first_seen: now.clone(),
                    last_seen: now.clone(),
                    collected_at: now.clone(),
                    inode: (s.inode != 0).then_some(s.inode),
                    uid: Some(s.uid),
                });
            }
        }
        out
    }

    /// All non-loopback local addresses.
    pub fn local_addresses() -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
            for addr in parse_fib_trie_local(&content) {
                if !addr.is_loopback() {
                    out.push(addr.to_string());
                }
            }
        }
        if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
            for (addr, _iface) in parse_if_inet6(&content) {
                if !addr.is_loopback() {
                    out.push(addr.to_string());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from a live x86_64 host (little-endian).
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:AD03 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3011 1 00000000fa449b17 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19874 1 0000000000000000 100 0 0 10 0
   2: 0200A8C0:B4F2 2A00A8C0:115C 01 00000000:00000000 02:000A7D5B 00000000  1000        0 55120 2 0000000000000000 20 4 30 10 -1
   3: 0200A8C0:D2B4 5DB8D822:01BB 06 00000000:00000000 03:00000DAE 00000000     0        0 0 3 0000000000000000
";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19876 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41001 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000200A8C0:0050 0000000000000000FFFF00002A00A8C0:C350 01 00000000:00000000 00:00000000 00000000    33        0 41002 1 0000000000000000 20 4 30 10 -1
   3: B80D0120000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41003 1 0000000000000000 100 0 0 10 0
";

    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  612: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 17436 2 0000000000000000 0
  830: 0200A8C0:E1C3 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 61001 2 0000000000000000 0
";

    #[cfg(target_endian = "little")]
    #[test]
    fn parses_ipv4_tcp_table() {
        let sockets = parse_proc_net(TCP, Transport::Tcp);
        assert_eq!(sockets.len(), 4);
        assert_eq!(sockets[0].local_ip.to_string(), "127.0.0.1");
        assert_eq!(sockets[0].local_port, 44291);
        assert_eq!(sockets[0].state(), "Listen");
        assert_eq!(sockets[0].inode, 3011);
        assert_eq!(sockets[1].local_ip.to_string(), "0.0.0.0");
        assert_eq!(sockets[1].local_port, 22);

        let established = &sockets[2];
        assert_eq!(established.local_ip.to_string(), "192.168.0.2");
        assert_eq!(established.remote_ip.to_string(), "192.168.0.42");
        assert_eq!(established.remote_port, 4444);
        assert_eq!(established.state(), "Established");
        assert_eq!(established.uid, 1000);

        let time_wait = &sockets[3];
        assert_eq!(time_wait.remote_ip.to_string(), "34.216.184.93");
        assert_eq!(time_wait.remote_port, 443);
        assert_eq!(time_wait.state(), "TimeWait");
        assert_eq!(time_wait.inode, 0);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn parses_ipv6_tcp_table() {
        let sockets = parse_proc_net(TCP6, Transport::Tcp);
        assert_eq!(sockets.len(), 4);
        assert_eq!(sockets[0].local_ip.to_string(), "::");
        assert_eq!(sockets[0].local_port, 22);
        assert_eq!(sockets[1].local_ip.to_string(), "::1");
        assert_eq!(sockets[1].local_port, 8080);
        // IPv4-mapped connection accepted by a dual-stack listener.
        assert_eq!(sockets[2].local_ip.to_string(), "::ffff:192.168.0.2");
        assert_eq!(sockets[2].remote_ip.to_string(), "::ffff:192.168.0.42");
        assert_eq!(sockets[2].remote_port, 50000);
        assert_eq!(sockets[2].state(), "Established");
        assert_eq!(sockets[3].local_ip.to_string(), "2001:db8::1");
        assert_eq!(sockets[3].local_port, 443);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn parses_udp_table() {
        let sockets = parse_proc_net(UDP, Transport::Udp);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].protocol(), "UDP");
        assert_eq!(sockets[0].local_ip.to_string(), "127.0.0.53");
        assert_eq!(sockets[0].local_port, 53);
        assert_eq!(sockets[0].state(), "Bound");
        assert_eq!(sockets[1].remote_ip.to_string(), "8.8.8.8");
        assert_eq!(sockets[1].state(), "Established");
    }

    #[test]
    fn rejects_malformed_rows() {
        let table = "header\n 0: ZZZZ:0016 00000000:0000 0A 0 0 0 0 0 1\n 1: short\n";
        assert!(parse_proc_net(table, Transport::Tcp).is_empty());
    }

    #[test]
    fn parses_socket_fd_links() {
        assert_eq!(parse_socket_link("socket:[19874]"), Some(19874));
        assert_eq!(parse_socket_link("pipe:[19874]"), None);
        assert_eq!(parse_socket_link("/dev/null"), None);
    }

    #[test]
    fn parses_local_addresses() {
        let trie = "Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
     +-- 192.0.2.0/24 2 0 2
           |-- 192.0.2.0
              /24 link UNICAST
           |-- 192.0.2.2
              /32 host LOCAL
        |-- 192.0.2.255
           /32 link BROADCAST
Local:
           |-- 192.0.2.2
              /32 host LOCAL
";
        let addrs = parse_fib_trie_local(trie);
        assert_eq!(
            addrs,
            vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );

        let inet6 = "00000000000000000000000000000001 01 80 10 80       lo\nfe800000000000000a0027fffe4d5c1e 02 40 20 80     eth0\n";
        let v6 = parse_if_inet6(inet6);
        assert_eq!(v6[0].0, Ipv6Addr::LOCALHOST);
        assert_eq!(v6[1].0.to_string(), "fe80::a00:27ff:fe4d:5c1e");
        assert_eq!(v6[1].1, "eth0");
    }
}

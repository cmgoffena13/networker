use anyhow::{Result, bail};
use if_addrs::{IfAddr, get_if_addrs};
use std::net::{IpAddr, Ipv4Addr};

// --- Network interface / LAN detection ---

pub struct NetworkInfo {
    pub ip: IpAddr,
    pub netmask: IpAddr,
    pub broadcast: IpAddr,
    pub interface_name: String,
}

pub fn get_local_network() -> Result<NetworkInfo> {
    let ifaces = get_if_addrs()?;

    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }

        if let IfAddr::V4(v4_addr) = iface.addr {
            let ip = IpAddr::V4(v4_addr.ip);
            let netmask = IpAddr::V4(v4_addr.netmask);
            let broadcast = calculate_broadcast(ip, netmask);
            let interface_name = iface.name;

            return Ok(NetworkInfo {
                ip,
                netmask,
                broadcast,
                interface_name,
            });
        }
    }

    bail!("No suitable IPv4 network interface found");
}

fn calculate_broadcast(ip: IpAddr, netmask: IpAddr) -> IpAddr {
    if let (IpAddr::V4(ip_v4), IpAddr::V4(mask_v4)) = (ip, netmask) {
        let octets = ip_v4.octets();
        let mask_octets = mask_v4.octets();

        let b_octets: [u8; 4] = [
            octets[0] | !mask_octets[0],
            octets[1] | !mask_octets[1],
            octets[2] | !mask_octets[2],
            octets[3] | !mask_octets[3],
        ];

        IpAddr::V4(Ipv4Addr::new(
            b_octets[0],
            b_octets[1],
            b_octets[2],
            b_octets[3],
        ))
    } else {
        // Fallback for IPv6 or errors
        ip
    }
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ipv4(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n)
}

fn network_address_ipv4(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    u32_to_ipv4(ipv4_to_u32(ip) & ipv4_to_u32(netmask))
}

fn prefix_len_ipv4(netmask: Ipv4Addr) -> u32 {
    ipv4_to_u32(netmask).count_ones()
}

pub fn iter_ipv4_ping_targets(info: &NetworkInfo) -> Option<impl Iterator<Item = Ipv4Addr>> {
    let (IpAddr::V4(ip), IpAddr::V4(mask), IpAddr::V4(bcast)) =
        (info.ip, info.netmask, info.broadcast)
    else {
        return None;
    };

    let net = network_address_ipv4(ip, mask);
    let prefix = prefix_len_ipv4(mask);
    let n = ipv4_to_u32(net);
    let b = ipv4_to_u32(bcast);

    let (start, end) = match prefix {
        32 => (n, n),
        31 => (n, b),
        _ if b <= n.wrapping_add(1) => (1u32, 0u32), // empty `1..=0`
        _ => (n + 1, b - 1),
    };

    Some((start..=end).map(u32_to_ipv4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_calculate_broadcast_class_c() {
        // 192.168.1.10 / 255.255.255.0 -> Broadcast 192.168.1.255
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mask = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));

        let expected = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(calculate_broadcast(ip, mask), expected);
    }

    #[test]
    fn test_calculate_broadcast_class_b() {
        // 10.0.5.5 / 255.255.0.0 -> Broadcast 10.0.255.255
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 5));
        let mask = IpAddr::V4(Ipv4Addr::new(255, 255, 0, 0));

        let expected = IpAddr::V4(Ipv4Addr::new(10, 0, 255, 255));
        assert_eq!(calculate_broadcast(ip, mask), expected);
    }

    #[test]
    fn test_get_local_network_exists() {
        // Just check that we don't crash and get *some* interface
        let result = get_local_network();
        assert!(
            result.is_ok(),
            "Should find at least one non-loopback interface"
        );

        let info = result.unwrap();
        assert!(!info.interface_name.is_empty());
        assert!(info.ip.is_ipv4());
    }

    #[test]
    fn test_iter_ping_targets_class_c() {
        let info = NetworkInfo {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            broadcast: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
            interface_name: "en0".into(),
        };
        let addrs: Vec<_> = iter_ipv4_ping_targets(&info).unwrap().collect();
        assert_eq!(addrs.len(), 254);
        assert_eq!(addrs[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addrs[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_iter_ping_targets_slash_30() {
        let info = NetworkInfo {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 252)),
            broadcast: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            interface_name: "eth0".into(),
        };
        let addrs: Vec<_> = iter_ipv4_ping_targets(&info).unwrap().collect();
        assert_eq!(
            addrs,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2),]
        );
    }
}

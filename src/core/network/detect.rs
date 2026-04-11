use if_addrs::{get_if_addrs, IfAddr};
use std::net::{IpAddr, Ipv4Addr};
use anyhow::{Result, bail};

#[derive(Debug)]
pub struct NetworkInfo {
    pub ip: IpAddr,
    pub netmask: IpAddr,
    pub broadcast: IpAddr,
    pub interface_name: String
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
                interface_name
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
        
        IpAddr::V4(Ipv4Addr::new(b_octets[0], b_octets[1], b_octets[2], b_octets[3]))
    } else {
        // Fallback for IPv6 or errors
        ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, IpAddr};

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
        assert!(result.is_ok(), "Should find at least one non-loopback interface");
        
        let info = result.unwrap();
        assert!(!info.interface_name.is_empty());
        assert!(info.ip.is_ipv4());
    }
}
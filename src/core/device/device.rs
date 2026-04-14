use std::net::Ipv4Addr;

pub struct Device {
    ipv4: Ipv4Addr,
}

impl Device {
    pub fn new(ipv4: Ipv4Addr) -> Self {
        Self { ipv4 }
    }

    pub fn ipv4(&self) -> Ipv4Addr {
        self.ipv4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        assert_eq!(Device::new(ip).ipv4(), ip);
    }
}

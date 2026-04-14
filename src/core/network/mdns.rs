//! mDNS browse for `_services._dns-sd._udp.local.` — collect IPv4 addresses that appear in responses.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent};

use crate::core::device::Device;

pub const SERVICE_DISCOVERY_QUERY: &str = "_services._dns-sd._udp.local.";

/// Run a short DNS-SD meta browse on one interface and return distinct IPv4 addresses seen on the LAN.
pub async fn discover_ipv4_on_interface(
    interface_name: &str,
    duration: Duration,
) -> anyhow::Result<Vec<Device>> {
    let daemon = ServiceDaemon::new().context("ServiceDaemon::new")?;
    daemon.disable_interface(IfKind::All).context("disable_interface All")?;
    daemon
        .disable_interface(IfKind::IPv6)
        .context("disable_interface IPv6")?;
    daemon
        .enable_interface(interface_name)
        .context("enable_interface")?;

    let receiver = daemon
        .browse(SERVICE_DISCOVERY_QUERY)
        .context("browse")?;

    let stop = tokio::time::Instant::now() + duration;
    let mut ips = HashSet::new();

    loop {
        let now = tokio::time::Instant::now();
        if now >= stop {
            break;
        }
        let remaining = stop - now;
        tokio::select! {
            _ = tokio::time::sleep(remaining) => break,
            ev = receiver.recv_async() => {
                match ev {
                    Ok(ServiceEvent::ServiceResolved(r)) => {
                        for ip in r.get_addresses_v4() {
                            ips.insert(ip);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }

    let _ = daemon.stop_browse(SERVICE_DISCOVERY_QUERY);
    daemon.shutdown()?;

    let mut out: Vec<Device> = ips.into_iter().map(Device::new).collect();
    out.sort_by_key(|d| d.ipv4());
    Ok(out)
}

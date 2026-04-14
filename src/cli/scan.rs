use std::time::Duration;

use anyhow::Result;
use clap::Args;
use tokio::runtime::Runtime;

use crate::core::network::mdns::discover_ipv4_on_interface;
use crate::core::network::{get_local_network, iter_ipv4_ping_targets};

#[derive(Args)]
#[command(about = "Scan the network for devices")]
pub struct ScanCommand;

impl ScanCommand {
    pub fn run(&self) -> Result<()> {
        println!("Scanning network for devices...\n");

        let info = get_local_network()?;

        println!("Network Detected:");
        println!("   IP: {}", info.ip);
        println!("   Netmask: {}", info.netmask);
        println!("   Broadcast: {}", info.broadcast);
        println!("   Interface: {}", info.interface_name);
        if let Some(targets) = iter_ipv4_ping_targets(&info) {
            let count = targets.count();
            println!("   ICMP ping targets on this LAN: {count} host(s)");
        }

        let rt = Runtime::new()?;
        let mdns_ips = rt.block_on(discover_ipv4_on_interface(
            &info.interface_name,
            Duration::from_secs(5),
        ))?;
        println!(
            "   Hosts advertising services (mDNS, 5s listen): {}",
            mdns_ips.len()
        );
        for d in &mdns_ips {
            println!("      {}", d.ipv4());
        }

        println!();

        Ok(())
    }
}
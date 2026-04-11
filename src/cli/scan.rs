use clap::Args;
use crate::core::network::{get_local_network, iter_ipv4_ping_targets};
use anyhow::Result;

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
            println!("   Ping targets on this LAN: {count} host(s)");
        }
        println!("\nStarting scan...\n");

        Ok(())
    }
}
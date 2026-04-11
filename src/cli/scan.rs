use clap::Args;
use crate::core::network::get_local_network;
use anyhow::Result;

#[derive(Args, Debug)]
#[command(about = "Scan the network for open ports")]
pub struct ScanCommand;

impl ScanCommand {
    pub fn run(&self) -> Result<()> {
        println!("Scanning network for open ports...\n");

        let info = get_local_network()?;

        println!("Network Detected:");
        println!("   IP: {}", info.ip);
        println!("   Netmask: {}", info.netmask);
        println!("   Broadcast: {}", info.broadcast);
        println!("   Interface: {}", info.interface_name);
        println!("\nStarting scan...\n");

        Ok(())
    }
}
use clap::Args;
use crate::core::network::get_local_network;

#[derive(Args, Debug)]
#[command(about = "Scan the network for open ports")]
pub struct ScanCommand;

impl ScanCommand {
    pub fn run(&self) {
        println!("Scanning network for open ports...\n");

        match get_local_network() {
            Ok(info) => {
                println!("Network Detected:");
                println!("   IP: {}", info.ip);
                println!("   Netmask: {}", info.netmask);
                println!("   Broadcast: {}", info.broadcast);
                println!("   Interface: {}", info.interface_name);
                println!("\nStarting scan...\n");
            }
            Err(e) => {
                eprintln!("Error detecting network: {}", e);
                std::process::exit(1);
            }
        }
    }
}
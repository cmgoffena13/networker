use clap::Args;

#[derive(Args, Debug)]
#[command(about = "Scan the network for open ports")]
pub struct ScanCommand;

impl ScanCommand {
    pub fn run(&self) {
        println!("Scanning network for open ports...");
    }
}

use clap::{Parser, Subcommand};
use cli::ScanCommand;

mod cli;

#[derive(Parser)]
#[command(name = "networker")]
#[command(about = "Networker CLI - Interact with your local area network (LAN)")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan(ScanCommand),
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(scan) => scan.run(),
    }
}
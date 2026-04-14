use clap::{Parser, Subcommand};
use cli::ScanCommand;

mod cli;
mod core;

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

    let result = match cli.command {
        Commands::Scan(args) => args.run(),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

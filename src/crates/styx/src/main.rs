use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "styx",
    version,
    about = "Styx Rust runtime (foundation development build)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print build and contract identity; does not claim a running service.
    BuildInfo,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::BuildInfo => println!(
            "styx {} contract={} stage={}",
            env!("CARGO_PKG_VERSION"),
            styx_contracts::CONTRACT_VERSION,
            styx_runtime::IMPLEMENTATION_STAGE,
        ),
    }
}

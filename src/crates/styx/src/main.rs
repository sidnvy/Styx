mod cli;
use clap::Parser;
#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run(cli::Cli::parse()).await
}

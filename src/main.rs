mod cli;
mod commands;
mod cosmos;
mod evm;
mod state;
mod steps;
mod utils;

use clap::Parser;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv_override().ok();

    let cli = cli::Cli::parse();

    match cli.command {
        cli::Commands::Init => commands::init::run().await,
        cli::Commands::Status { axelar_id } => commands::status::run(axelar_id),
        cli::Commands::Deploy {
            axelar_id,
            private_key,
            artifact_path,
            salt,
            proxy_artifact_path,
        } => {
            commands::deploy::run(axelar_id, private_key, artifact_path, salt, proxy_artifact_path)
                .await
        }
        cli::Commands::Reset { axelar_id } => commands::reset::run(axelar_id),
    }
}

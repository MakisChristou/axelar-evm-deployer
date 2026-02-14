use std::fs;

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::Bytes,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use clap::{Parser, Subcommand};
use eyre::Result;

#[derive(Parser)]
#[command(name = "axelar-evm-deployer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy a contract via CREATE transaction
    Deploy {
        /// RPC endpoint URL
        #[arg(long)]
        rpc_url: String,

        /// Private key (hex, with or without 0x prefix)
        #[arg(long)]
        private_key: String,

        /// Path to Hardhat artifact JSON
        #[arg(long)]
        artifact_path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Deploy {
            rpc_url,
            private_key,
            artifact_path,
        } => {
            // Read artifact and extract bytecode
            let artifact: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&artifact_path)?)?;
            let bytecode_hex = artifact["bytecode"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("no bytecode field in artifact"))?;
            let bytecode = Bytes::from(hex::decode(bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex))?);

            // Set up signer + provider
            let signer: PrivateKeySigner = private_key.parse()?;
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(rpc_url.parse()?);
            
            // Send CREATE tx (with_deploy_code marks it as contract creation so the wallet filler doesn't require `to`)
            let tx = TransactionRequest::default().with_deploy_code(bytecode);
            let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
            println!("tx hash: {}", receipt.transaction_hash);
            let addr = receipt
                .contract_address
                .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;
            println!("deployed at: {addr}");
        }
    }

    Ok(())
}

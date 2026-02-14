use std::fs;
use std::path::PathBuf;

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Bytes, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use clap::{Parser, Subcommand};
use eyre::Result;
use serde_json::{Map, Value, json};


#[derive(Parser)]
#[command(name = "axelar-evm-deployer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new chain deployment
    Init {
        /// Human-readable chain name
        #[arg(long)]
        chain_name: String,

        /// Axelar chain identifier (also the key in the JSON)
        #[arg(long)]
        axelar_id: String,

        /// EVM chain ID
        #[arg(long)]
        chain_id: u64,

        /// RPC endpoint URL
        #[arg(long)]
        rpc_url: String,

        /// Native token symbol
        #[arg(long)]
        token_symbol: String,

        /// Token decimals
        #[arg(long)]
        decimals: u8,

        /// Explorer name
        #[arg(long)]
        explorer_name: Option<String>,

        /// Explorer URL
        #[arg(long)]
        explorer_url: Option<String>,

        /// Path to target chains config JSON (e.g. testnet.json)
        #[arg(long)]
        target_json: PathBuf,
    },

    /// Deploy a contract via CREATE transaction
    Deploy {
        /// Axelar chain identifier (loads state from ./deployments/<id>.json)
        #[arg(long)]
        axelar_id: String,

        /// Private key (hex, with or without 0x prefix)
        #[arg(long)]
        private_key: String,

        /// Path to Hardhat artifact JSON
        #[arg(long)]
        artifact_path: String,

        /// Contract name (key in contracts object, e.g. ConstAddressDeployer)
        #[arg(long)]
        contract_name: String,
    },
}

fn data_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .ok_or_else(|| eyre::eyre!("could not determine data directory"))?
        .join("axelar-evm-deployer");
    Ok(dir)
}

fn state_path(axelar_id: &str) -> Result<PathBuf> {
    Ok(data_dir()?.join(format!("{axelar_id}.json")))
}

fn read_state(axelar_id: &str) -> Result<Value> {
    let path = state_path(axelar_id)?;
    let content = fs::read_to_string(&path)
        .map_err(|e| eyre::eyre!("failed to read state file {}: {e}. Run `init` first.", path.display()))?;
    Ok(serde_json::from_str(&content)?)
}

fn update_target_json(
    path: &PathBuf,
    axelar_id: &str,
    contract_name: &str,
    contract_data: Value,
) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let mut root: Value = serde_json::from_str(&content)?;

    let contracts = root
        .pointer_mut(&format!("/chains/{axelar_id}/contracts"))
        .ok_or_else(|| eyre::eyre!("chain '{axelar_id}' not found in {}", path.display()))?
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("contracts is not an object"))?;

    contracts.insert(contract_name.to_string(), contract_data);

    fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    println!("updated {} -> chains.{axelar_id}.contracts.{contract_name}", path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            chain_name,
            axelar_id,
            chain_id,
            rpc_url,
            token_symbol,
            decimals,
            explorer_name,
            explorer_url,
            target_json,
        } => {
            // Build chain entry
            let mut chain_entry = json!({
                "name": chain_name,
                "axelarId": axelar_id,
                "chainId": chain_id,
                "rpc": rpc_url,
                "tokenSymbol": token_symbol,
                "confirmations": 1,
                "finality": "finalized",
                "decimals": decimals,
                "approxFinalityWaitTime": 1,
                "chainType": "evm",
                "contracts": {}
            });

            // Add explorer if provided
            if let (Some(name), Some(url)) = (&explorer_name, &explorer_url) {
                chain_entry["explorer"] = json!({
                    "name": name,
                    "url": url,
                });
            }

            // Insert into target JSON
            let content = fs::read_to_string(&target_json)?;
            let mut root: Value = serde_json::from_str(&content)?;
            let chains = root
                .get_mut("chains")
                .and_then(|c| c.as_object_mut())
                .ok_or_else(|| eyre::eyre!("no 'chains' object in {}", target_json.display()))?;

            if chains.contains_key(&axelar_id) {
                return Err(eyre::eyre!("chain '{axelar_id}' already exists in {}", target_json.display()));
            }

            chains.insert(axelar_id.clone(), chain_entry);
            fs::write(&target_json, serde_json::to_string_pretty(&root)? + "\n")?;
            println!("added chain '{axelar_id}' to {}", target_json.display());

            // Save local state file
            let dir = data_dir()?;
            fs::create_dir_all(&dir)?;
            let state = json!({
                "axelarId": axelar_id,
                "rpcUrl": rpc_url,
                "targetJson": target_json.to_string_lossy(),
            });
            let state_file = state_path(&axelar_id)?;
            fs::write(&state_file, serde_json::to_string_pretty(&state)? + "\n")?;
            println!("saved state to {}", state_file.display());
        }

        Commands::Deploy {
            axelar_id,
            private_key,
            artifact_path,
            contract_name,
        } => {
            // Load state
            let state = read_state(&axelar_id)?;
            let rpc_url = state["rpcUrl"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("no rpcUrl in state"))?;
            let target_json = PathBuf::from(
                state["targetJson"]
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("no targetJson in state"))?,
            );

            // Read artifact and extract bytecode
            let artifact: Value = serde_json::from_str(&fs::read_to_string(&artifact_path)?)?;
            let bytecode_hex = artifact["bytecode"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("no bytecode field in artifact"))?;
            let bytecode_raw = hex::decode(bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex))?;
            let bytecode = Bytes::from(bytecode_raw.clone());

            // Set up signer + provider
            let signer: PrivateKeySigner = private_key.parse()?;
            let deployer_addr = signer.address();
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(rpc_url.parse()?);

            // Send CREATE tx
            let tx = TransactionRequest::default().with_deploy_code(bytecode);
            let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
            println!("tx hash: {}", receipt.transaction_hash);
            let addr = receipt
                .contract_address
                .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;
            println!("deployed at: {addr}");

            // Compute code hashes
            let predeploy_codehash = keccak256(&bytecode_raw);
            let deployed_code = provider.get_code_at(addr).await?;
            let codehash = keccak256(&deployed_code);

            // Update target JSON
            let mut contract_data = Map::new();
            contract_data.insert("address".into(), json!(format!("{addr}")));
            contract_data.insert("deployer".into(), json!(format!("{deployer_addr}")));
            contract_data.insert("deploymentMethod".into(), json!("create"));
            contract_data.insert("codehash".into(), json!(format!("{codehash}")));
            contract_data.insert("predeployCodehash".into(), json!(format!("{predeploy_codehash}")));

            update_target_json(&target_json, &axelar_id, &contract_name, Value::Object(contract_data))?;
        }
    }

    Ok(())
}

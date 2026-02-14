use std::fs;
use std::path::PathBuf;

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Address, Bytes, FixedBytes, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use clap::{Parser, Subcommand};
use eyre::Result;
use serde_json::{Map, Value, json};

// ConstAddressDeployer ABI (just what we need)
sol! {
    #[sol(rpc)]
    contract ConstAddressDeployer {
        function deploy(bytes bytecode, bytes32 salt) external returns (address deployedAddress_);
        function deployedAddress(bytes bytecode, address sender, bytes32 salt) external view returns (address deployedAddress_);
    }
}

const STEPS: &[&str] = &["ConstAddressDeployer", "Create3Deployer"];

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

    /// Show deployment progress
    Status {
        /// Axelar chain identifier
        #[arg(long)]
        axelar_id: String,
    },

    /// Run the next pending deployment step
    Deploy {
        /// Axelar chain identifier
        #[arg(long)]
        axelar_id: String,

        /// Private key (hex, with or without 0x prefix)
        #[arg(long)]
        private_key: String,

        /// Path to Hardhat artifact JSON
        #[arg(long)]
        artifact_path: String,

        /// Salt for create2/create3 deployments (defaults to step name)
        #[arg(long)]
        salt: Option<String>,
    },
}

// --- state helpers ---

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

fn save_state(axelar_id: &str, state: &Value) -> Result<()> {
    let path = state_path(axelar_id)?;
    fs::write(&path, serde_json::to_string_pretty(state)? + "\n")?;
    Ok(())
}

fn next_pending_step(state: &Value) -> Option<(usize, String)> {
    let steps = state["steps"].as_array()?;
    for (i, step) in steps.iter().enumerate() {
        if step["status"].as_str() == Some("pending") {
            return Some((i, step["name"].as_str()?.to_string()));
        }
    }
    None
}

fn mark_step_completed(state: &mut Value, idx: usize) {
    if let Some(step) = state["steps"].as_array_mut().and_then(|a| a.get_mut(idx)) {
        step["status"] = json!("completed");
    }
}

// --- target json helpers ---

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

fn read_contract_address(target_json: &PathBuf, axelar_id: &str, contract_name: &str) -> Result<Address> {
    let content = fs::read_to_string(target_json)?;
    let root: Value = serde_json::from_str(&content)?;
    let addr_str = root
        .pointer(&format!("/chains/{axelar_id}/contracts/{contract_name}/address"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("{contract_name} not deployed yet for {axelar_id}"))?;
    Ok(addr_str.parse()?)
}

// --- salt encoding (matches JS getSaltFromKey) ---

fn get_salt_from_key(key: &str) -> FixedBytes<32> {
    // JS: keccak256(defaultAbiCoder.encode(['string'], [key]))
    let encoded = key.abi_encode();
    keccak256(&encoded)
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

            // Build steps list
            let steps: Vec<Value> = STEPS
                .iter()
                .map(|name| json!({ "name": name, "status": "pending" }))
                .collect();

            // Save state
            let dir = data_dir()?;
            fs::create_dir_all(&dir)?;
            let state = json!({
                "axelarId": axelar_id,
                "rpcUrl": rpc_url,
                "targetJson": target_json.to_string_lossy(),
                "steps": steps,
            });
            let state_file = state_path(&axelar_id)?;
            fs::write(&state_file, serde_json::to_string_pretty(&state)? + "\n")?;
            println!("saved state to {}", state_file.display());
        }

        Commands::Status { axelar_id } => {
            let state = read_state(&axelar_id)?;
            let steps = state["steps"]
                .as_array()
                .ok_or_else(|| eyre::eyre!("no steps in state"))?;

            println!("deployment progress for '{axelar_id}':");
            for step in steps {
                let name = step["name"].as_str().unwrap_or("?");
                let status = step["status"].as_str().unwrap_or("?");
                let marker = if status == "completed" { "[x]" } else { "[ ]" };
                println!("  {marker} {name}");
            }

            match next_pending_step(&state) {
                Some((_, name)) => println!("\nnext: {name}"),
                None => println!("\nall steps completed!"),
            }
        }

        Commands::Deploy {
            axelar_id,
            private_key,
            artifact_path,
            salt,
        } => {
            let mut state = read_state(&axelar_id)?;
            let rpc_url = state["rpcUrl"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("no rpcUrl in state"))?
                .to_string();
            let target_json = PathBuf::from(
                state["targetJson"]
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("no targetJson in state"))?,
            );

            let (step_idx, step_name) =
                next_pending_step(&state).ok_or_else(|| eyre::eyre!("all steps already completed"))?;

            println!("running step: {step_name}");

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

            // Dispatch based on step
            let (addr, deploy_method, salt_used) = match step_name.as_str() {
                "ConstAddressDeployer" => {
                    // Plain CREATE
                    let tx = TransactionRequest::default().with_deploy_code(bytecode);
                    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
                    println!("tx hash: {}", receipt.transaction_hash);
                    let addr = receipt
                        .contract_address
                        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;
                    (addr, "create", None)
                }

                "Create3Deployer" => {
                    // CREATE2 via ConstAddressDeployer
                    let const_deployer_addr =
                        read_contract_address(&target_json, &axelar_id, "ConstAddressDeployer")?;

                    let salt_string = salt.clone().unwrap_or_else(|| step_name.clone());
                    let salt_bytes = get_salt_from_key(&salt_string);

                    let const_deployer =
                        ConstAddressDeployer::new(const_deployer_addr, &provider);

                    // Predict address first (view call)
                    let addr = const_deployer
                        .deployedAddress(
                            Bytes::from(bytecode_raw.clone()),
                            deployer_addr,
                            salt_bytes,
                        )
                        .call()
                        .await?;
                    println!("predicted address: {addr}");

                    let tx_hash = const_deployer
                        .deploy_call(bytecode, salt_bytes)
                        .send()
                        .await?
                        .watch()
                        .await?;
                    println!("tx hash: {tx_hash}");

                    (addr, "create2", Some(salt_string))
                }

                other => {
                    return Err(eyre::eyre!("unknown step: {other}"));
                }
            };

            println!("deployed at: {addr}");

            // Compute code hashes
            let predeploy_codehash = keccak256(&bytecode_raw);
            let deployed_code = provider.get_code_at(addr).await?;
            let codehash = keccak256(&deployed_code);

            // Build contract data for target JSON
            let mut contract_data = Map::new();
            contract_data.insert("address".into(), json!(format!("{addr}")));
            contract_data.insert("deployer".into(), json!(format!("{deployer_addr}")));
            contract_data.insert("deploymentMethod".into(), json!(deploy_method));
            contract_data.insert("codehash".into(), json!(format!("{codehash}")));
            contract_data.insert("predeployCodehash".into(), json!(format!("{predeploy_codehash}")));
            if let Some(ref s) = salt_used {
                contract_data.insert("salt".into(), json!(s));
            }

            update_target_json(&target_json, &axelar_id, &step_name, Value::Object(contract_data))?;

            // Mark step completed and save state
            mark_step_completed(&mut state, step_idx);
            save_state(&axelar_id, &state)?;
            println!("step '{step_name}' completed");
        }
    }

    Ok(())
}

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

sol! {
    #[sol(rpc)]
    contract ConstAddressDeployer {
        function deploy(bytes bytecode, bytes32 salt) external returns (address deployedAddress_);
        function deployedAddress(bytes bytecode, address sender, bytes32 salt) external view returns (address deployedAddress_);
    }

    #[sol(rpc)]
    contract Ownable {
        function transferOwnership(address newOwner) external;
        function owner() external view returns (address);
    }

    #[sol(rpc)]
    contract Operators {
        function addOperator(address operator) external;
    }
}

fn default_steps() -> Vec<Value> {
    vec![
        json!({ "name": "ConstAddressDeployer", "kind": "deploy-create", "status": "pending" }),
        json!({ "name": "Create3Deployer", "kind": "deploy-create2", "status": "pending" }),
        json!({ "name": "AxelarGateway", "kind": "deploy-gateway", "status": "pending" }),
        json!({ "name": "Operators", "kind": "deploy-create2", "status": "pending" }),
        json!({ "name": "RegisterOperators", "kind": "register-operators", "status": "pending" }),
        json!({ "name": "AxelarGasService", "kind": "deploy-upgradable", "status": "pending" }),
        json!({ "name": "TransferOperatorsOwnership", "kind": "transfer-ownership", "status": "pending",
                "contract": "Operators", "newOwner": "0x49845e5d9985d8dc941462293ed38EEfF18B0eAE" }),
        json!({ "name": "TransferGatewayOwnership", "kind": "transfer-ownership", "status": "pending",
                "contract": "AxelarGateway", "newOwner": "0x49845e5d9985d8dc941462293ed38EEfF18B0eAE" }),
        json!({ "name": "TransferGasServiceOwnership", "kind": "transfer-ownership", "status": "pending",
                "contract": "AxelarGasService", "newOwner": "0x49845e5d9985d8dc941462293ed38EEfF18B0eAE" }),
    ]
}

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
        #[arg(long)]
        chain_name: String,
        #[arg(long)]
        axelar_id: String,
        #[arg(long)]
        chain_id: u64,
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        token_symbol: String,
        #[arg(long)]
        decimals: u8,
        #[arg(long)]
        explorer_name: Option<String>,
        #[arg(long)]
        explorer_url: Option<String>,
        #[arg(long)]
        target_json: PathBuf,
    },

    /// Show deployment progress
    Status {
        #[arg(long)]
        axelar_id: String,
    },

    /// Run the next pending deployment step
    Deploy {
        #[arg(long)]
        axelar_id: String,
        /// Private key (required for on-chain steps)
        #[arg(long)]
        private_key: Option<String>,
        /// Path to Hardhat artifact JSON (required for deploy steps)
        #[arg(long)]
        artifact_path: Option<String>,
        /// Salt for create2 deployments (defaults to step name)
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

fn next_pending_step(state: &Value) -> Option<(usize, Value)> {
    let steps = state["steps"].as_array()?;
    for (i, step) in steps.iter().enumerate() {
        if step["status"].as_str() == Some("pending") {
            return Some((i, step.clone()));
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

/// Merge fields into an existing contract entry (for ownership updates etc.)
fn patch_target_json(
    path: &PathBuf,
    axelar_id: &str,
    contract_name: &str,
    patches: &Map<String, Value>,
) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let mut root: Value = serde_json::from_str(&content)?;

    let contract = root
        .pointer_mut(&format!("/chains/{axelar_id}/contracts/{contract_name}"))
        .ok_or_else(|| eyre::eyre!("{contract_name} not found for {axelar_id}"))?
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("contract entry is not an object"))?;

    for (k, v) in patches {
        contract.insert(k.clone(), v.clone());
    }

    fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    println!("patched {} -> chains.{axelar_id}.contracts.{contract_name}", path.display());
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
    let encoded = key.abi_encode();
    keccak256(&encoded)
}

// --- artifact helpers ---

fn read_artifact_bytecode(artifact_path: &str) -> Result<Vec<u8>> {
    let artifact: Value = serde_json::from_str(&fs::read_to_string(artifact_path)?)?;
    let bytecode_hex = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no bytecode field in artifact"))?;
    Ok(hex::decode(bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex))?)
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
                chain_entry["explorer"] = json!({ "name": name, "url": url });
            }

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

            let dir = data_dir()?;
            fs::create_dir_all(&dir)?;
            let state = json!({
                "axelarId": axelar_id,
                "rpcUrl": rpc_url,
                "targetJson": target_json.to_string_lossy(),
                "steps": default_steps(),
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
                let kind = step["kind"].as_str().unwrap_or("?");
                let status = step["status"].as_str().unwrap_or("?");
                let marker = if status == "completed" { "[x]" } else { "[ ]" };
                println!("  {marker} {name} ({kind})");
            }

            match next_pending_step(&state) {
                Some((_, step)) => println!("\nnext: {}", step["name"].as_str().unwrap_or("?")),
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

            let (step_idx, step) =
                next_pending_step(&state).ok_or_else(|| eyre::eyre!("all steps already completed"))?;

            let step_name = step["name"].as_str().unwrap_or("?").to_string();
            let step_kind = step["kind"].as_str().unwrap_or("?").to_string();

            println!("running step: {step_name} ({step_kind})");

            match step_kind.as_str() {
                "deploy-create" | "deploy-create2" => {
                    let pk = private_key
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--private-key required for deploy steps"))?;
                    let ap = artifact_path
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--artifact-path required for deploy steps"))?;

                    let bytecode_raw = read_artifact_bytecode(ap)?;

                    let signer: PrivateKeySigner = pk.parse()?;
                    let deployer_addr = signer.address();
                    let provider = ProviderBuilder::new()
                        .wallet(signer)
                        .connect_http(rpc_url.parse()?);

                    let (addr, deploy_method, salt_used) = if step_kind == "deploy-create" {
                        let tx = TransactionRequest::default()
                            .with_deploy_code(Bytes::from(bytecode_raw.clone()));
                        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
                        println!("tx hash: {}", receipt.transaction_hash);
                        let addr = receipt
                            .contract_address
                            .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;
                        (addr, "create", None)
                    } else {
                        // deploy-create2
                        let const_deployer_addr =
                            read_contract_address(&target_json, &axelar_id, "ConstAddressDeployer")?;
                        let salt_string = salt.clone().unwrap_or_else(|| step_name.clone());
                        let salt_bytes = get_salt_from_key(&salt_string);

                        // For contracts with constructor args (e.g. Operators(address owner)),
                        // append ABI-encoded args to bytecode
                        let deploy_bytecode = match step_name.as_str() {
                            "Operators" => {
                                let mut b = bytecode_raw.clone();
                                b.extend_from_slice(&deployer_addr.abi_encode());
                                b
                            }
                            _ => bytecode_raw.clone(),
                        };

                        let const_deployer =
                            ConstAddressDeployer::new(const_deployer_addr, &provider);

                        let deploy_bytes = Bytes::from(deploy_bytecode.clone());

                        // Predict address
                        let addr = const_deployer
                            .deployedAddress(deploy_bytes.clone(), deployer_addr, salt_bytes)
                            .call()
                            .await?;
                        println!("predicted address: {addr}");

                        let tx_hash = const_deployer
                            .deploy_call(deploy_bytes, salt_bytes)
                            .send()
                            .await?
                            .watch()
                            .await?;
                        println!("tx hash: {tx_hash}");

                        (addr, "create2", Some(salt_string))
                    };

                    println!("deployed at: {addr}");

                    let predeploy_codehash = keccak256(&bytecode_raw);
                    let deployed_code = provider.get_code_at(addr).await?;
                    let codehash = keccak256(&deployed_code);

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
                }

                "register-operators" => {
                    let pk = private_key
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--private-key required"))?;
                    let signer: PrivateKeySigner = pk.parse()?;
                    let provider = ProviderBuilder::new()
                        .wallet(signer)
                        .connect_http(rpc_url.parse()?);

                    let operators_addr =
                        read_contract_address(&target_json, &axelar_id, "Operators")?;
                    let operators = Operators::new(operators_addr, &provider);

                    // Testnet operator addresses
                    let operator_addrs: Vec<Address> = vec![
                        "0x8f23e84c49624a22e8c252684129910509ade4e2".parse()?,
                        "0x3b401fa00191acb03c24ebb7754fe35d34dd1abd".parse()?,
                    ];

                    for op in &operator_addrs {
                        println!("adding operator: {op}");
                        let tx_hash = operators
                            .addOperator(*op)
                            .send()
                            .await?
                            .watch()
                            .await?;
                        println!("  tx hash: {tx_hash}");
                    }
                }

                "transfer-ownership" => {
                    let pk = private_key
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--private-key required"))?;
                    let signer: PrivateKeySigner = pk.parse()?;
                    let provider = ProviderBuilder::new()
                        .wallet(signer)
                        .connect_http(rpc_url.parse()?);

                    let contract_name = step["contract"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no 'contract' field in step"))?;
                    let new_owner: Address = step["newOwner"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no 'newOwner' field in step"))?
                        .parse()?;

                    let contract_addr =
                        read_contract_address(&target_json, &axelar_id, contract_name)?;
                    let ownable = Ownable::new(contract_addr, &provider);

                    println!("transferring {contract_name} ownership to {new_owner}");
                    let tx_hash = ownable
                        .transferOwnership(new_owner)
                        .send()
                        .await?
                        .watch()
                        .await?;
                    println!("tx hash: {tx_hash}");

                    // Verify
                    let current_owner = ownable.owner().call().await?;
                    println!("verified owner: {current_owner}");

                    // Patch target JSON with new owner
                    let mut patches = Map::new();
                    patches.insert("owner".into(), json!(format!("{new_owner}")));
                    patch_target_json(&target_json, &axelar_id, contract_name, &patches)?;
                }

                "deploy-gateway" | "deploy-upgradable" => {
                    return Err(eyre::eyre!(
                        "step kind '{step_kind}' not yet implemented — coming in next phase"
                    ));
                }

                other => {
                    return Err(eyre::eyre!("unknown step kind: {other}"));
                }
            }

            mark_step_completed(&mut state, step_idx);
            save_state(&axelar_id, &state)?;
            println!("step '{step_name}' completed");
        }
    }

    Ok(())
}

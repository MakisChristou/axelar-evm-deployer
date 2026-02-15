use std::fs;
use std::path::{Path, PathBuf};

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Address, Bytes, FixedBytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolValue},
};
use base64::Engine;
use clap::{Parser, Subcommand};
use bip32::Mnemonic;
use cosmrs::bip32::XPrv;
use cosmrs::crypto::secp256k1::SigningKey;
use cosmrs::tx::{self, Fee, SignDoc, SignerInfo};
use cosmos_sdk_proto::cosmos::base::v1beta1::Coin as ProtoCoin;
use cosmos_sdk_proto::cosmos::gov::v1::MsgSubmitProposal;
use cosmos_sdk_proto::cosmwasm::wasm::v1::MsgExecuteContract as ProtoMsgExecuteContract;
use eyre::Result;
use prost::Message;
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
        function isOperator(address account) external view returns (bool);
    }

    /// Legacy init-based proxy (AxelarGasServiceProxy, AxelarDepositServiceProxy)
    #[sol(rpc)]
    contract LegacyProxy {
        function init(address implementationAddress, address newOwner, bytes memory params) external;
    }

    // WeightedSigners type for gateway setup params encoding
    struct WeightedSigner {
        address signer;
        uint128 weight;
    }

    struct WeightedSigners {
        WeightedSigner[] signers;
        uint128 threshold;
        bytes32 nonce;
    }

    // Gateway setup params: abi.encode(address operator, WeightedSigners[] signers)
    function setupParams(address operator, WeightedSigners[] signers);
}

fn default_steps() -> Vec<Value> {
    vec![
        json!({ "name": "ConstAddressDeployer", "kind": "deploy-create", "status": "pending" }),
        json!({ "name": "Create3Deployer", "kind": "deploy-create2", "status": "pending" }),
        json!({ "name": "PredictGatewayAddress", "kind": "predict-address", "status": "pending" }),
        json!({ "name": "AddCosmWasmConfig", "kind": "config-edit", "status": "pending" }),
        json!({ "name": "InstantiateChainContracts", "kind": "cosmos-tx", "status": "pending",
                "proposalKey": "instantiate" }),
        json!({ "name": "WaitInstantiateProposal", "kind": "cosmos-poll", "status": "pending",
                "proposalKey": "instantiate" }),
        json!({ "name": "SaveDeployedContracts", "kind": "cosmos-query", "status": "pending" }),
        json!({ "name": "RegisterDeployment", "kind": "cosmos-tx", "status": "pending",
                "proposalKey": "register" }),
        json!({ "name": "WaitRegisterProposal", "kind": "cosmos-poll", "status": "pending",
                "proposalKey": "register" }),
        json!({ "name": "CreateRewardPools", "kind": "cosmos-tx", "status": "pending",
                "proposalKey": "rewardPools" }),
        json!({ "name": "WaitRewardPoolsProposal", "kind": "cosmos-poll", "status": "pending",
                "proposalKey": "rewardPools" }),
        json!({ "name": "AddRewards", "kind": "cosmos-tx", "status": "pending" }),
        json!({ "name": "WaitForVerifierSet", "kind": "wait-verifier-set", "status": "pending" }),
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

    /// Initialize Cosmos deployment config (mnemonic, env, gateway deployer)
    CosmosInit {
        #[arg(long)]
        axelar_id: String,
        /// BIP39 mnemonic for the Axelar deployer wallet
        #[arg(long)]
        mnemonic: String,
        /// Deployment environment (devnet-amplifier, testnet, mainnet)
        #[arg(long)]
        env: String,
        /// Salt for CosmWasm instantiation (e.g. "v1.0.11")
        #[arg(long)]
        salt: String,
        /// BIP39 mnemonic for the prover admin wallet (for update_verifier_set)
        #[arg(long)]
        admin_mnemonic: Option<String>,
        /// EVM private key for ConstAddressDeployer and Create3Deployer
        #[arg(long)]
        deployer_private_key: Option<String>,
        /// EVM private key for Gateway, Operators, RegisterOperators, and ownership transfers
        #[arg(long)]
        gateway_deployer_private_key: Option<String>,
        /// EVM private key for AxelarGasService
        #[arg(long)]
        gas_service_deployer_private_key: Option<String>,
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
        /// Path to proxy artifact JSON (required for gateway deploy)
        #[arg(long)]
        proxy_artifact_path: Option<String>,
    },

    /// Reset all steps to pending and remove all changes from target JSON
    Reset {
        #[arg(long)]
        axelar_id: String,
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

// --- gateway helpers ---

/// Compute domain separator: keccak256(chainAxelarId + routerAddress + axelarChainId)
/// Matches JS: calculateDomainSeparator = (chain, router, network) => keccak256(Buffer.from(`${chain}${router}${network}`))
fn compute_domain_separator(target_json: &Path, axelar_id: &str) -> Result<FixedBytes<32>> {
    let content = fs::read_to_string(target_json)?;
    let root: Value = serde_json::from_str(&content)?;

    let chain_axelar_id = root
        .pointer(&format!("/chains/{axelar_id}/axelarId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("no axelarId for chain {axelar_id}"))?;

    let router_address = root
        .pointer("/axelar/contracts/Router/address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("no axelar.contracts.Router.address in target json"))?;

    let axelar_chain_id = root
        .pointer("/axelar/chainId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("no axelar.chainId in target json"))?;

    let input = format!("{chain_axelar_id}{router_address}{axelar_chain_id}");
    let hash = keccak256(input.as_bytes());
    println!("domain separator input: {input}");
    println!("domain separator: {hash}");
    Ok(hash)
}

/// Fetch the current verifier set from Axelar chain via LCD REST endpoint.
/// Returns (signers sorted by address, threshold, nonce, verifierSetId)
async fn fetch_verifier_set(
    target_json: &Path,
    chain_axelar_id: &str,
) -> Result<(Vec<(Address, u128)>, u128, FixedBytes<32>, String)> {
    let content = fs::read_to_string(target_json)?;
    let root: Value = serde_json::from_str(&content)?;

    let lcd = root
        .pointer("/axelar/lcd")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("no axelar.lcd in target json"))?;

    let prover_addr = root
        .pointer(&format!(
            "/axelar/contracts/MultisigProver/{chain_axelar_id}/address"
        ))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            eyre::eyre!("no MultisigProver.{chain_axelar_id}.address in target json")
        })?;

    // Base64-encode the query message
    let query_msg = "\"current_verifier_set\"";
    let query_b64 = base64::engine::general_purpose::STANDARD.encode(query_msg.as_bytes());

    let url = format!(
        "{lcd}/cosmwasm/wasm/v1/contract/{prover_addr}/smart/{query_b64}"
    );
    println!("fetching verifier set from: {url}");

    let resp: Value = reqwest::get(&url).await?.json().await?;

    let data = &resp["data"];
    let verifier_set_id = data["id"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no id in verifier set response"))?
        .to_string();

    let verifier_set = &data["verifier_set"];
    let signers_obj = verifier_set["signers"]
        .as_object()
        .ok_or_else(|| eyre::eyre!("no signers object in verifier set"))?;

    let threshold: u128 = verifier_set["threshold"]
        .as_str()
        .or_else(|| verifier_set["threshold"].as_u64().map(|_| ""))
        .ok_or_else(|| eyre::eyre!("no threshold in verifier set"))
        .and_then(|s| {
            if s.is_empty() {
                Ok(verifier_set["threshold"].as_u64().unwrap() as u128)
            } else {
                s.parse::<u128>()
                    .map_err(|e| eyre::eyre!("invalid threshold: {e}"))
            }
        })?;

    let created_at = verifier_set["created_at"]
        .as_u64()
        .ok_or_else(|| eyre::eyre!("no created_at in verifier set"))?;

    // Convert created_at to bytes32 nonce (zero-padded)
    let nonce = FixedBytes::<32>::from(U256::from(created_at).to_be_bytes::<32>());

    // Convert ECDSA pubkeys to EVM addresses
    let mut weighted_signers: Vec<(Address, u128)> = Vec::new();

    for (_key, signer) in signers_obj {
        let pubkey_hex = signer
            .pointer("/pub_key/ecdsa")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("no pub_key.ecdsa for signer"))?;

        let weight: u128 = signer["weight"]
            .as_str()
            .map(|s| s.parse::<u128>())
            .unwrap_or_else(|| Ok(signer["weight"].as_u64().unwrap_or(1) as u128))
            .map_err(|e| eyre::eyre!("invalid weight: {e}"))?;

        // Decode pubkey and compute EVM address: keccak256(uncompressed_pubkey_64_bytes)[12..]
        let pubkey_bytes = hex::decode(pubkey_hex.strip_prefix("0x").unwrap_or(pubkey_hex))?;

        let addr = pubkey_to_address(&pubkey_bytes)?;
        weighted_signers.push((addr, weight));
    }

    // Sort by address ascending (matches JS .sort((a,b) => a.address.localeCompare(b.address)))
    weighted_signers.sort_by_key(|(addr, _)| *addr);

    println!(
        "verifier set: {} signers, threshold={}, created_at={}, id={}",
        weighted_signers.len(),
        threshold,
        created_at,
        verifier_set_id
    );
    for (addr, weight) in &weighted_signers {
        println!("  {addr} weight={weight}");
    }

    Ok((weighted_signers, threshold, nonce, verifier_set_id))
}

/// Convert an ECDSA public key (compressed or uncompressed) to an EVM address.
fn pubkey_to_address(pubkey_bytes: &[u8]) -> Result<Address> {
    use alloy::signers::k256::PublicKey;
    use alloy::signers::k256::elliptic_curve::sec1::ToEncodedPoint;

    let pubkey = PublicKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| eyre::eyre!("invalid pubkey: {e}"))?;

    // Get uncompressed SEC1 encoding (65 bytes: 0x04 || x || y)
    let uncompressed = pubkey.to_encoded_point(false);

    // EVM address = keccak256(x || y)[12..32]  (skip the 0x04 prefix)
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    Ok(Address::from_slice(&hash[12..]))
}

/// Encode gateway setup params: abi.encode(address operator, WeightedSigners[] signers)
fn encode_gateway_setup_params(
    operator: Address,
    signers: &[(Address, u128)],
    threshold: u128,
    nonce: FixedBytes<32>,
) -> Bytes {
    let weighted_signers = vec![WeightedSigners {
        signers: signers
            .iter()
            .map(|(addr, weight)| WeightedSigner {
                signer: *addr,
                weight: *weight,
            })
            .collect(),
        threshold,
        nonce,
    }];

    let encoded = setupParamsCall {
        operator,
        signers: weighted_signers,
    }
    .abi_encode();

    // setupParamsCall encodes with the function selector (4 bytes) — we need just the params
    // Skip the first 4 bytes (function selector)
    Bytes::from(encoded[4..].to_vec())
}

/// Decode EVM revert data into a human-readable error name.
fn decode_revert_data(hex_str: &str) -> String {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex.len() < 8 {
        return format!("unknown revert data: 0x{hex}");
    }
    let selector = &hex[..8];
    match selector {
        // AxelarAmplifierGatewayProxy errors
        "68155f9a" => "InvalidImplementation() — implementation has no code".into(),
        "97905dfb" => "SetupFailed() — gateway setup() reverted".into(),
        "49e27cff" => "InvalidOwner() — owner is zero address".into(),
        "0dc149f0" => "AlreadyInitialized() — proxy already initialized".into(),
        "30cd7471" => "NotOwner() — caller is not owner".into(),
        // AxelarAmplifierGateway errors (from setup delegatecall)
        "5e231fff" => "InvalidSigners() — signers array invalid".into(),
        "aabd5a09" => "InvalidThreshold() — threshold out of range".into(),
        "84677ce8" => "InvalidWeights() — signer weights invalid".into(),
        "bf10dd3a" => "NotProxy() — must be called via proxy delegatecall".into(),
        "d924e5f4" => "InvalidOwnerAddress()".into(),
        // Error(string)
        "08c379a0" => {
            if let Ok(bytes) = hex::decode(hex) {
                if bytes.len() > 4 + 32 + 32 {
                    let offset = 4 + 32;
                    let len = u32::from_be_bytes(
                        bytes[offset + 28..offset + 32].try_into().unwrap_or([0; 4]),
                    ) as usize;
                    let str_start = offset + 32;
                    let str_end = (str_start + len).min(bytes.len());
                    let msg = String::from_utf8_lossy(&bytes[str_start..str_end]);
                    return format!("revert: \"{msg}\"");
                }
            }
            format!("Error(string) — data: 0x{hex}")
        }
        _ => format!("unknown error selector 0x{selector} (data: 0x{hex})"),
    }
}

/// Try to extract revert data hex from an alloy error's Debug representation.
fn decode_evm_error(err: &dyn std::fmt::Debug) -> String {
    let debug = format!("{err:?}");
    // Look for "data: Some(RawValue(\"0x..."))" or similar patterns
    // Also check for bare "0x" hex data in the error
    for pattern in ["\"0x", "data: \"0x"] {
        if let Some(pos) = debug.find(pattern) {
            let start = debug[pos..].find("0x").map(|i| pos + i).unwrap_or(pos);
            let hex_end = debug[start + 2..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .map(|i| start + 2 + i)
                .unwrap_or(debug.len());
            let hex_data = &debug[start..hex_end];
            if hex_data.len() >= 10 {
                return decode_revert_data(hex_data);
            }
        }
    }
    format!("{debug}")
}

// --- cosmos wallet helpers ---

fn derive_axelar_wallet(mnemonic_str: &str) -> Result<(SigningKey, String)> {
    let mnemonic = Mnemonic::new(mnemonic_str, bip32::Language::English)
        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");
    let path: cosmrs::bip32::DerivationPath = "m/44'/118'/0'/0/0"
        .parse()
        .map_err(|e| eyre::eyre!("invalid derivation path: {e}"))?;
    let child_xprv = XPrv::derive_from_path(seed, &path)
        .map_err(|e| eyre::eyre!("key derivation failed: {e}"))?;
    let signing_key = SigningKey::from_slice(&child_xprv.private_key().to_bytes())
        .map_err(|e| eyre::eyre!("invalid signing key: {e}"))?;
    let account_id = signing_key
        .public_key()
        .account_id("axelar")
        .map_err(|e| eyre::eyre!("account id derivation failed: {e}"))?;
    Ok((signing_key, account_id.to_string()))
}

// --- LCD REST query helpers ---

async fn lcd_query_account(lcd: &str, address: &str) -> Result<(u64, u64)> {
    let url = format!("{lcd}/cosmos/auth/v1beta1/accounts/{address}");
    let resp: Value = reqwest::get(&url).await?.json().await?;
    // The account may be nested under "account" with a "@type" field
    let account = resp
        .get("account")
        .ok_or_else(|| eyre::eyre!("no account in response: {resp}"))?;
    let account_number: u64 = account["account_number"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let sequence: u64 = account["sequence"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    Ok((account_number, sequence))
}

async fn lcd_simulate_tx(lcd: &str, tx_bytes: &[u8]) -> Result<u64> {
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(tx_bytes);
    let body = json!({
        "tx_bytes": tx_b64,
        "mode": "BROADCAST_MODE_UNSPECIFIED"
    });
    let client = reqwest::Client::new();
    let resp: Value = client
        .post(format!("{lcd}/cosmos/tx/v1beta1/simulate"))
        .json(&body)
        .send()
        .await?
        .json()
        .await?;
    // Check for simulation error
    if let Some(err) = resp.get("message").and_then(|v| v.as_str()) {
        if !err.is_empty() {
            return Err(eyre::eyre!("simulation failed: {err}"));
        }
    }

    let gas_used: u64 = resp
        .pointer("/gas_info/gas_used")
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    if gas_used == 0 {
        return Err(eyre::eyre!("simulation returned 0 gas — response: {}", serde_json::to_string_pretty(&resp)?));
    }

    Ok(gas_used)
}

async fn lcd_broadcast_tx(lcd: &str, tx_bytes: &[u8]) -> Result<Value> {
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(tx_bytes);
    let body = json!({
        "tx_bytes": tx_b64,
        "mode": "BROADCAST_MODE_SYNC"
    });
    let client = reqwest::Client::new();
    let resp: Value = client
        .post(format!("{lcd}/cosmos/tx/v1beta1/txs"))
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    let code = resp
        .pointer("/tx_response/code")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if code != 0 {
        let raw_log = resp
            .pointer("/tx_response/raw_log")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(eyre::eyre!("broadcast failed (code {code}): {raw_log}"));
    }
    Ok(resp)
}

/// Wait for a tx to be included in a block and return the full tx response with events.
async fn lcd_wait_for_tx(lcd: &str, tx_hash: &str) -> Result<Value> {
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let url = format!("{lcd}/cosmos/tx/v1beta1/txs/{tx_hash}");
        let resp: Value = match reqwest::get(&url).await {
            Ok(r) => r.json().await.unwrap_or(json!({})),
            Err(_) => continue,
        };
        if resp.get("tx_response").is_some() {
            let code = resp
                .pointer("/tx_response/code")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);
            if code != 0 {
                let raw_log = resp
                    .pointer("/tx_response/raw_log")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(eyre::eyre!("tx failed (code {code}): {raw_log}"));
            }
            return Ok(resp);
        }
    }
    Err(eyre::eyre!("timeout waiting for tx {tx_hash}"))
}

async fn lcd_query_proposal(lcd: &str, proposal_id: u64) -> Result<Value> {
    let url = format!("{lcd}/cosmos/gov/v1/proposals/{proposal_id}");
    let resp: Value = reqwest::get(&url).await?.json().await?;
    let proposal = resp
        .get("proposal")
        .cloned()
        .ok_or_else(|| eyre::eyre!("no 'proposal' field in response"))?;
    Ok(proposal)
}

async fn lcd_cosmwasm_smart_query(lcd: &str, contract: &str, query_msg: &Value) -> Result<Value> {
    let query_json = serde_json::to_string(query_msg)?;
    let query_b64 =
        base64::engine::general_purpose::STANDARD.encode(query_json.as_bytes());
    let url = format!("{lcd}/cosmwasm/wasm/v1/contract/{contract}/smart/{query_b64}");
    let resp: Value = reqwest::get(&url).await?.json().await?;
    Ok(resp["data"].clone())
}

/// Fetch code IDs by matching storeCodeProposalCodeHash against on-chain checksums.
async fn lcd_fetch_code_id(lcd: &str, expected_checksum: &str) -> Result<u64> {
    let expected = expected_checksum.to_uppercase();
    let mut next_key: Option<String> = None;
    // Query pages in reverse to find recent codes first
    loop {
        let mut url = format!(
            "{lcd}/cosmwasm/wasm/v1/code?pagination.limit=100&pagination.reverse=true"
        );
        if let Some(ref key) = next_key {
            url.push_str(&format!("&pagination.key={key}"));
        }
        let resp: Value = reqwest::get(&url).await?.json().await?;
        let codes = resp["code_infos"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("no code_infos in response"))?;
        for code in codes {
            let checksum = code["data_hash"]
                .as_str()
                .unwrap_or("")
                .to_uppercase();
            if checksum == expected {
                let code_id: u64 = code["code_id"]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                return Ok(code_id);
            }
        }
        // Check pagination
        let nk = resp
            .pointer("/pagination/next_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if nk.is_empty() {
            break;
        }
        next_key = Some(nk.to_string());
    }
    Err(eyre::eyre!(
        "code not found for checksum {expected_checksum}"
    ))
}

// --- cosmos tx builder ---

fn build_and_sign_cosmos_tx(
    signing_key: &SigningKey,
    chain_id: &str,
    account_number: u64,
    sequence: u64,
    gas_limit: u64,
    fee_amount: u128,
    fee_denom: &str,
    messages: Vec<cosmrs::Any>,
) -> Result<Vec<u8>> {
    let tx_body = tx::Body::new(messages, "", 0u32);
    let signer_info = SignerInfo::single_direct(Some(signing_key.public_key()), sequence);
    let fee = Fee::from_amount_and_gas(
        cosmrs::Coin {
            denom: fee_denom
                .parse()
                .map_err(|e| eyre::eyre!("invalid denom: {e}"))?,
            amount: fee_amount,
        },
        gas_limit,
    );
    let auth_info = signer_info.auth_info(fee);
    let cosmos_chain_id: cosmrs::tendermint::chain::Id = chain_id
        .parse()
        .map_err(|e| eyre::eyre!("invalid chain id: {e}"))?;
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &cosmos_chain_id, account_number)
        .map_err(|e| eyre::eyre!("sign doc error: {e}"))?;
    let tx_signed = sign_doc
        .sign(signing_key)
        .map_err(|e| eyre::eyre!("signing error: {e}"))?;
    let tx_bytes = tx_signed
        .to_bytes()
        .map_err(|e| eyre::eyre!("serialize error: {e}"))?;
    Ok(tx_bytes)
}

/// Build a MsgExecuteContract as protobuf Any
fn build_execute_msg_any(
    sender: &str,
    contract: &str,
    msg_json: &Value,
) -> Result<cosmrs::Any> {
    build_execute_msg_any_with_funds(sender, contract, msg_json, vec![])
}

fn build_execute_msg_any_with_funds(
    sender: &str,
    contract: &str,
    msg_json: &Value,
    funds: Vec<ProtoCoin>,
) -> Result<cosmrs::Any> {
    let msg_bytes = serde_json::to_vec(msg_json)?;
    let proto_msg = ProtoMsgExecuteContract {
        sender: sender.to_string(),
        contract: contract.to_string(),
        msg: msg_bytes,
        funds,
    };
    let mut buf = Vec::new();
    proto_msg.encode(&mut buf)?;
    Ok(cosmrs::Any {
        type_url: "/cosmwasm.wasm.v1.MsgExecuteContract".to_string(),
        value: buf,
    })
}

/// Wrap execute messages in a MsgSubmitProposal as protobuf Any
fn build_submit_proposal_any(
    proposer: &str,
    inner_messages: Vec<cosmrs::Any>,
    title: &str,
    summary: &str,
    deposit_amount: &str,
    deposit_denom: &str,
    expedited: bool,
) -> Result<cosmrs::Any> {
    // Convert inner messages to tendermint_proto Any
    let prost_messages: Vec<tendermint_proto::google::protobuf::Any> = inner_messages
        .into_iter()
        .map(|a| tendermint_proto::google::protobuf::Any {
            type_url: a.type_url,
            value: a.value,
        })
        .collect();

    let proposal = MsgSubmitProposal {
        messages: prost_messages,
        initial_deposit: vec![ProtoCoin {
            denom: deposit_denom.to_string(),
            amount: deposit_amount.to_string(),
        }],
        proposer: proposer.to_string(),
        metadata: String::new(),
        title: title.to_string(),
        summary: summary.to_string(),
        expedited,
    };
    let mut buf = Vec::new();
    proposal.encode(&mut buf)?;
    Ok(cosmrs::Any {
        type_url: "/cosmos.gov.v1.MsgSubmitProposal".to_string(),
        value: buf,
    })
}

/// Sign, simulate, re-sign with correct gas, broadcast, and return proposal ID.
async fn sign_and_broadcast_cosmos_tx(
    signing_key: &SigningKey,
    address: &str,
    lcd: &str,
    chain_id: &str,
    fee_denom: &str,
    gas_price: f64,
    messages: Vec<cosmrs::Any>,
) -> Result<Value> {
    let (account_number, sequence) = lcd_query_account(lcd, address).await?;
    println!("  account: {address}, number={account_number}, sequence={sequence}");

    // First: build tx with high gas for simulation
    let sim_tx = build_and_sign_cosmos_tx(
        signing_key,
        chain_id,
        account_number,
        sequence,
        10_000_000,
        0,
        fee_denom,
        messages.clone(),
    )?;

    let gas_used = lcd_simulate_tx(lcd, &sim_tx).await?;
    let gas_limit = (gas_used as f64 * 1.4) as u64;
    let fee_amount = ((gas_limit as f64) * gas_price).ceil() as u128;
    println!("  gas: used={gas_used}, limit={gas_limit}, fee={fee_amount}{fee_denom}");

    // Re-sign with correct gas
    let tx_bytes = build_and_sign_cosmos_tx(
        signing_key,
        chain_id,
        account_number,
        sequence,
        gas_limit,
        fee_amount,
        fee_denom,
        messages,
    )?;

    let broadcast_resp = lcd_broadcast_tx(lcd, &tx_bytes).await?;
    let tx_hash = broadcast_resp
        .pointer("/tx_response/txhash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    println!("  tx hash: {tx_hash}");

    // Wait for tx to be included
    println!("  waiting for tx confirmation...");
    let tx_resp = lcd_wait_for_tx(lcd, &tx_hash).await?;
    Ok(tx_resp)
}

/// Extract proposal_id from tx response events
fn extract_proposal_id(tx_resp: &Value) -> Result<u64> {
    let events = tx_resp
        .pointer("/tx_response/events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre::eyre!("no events in tx response"))?;
    for event in events {
        let event_type = event["type"].as_str().unwrap_or("");
        if event_type == "submit_proposal" || event_type == "proposal_submitted" {
            if let Some(attrs) = event["attributes"].as_array() {
                for attr in attrs {
                    let key = attr["key"].as_str().unwrap_or("");
                    if key == "proposal_id" {
                        let val = attr["value"].as_str().unwrap_or("0");
                        return Ok(val.parse()?);
                    }
                }
            }
        }
    }
    Err(eyre::eyre!("proposal_id not found in tx events"))
}

/// Read Axelar LCD url and chain ID from target json
fn read_axelar_config(target_json: &Path) -> Result<(String, String, String, f64)> {
    let content = fs::read_to_string(target_json)?;
    let root: Value = serde_json::from_str(&content)?;
    let lcd = root
        .pointer("/axelar/lcd")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("no axelar.lcd in target json"))?
        .to_string();
    let chain_id = root
        .pointer("/axelar/chainId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("no axelar.chainId in target json"))?
        .to_string();
    // Parse gas price like "0.007uaxl"
    let gas_price_str = root
        .pointer("/axelar/gasPrice")
        .and_then(|v| v.as_str())
        .unwrap_or("0.007uaxl");
    let (price_num, denom) = parse_gas_price(gas_price_str);
    Ok((lcd, chain_id, denom, price_num))
}

fn parse_gas_price(s: &str) -> (f64, String) {
    let mut split_at = 0;
    for (i, c) in s.char_indices() {
        if c.is_alphabetic() {
            split_at = i;
            break;
        }
    }
    if split_at == 0 {
        return (0.007, "uaxl".to_string());
    }
    let price: f64 = s[..split_at].parse().unwrap_or(0.007);
    let denom = s[split_at..].to_string();
    (price, denom)
}

/// Read a string field from axelar contracts config
fn read_axelar_contract_field(target_json: &Path, pointer: &str) -> Result<String> {
    let content = fs::read_to_string(target_json)?;
    let root: Value = serde_json::from_str(&content)?;
    root.pointer(pointer)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| eyre::eyre!("field not found: {pointer}"))
}

// --- predict address helper ---

/// Compute CREATE address: keccak256(rlp([sender, nonce]))[12..]
fn compute_create_address(sender: Address, nonce: u64) -> Address {
    // RLP encode [sender, nonce]
    let mut stream = Vec::new();

    // RLP list: first encode both items, then wrap with list header
    let sender_bytes = sender.as_slice();
    let mut items = Vec::new();

    // RLP encode 20-byte address
    items.push(0x94u8); // 0x80 + 20
    items.extend_from_slice(sender_bytes);

    // RLP encode nonce
    if nonce == 0 {
        items.push(0x80);
    } else if nonce < 0x80 {
        items.push(nonce as u8);
    } else {
        // Encode as bytes
        let nonce_bytes = {
            let mut b = nonce.to_be_bytes().to_vec();
            while b.first() == Some(&0) {
                b.remove(0);
            }
            b
        };
        items.push(0x80 + nonce_bytes.len() as u8);
        items.extend_from_slice(&nonce_bytes);
    }

    // List header
    let len = items.len();
    if len < 56 {
        stream.push(0xc0 + len as u8);
    } else {
        let len_bytes = {
            let mut b = len.to_be_bytes().to_vec();
            while b.first() == Some(&0) {
                b.remove(0);
            }
            b
        };
        stream.push(0xf7 + len_bytes.len() as u8);
        stream.extend_from_slice(&len_bytes);
    }
    stream.extend_from_slice(&items);

    let hash = keccak256(&stream);
    Address::from_slice(&hash[12..])
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

            let init_done = state.get("rpcUrl").is_some();
            let cosmos_done = state.get("mnemonic").is_some() && state.get("env").is_some();
            let init_marker = if init_done { "[x]" } else { "[ ]" };
            let cosmos_marker = if cosmos_done { "[x]" } else { "[ ]" };

            println!("deployment progress for '{axelar_id}':");
            println!("  {init_marker} Init");
            println!("  {cosmos_marker} CosmosInit");
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

        Commands::CosmosInit {
            axelar_id,
            mnemonic,
            env,
            salt,
            admin_mnemonic,
            deployer_private_key,
            gateway_deployer_private_key,
            gas_service_deployer_private_key,
        } => {
            let mut state = read_state(&axelar_id)?;

            // Derive and display the Axelar address
            let (_, axelar_address) = derive_axelar_wallet(&mnemonic)?;
            println!("axelar deployer address: {axelar_address}");

            // Validate and display admin address if provided
            if let Some(ref admin_mn) = admin_mnemonic {
                let (_, admin_address) = derive_axelar_wallet(admin_mn)?;
                println!("prover admin address: {admin_address}");
                state["adminMnemonic"] = json!(admin_mn);
            }

            // Save EVM private keys if provided
            if let Some(ref pk) = deployer_private_key {
                let signer: PrivateKeySigner = pk.parse()
                    .map_err(|e| eyre::eyre!("invalid deployer private key: {e}"))?;
                println!("deployer address: {}", signer.address());
                state["deployerPrivateKey"] = json!(pk);
            }
            if let Some(ref pk) = gateway_deployer_private_key {
                let signer: PrivateKeySigner = pk.parse()
                    .map_err(|e| eyre::eyre!("invalid gateway deployer private key: {e}"))?;
                let gw_addr = signer.address();
                println!("gateway deployer address: {gw_addr}");
                state["gatewayDeployerPrivateKey"] = json!(pk);
                state["gatewayDeployer"] = json!(format!("{gw_addr}"));
            }
            if let Some(ref pk) = gas_service_deployer_private_key {
                let signer: PrivateKeySigner = pk.parse()
                    .map_err(|e| eyre::eyre!("invalid gas service deployer private key: {e}"))?;
                println!("gas service deployer address: {}", signer.address());
                state["gasServiceDeployerPrivateKey"] = json!(pk);
            }

            state["mnemonic"] = json!(mnemonic);
            state["env"] = json!(env);
            state["cosmSalt"] = json!(salt);

            save_state(&axelar_id, &state)?;
            println!("cosmos config saved for '{axelar_id}' (env={env})");

            // Query and display the deployer balance
            let target_json: PathBuf = state["targetJson"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("no targetJson in state"))?
                .into();
            if target_json.exists() {
                let (lcd, _, fee_denom, _) = read_axelar_config(&target_json)?;
                let url = format!("{lcd}/cosmos/bank/v1beta1/balances/{axelar_address}");
                match reqwest::get(&url).await {
                    Ok(resp) => {
                        let data: Value = resp.json().await?;
                        if let Some(balances) = data["balances"].as_array() {
                            let bal = balances
                                .iter()
                                .find(|b| b["denom"].as_str() == Some(&fee_denom))
                                .and_then(|b| b["amount"].as_str())
                                .unwrap_or("0");
                            let display_denom = fee_denom.strip_prefix('u').unwrap_or(&fee_denom);
                            let bal_major: f64 = bal.parse::<f64>().unwrap_or(0.0) / 1_000_000.0;
                            println!("balance: {bal_major:.6} {display_denom}");
                        }
                    }
                    Err(e) => println!("could not query balance: {e}"),
                }
            }
        }

        Commands::Deploy {
            axelar_id,
            private_key,
            artifact_path,
            salt,
            proxy_artifact_path,
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

            let (step_idx, step) = match next_pending_step(&state) {
                Some(s) => s,
                None => {
                    println!("All steps completed! {axelar_id} EVM deployment is fully done.\n");
                    println!("To test GMP (EVM -> {axelar_id}):\n");
                    println!("  1. Send a GMP call from another chain:");
                    println!("     ts-node evm/gateway.js -n [source-chain] --action callContract \\");
                    println!("       --destinationChain {axelar_id} \\");
                    println!("       --destination 0xba76c6980428A0b10CFC5d8ccb61949677A61233 --payload 0x1234\n");
                    println!("  2. Route via Amplifier:");
                    println!("     https://docs.axelar.dev/dev/amplifier/chain-integration/relay-messages\n");
                    println!("  3. Submit proof:");
                    println!("     ts-node evm/gateway.js -n {axelar_id} --action submitProof \\");
                    println!("       --multisigSessionId [session-id]\n");
                    println!("  4. Verify approval:");
                    println!("     ts-node evm/gateway.js -n {axelar_id} --action isContractCallApproved \\");
                    println!("       --commandID [id] --sourceChain [chain] --sourceAddress [addr] \\");
                    println!("       --destination [addr] --payloadHash [hash]");
                    return Ok(());
                }
            };

            let step_name = step["name"].as_str().unwrap_or("?").to_string();
            let step_kind = step["kind"].as_str().unwrap_or("?").to_string();

            println!("running step: {step_name} ({step_kind})");

            // Resolve EVM private key: --private-key flag > state key based on step
            let resolve_evm_key = |step_name: &str| -> Result<String> {
                if let Some(ref pk) = private_key {
                    return Ok(pk.clone());
                }
                let state_key = match step_name {
                    "ConstAddressDeployer" | "Create3Deployer" => "deployerPrivateKey",
                    "AxelarGateway" => "gatewayDeployerPrivateKey",
                    "Operators" | "RegisterOperators" |
                    "TransferOperatorsOwnership" | "TransferGatewayOwnership" => "gatewayDeployerPrivateKey",
                    "TransferGasServiceOwnership" => "gasServiceDeployerPrivateKey",
                    "AxelarGasService" => "gasServiceDeployerPrivateKey",
                    _ => return Err(eyre::eyre!("--private-key required for step {step_name}")),
                };
                state[state_key]
                    .as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| eyre::eyre!("no {state_key} in state and --private-key not provided. Run cosmos-init with the key or pass --private-key"))
            };

            match step_kind.as_str() {
                "deploy-create" | "deploy-create2" => {
                    let pk = resolve_evm_key(&step_name)?;
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
                    let pk = resolve_evm_key(&step_name)?;
                    let signer: PrivateKeySigner = pk.parse()?;
                    let provider = ProviderBuilder::new()
                        .wallet(signer)
                        .connect_http(rpc_url.parse()?);

                    let operators_addr =
                        read_contract_address(&target_json, &axelar_id, "Operators")?;
                    let operators = Operators::new(operators_addr, &provider);

                    let env = state["env"].as_str().unwrap_or("testnet");
                    let operator_addrs: Vec<Address> = match env {
                        "testnet" => vec![
                            "0x8f23e84c49624a22e8c252684129910509ade4e2".parse()?,
                            "0x3b401fa00191acb03c24ebb7754fe35d34dd1abd".parse()?,
                        ],
                        _ => return Err(eyre::eyre!(
                            "operator addresses not configured for env '{env}' — add them to the RegisterOperators handler"
                        )),
                    };

                    for op in &operator_addrs {
                        let already = operators.isOperator(*op).call().await?;
                        if already {
                            println!("operator {op} already registered, skipping");
                            continue;
                        }
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
                    let pk = resolve_evm_key(&step_name)?;
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

                "deploy-gateway" => {
                    let pk = resolve_evm_key(&step_name)?;
                    let impl_artifact = artifact_path
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--artifact-path required (implementation artifact)"))?;
                    let proxy_artifact = proxy_artifact_path
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--proxy-artifact-path required (proxy artifact)"))?;

                    let signer: PrivateKeySigner = pk.parse()?;
                    let deployer_addr = signer.address();
                    let provider = ProviderBuilder::new()
                        .wallet(signer)
                        .connect_http(rpc_url.parse()?);

                    // Compute domain separator from target json
                    let domain_separator = compute_domain_separator(&target_json, &axelar_id)?;

                    // Testnet values
                    let previous_signers_retention = U256::from(15);
                    let minimum_rotation_delay = U256::from(3600);

                    // --- Tx 1: Deploy implementation (skip if already deployed on a previous attempt) ---
                    let (impl_addr, impl_codehash) = if let Some(saved) = step.get("implementationAddress").and_then(|v| v.as_str()) {
                        let addr: Address = saved.parse()?;
                        let code = provider.get_code_at(addr).await?;
                        if code.is_empty() {
                            return Err(eyre::eyre!("saved implementation {addr} has no code on-chain"));
                        }
                        println!("reusing previously deployed implementation: {addr}");
                        (addr, keccak256(&code))
                    } else {
                        println!("deploying AxelarAmplifierGateway implementation...");
                        let impl_bytecode = read_artifact_bytecode(impl_artifact)?;
                        let mut impl_deploy_code = impl_bytecode.clone();
                        impl_deploy_code.extend_from_slice(
                            &(previous_signers_retention, domain_separator, minimum_rotation_delay)
                                .abi_encode(),
                        );

                        let tx = TransactionRequest::default()
                            .with_deploy_code(Bytes::from(impl_deploy_code));
                        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
                        println!("implementation tx hash: {}", receipt.transaction_hash);
                        let addr = receipt
                            .contract_address
                            .ok_or_else(|| eyre::eyre!("no contract address in implementation receipt"))?;
                        println!("implementation deployed at: {addr}");

                        let code = provider.get_code_at(addr).await?;
                        let codehash = keccak256(&code);

                        // Save implementation address to step so retries skip re-deployment
                        if let Some(s) = state["steps"].as_array_mut().and_then(|a| a.get_mut(step_idx)) {
                            s["implementationAddress"] = json!(format!("{addr}"));
                        }
                        save_state(&axelar_id, &state)?;

                        (addr, codehash)
                    };

                    // --- Fetch verifier set from Axelar chain ---
                    let chain_axelar_id = {
                        let content = fs::read_to_string(&target_json)?;
                        let root: Value = serde_json::from_str(&content)?;
                        root.pointer(&format!("/chains/{axelar_id}/axelarId"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&axelar_id)
                            .to_string()
                    };
                    let (signers, threshold, nonce, verifier_set_id) =
                        fetch_verifier_set(&target_json, &chain_axelar_id).await?;

                    // --- Encode setup params ---
                    let operator = deployer_addr;
                    let owner = deployer_addr;
                    let setup_params = encode_gateway_setup_params(operator, &signers, threshold, nonce);
                    println!("setup params ({} bytes): 0x{}", setup_params.len(), hex::encode(&setup_params));

                    // --- Tx 2: Deploy proxy ---
                    println!("deploying AxelarAmplifierGatewayProxy...");
                    let proxy_bytecode = read_artifact_bytecode(proxy_artifact)?;
                    let mut proxy_deploy_code = proxy_bytecode.clone();
                    // Append constructor args: (address implementation, address owner, bytes setupParams)
                    // Must use abi_encode_params (not abi_encode) — abi_encode wraps dynamic tuples
                    // with an extra offset prefix that corrupts the constructor args.
                    proxy_deploy_code
                        .extend_from_slice(&(impl_addr, owner, setup_params.clone()).abi_encode_params());

                    let proxy_deploy_bytes = Bytes::from(proxy_deploy_code);
                    let tx = TransactionRequest::default()
                        .with_deploy_code(proxy_deploy_bytes.clone())
                        .with_gas_limit(5_000_000); // explicit limit — proxy+setup uses ~2.7M gas

                    // Simulate via eth_call (non-fatal — some RPCs don't support contract creation simulation)
                    match provider.call(tx.clone()).await {
                        Ok(_) => println!("  eth_call simulation passed"),
                        Err(e) => {
                            let reason = decode_evm_error(&e);
                            eprintln!("  WARNING: eth_call simulation failed: {reason}");
                            eprintln!("  proceeding with send_transaction anyway...");
                        }
                    }

                    let receipt = match provider.send_transaction(tx).await {
                        Ok(pending) => pending.get_receipt().await?,
                        Err(e) => {
                            let reason = decode_evm_error(&e);
                            return Err(eyre::eyre!("proxy deployment failed: {reason}"));
                        }
                    };
                    println!("proxy tx hash: {}", receipt.transaction_hash);

                    if !receipt.status() {
                        return Err(eyre::eyre!(
                            "proxy deployment tx {} reverted on-chain (status=0)",
                            receipt.transaction_hash
                        ));
                    }

                    let proxy_addr = receipt
                        .contract_address
                        .ok_or_else(|| eyre::eyre!("no contract address in proxy receipt"))?;
                    println!("proxy deployed at: {proxy_addr}");

                    // --- Write to target JSON ---
                    let mut contract_data = Map::new();
                    contract_data.insert("address".into(), json!(format!("{proxy_addr}")));
                    contract_data.insert("implementation".into(), json!(format!("{impl_addr}")));
                    contract_data.insert("deployer".into(), json!(format!("{deployer_addr}")));
                    contract_data.insert("deploymentMethod".into(), json!("create"));
                    contract_data.insert("implementationCodehash".into(), json!(format!("{impl_codehash}")));
                    contract_data.insert("previousSignersRetention".into(), json!(15));
                    contract_data.insert("domainSeparator".into(), json!(format!("{domain_separator}")));
                    contract_data.insert("minimumRotationDelay".into(), json!(3600));
                    contract_data.insert("operator".into(), json!(format!("{operator}")));
                    contract_data.insert("owner".into(), json!(format!("{owner}")));
                    contract_data.insert("connectionType".into(), json!("amplifier"));
                    contract_data.insert("initialVerifierSetId".into(), json!(verifier_set_id));

                    update_target_json(&target_json, &axelar_id, "AxelarGateway", Value::Object(contract_data))?;
                }

                "predict-address" => {
                    let gateway_deployer_str = state["gatewayDeployer"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no gatewayDeployer in state. Run cosmos-init first"))?;
                    let gateway_deployer: Address = gateway_deployer_str.parse()?;

                    let provider = ProviderBuilder::new()
                        .connect_http(rpc_url.parse()?);
                    let nonce = provider.get_transaction_count(gateway_deployer).await?;
                    let proxy_nonce = nonce + 1; // +1 for implementation tx
                    let predicted = compute_create_address(gateway_deployer, proxy_nonce);
                    println!("gateway deployer: {gateway_deployer}");
                    println!("current nonce: {nonce}");
                    println!("proxy nonce (impl+1): {proxy_nonce}");
                    println!("predicted gateway proxy address: {predicted}");

                    state["predictedGatewayAddress"] = json!(format!("{predicted}"));
                }

                "config-edit" => {
                    let predicted_addr = state["predictedGatewayAddress"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no predictedGatewayAddress in state. Run predict-address step first"))?
                        .to_string();
                    let env = state["env"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no env in state. Run cosmos-init first"))?
                        .to_string();

                    let content = fs::read_to_string(&target_json)?;
                    let mut root: Value = serde_json::from_str(&content)?;

                    // Read chain's axelarId
                    let chain_axelar_id = root
                        .pointer(&format!("/chains/{axelar_id}/axelarId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&axelar_id)
                        .to_string();

                    // Determine per-environment values
                    let (governance_address, admin_address, service_name, voting_threshold, signing_threshold) = match env.as_str() {
                        "devnet-amplifier" => (
                            "axelar1zlr7e5qf3sz7yf890rkh9tcnu87234k6k7ytd9",
                            "axelar1zlr7e5qf3sz7yf890rkh9tcnu87234k6k7ytd9",
                            "validators",
                            json!(["6", "10"]),
                            json!(["6", "10"]),
                        ),
                        "testnet" => (
                            "axelar10d07y265gmmuvt4z0w9aw880jnsr700j7v9daj",
                            "axelar17qafmnc4hrfa96cq37wg5l68sxh354pj6eky35",
                            "amplifier",
                            json!(["51", "100"]),
                            json!(["51", "100"]),
                        ),
                        "mainnet" => (
                            "axelar10d07y265gmmuvt4z0w9aw880jnsr700j7v9daj",
                            "axelar1pczf792wf3p3xssk4dmwfxrh6hcqnrjp70danj",
                            "amplifier",
                            json!(["2", "3"]),
                            json!(["2", "3"]),
                        ),
                        _ => (
                            "axelar10d07y265gmmuvt4z0w9aw880jnsr700j7v9daj",
                            "axelar1l7vz4m5g92kvga050vk9ycjynywdlk4zhs07dv",
                            "amplifier",
                            json!(["51", "100"]),
                            json!(["51", "100"]),
                        ),
                    };

                    // Add VotingVerifier chain config
                    let voting_verifier_config = json!({
                        "governanceAddress": governance_address,
                        "serviceName": service_name,
                        "sourceGatewayAddress": predicted_addr,
                        "votingThreshold": voting_threshold,
                        "blockExpiry": 50,
                        "confirmationHeight": 1000000,
                        "msgIdFormat": "hex_tx_hash_and_event_index",
                        "addressFormat": "eip55"
                    });

                    let vv = root
                        .pointer_mut("/axelar/contracts/VotingVerifier")
                        .ok_or_else(|| eyre::eyre!("no axelar.contracts.VotingVerifier in target json"))?
                        .as_object_mut()
                        .ok_or_else(|| eyre::eyre!("VotingVerifier is not an object"))?;
                    vv.insert(chain_axelar_id.clone(), voting_verifier_config);
                    println!("added VotingVerifier.{chain_axelar_id} config");

                    // Add MultisigProver chain config
                    let multisig_prover_config = json!({
                        "governanceAddress": governance_address,
                        "adminAddress": admin_address,
                        "signingThreshold": signing_threshold,
                        "serviceName": service_name,
                        "verifierSetDiffThreshold": 0,
                        "encoder": "abi",
                        "keyType": "ecdsa"
                    });

                    let mp = root
                        .pointer_mut("/axelar/contracts/MultisigProver")
                        .ok_or_else(|| eyre::eyre!("no axelar.contracts.MultisigProver in target json"))?
                        .as_object_mut()
                        .ok_or_else(|| eyre::eyre!("MultisigProver is not an object"))?;
                    mp.insert(chain_axelar_id.clone(), multisig_prover_config);
                    println!("added MultisigProver.{chain_axelar_id} config");

                    fs::write(&target_json, serde_json::to_string_pretty(&root)? + "\n")?;
                    println!("updated {}", target_json.display());
                }

                "cosmos-tx" => {
                    let mnemonic = state["mnemonic"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no mnemonic in state. Run cosmos-init first"))?
                        .to_string();
                    let env = state["env"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no env in state"))?
                        .to_string();
                    let (signing_key, axelar_address) = derive_axelar_wallet(&mnemonic)?;
                    let (lcd, chain_id, fee_denom, gas_price) = read_axelar_config(&target_json)?;
                    let use_governance = env != "devnet-amplifier";

                    let chain_axelar_id = {
                        let content = fs::read_to_string(&target_json)?;
                        let root: Value = serde_json::from_str(&content)?;
                        root.pointer(&format!("/chains/{axelar_id}/axelarId"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&axelar_id)
                            .to_string()
                    };

                    let proposal_key = step["proposalKey"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    match step_name.as_str() {
                        "InstantiateChainContracts" => {
                            println!("instantiating chain contracts for {chain_axelar_id}...");

                            let coordinator_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Coordinator/address")?;
                            let rewards_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Rewards/address")?;
                            let multisig_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Multisig/address")?;
                            let _router_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Router/address")?;
                            let chain_codec_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/ChainCodecEvm/address")?;
                            let governance_address = read_axelar_contract_field(&target_json, "/axelar/governanceAddress")?;

                            // Fetch code IDs
                            println!("  fetching code IDs...");
                            let gateway_hash = read_axelar_contract_field(&target_json, "/axelar/contracts/Gateway/storeCodeProposalCodeHash")?;
                            let verifier_hash = read_axelar_contract_field(&target_json, "/axelar/contracts/VotingVerifier/storeCodeProposalCodeHash")?;
                            let prover_hash = read_axelar_contract_field(&target_json, "/axelar/contracts/MultisigProver/storeCodeProposalCodeHash")?;

                            let gateway_code_id = lcd_fetch_code_id(&lcd, &gateway_hash).await?;
                            let verifier_code_id = lcd_fetch_code_id(&lcd, &verifier_hash).await?;
                            let prover_code_id = lcd_fetch_code_id(&lcd, &prover_hash).await?;
                            println!("  code IDs: gateway={gateway_code_id}, verifier={verifier_code_id}, prover={prover_code_id}");

                            // Read per-chain config from VotingVerifier and MultisigProver
                            let content = fs::read_to_string(&target_json)?;
                            let root: Value = serde_json::from_str(&content)?;
                            let vv_config = root
                                .pointer(&format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}"))
                                .ok_or_else(|| eyre::eyre!("no VotingVerifier.{chain_axelar_id} config"))?;
                            let mp_config = root
                                .pointer(&format!("/axelar/contracts/MultisigProver/{chain_axelar_id}"))
                                .ok_or_else(|| eyre::eyre!("no MultisigProver.{chain_axelar_id} config"))?;

                            // Compute salt: keccak256(abi.encode(["string"], [salt_key]))
                            let salt_key = state["cosmSalt"]
                                .as_str()
                                .ok_or_else(|| eyre::eyre!("no cosmSalt in state. Run cosmos-init with --salt first"))?;
                            let salt_bytes = get_salt_from_key(salt_key);
                            let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt_bytes.as_slice());

                            // Compute domain separator
                            let domain_separator = compute_domain_separator(&target_json, &axelar_id)?;
                            let domain_sep_hex = hex::encode(domain_separator.as_slice());

                            // Determine contract admin per env
                            let contract_admin = match env.as_str() {
                                "devnet-amplifier" => "axelar1zlr7e5qf3sz7yf890rkh9tcnu87234k6k7ytd9",
                                "testnet" => "axelar1wxej3l9aczsns3harrtdzk7rct29jl47tvu8mp",
                                "mainnet" => "axelar1nctnr9x0qexemeld5w7w752rmqdsqqv92dw9am",
                                _ => "axelar12qvsvse32cjyw60ztysd3v655aj5urqeup82ky",
                            };

                            let deployment_name = format!("{chain_axelar_id}-{gateway_code_id}-{verifier_code_id}-{prover_code_id}");

                            let execute_msg = json!({
                                "instantiate_chain_contracts": {
                                    "deployment_name": deployment_name,
                                    "salt": salt_b64,
                                    "params": {
                                        "manual": {
                                            "gateway": {
                                                "code_id": gateway_code_id,
                                                "label": format!("Gateway-{chain_axelar_id}"),
                                                "msg": null,
                                                "contract_admin": contract_admin
                                            },
                                            "verifier": {
                                                "code_id": verifier_code_id,
                                                "label": format!("VotingVerifier-{chain_axelar_id}"),
                                                "msg": {
                                                    "governance_address": vv_config["governanceAddress"],
                                                    "service_name": vv_config["serviceName"],
                                                    "source_gateway_address": vv_config["sourceGatewayAddress"],
                                                    "voting_threshold": vv_config["votingThreshold"],
                                                    "block_expiry": vv_config["blockExpiry"].as_u64().unwrap_or(50).to_string(),
                                                    "confirmation_height": vv_config["confirmationHeight"],
                                                    "source_chain": chain_axelar_id,
                                                    "rewards_address": rewards_addr,
                                                    "msg_id_format": vv_config["msgIdFormat"],
                                                    "chain_codec_address": chain_codec_addr,
                                                    "address_format": vv_config["addressFormat"]
                                                },
                                                "contract_admin": contract_admin
                                            },
                                            "prover": {
                                                "code_id": prover_code_id,
                                                "label": format!("MultisigProver-{chain_axelar_id}"),
                                                "msg": {
                                                    "governance_address": mp_config["governanceAddress"],
                                                    "admin_address": match env.as_str() {
                                                        "testnet" => "axelar1w7y7v26rtnrj4vrx6q3qq4hfsmc68hhsxnadlf",
                                                        _ => mp_config.get("adminAddress").and_then(|v| v.as_str())
                                                            .ok_or_else(|| eyre::eyre!("no adminAddress in MultisigProver config for {env}"))?,
                                                    },
                                                    "multisig_address": multisig_addr,
                                                    "signing_threshold": mp_config["signingThreshold"],
                                                    "service_name": mp_config["serviceName"],
                                                    "chain_name": chain_axelar_id,
                                                    "verifier_set_diff_threshold": mp_config["verifierSetDiffThreshold"],
                                                    "key_type": mp_config["keyType"],
                                                    "domain_separator": domain_sep_hex,
                                                    "notify_signing_session": false,
                                                    "expect_full_message_payloads": false,
                                                    "sig_verifier_address": null,
                                                    "chain_codec_address": chain_codec_addr
                                                },
                                                "contract_admin": contract_admin
                                            }
                                        }
                                    }
                                }
                            });

                            println!("  execute msg: {}", serde_json::to_string_pretty(&execute_msg)?);

                            let sender = if use_governance { &governance_address } else { &axelar_address };
                            let inner_msg = build_execute_msg_any(sender, &coordinator_addr, &execute_msg)?;

                            let messages = if use_governance {
                                let deposit_amount = read_axelar_contract_field(&target_json, "/axelar/govProposalExpeditedDepositAmount")
                                    .unwrap_or_else(|_| "3000000000".to_string());
                                let title = format!("Instantiate chain contracts for {chain_axelar_id}");
                                let summary = format!("Instantiate Gateway, VotingVerifier and MultisigProver contracts for {chain_axelar_id} via Coordinator");
                                vec![build_submit_proposal_any(&axelar_address, vec![inner_msg], &title, &summary, &deposit_amount, &fee_denom, true)?]
                            } else {
                                vec![inner_msg]
                            };

                            let tx_resp = sign_and_broadcast_cosmos_tx(
                                &signing_key, &axelar_address, &lcd, &chain_id, &fee_denom, gas_price, messages,
                            ).await?;

                            // Save deployment name to testnet.json
                            let content = fs::read_to_string(&target_json)?;
                            let mut root: Value = serde_json::from_str(&content)?;
                            let coord = root
                                .pointer_mut("/axelar/contracts/Coordinator")
                                .and_then(|v| v.as_object_mut())
                                .ok_or_else(|| eyre::eyre!("no Coordinator config"))?;
                            if coord.get("deployments").is_none() {
                                coord.insert("deployments".to_string(), json!({}));
                            }
                            coord["deployments"]
                                .as_object_mut()
                                .unwrap()
                                .insert(chain_axelar_id.clone(), json!({
                                    "deploymentName": deployment_name,
                                    "salt": salt_key
                                }));

                            // Also save code IDs to per-chain config
                            if let Some(vv) = root.pointer_mut(&format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}")) {
                                vv["codeId"] = json!(verifier_code_id);
                                vv["contractAdmin"] = json!(contract_admin);
                            }
                            if let Some(mp) = root.pointer_mut(&format!("/axelar/contracts/MultisigProver/{chain_axelar_id}")) {
                                mp["codeId"] = json!(prover_code_id);
                                mp["domainSeparator"] = json!(format!("0x{domain_sep_hex}"));
                                mp["contractAdmin"] = json!(contract_admin);
                            }
                            if let Some(gw) = root.pointer_mut(&format!("/axelar/contracts/Gateway/{chain_axelar_id}")) {
                                gw["codeId"] = json!(gateway_code_id);
                                gw["contractAdmin"] = json!(contract_admin);
                            } else {
                                // Create the Gateway chain entry if it doesn't exist
                                if let Some(gateway_obj) = root.pointer_mut("/axelar/contracts/Gateway").and_then(|v| v.as_object_mut()) {
                                    gateway_obj.insert(chain_axelar_id.clone(), json!({
                                        "codeId": gateway_code_id,
                                        "contractAdmin": contract_admin
                                    }));
                                }
                            }
                            fs::write(&target_json, serde_json::to_string_pretty(&root)? + "\n")?;

                            if use_governance {
                                let proposal_id = extract_proposal_id(&tx_resp)?;
                                println!("  proposal submitted: {proposal_id}");
                                println!();
                                println!("  ACTION REQUIRED: vote on the proposal:");
                                println!("  ./vote_{env}_proposal.sh {env}-nodes {proposal_id}");
                                if state.get("proposals").is_none() {
                                    state["proposals"] = json!({});
                                }
                                state["proposals"][&proposal_key] = json!(proposal_id);
                            } else {
                                println!("  direct execution completed");
                            }
                        }

                        "RegisterDeployment" => {
                            println!("registering deployment for {chain_axelar_id}...");

                            let coordinator_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Coordinator/address")?;
                            let governance_address = read_axelar_contract_field(&target_json, "/axelar/governanceAddress")?;

                            // Read deployment name from Coordinator.deployments.{chain}
                            let deployment_name = read_axelar_contract_field(
                                &target_json,
                                &format!("/axelar/contracts/Coordinator/deployments/{chain_axelar_id}/deploymentName"),
                            )?;

                            let execute_msg = json!({
                                "register_deployment": {
                                    "deployment_name": deployment_name
                                }
                            });

                            let sender = if use_governance { &governance_address } else { &axelar_address };
                            let inner_msg = build_execute_msg_any(sender, &coordinator_addr, &execute_msg)?;

                            let messages = if use_governance {
                                let deposit_amount = read_axelar_contract_field(&target_json, "/axelar/govProposalExpeditedDepositAmount")
                                    .unwrap_or_else(|_| "3000000000".to_string());
                                let title = format!("Register {chain_axelar_id} deployment on Coordinator");
                                vec![build_submit_proposal_any(&axelar_address, vec![inner_msg], &title, &title, &deposit_amount, &fee_denom, true)?]
                            } else {
                                vec![inner_msg]
                            };

                            let tx_resp = sign_and_broadcast_cosmos_tx(
                                &signing_key, &axelar_address, &lcd, &chain_id, &fee_denom, gas_price, messages,
                            ).await?;

                            if use_governance {
                                let proposal_id = extract_proposal_id(&tx_resp)?;
                                println!("  proposal submitted: {proposal_id}");
                                println!();
                                println!("  ACTION REQUIRED: vote on the proposal:");
                                println!("  ./vote_{env}_proposal.sh {env}-nodes {proposal_id}");
                                if state.get("proposals").is_none() {
                                    state["proposals"] = json!({});
                                }
                                state["proposals"][&proposal_key] = json!(proposal_id);
                            } else {
                                println!("  direct execution completed");
                            }
                        }

                        "CreateRewardPools" => {
                            println!("creating reward pools for {chain_axelar_id}...");

                            let rewards_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Rewards/address")?;
                            let governance_address = read_axelar_contract_field(&target_json, "/axelar/governanceAddress")?;
                            let multisig_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Multisig/address")?;
                            let voting_verifier_addr = read_axelar_contract_field(
                                &target_json,
                                &format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}/address"),
                            )?;

                            // Per-environment reward pool params
                            let (epoch_duration, participation_threshold, rewards_per_epoch) = match env.as_str() {
                                "devnet-amplifier" => ("100", json!(["7", "10"]), "100"),
                                "mainnet" => ("14845", json!(["8", "10"]), "3424660000"),
                                _ => ("600", json!(["7", "10"]), "100"),
                            };

                            let msg1 = json!({
                                "create_pool": {
                                    "params": {
                                        "epoch_duration": epoch_duration,
                                        "participation_threshold": participation_threshold,
                                        "rewards_per_epoch": rewards_per_epoch
                                    },
                                    "pool_id": {
                                        "chain_name": chain_axelar_id,
                                        "contract": voting_verifier_addr
                                    }
                                }
                            });
                            let msg2 = json!({
                                "create_pool": {
                                    "params": {
                                        "epoch_duration": epoch_duration,
                                        "participation_threshold": participation_threshold,
                                        "rewards_per_epoch": rewards_per_epoch
                                    },
                                    "pool_id": {
                                        "chain_name": chain_axelar_id,
                                        "contract": multisig_addr
                                    }
                                }
                            });

                            let sender = if use_governance { &governance_address } else { &axelar_address };
                            let inner_msg1 = build_execute_msg_any(sender, &rewards_addr, &msg1)?;
                            let inner_msg2 = build_execute_msg_any(sender, &rewards_addr, &msg2)?;

                            let messages = if use_governance {
                                let deposit_amount = read_axelar_contract_field(&target_json, "/axelar/govProposalExpeditedDepositAmount")
                                    .unwrap_or_else(|_| "3000000000".to_string());
                                let title = format!("Create reward pools for {chain_axelar_id}");
                                let summary = format!("Create reward pools for {chain_axelar_id} voting verifier and multisig");
                                vec![build_submit_proposal_any(&axelar_address, vec![inner_msg1, inner_msg2], &title, &summary, &deposit_amount, &fee_denom, true)?]
                            } else {
                                vec![inner_msg1, inner_msg2]
                            };

                            let tx_resp = sign_and_broadcast_cosmos_tx(
                                &signing_key, &axelar_address, &lcd, &chain_id, &fee_denom, gas_price, messages,
                            ).await?;

                            if use_governance {
                                let proposal_id = extract_proposal_id(&tx_resp)?;
                                println!("  proposal submitted: {proposal_id}");
                                println!();
                                println!("  ACTION REQUIRED: vote on the proposal:");
                                println!("  ./vote_{env}_proposal.sh {env}-nodes {proposal_id}");
                                if state.get("proposals").is_none() {
                                    state["proposals"] = json!({});
                                }
                                state["proposals"][&proposal_key] = json!(proposal_id);
                            } else {
                                println!("  direct execution completed");
                            }
                        }

                        "AddRewards" => {
                            println!("adding rewards for {chain_axelar_id}...");

                            let rewards_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Rewards/address")?;
                            let multisig_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Multisig/address")?;
                            let voting_verifier_addr = read_axelar_contract_field(
                                &target_json,
                                &format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}/address"),
                            )?;

                            let reward_amount = "1000000";
                            let funds = vec![ProtoCoin {
                                denom: fee_denom.to_string(),
                                amount: reward_amount.to_string(),
                            }];

                            let msg1 = json!({
                                "add_rewards": {
                                    "pool_id": {
                                        "chain_name": chain_axelar_id,
                                        "contract": multisig_addr
                                    }
                                }
                            });
                            let msg2 = json!({
                                "add_rewards": {
                                    "pool_id": {
                                        "chain_name": chain_axelar_id,
                                        "contract": voting_verifier_addr
                                    }
                                }
                            });

                            // Direct execution (not governance-wrapped) — each msg carries funds
                            let inner_msg1 = build_execute_msg_any_with_funds(&axelar_address, &rewards_addr, &msg1, funds.clone())?;
                            let inner_msg2 = build_execute_msg_any_with_funds(&axelar_address, &rewards_addr, &msg2, funds)?;

                            println!("  sending {reward_amount}{fee_denom} to each reward pool");
                            let tx_resp = sign_and_broadcast_cosmos_tx(
                                &signing_key, &axelar_address, &lcd, &chain_id, &fee_denom, gas_price, vec![inner_msg1, inner_msg2],
                            ).await?;

                            let code = tx_resp.pointer("/tx_response/code").and_then(|v| v.as_u64()).unwrap_or(0);
                            if code != 0 {
                                let raw_log = tx_resp.pointer("/tx_response/raw_log").and_then(|v| v.as_str()).unwrap_or("unknown");
                                return Err(eyre::eyre!("add_rewards tx failed (code {code}): {raw_log}"));
                            }
                            println!("  rewards added to both pools");
                        }

                        _ => {
                            return Err(eyre::eyre!("unknown cosmos-tx step: {step_name}"));
                        }
                    }
                }

                "cosmos-poll" => {
                    let proposal_key = step["proposalKey"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no proposalKey in step"))?
                        .to_string();
                    let proposal_id = state
                        .pointer(&format!("/proposals/{proposal_key}"))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| eyre::eyre!("no proposal ID for key '{proposal_key}' in state. Was the previous cosmos-tx step completed?"))?;

                    let (lcd, _, _, _) = read_axelar_config(&target_json)?;

                    println!("polling proposal {proposal_id}...");
                    loop {
                        let proposal = lcd_query_proposal(&lcd, proposal_id).await?;
                        let status = proposal["status"].as_str().unwrap_or("UNKNOWN");
                        println!("  proposal {proposal_id}: {status}");

                        match status {
                            "PROPOSAL_STATUS_PASSED" => {
                                println!("  proposal passed!");
                                break;
                            }
                            "PROPOSAL_STATUS_REJECTED" | "PROPOSAL_STATUS_FAILED" => {
                                let reason = proposal["failed_reason"]
                                    .as_str()
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or("no reason provided");
                                let tally = &proposal["final_tally_result"];
                                return Err(eyre::eyre!(
                                    "proposal {proposal_id} {status}\n  reason: {reason}\n  tally: yes={} no={} abstain={} no_with_veto={}",
                                    tally["yes_count"].as_str().unwrap_or("?"),
                                    tally["no_count"].as_str().unwrap_or("?"),
                                    tally["abstain_count"].as_str().unwrap_or("?"),
                                    tally["no_with_veto_count"].as_str().unwrap_or("?"),
                                ));
                            }
                            _ => {
                                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                            }
                        }
                    }
                }

                "cosmos-query" => {
                    // SaveDeployedContracts: query Coordinator for deployed addresses
                    let (lcd, _, _, _) = read_axelar_config(&target_json)?;
                    let coordinator_addr = read_axelar_contract_field(&target_json, "/axelar/contracts/Coordinator/address")?;

                    let chain_axelar_id = {
                        let content = fs::read_to_string(&target_json)?;
                        let root: Value = serde_json::from_str(&content)?;
                        root.pointer(&format!("/chains/{axelar_id}/axelarId"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&axelar_id)
                            .to_string()
                    };

                    let deployment_name = read_axelar_contract_field(
                        &target_json,
                        &format!("/axelar/contracts/Coordinator/deployments/{chain_axelar_id}/deploymentName"),
                    )?;

                    println!("querying deployed contracts for {chain_axelar_id} (deployment: {deployment_name})...");

                    let query = json!({
                        "deployment": {
                            "deployment_name": deployment_name
                        }
                    });
                    let result = lcd_cosmwasm_smart_query(&lcd, &coordinator_addr, &query).await?;

                    let verifier_address = result["verifier_address"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no verifier_address in response"))?;
                    let prover_address = result["prover_address"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no prover_address in response"))?;
                    let gateway_address = result["gateway_address"]
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("no gateway_address in response"))?;

                    println!("  VotingVerifier: {verifier_address}");
                    println!("  MultisigProver: {prover_address}");
                    println!("  Gateway: {gateway_address}");

                    // Write addresses to testnet.json
                    let content = fs::read_to_string(&target_json)?;
                    let mut root: Value = serde_json::from_str(&content)?;

                    if let Some(vv) = root.pointer_mut(&format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}")) {
                        vv["address"] = json!(verifier_address);
                    }
                    if let Some(mp) = root.pointer_mut(&format!("/axelar/contracts/MultisigProver/{chain_axelar_id}")) {
                        mp["address"] = json!(prover_address);
                    }
                    if let Some(gw) = root.pointer_mut(&format!("/axelar/contracts/Gateway/{chain_axelar_id}")) {
                        gw["address"] = json!(gateway_address);
                    }

                    fs::write(&target_json, serde_json::to_string_pretty(&root)? + "\n")?;
                    println!("  updated {}", target_json.display());
                }

                "wait-verifier-set" => {
                    let content = fs::read_to_string(&target_json)?;
                    let root: Value = serde_json::from_str(&content)?;
                    let chain_axelar_id = root.pointer(&format!("/chains/{axelar_id}/axelarId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&axelar_id)
                        .to_string();
                    let rpc_url = state["rpcUrl"].as_str().unwrap_or("").to_string();

                    let prover_addr = read_axelar_contract_field(
                        &target_json,
                        &format!("/axelar/contracts/MultisigProver/{chain_axelar_id}/address"),
                    )?;
                    let verifier_addr = read_axelar_contract_field(
                        &target_json,
                        &format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}/address"),
                    )?;
                    let multisig_addr = read_axelar_contract_field(
                        &target_json,
                        "/axelar/contracts/Multisig/address",
                    )?;
                    let service_registry_addr = read_axelar_contract_field(
                        &target_json,
                        "/axelar/contracts/ServiceRegistry/address",
                    )?;
                    let admin_addr = if let Some(admin_mn) = state["adminMnemonic"].as_str() {
                        let (_, addr) = derive_axelar_wallet(admin_mn)?;
                        addr
                    } else {
                        root.pointer("/axelar/multisigProverAdminAddress")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<prover-admin>")
                            .to_string()
                    };
                    let axelar_chain_id = root.pointer("/axelar/chainId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<chain-id>");
                    let axelar_rpc = root.pointer("/axelar/rpc")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<rpc>");

                    let (lcd, chain_id, fee_denom, gas_price) = read_axelar_config(&target_json)?;
                    let env = state["env"].as_str().unwrap_or("testnet");

                    // Check if verifier set already exists
                    let query_msg = json!("current_verifier_set");
                    if let Ok(data) = lcd_cosmwasm_smart_query(&lcd, &prover_addr, &query_msg).await {
                        if !data.is_null() && data.get("id").is_some() {
                            let id = data["id"].as_str().unwrap_or("?");
                            println!("verifier set already exists! id: {id}");
                            // skip to step completion
                        } else {
                            // Print instructions and poll
                            println!("waiting for verifier set on MultisigProver ({prover_addr})...");
                            println!();
                            println!("  ACTION REQUIRED: An admin must complete these steps in order:");
                            println!();
                            println!("  1. Open a PR in https://github.com/axelarnetwork/infrastructure");
                            println!();
                            println!("     File: infrastructure/{env}/apps/axelar-{env}/ampd/ampd-epsilon/helm-values.yaml");
                            println!();
                            println!("     Add to config_toml.chains:");
                            println!();
                            println!("        - chain_name: {chain_axelar_id}");
                            println!("          multisig: {multisig_addr}");
                            println!("          multisig_prover: {prover_addr}");
                            println!("          voting_verifier: {verifier_addr}");
                            println!();
                            println!("     Add to handlers:");
                            println!();
                            println!("     {chain_axelar_id}:");
                            println!("       handler_type: evm");
                            println!("       enabled: true");
                            println!("       image:");
                            println!("         repository: axelarnet/axelar-ampd-evm-handler");
                            println!("         tag: v0.1.0");
                            println!("       rpc_url: {rpc_url}");
                            println!();
                            println!("     File: infrastructure/{env}/apps/axelar-{env}/ampd/ampd/helm-values.yaml");
                            println!();
                            println!("     Add to handlers:");
                            println!();
                            println!("       - type: MultisigSigner");
                            println!("         cosmwasm_contract: {multisig_addr}");
                            println!("         chain_name: {chain_axelar_id}");
                            println!("       - type: EvmMsgVerifier");
                            println!("         cosmwasm_contract: {verifier_addr}");
                            println!("         chain_name: {chain_axelar_id}");
                            println!("         chain_rpc_url: {rpc_url}");
                            println!("         chain_finalization: RPCFinalizedBlock");
                            println!("       - type: EvmVerifierSetVerifier");
                            println!("         cosmwasm_contract: {verifier_addr}");
                            println!("         chain_name: {chain_axelar_id}");
                            println!("         chain_rpc_url: {rpc_url}");
                            println!("         chain_finalization: RPCFinalizedBlock");
                            println!();
                            println!("  2. Wait for the PR to be merged and deployed.");
                            println!();
                            println!("  3. Register chain support:");
                            println!("     ./register_chain_support.sh {chain_axelar_id}");
                            println!();
                            println!("  4. Update verifier set:");
                            println!("     axelard tx wasm execute {prover_addr} '\"update_verifier_set\"' \\");
                            println!("       --from {admin_addr} --chain-id {axelar_chain_id} --node {axelar_rpc} \\");
                            println!("       --gas auto --gas-adjustment 1.3");
                            println!();

                            // Phase 1: poll ServiceRegistry for active verifiers
                            let min_verifiers: usize = match env {
                                "devnet-amplifier" => 3,
                                "mainnet" => 25,
                                _ => 22, // testnet
                            };
                            println!("  polling ServiceRegistry for active verifiers (need {min_verifiers})...");
                            loop {
                                let verifier_query = json!({
                                    "active_verifiers": {
                                        "service_name": "amplifier",
                                        "chain_name": chain_axelar_id
                                    }
                                });
                                match lcd_cosmwasm_smart_query(&lcd, &service_registry_addr, &verifier_query).await {
                                    Ok(data) if data.is_array() => {
                                        let count = data.as_array().map(|a| a.len()).unwrap_or(0);
                                        if count >= min_verifiers {
                                            println!("  {count} active verifiers registered for {chain_axelar_id} (>= {min_verifiers})");
                                            break;
                                        }
                                        println!("  {count}/{min_verifiers} verifiers, retrying in 30s...");
                                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                    }
                                    _ => {
                                        println!("  not enough verifiers yet, retrying in 30s...");
                                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                    }
                                }
                            }

                            // Phase 2: call update_verifier_set
                            if let Some(admin_mn) = state["adminMnemonic"].as_str() {
                                println!("  calling update_verifier_set with admin key...");
                                let (admin_key, admin_address) = derive_axelar_wallet(admin_mn)?;
                                let execute_msg = json!("update_verifier_set");
                                let msg_any = build_execute_msg_any(&admin_address, &prover_addr, &execute_msg)?;
                                sign_and_broadcast_cosmos_tx(
                                    &admin_key, &admin_address, &lcd, &chain_id, &fee_denom, gas_price, vec![msg_any],
                                ).await?;
                                println!("  update_verifier_set tx succeeded!");
                            } else {
                                println!("  no admin mnemonic provided, waiting for manual update_verifier_set...");
                                println!("  (provide --admin-mnemonic in cosmos-init to automate this)");
                                loop {
                                    let query_msg = json!("current_verifier_set");
                                    match lcd_cosmwasm_smart_query(&lcd, &prover_addr, &query_msg).await {
                                        Ok(data) if !data.is_null() && data.get("id").is_some() => {
                                            let id = data["id"].as_str().unwrap_or("?");
                                            println!("  verifier set found! id: {id}");
                                            break;
                                        }
                                        _ => {
                                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                "deploy-upgradable" => {
                    // Currently only AxelarGasService uses this step kind.
                    // Flow: deploy implementation (CREATE) → deploy proxy (CREATE) → proxy.init()
                    let pk = resolve_evm_key(&step_name)?;
                    let impl_artifact = artifact_path
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--artifact-path required (implementation artifact)"))?;
                    let proxy_artifact = proxy_artifact_path
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("--proxy-artifact-path required (proxy artifact)"))?;

                    let signer: PrivateKeySigner = pk.parse()?;
                    let deployer_addr = signer.address();
                    let provider = ProviderBuilder::new()
                        .wallet(signer)
                        .connect_http(rpc_url.parse()?);

                    // Read the gas collector address (= Operators contract)
                    let gas_collector = read_contract_address(&target_json, &axelar_id, "Operators")?;
                    println!("gas collector (Operators): {gas_collector}");

                    // --- Tx 1: Deploy implementation (skip if already deployed on a previous attempt) ---
                    let impl_addr = if let Some(saved) = step.get("implementationAddress").and_then(|v| v.as_str()) {
                        let addr: Address = saved.parse()?;
                        let code = provider.get_code_at(addr).await?;
                        if code.is_empty() {
                            return Err(eyre::eyre!("saved implementation {addr} has no code on-chain"));
                        }
                        println!("reusing previously deployed implementation: {addr}");
                        addr
                    } else {
                        println!("deploying AxelarGasService implementation...");
                        let impl_bytecode = read_artifact_bytecode(impl_artifact)?;
                        let mut impl_deploy_code = impl_bytecode.clone();
                        // Constructor: constructor(address gasCollector_) — single static arg
                        impl_deploy_code.extend_from_slice(&gas_collector.abi_encode());

                        let tx = TransactionRequest::default()
                            .with_deploy_code(Bytes::from(impl_deploy_code));
                        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
                        println!("  implementation tx hash: {}", receipt.transaction_hash);

                        if !receipt.status() {
                            return Err(eyre::eyre!(
                                "implementation deployment tx {} reverted on-chain",
                                receipt.transaction_hash
                            ));
                        }

                        let addr = receipt
                            .contract_address
                            .ok_or_else(|| eyre::eyre!("no contract address in implementation receipt"))?;
                        println!("  implementation deployed at: {addr}");

                        // Save to state so retries skip re-deployment
                        if let Some(s) = state["steps"].as_array_mut().and_then(|a| a.get_mut(step_idx)) {
                            s["implementationAddress"] = json!(format!("{addr}"));
                        }
                        save_state(&axelar_id, &state)?;
                        addr
                    };

                    // --- Tx 2: Deploy proxy (skip if already deployed on a previous attempt) ---
                    let proxy_addr = if let Some(saved) = step.get("proxyAddress").and_then(|v| v.as_str()) {
                        let addr: Address = saved.parse()?;
                        let code = provider.get_code_at(addr).await?;
                        if code.is_empty() {
                            return Err(eyre::eyre!("saved proxy {addr} has no code on-chain"));
                        }
                        println!("reusing previously deployed proxy: {addr}");
                        addr
                    } else {
                        println!("deploying AxelarGasServiceProxy...");
                        let proxy_bytecode = read_artifact_bytecode(proxy_artifact)?;
                        // Legacy proxy has no constructor args — constructor just sets owner = msg.sender

                        let tx = TransactionRequest::default()
                            .with_deploy_code(Bytes::from(proxy_bytecode));
                        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
                        println!("  proxy tx hash: {}", receipt.transaction_hash);

                        if !receipt.status() {
                            return Err(eyre::eyre!(
                                "proxy deployment tx {} reverted on-chain",
                                receipt.transaction_hash
                            ));
                        }

                        let addr = receipt
                            .contract_address
                            .ok_or_else(|| eyre::eyre!("no contract address in proxy receipt"))?;
                        println!("  proxy deployed at: {addr}");

                        // Save to state so retries skip re-deployment
                        if let Some(s) = state["steps"].as_array_mut().and_then(|a| a.get_mut(step_idx)) {
                            s["proxyAddress"] = json!(format!("{addr}"));
                        }
                        save_state(&axelar_id, &state)?;
                        addr
                    };

                    // --- Tx 3: Call proxy.init(implementation, owner, setupParams) ---
                    // Check if already initialized by reading the implementation slot
                    // EIP-1967 implementation slot: keccak256('eip1967.proxy.implementation') - 1
                    let eip1967_impl_slot: U256 = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc".parse()?;
                    let impl_slot = provider
                        .get_storage_at(proxy_addr, eip1967_impl_slot)
                        .await?;

                    if impl_slot != U256::ZERO {
                        let stored_impl = Address::from_word(impl_slot.into());
                        println!("proxy already initialized with implementation: {stored_impl}");
                    } else {
                        println!("calling proxy.init({impl_addr}, {deployer_addr}, 0x)...");
                        let proxy = LegacyProxy::new(proxy_addr, &provider);
                        let init_tx = proxy.init(impl_addr, deployer_addr, Bytes::new());

                        let receipt = init_tx.send().await?.get_receipt().await?;
                        println!("  init tx hash: {}", receipt.transaction_hash);

                        if !receipt.status() {
                            return Err(eyre::eyre!(
                                "proxy init tx {} reverted on-chain",
                                receipt.transaction_hash
                            ));
                        }
                        println!("  proxy initialized successfully");
                    }

                    // --- Write to target JSON ---
                    let mut contract_data = Map::new();
                    contract_data.insert("address".into(), json!(format!("{proxy_addr}")));
                    contract_data.insert("implementation".into(), json!(format!("{impl_addr}")));
                    contract_data.insert("deployer".into(), json!(format!("{deployer_addr}")));
                    contract_data.insert("deploymentMethod".into(), json!("create"));
                    contract_data.insert("collector".into(), json!(format!("{gas_collector}")));

                    update_target_json(&target_json, &axelar_id, "AxelarGasService", Value::Object(contract_data))?;
                }

                other => {
                    return Err(eyre::eyre!("unknown step kind: {other}"));
                }
            }

            mark_step_completed(&mut state, step_idx);
            save_state(&axelar_id, &state)?;
            println!("step '{step_name}' completed");
        }

        Commands::Reset { axelar_id } => {
            let state = read_state(&axelar_id)?;
            let target_json: PathBuf = state["targetJson"]
                .as_str()
                .ok_or_else(|| eyre::eyre!("no targetJson in state"))?
                .into();

            // --- Delete state file ---
            let sf = state_path(&axelar_id)?;
            fs::remove_file(&sf)?;
            println!("deleted {}", sf.display());

            // --- Clean up target JSON ---
            if !target_json.exists() {
                println!("target json {} does not exist, skipping", target_json.display());
                return Ok(());
            }

            let content = fs::read_to_string(&target_json)?;
            let mut root: Value = serde_json::from_str(&content)?;

            // Remove the entire chain entry (chains/{axelarId})
            if let Some(chains) = root.get_mut("chains").and_then(|v| v.as_object_mut()) {
                if chains.remove(&axelar_id).is_some() {
                    println!("removed chains.{axelar_id}");
                }
            }

            // Remove axelar.contracts.VotingVerifier.{axelarId}
            if let Some(vv) = root
                .pointer_mut("/axelar/contracts/VotingVerifier")
                .and_then(|v| v.as_object_mut())
            {
                if vv.remove(&axelar_id).is_some() {
                    println!("removed axelar.contracts.VotingVerifier.{axelar_id}");
                }
            }

            // Remove axelar.contracts.MultisigProver.{axelarId}
            if let Some(mp) = root
                .pointer_mut("/axelar/contracts/MultisigProver")
                .and_then(|v| v.as_object_mut())
            {
                if mp.remove(&axelar_id).is_some() {
                    println!("removed axelar.contracts.MultisigProver.{axelar_id}");
                }
            }

            // Remove axelar.contracts.Gateway.{axelarId}
            if let Some(gw) = root
                .pointer_mut("/axelar/contracts/Gateway")
                .and_then(|v| v.as_object_mut())
            {
                if gw.remove(&axelar_id).is_some() {
                    println!("removed axelar.contracts.Gateway.{axelar_id}");
                }
            }

            // Remove axelar.contracts.Coordinator.deployments.{axelarId}
            if let Some(deployments) = root
                .pointer_mut("/axelar/contracts/Coordinator/deployments")
                .and_then(|v| v.as_object_mut())
            {
                if deployments.remove(&axelar_id).is_some() {
                    println!("removed axelar.contracts.Coordinator.deployments.{axelar_id}");
                }
            }

            fs::write(&target_json, serde_json::to_string_pretty(&root)? + "\n")?;
            println!("cleaned up {}", target_json.display());
        }
    }

    Ok(())
}

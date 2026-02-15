use std::fs;
use std::path::PathBuf;

use alloy::signers::local::PrivateKeySigner;
use eyre::Result;
use serde_json::{Value, json};

use crate::cosmos::{derive_axelar_wallet, read_axelar_config};
use crate::state::{data_dir, default_steps, save_state, state_path};

pub async fn run() -> Result<()> {
    let require = |name: &str| -> Result<String> {
        std::env::var(name).map_err(|_| eyre::eyre!("missing required env var: {name}"))
    };

    let axelar_id = require("CHAIN")?;
    let chain_name = require("CHAIN_NAME")?;
    let chain_id: u64 = require("CHAIN_ID")?
        .parse()
        .map_err(|_| eyre::eyre!("CHAIN_ID must be a number"))?;
    let rpc_url = require("RPC_URL")?;
    let token_symbol = require("TOKEN_SYMBOL")?;
    let decimals: u8 = require("DECIMALS")?
        .parse()
        .map_err(|_| eyre::eyre!("DECIMALS must be a number"))?;
    let target_json = PathBuf::from(require("TARGET_JSON")?);
    let mnemonic = require("MNEMONIC")?;
    let env = require("ENV")?;
    let salt = require("SALT")?;

    // Optional env vars
    let explorer_name = std::env::var("EXPLORER_NAME").ok();
    let explorer_url = std::env::var("EXPLORER_URL").ok();
    let admin_mnemonic = std::env::var("MULTISIG_PROVER_MNEMONIC").ok();
    let deployer_private_key = std::env::var("DEPLOYER_PRIVATE_KEY").ok();
    let gateway_deployer_private_key = std::env::var("GATEWAY_DEPLOYER_PRIVATE_KEY").ok();
    let gas_service_deployer_private_key = std::env::var("GAS_SERVICE_DEPLOYER_PRIVATE_KEY").ok();

    // --- Chain config → target json ---
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
        return Err(eyre::eyre!(
            "chain '{axelar_id}' already exists in {}",
            target_json.display()
        ));
    }

    chains.insert(axelar_id.clone(), chain_entry);
    fs::write(&target_json, serde_json::to_string_pretty(&root)? + "\n")?;
    println!("added chain '{axelar_id}' to {}", target_json.display());

    // --- State file ---
    let dir = data_dir()?;
    fs::create_dir_all(&dir)?;
    let mut state = json!({
        "axelarId": axelar_id,
        "rpcUrl": rpc_url,
        "targetJson": target_json.to_string_lossy(),
        "steps": default_steps(),
        "mnemonic": mnemonic,
        "env": env,
        "cosmSalt": salt,
    });

    let (_, axelar_address) = derive_axelar_wallet(&mnemonic)?;
    println!("axelar deployer address: {axelar_address}");

    if let Some(ref admin_mn) = admin_mnemonic {
        let (_, admin_address) = derive_axelar_wallet(admin_mn)?;
        println!("prover admin address: {admin_address}");
        state["adminMnemonic"] = json!(admin_mn);
    }

    if let Some(ref pk) = deployer_private_key {
        let signer: PrivateKeySigner = pk
            .parse()
            .map_err(|e| eyre::eyre!("invalid deployer private key: {e}"))?;
        println!("deployer address: {}", signer.address());
        state["deployerPrivateKey"] = json!(pk);
    }
    if let Some(ref pk) = gateway_deployer_private_key {
        let signer: PrivateKeySigner = pk
            .parse()
            .map_err(|e| eyre::eyre!("invalid gateway deployer private key: {e}"))?;
        let gw_addr = signer.address();
        println!("gateway deployer address: {gw_addr}");
        state["gatewayDeployerPrivateKey"] = json!(pk);
        state["gatewayDeployer"] = json!(format!("{gw_addr}"));
    }
    if let Some(ref pk) = gas_service_deployer_private_key {
        let signer: PrivateKeySigner = pk
            .parse()
            .map_err(|e| eyre::eyre!("invalid gas service deployer private key: {e}"))?;
        println!("gas service deployer address: {}", signer.address());
        state["gasServiceDeployerPrivateKey"] = json!(pk);
    }

    let state_file = state_path(&axelar_id)?;
    save_state(&axelar_id, &state)?;
    println!("saved state to {}", state_file.display());
    println!("init complete for '{axelar_id}' (env={env})");

    // Query and display the deployer balance
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

    Ok(())
}

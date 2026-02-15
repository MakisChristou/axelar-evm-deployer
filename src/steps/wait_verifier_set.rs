use std::fs;

use eyre::Result;
use serde_json::{Value, json};

use crate::commands::deploy::DeployContext;
use crate::cosmos::{
    build_execute_msg_any, derive_axelar_wallet, lcd_cosmwasm_smart_query, read_axelar_config,
    read_axelar_contract_field, sign_and_broadcast_cosmos_tx,
};

pub async fn run(ctx: &DeployContext) -> Result<()> {
    let content = fs::read_to_string(&ctx.target_json)?;
    let root: Value = serde_json::from_str(&content)?;
    let chain_axelar_id = root
        .pointer(&format!("/chains/{}/axelarId", ctx.axelar_id))
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.axelar_id)
        .to_string();
    let rpc_url = ctx.state["rpcUrl"].as_str().unwrap_or("").to_string();

    let prover_addr = read_axelar_contract_field(
        &ctx.target_json,
        &format!("/axelar/contracts/MultisigProver/{chain_axelar_id}/address"),
    )?;
    let verifier_addr = read_axelar_contract_field(
        &ctx.target_json,
        &format!("/axelar/contracts/VotingVerifier/{chain_axelar_id}/address"),
    )?;
    let multisig_addr =
        read_axelar_contract_field(&ctx.target_json, "/axelar/contracts/Multisig/address")?;
    let service_registry_addr = read_axelar_contract_field(
        &ctx.target_json,
        "/axelar/contracts/ServiceRegistry/address",
    )?;
    let admin_addr = if let Some(admin_mn) = ctx.state["adminMnemonic"].as_str() {
        let (_, addr) = derive_axelar_wallet(admin_mn)?;
        addr
    } else {
        root.pointer("/axelar/multisigProverAdminAddress")
            .and_then(|v| v.as_str())
            .unwrap_or("<prover-admin>")
            .to_string()
    };
    let axelar_chain_id = root
        .pointer("/axelar/chainId")
        .and_then(|v| v.as_str())
        .unwrap_or("<chain-id>");
    let axelar_rpc = root
        .pointer("/axelar/rpc")
        .and_then(|v| v.as_str())
        .unwrap_or("<rpc>");

    let (lcd, chain_id, fee_denom, gas_price) = read_axelar_config(&ctx.target_json)?;
    let env = ctx.state["env"].as_str().unwrap_or("testnet");

    // Check if verifier set already exists
    let query_msg = json!("current_verifier_set");
    if let Ok(data) = lcd_cosmwasm_smart_query(&lcd, &prover_addr, &query_msg).await {
        if !data.is_null() && data.get("id").is_some() {
            let id = data["id"].as_str().unwrap_or("?");
            println!("verifier set already exists! id: {id}");
            return Ok(());
        }
    }

    // Print instructions and poll
    println!("waiting for verifier set on MultisigProver ({prover_addr})...");
    println!();
    println!("  ACTION REQUIRED: An admin must complete these steps in order:");
    println!();
    println!("  1. Open a PR in https://github.com/axelarnetwork/infrastructure");
    println!();
    println!(
        "     File: infrastructure/{env}/apps/axelar-{env}/ampd/ampd-epsilon/helm-values.yaml"
    );
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
    println!(
        "     File: infrastructure/{env}/apps/axelar-{env}/ampd/ampd/helm-values.yaml"
    );
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
    println!(
        "       --from {admin_addr} --chain-id {axelar_chain_id} --node {axelar_rpc} \\"
    );
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
                    println!(
                        "  {count} active verifiers registered for {chain_axelar_id} (>= {min_verifiers})"
                    );
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
    if let Some(admin_mn) = ctx.state["adminMnemonic"].as_str() {
        println!("  calling update_verifier_set with admin key...");
        let (admin_key, admin_address) = derive_axelar_wallet(admin_mn)?;
        let execute_msg = json!("update_verifier_set");
        let msg_any = build_execute_msg_any(&admin_address, &prover_addr, &execute_msg)?;
        sign_and_broadcast_cosmos_tx(
            &admin_key,
            &admin_address,
            &lcd,
            &chain_id,
            &fee_denom,
            gas_price,
            vec![msg_any],
        )
        .await?;
        println!("  update_verifier_set tx succeeded!");
    } else {
        println!("  no admin mnemonic provided, waiting for manual update_verifier_set...");
        println!("  (provide MULTISIG_PROVER_MNEMONIC in .env to automate this)");
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

    Ok(())
}

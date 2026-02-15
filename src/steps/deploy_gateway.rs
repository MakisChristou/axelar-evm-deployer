use std::fs;

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use eyre::Result;
use serde_json::{Value, json};

use crate::commands::deploy::DeployContext;
use crate::cosmos::fetch_verifier_set;
use crate::evm::{decode_evm_error, encode_gateway_setup_params, read_artifact_bytecode};
use crate::state::save_state;
use crate::utils::{compute_domain_separator, update_target_json};

pub async fn run(
    ctx: &mut DeployContext,
    step_idx: usize,
    step: &Value,
    private_key: &str,
    impl_artifact: &str,
    proxy_artifact: &str,
) -> Result<()> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let deployer_addr = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(ctx.rpc_url.parse()?);

    let domain_separator = compute_domain_separator(&ctx.target_json, &ctx.axelar_id)?;

    let previous_signers_retention = U256::from(15);
    let minimum_rotation_delay = U256::from(3600);

    // --- Tx 1: Deploy implementation (skip if already deployed) ---
    let (impl_addr, impl_codehash) =
        if let Some(saved) = step.get("implementationAddress").and_then(|v| v.as_str()) {
            let addr = saved.parse()?;
            let code = provider.get_code_at(addr).await?;
            if code.is_empty() {
                return Err(eyre::eyre!(
                    "saved implementation {addr} has no code on-chain"
                ));
            }
            println!("reusing previously deployed implementation: {addr}");
            (addr, keccak256(&code))
        } else {
            println!("deploying AxelarAmplifierGateway implementation...");
            let impl_bytecode = read_artifact_bytecode(impl_artifact)?;
            let mut impl_deploy_code = impl_bytecode.clone();
            impl_deploy_code.extend_from_slice(
                &(
                    previous_signers_retention,
                    domain_separator,
                    minimum_rotation_delay,
                )
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
            if let Some(s) = ctx.state["steps"]
                .as_array_mut()
                .and_then(|a| a.get_mut(step_idx))
            {
                s["implementationAddress"] = json!(format!("{addr}"));
            }
            save_state(&ctx.axelar_id, &ctx.state)?;

            (addr, codehash)
        };

    // --- Fetch verifier set from Axelar chain ---
    let chain_axelar_id = {
        let content = fs::read_to_string(&ctx.target_json)?;
        let root: Value = serde_json::from_str(&content)?;
        root.pointer(&format!("/chains/{}/axelarId", ctx.axelar_id))
            .and_then(|v| v.as_str())
            .unwrap_or(&ctx.axelar_id)
            .to_string()
    };
    let (signers, threshold, nonce, verifier_set_id) =
        fetch_verifier_set(&ctx.target_json, &chain_axelar_id).await?;

    // --- Encode setup params ---
    let operator = deployer_addr;
    let owner = deployer_addr;
    let setup_params = encode_gateway_setup_params(operator, &signers, threshold, nonce);
    println!(
        "setup params ({} bytes): 0x{}",
        setup_params.len(),
        hex::encode(&setup_params)
    );

    // --- Tx 2: Deploy proxy ---
    println!("deploying AxelarAmplifierGatewayProxy...");
    let proxy_bytecode = read_artifact_bytecode(proxy_artifact)?;
    let mut proxy_deploy_code = proxy_bytecode.clone();
    proxy_deploy_code
        .extend_from_slice(&(impl_addr, owner, setup_params.clone()).abi_encode_params());

    let proxy_deploy_bytes = Bytes::from(proxy_deploy_code);
    let tx = TransactionRequest::default()
        .with_deploy_code(proxy_deploy_bytes.clone())
        .with_gas_limit(5_000_000);

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
    let mut contract_data = serde_json::Map::new();
    contract_data.insert("address".into(), json!(format!("{proxy_addr}")));
    contract_data.insert("implementation".into(), json!(format!("{impl_addr}")));
    contract_data.insert("deployer".into(), json!(format!("{deployer_addr}")));
    contract_data.insert("deploymentMethod".into(), json!("create"));
    contract_data.insert(
        "implementationCodehash".into(),
        json!(format!("{impl_codehash}")),
    );
    contract_data.insert("previousSignersRetention".into(), json!(15));
    contract_data.insert(
        "domainSeparator".into(),
        json!(format!("{domain_separator}")),
    );
    contract_data.insert("minimumRotationDelay".into(), json!(3600));
    contract_data.insert("operator".into(), json!(format!("{operator}")));
    contract_data.insert("owner".into(), json!(format!("{owner}")));
    contract_data.insert("connectionType".into(), json!("amplifier"));
    contract_data.insert("initialVerifierSetId".into(), json!(verifier_set_id));

    update_target_json(
        &ctx.target_json,
        &ctx.axelar_id,
        "AxelarGateway",
        Value::Object(contract_data),
    )?;

    Ok(())
}

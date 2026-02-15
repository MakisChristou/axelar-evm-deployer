use std::path::PathBuf;

use alloy::{
    network::TransactionBuilder,
    primitives::{keccak256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::{SolEvent, SolValue},
};
use eyre::Result;
use serde_json::json;

use crate::cli::resolve_axelar_id;
use crate::cosmos::{
    build_execute_msg_any, derive_axelar_wallet, lcd_cosmwasm_smart_query, read_axelar_config,
    read_axelar_contract_field, sign_and_broadcast_cosmos_tx,
};
use crate::evm::{ContractCall, SenderReceiver, read_artifact_bytecode};
use crate::state::{read_state, save_state};
use crate::utils::read_contract_address;

pub async fn run(axelar_id: Option<String>) -> Result<()> {
    let axelar_id = resolve_axelar_id(axelar_id)?;
    let mut state = read_state(&axelar_id)?;

    let rpc_url: String = state["rpcUrl"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no rpcUrl in state"))?
        .to_string();
    let target_json = PathBuf::from(
        state["targetJson"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("no targetJson in state"))?,
    );

    let private_key = state["deployerPrivateKey"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no deployerPrivateKey in state"))?
        .to_string();

    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc_url.parse()?);

    let gateway_addr = read_contract_address(&target_json, &axelar_id, "AxelarGateway")?;
    let gas_service_addr = read_contract_address(&target_json, &axelar_id, "AxelarGasService")?;

    println!("gateway: {gateway_addr}");
    println!("gas service: {gas_service_addr}");

    // --- Deploy SenderReceiver if needed ---
    let sender_receiver_addr = if let Some(addr_str) = state
        .get("senderReceiverAddress")
        .and_then(|v| v.as_str())
    {
        let addr: alloy::primitives::Address = addr_str.parse()?;
        let code = provider.get_code_at(addr).await?;
        if code.is_empty() {
            println!("SenderReceiver at {addr} has no code, redeploying...");
            deploy_sender_receiver(&provider, gateway_addr, gas_service_addr).await?
        } else {
            println!("SenderReceiver: reusing {addr}");
            addr
        }
    } else {
        println!("deploying SenderReceiver...");
        deploy_sender_receiver(&provider, gateway_addr, gas_service_addr).await?
    };

    state["senderReceiverAddress"] = json!(format!("{sender_receiver_addr}"));
    save_state(&axelar_id, &state)?;
    println!("SenderReceiver: {sender_receiver_addr}");

    // --- Send GMP message ---
    let destination_chain = axelar_id.clone();
    let destination_address = format!("{sender_receiver_addr}");
    let message = "hello from axelar evm deployer".to_string();

    println!("\nsending GMP callContract...");
    println!("  destination chain: {destination_chain}");
    println!("  destination address: {destination_address}");
    println!("  message: \"{message}\"");

    let contract = SenderReceiver::new(sender_receiver_addr, &provider);
    let call = contract
        .sendMessage(
            destination_chain.clone(),
            destination_address.clone(),
            message.clone(),
        )
        .value(U256::from(1_000_000_000_000_000u64)); // 0.001 ETH for gas payment

    let pending = call.send().await?;
    let tx_hash = *pending.tx_hash();
    println!("  tx: {tx_hash} (waiting for confirmation...)");

    let receipt = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        pending.get_receipt(),
    )
    .await
    .map_err(|_| eyre::eyre!("tx {tx_hash} timed out after 120s"))??;

    println!(
        "  confirmed in block {}",
        receipt.block_number.unwrap_or(0)
    );

    // --- Extract ContractCall event index from receipt ---
    let event_index = receipt
        .inner
        .logs()
        .iter()
        .enumerate()
        .find_map(|(i, log)| {
            if log.topics().first() == Some(&ContractCall::SIGNATURE_HASH) {
                Some(i)
            } else {
                None
            }
        })
        .ok_or_else(|| eyre::eyre!("ContractCall event not found in receipt logs"))?;

    let payload_bytes = (message,).abi_encode_params();
    let payload_hash = keccak256(&payload_bytes);
    let message_id = format!("{tx_hash:#x}-{event_index}");

    println!("\nGMP call submitted!");
    println!("  message_id: {message_id}");
    println!("  payload_hash: {payload_hash}");

    // --- Amplifier routing ---
    println!("\n--- Amplifier routing ---");

    let mnemonic = state["mnemonic"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no mnemonic in state"))?;
    let (signing_key, axelar_address) = derive_axelar_wallet(mnemonic)?;
    let (lcd, chain_id, fee_denom, gas_price) = read_axelar_config(&target_json)?;

    let cosm_gateway = read_axelar_contract_field(
        &target_json,
        &format!("/axelar/contracts/Gateway/{axelar_id}/address"),
    )?;
    let voting_verifier = read_axelar_contract_field(
        &target_json,
        &format!("/axelar/contracts/VotingVerifier/{axelar_id}/address"),
    )?;

    println!("  cosmos gateway: {cosm_gateway}");
    println!("  voting verifier: {voting_verifier}");
    println!("  axelar address: {axelar_address}");

    // Build the message object (shared by verify and route)
    let gmp_msg = json!({
        "cc_id": {
            "message_id": message_id,
            "source_chain": axelar_id,
        },
        "destination_chain": destination_chain,
        "destination_address": destination_address,
        "source_address": format!("{sender_receiver_addr}"),
        "payload_hash": format!("{}", alloy::hex::encode(payload_hash.as_slice())),
    });

    // Step 1: verify_messages
    println!("\nstep 1: verify_messages...");
    let verify_msg = json!({ "verify_messages": [gmp_msg] });
    let verify_any = build_execute_msg_any(&axelar_address, &cosm_gateway, &verify_msg)?;
    let verify_resp = sign_and_broadcast_cosmos_tx(
        &signing_key,
        &axelar_address,
        &lcd,
        &chain_id,
        &fee_denom,
        gas_price,
        vec![verify_any],
    )
    .await?;

    // Extract poll_id from tx events
    let poll_id = extract_poll_id(&verify_resp)?;
    println!("  poll_id: {poll_id}");

    // Step 2: Poll VotingVerifier until poll passes
    println!("\nstep 2: waiting for poll to pass...");
    wait_for_poll(&lcd, &voting_verifier, &poll_id).await?;
    println!("  poll passed!");

    // Step 3: route_messages
    println!("\nstep 3: route_messages...");
    let route_msg = json!({ "route_messages": [gmp_msg] });
    let route_any = build_execute_msg_any(&axelar_address, &cosm_gateway, &route_msg)?;
    sign_and_broadcast_cosmos_tx(
        &signing_key,
        &axelar_address,
        &lcd,
        &chain_id,
        &fee_denom,
        gas_price,
        vec![route_any],
    )
    .await?;

    println!("\nGMP message routed successfully!");

    Ok(())
}

/// Extract poll_id from the verify_messages tx response events.
/// Looks for a wasm event with a "poll_id" attribute.
fn extract_poll_id(tx_resp: &serde_json::Value) -> Result<String> {
    let events = tx_resp
        .pointer("/tx_response/events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre::eyre!("no events in verify_messages tx response"))?;

    for event in events {
        let event_type = event["type"].as_str().unwrap_or("");
        if event_type == "wasm" || event_type.starts_with("wasm-") {
            if let Some(attrs) = event["attributes"].as_array() {
                for attr in attrs {
                    let key = attr["key"].as_str().unwrap_or("");
                    if key == "poll_id" {
                        let val = attr["value"]
                            .as_str()
                            .ok_or_else(|| eyre::eyre!("poll_id attribute has no value"))?;
                        return Ok(val.to_string());
                    }
                }
            }
        }
    }

    // Print all events for debugging
    println!("  debug: tx events:");
    for event in events {
        let event_type = event["type"].as_str().unwrap_or("?");
        if let Some(attrs) = event["attributes"].as_array() {
            for attr in attrs {
                let key = attr["key"].as_str().unwrap_or("?");
                let val = attr["value"].as_str().unwrap_or("?");
                println!("    {event_type}: {key} = {val}");
            }
        }
    }

    Err(eyre::eyre!("poll_id not found in verify_messages tx events"))
}

/// Poll the VotingVerifier until the poll passes or times out.
async fn wait_for_poll(lcd: &str, voting_verifier: &str, poll_id: &str) -> Result<()> {
    let query = json!({ "poll": { "poll_id": poll_id } });

    for i in 0..60 {
        // 60 * 5s = 5 minutes
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        let resp = lcd_cosmwasm_smart_query(lcd, voting_verifier, &query).await?;

        // The poll response contains status info — check for completion
        let resp_str = serde_json::to_string(&resp)?;

        if resp_str.contains("succeeded_on_source_chain")
            || resp_str.contains("SucceededOnSourceChain")
        {
            return Ok(());
        }

        if resp_str.contains("failed_on_source_chain")
            || resp_str.contains("FailedOnSourceChain")
            || resp_str.contains("not_found_on_source_chain")
            || resp_str.contains("NotFoundOnSourceChain")
            || resp_str.contains("failed_to_verify")
            || resp_str.contains("FailedToVerify")
        {
            return Err(eyre::eyre!("poll failed: {resp_str}"));
        }

        if i % 6 == 0 {
            // Print status every 30s
            println!("  still waiting... (attempt {}/60)", i + 1);
        }
    }

    Err(eyre::eyre!("poll {poll_id} timed out after 5 minutes"))
}

async fn deploy_sender_receiver<P: Provider>(
    provider: &P,
    gateway: alloy::primitives::Address,
    gas_service: alloy::primitives::Address,
) -> Result<alloy::primitives::Address> {
    let bytecode = read_artifact_bytecode("artifacts/SenderReceiver.json")?;
    let mut deploy_code = bytecode;
    deploy_code.extend_from_slice(&(gateway, gas_service).abi_encode_params());

    let tx = TransactionRequest::default().with_deploy_code(Bytes::from(deploy_code));

    let pending = provider.send_transaction(tx).await?;
    let tx_hash = *pending.tx_hash();
    println!("  deploy tx: {tx_hash} (waiting for confirmation...)");

    let receipt = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        pending.get_receipt(),
    )
    .await
    .map_err(|_| eyre::eyre!("deploy tx {tx_hash} timed out after 120s"))??;

    let addr = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    println!(
        "  deployed in block {}",
        receipt.block_number.unwrap_or(0)
    );
    Ok(addr)
}

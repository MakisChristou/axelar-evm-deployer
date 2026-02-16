use std::path::PathBuf;
use std::time::Instant;

use alloy::{
    network::TransactionBuilder,
    primitives::{Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::{SolEvent, SolValue},
};
use eyre::Result;
use serde_json::json;

use crate::cli::resolve_axelar_id;
use crate::commands::test_helpers::{
    extract_event_attr, extract_poll_id, wait_for_poll_votes, wait_for_proof,
};
use crate::cosmos::{
    build_execute_msg_any, derive_axelar_wallet, read_axelar_config, read_axelar_contract_field,
    sign_and_broadcast_cosmos_tx,
};
use crate::evm::{AxelarAmplifierGateway, ContractCall, SenderReceiver, read_artifact_bytecode};
use crate::state::{read_state, save_state};
use crate::ui;
use crate::utils::read_contract_address;

const TOTAL_STEPS: usize = 8;

pub async fn run(axelar_id: Option<String>) -> Result<()> {
    let axelar_id = resolve_axelar_id(axelar_id)?;
    let mut state = read_state(&axelar_id)?;
    let gmp_start = Instant::now();

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

    ui::section(&format!("GMP Test: {axelar_id}"));
    ui::address("gateway", &format!("{gateway_addr}"));
    ui::address("gas service", &format!("{gas_service_addr}"));

    // --- Deploy SenderReceiver if needed ---
    let sender_receiver_addr =
        if let Some(addr_str) = state.get("senderReceiverAddress").and_then(|v| v.as_str()) {
            let addr: alloy::primitives::Address = addr_str.parse()?;
            let code = provider.get_code_at(addr).await?;
            if code.is_empty() {
                ui::warn(&format!(
                    "SenderReceiver at {addr} has no code, redeploying..."
                ));
                deploy_sender_receiver(&provider, gateway_addr, gas_service_addr).await?
            } else {
                ui::info(&format!("SenderReceiver: reusing {addr}"));
                addr
            }
        } else {
            ui::info("deploying SenderReceiver...");
            deploy_sender_receiver(&provider, gateway_addr, gas_service_addr).await?
        };

    state["senderReceiverAddress"] = json!(format!("{sender_receiver_addr}"));
    save_state(&axelar_id, &state)?;
    ui::address("SenderReceiver", &format!("{sender_receiver_addr}"));

    // --- Send GMP message ---
    let destination_chain = axelar_id.clone();
    let destination_address = format!("{sender_receiver_addr}");
    let message = "hello from axelar evm deployer".to_string();

    ui::step_header(1, TOTAL_STEPS, "Send GMP callContract");
    ui::kv("destination chain", &destination_chain);
    ui::kv("destination address", &destination_address);
    ui::kv("message", &format!("\"{message}\""));

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
    ui::tx_hash("tx", &format!("{tx_hash}"));
    ui::info("waiting for confirmation...");

    let receipt = tokio::time::timeout(std::time::Duration::from_secs(120), pending.get_receipt())
        .await
        .map_err(|_| eyre::eyre!("tx {tx_hash} timed out after 120s"))??;

    ui::success(&format!(
        "confirmed in block {}",
        receipt.block_number.unwrap_or(0)
    ));

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

    ui::kv("message_id", &message_id);
    ui::kv("payload_hash", &format!("{payload_hash}"));

    // --- Amplifier routing ---
    ui::section("Amplifier Routing");

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

    ui::address("cosmos gateway", &cosm_gateway);
    ui::address("voting verifier", &voting_verifier);
    ui::address("axelar address", &axelar_address);

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

    // Step 2: verify_messages
    ui::step_header(2, TOTAL_STEPS, "verify_messages");
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

    if let Some(poll_id) = extract_poll_id(&verify_resp) {
        ui::kv("poll_id", &poll_id);

        // Step 3: Wait for votes + end poll
        ui::step_header(3, TOTAL_STEPS, "Wait for poll votes + end poll");
        wait_for_poll_votes(&lcd, &voting_verifier, &poll_id).await?;

        // End the poll — retry if it hasn't expired yet (blockExpiry not reached)
        let spinner = ui::wait_spinner("Ending poll (waiting for block expiry)...");
        for attempt in 0..60 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            let end_poll_msg = json!({ "end_poll": { "poll_id": poll_id } });
            let end_poll_any =
                build_execute_msg_any(&axelar_address, &voting_verifier, &end_poll_msg)?;
            match sign_and_broadcast_cosmos_tx(
                &signing_key,
                &axelar_address,
                &lcd,
                &chain_id,
                &fee_denom,
                gas_price,
                vec![end_poll_any],
            )
            .await
            {
                Ok(_) => {
                    spinner.finish_and_clear();
                    ui::success("poll ended");
                    break;
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("cannot tally before poll end") {
                        spinner.set_message(format!(
                            "Poll not expired yet (attempt {})...",
                            attempt + 1
                        ));
                        continue;
                    }
                    spinner.finish_and_clear();
                    return Err(e);
                }
            }
        }
    } else {
        ui::info("no new poll created — message already being verified by active verifiers");
        ui::step_header(3, TOTAL_STEPS, "Wait for poll votes + end poll");
        ui::info("skipped (existing poll)");
    }

    // Step 4: route_messages
    ui::step_header(4, TOTAL_STEPS, "route_messages");
    let spinner = ui::wait_spinner("Routing message...");
    for attempt in 0..60 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        let route_msg = json!({ "route_messages": [gmp_msg] });
        let route_any = build_execute_msg_any(&axelar_address, &cosm_gateway, &route_msg)?;
        match sign_and_broadcast_cosmos_tx(
            &signing_key,
            &axelar_address,
            &lcd,
            &chain_id,
            &fee_denom,
            gas_price,
            vec![route_any],
        )
        .await
        {
            Ok(_) => {
                spinner.finish_and_clear();
                ui::success("message routed");
                break;
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("not verified") {
                    spinner.set_message(format!(
                        "Message not yet verified (attempt {}/60)...",
                        attempt + 1
                    ));
                    continue;
                }
                spinner.finish_and_clear();
                return Err(e);
            }
        }
    }

    // Step 5: construct_proof on MultisigProver
    ui::step_header(5, TOTAL_STEPS, "construct_proof");
    let multisig_prover = read_axelar_contract_field(
        &target_json,
        &format!("/axelar/contracts/MultisigProver/{axelar_id}/address"),
    )?;
    ui::address("multisig prover", &multisig_prover);

    let construct_proof_msg = json!({
        "construct_proof": [{
            "source_chain": axelar_id,
            "message_id": message_id,
        }]
    });
    let construct_any =
        build_execute_msg_any(&axelar_address, &multisig_prover, &construct_proof_msg)?;
    let construct_resp = sign_and_broadcast_cosmos_tx(
        &signing_key,
        &axelar_address,
        &lcd,
        &chain_id,
        &fee_denom,
        gas_price,
        vec![construct_any],
    )
    .await?;

    let session_id = extract_event_attr(&construct_resp, "multisig_session_id")?;
    ui::kv("multisig_session_id", &session_id);

    // Step 6: Poll proof until signed
    ui::step_header(6, TOTAL_STEPS, "Wait for proof signing");
    let proof = wait_for_proof(&lcd, &multisig_prover, &session_id).await?;
    ui::success("proof ready");

    // Step 7: Submit execute_data to EVM gateway + check approval
    ui::step_header(7, TOTAL_STEPS, "Submit proof to EVM gateway");
    let execute_data_hex = proof["status"]["completed"]["execute_data"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no execute_data in proof response"))?;
    let execute_data = alloy::hex::decode(execute_data_hex)?;

    let approve_tx = TransactionRequest::default()
        .to(gateway_addr)
        .input(Bytes::from(execute_data).into());
    let pending_approve = provider.send_transaction(approve_tx).await?;
    let approve_hash = *pending_approve.tx_hash();
    ui::tx_hash("tx", &format!("{approve_hash}"));
    ui::info("waiting for confirmation...");

    let approve_receipt = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        pending_approve.get_receipt(),
    )
    .await
    .map_err(|_| eyre::eyre!("approve tx timed out after 120s"))??;

    ui::success(&format!(
        "confirmed in block {}",
        approve_receipt.block_number.unwrap_or(0)
    ));

    // Extract commandId from the ContractCallApproved event (topic[1])
    let command_id = approve_receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            if log.topics().len() >= 2 && log.address() == gateway_addr {
                Some(log.topics()[1])
            } else {
                None
            }
        })
        .ok_or_else(|| eyre::eyre!("commandId not found in approve tx logs"))?;
    ui::kv("commandId", &format!("{command_id}"));

    let gw_contract = AxelarAmplifierGateway::new(gateway_addr, &provider);
    let approved = gw_contract
        .isContractCallApproved(
            command_id,
            axelar_id.clone(),
            format!("{sender_receiver_addr}"),
            sender_receiver_addr,
            payload_hash,
        )
        .call()
        .await?;
    ui::kv("isContractCallApproved", &format!("{approved}"));

    if !approved {
        return Err(eyre::eyre!("message not approved on EVM gateway"));
    }

    // Step 8: Execute on SenderReceiver
    ui::step_header(8, TOTAL_STEPS, "Execute on SenderReceiver");
    let sr_contract = SenderReceiver::new(sender_receiver_addr, &provider);
    let exec_call = sr_contract.execute(
        command_id,
        axelar_id.clone(),
        format!("{sender_receiver_addr}"),
        Bytes::from(payload_bytes.clone()),
    );
    let pending_exec = exec_call.send().await?;
    let exec_hash = *pending_exec.tx_hash();
    ui::tx_hash("tx", &format!("{exec_hash}"));
    ui::info("waiting for confirmation...");

    let exec_receipt = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        pending_exec.get_receipt(),
    )
    .await
    .map_err(|_| eyre::eyre!("execute tx timed out after 120s"))??;

    ui::success(&format!(
        "confirmed in block {}",
        exec_receipt.block_number.unwrap_or(0)
    ));

    // Verify the message was stored
    let stored_message = sr_contract.message().call().await?;
    ui::kv("stored message", &format!("\"{stored_message}\""));

    ui::section("Complete");
    ui::success(&format!(
        "GMP flow complete ({})",
        ui::format_elapsed(gmp_start)
    ));

    Ok(())
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
    ui::tx_hash("deploy tx", &format!("{tx_hash}"));
    ui::info("waiting for confirmation...");

    let receipt = tokio::time::timeout(std::time::Duration::from_secs(120), pending.get_receipt())
        .await
        .map_err(|_| eyre::eyre!("deploy tx {tx_hash} timed out after 120s"))??;

    let addr = receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("no contract address in receipt"))?;

    ui::success(&format!(
        "deployed in block {}",
        receipt.block_number.unwrap_or(0)
    ));
    Ok(addr)
}

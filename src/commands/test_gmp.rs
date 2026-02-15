use std::path::PathBuf;

use alloy::{
    network::TransactionBuilder,
    primitives::{Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use eyre::Result;
use serde_json::json;

use crate::cli::resolve_axelar_id;
use crate::evm::{SenderReceiver, read_artifact_bytecode};
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
    let _deployer_addr = signer.address();
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
            deploy_sender_receiver(
                &provider, gateway_addr, gas_service_addr,
            ).await?
        } else {
            println!("SenderReceiver: reusing {addr}");
            addr
        }
    } else {
        println!("deploying SenderReceiver...");
        deploy_sender_receiver(
            &provider, gateway_addr, gas_service_addr,
        ).await?
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

    // Encode payload the same way the contract does: abi.encode(message)
    let payload_hex = alloy::hex::encode((message,).abi_encode_params());
    println!("\nGMP call submitted!");
    println!("  tx hash: {tx_hash}");
    println!("  payload: 0x{payload_hex}");
    println!("\nNext: route this message through Amplifier to complete the GMP flow.");

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

    let tx = TransactionRequest::default()
        .with_deploy_code(Bytes::from(deploy_code));

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

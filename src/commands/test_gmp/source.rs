use alloy::{
    primitives::{Address, B256, keccak256},
    providers::Provider,
    sol_types::{SolEvent, SolValue},
};
use eyre::Result;

use crate::evm::{ContractCall, SenderReceiver};
use crate::ui;

/// The bits of a freshly sent GMP `callContract` that downstream Amplifier
/// steps need: the routing fields, the message id, and both the raw payload
/// (for `execute`) and its hash (for `isContractCallApproved`).
pub struct SentGmp {
    pub destination_chain: String,
    pub destination_address: String,
    pub message_id: String,
    pub payload_bytes: Vec<u8>,
    pub payload_hash: B256,
}

/// Step 1 of the GMP smoke test: call `sendMessage` on the SenderReceiver,
/// then locate the ContractCall log in the receipt to derive the message id
/// (`<tx_hash>-<log_index>`). The flow loops back to the same chain, so the
/// destination is `(source_chain, sender_receiver)`.
pub async fn send_evm_call_contract<P: Provider>(
    provider: &P,
    sender_receiver: Address,
    source_chain: &str,
    step_idx: usize,
    total_steps: usize,
) -> Result<SentGmp> {
    let destination_chain = source_chain.to_string();
    let destination_address = format!("{sender_receiver}");
    let message = "hello from axelar evm deployer".to_string();

    ui::step_header(step_idx, total_steps, "Send GMP callContract");
    ui::kv("destination chain", &destination_chain);
    ui::kv("destination address", &destination_address);
    ui::kv("message", &format!("\"{message}\""));

    let contract = SenderReceiver::new(sender_receiver, provider);
    let call = contract
        .sendMessage(
            destination_chain.clone(),
            destination_address.clone(),
            message.clone(),
        )
        .value(crate::types::eth_milli(1)); // 0.001 ETH cross-chain gas budget

    let pending = call.send().await?;
    let tx_hash = *pending.tx_hash();
    let receipt = crate::evm::broadcast_and_log(pending, "tx").await?;

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

    Ok(SentGmp {
        destination_chain,
        destination_address,
        message_id,
        payload_bytes,
        payload_hash,
    })
}

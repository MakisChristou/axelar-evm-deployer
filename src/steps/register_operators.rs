use alloy::{providers::ProviderBuilder, signers::local::PrivateKeySigner};
use eyre::Result;

use crate::commands::deploy::DeployContext;
use crate::evm::Operators;
use crate::timing::EVM_TX_RECEIPT_TIMEOUT;
use crate::ui;
use crate::utils::read_contract_address;

pub async fn run(ctx: &DeployContext, private_key: &str) -> Result<()> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(ctx.rpc_url.parse()?);

    let operators_addr = read_contract_address(&ctx.target_json, &ctx.axelar_id, "Operators")?;
    let operators = Operators::new(operators_addr, &provider);

    let operator_addrs = ctx.state.env.axelar_operators();

    for op in operator_addrs {
        let already = operators.isOperator(*op).call().await?;
        if already {
            ui::info(&format!("operator {op} already registered, skipping"));
            continue;
        }
        ui::info(&format!("adding operator: {op}"));
        let pending = operators.addOperator(*op).send().await?;
        let tx_hash = *pending.tx_hash();
        ui::tx_hash("tx submitted", &format!("{tx_hash}"));
        ui::info("waiting for confirmation (timeout 120s)...");
        let receipt = tokio::time::timeout(EVM_TX_RECEIPT_TIMEOUT, pending.get_receipt())
            .await
            .map_err(|_| {
                eyre::eyre!(
                    "tx {tx_hash} timed out after {}s — check the explorer and re-run deploy to retry",
                    EVM_TX_RECEIPT_TIMEOUT.as_secs()
                )
            })??;
        ui::success(&format!(
            "confirmed in block {}",
            receipt.block_number.unwrap_or(0)
        ));
    }

    Ok(())
}

use alloy::{primitives::Address, providers::ProviderBuilder, signers::local::PrivateKeySigner};
use eyre::Result;
use serde_json::{Map, Value, json};

use crate::commands::deploy::DeployContext;
use crate::evm::Ownable;
use crate::ui;
use crate::utils::{patch_target_json, read_contract_address};

pub async fn run(ctx: &DeployContext, step: &Value, private_key: &str) -> Result<()> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(ctx.rpc_url.parse()?);

    let contract_name = step["contract"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no 'contract' field in step"))?;
    let new_owner: Address = step["newOwner"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no 'newOwner' field in step"))?
        .parse()?;

    let contract_addr = read_contract_address(&ctx.target_json, &ctx.axelar_id, contract_name)?;
    let ownable = Ownable::new(contract_addr, &provider);

    ui::info(&format!(
        "transferring {contract_name} ownership to {new_owner}"
    ));
    let tx_hash = ownable
        .transferOwnership(new_owner)
        .send()
        .await?
        .watch()
        .await?;
    ui::tx_hash("tx hash", &format!("{tx_hash}"));

    let current_owner = ownable.owner().call().await?;
    ui::address("verified owner", &format!("{current_owner}"));

    let mut patches = Map::new();
    patches.insert("owner".into(), json!(format!("{new_owner}")));
    patch_target_json(&ctx.target_json, &ctx.axelar_id, contract_name, &patches)?;

    Ok(())
}

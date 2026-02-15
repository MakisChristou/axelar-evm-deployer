use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use eyre::Result;
use serde_json::json;

use crate::commands::deploy::DeployContext;
use crate::evm::compute_create_address;

pub async fn run(ctx: &mut DeployContext) -> Result<()> {
    let gateway_deployer_str = ctx.state["gatewayDeployer"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no gatewayDeployer in state. Run init first"))?;
    let gateway_deployer: Address = gateway_deployer_str.parse()?;

    let provider = ProviderBuilder::new().connect_http(ctx.rpc_url.parse()?);
    let nonce = provider.get_transaction_count(gateway_deployer).await?;
    let proxy_nonce = nonce + 1; // +1 for implementation tx
    let predicted = compute_create_address(gateway_deployer, proxy_nonce);
    println!("gateway deployer: {gateway_deployer}");
    println!("current nonce: {nonce}");
    println!("proxy nonce (impl+1): {proxy_nonce}");
    println!("predicted gateway proxy address: {predicted}");

    ctx.state["predictedGatewayAddress"] = json!(format!("{predicted}"));

    Ok(())
}

use alloy::{
    primitives::Address,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use eyre::Result;

use crate::commands::deploy::DeployContext;
use crate::evm::Operators;
use crate::utils::read_contract_address;

pub async fn run(ctx: &DeployContext, private_key: &str) -> Result<()> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(ctx.rpc_url.parse()?);

    let operators_addr = read_contract_address(&ctx.target_json, &ctx.axelar_id, "Operators")?;
    let operators = Operators::new(operators_addr, &provider);

    let env = ctx.state["env"].as_str().unwrap_or("testnet");
    let operator_addrs: Vec<Address> = match env {
        "testnet" => vec![
            "0x8f23e84c49624a22e8c252684129910509ade4e2".parse()?,
            "0x3b401fa00191acb03c24ebb7754fe35d34dd1abd".parse()?,
        ],
        _ => {
            return Err(eyre::eyre!(
                "operator addresses not configured for env '{env}' — add them to the RegisterOperators handler"
            ))
        }
    };

    for op in &operator_addrs {
        let already = operators.isOperator(*op).call().await?;
        if already {
            println!("operator {op} already registered, skipping");
            continue;
        }
        println!("adding operator: {op}");
        let tx_hash = operators.addOperator(*op).send().await?.watch().await?;
        println!("  tx hash: {tx_hash}");
    }

    Ok(())
}

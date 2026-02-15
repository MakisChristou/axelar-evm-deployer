use std::path::PathBuf;

use eyre::Result;
use serde_json::Value;

use crate::cli::resolve_axelar_id;
use crate::state::{mark_step_completed, next_pending_step, read_state, save_state};
use crate::steps;
use crate::utils::{artifact_paths_for_step, deployments_root};

pub struct DeployContext {
    pub axelar_id: String,
    pub state: Value,
    pub rpc_url: String,
    pub target_json: PathBuf,
}

pub async fn run(
    axelar_id: Option<String>,
    private_key: Option<String>,
    artifact_path: Option<String>,
    salt: Option<String>,
    proxy_artifact_path: Option<String>,
) -> Result<()> {
    let axelar_id = resolve_axelar_id(axelar_id)?;
    let state = read_state(&axelar_id)?;
    let rpc_url = state["rpcUrl"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no rpcUrl in state"))?
        .to_string();
    let target_json = PathBuf::from(
        state["targetJson"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("no targetJson in state"))?,
    );

    let mut ctx = DeployContext {
        axelar_id,
        state,
        rpc_url,
        target_json,
    };

    loop {
        let (step_idx, step) = match next_pending_step(&ctx.state) {
            Some(s) => s,
            None => {
                print_completion_message(&ctx.axelar_id);
                break;
            }
        };

        let step_name = step["name"].as_str().unwrap_or("?").to_string();
        let step_kind = step["kind"].as_str().unwrap_or("?").to_string();

        println!("running step: {step_name} ({step_kind})");

        // Resolve artifact paths: CLI flags override built-in defaults
        let repo_root = deployments_root(&ctx.target_json)?;
        let (resolved_artifact, resolved_proxy_artifact) = {
            let defaults = artifact_paths_for_step(&step_name, &repo_root);
            let art = artifact_path
                .clone()
                .or_else(|| defaults.as_ref().map(|(a, _)| a.clone()));
            let proxy_art = proxy_artifact_path
                .clone()
                .or_else(|| defaults.and_then(|(_, p)| p));
            (art, proxy_art)
        };

        // Resolve EVM private key: --private-key flag > state key based on step
        let resolve_evm_key = |step_name: &str| -> Result<String> {
            if let Some(ref pk) = private_key {
                return Ok(pk.clone());
            }
            let state_key = match step_name {
                "ConstAddressDeployer" | "Create3Deployer" => "deployerPrivateKey",
                "AxelarGateway" => "gatewayDeployerPrivateKey",
                "Operators" | "RegisterOperators" | "TransferOperatorsOwnership"
                | "TransferGatewayOwnership" => "gatewayDeployerPrivateKey",
                "TransferGasServiceOwnership" => "gasServiceDeployerPrivateKey",
                "AxelarGasService" => "gasServiceDeployerPrivateKey",
                _ => {
                    return Err(eyre::eyre!(
                        "--private-key required for step {step_name}"
                    ))
                }
            };
            ctx.state[state_key]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    eyre::eyre!(
                        "no {state_key} in state and --private-key not provided. Run init with the key or pass --private-key"
                    )
                })
        };

        match step_kind.as_str() {
            "deploy-create" | "deploy-create2" => {
                let pk = resolve_evm_key(&step_name)?;
                let ap = resolved_artifact
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--artifact-path required for deploy steps"))?;
                steps::evm_deploy::run(
                    &mut ctx,
                    &step_name,
                    &step_kind,
                    &pk,
                    ap,
                    &salt,
                )
                .await?;
            }

            "register-operators" => {
                let pk = resolve_evm_key(&step_name)?;
                steps::register_operators::run(&ctx, &pk).await?;
            }

            "transfer-ownership" => {
                let pk = resolve_evm_key(&step_name)?;
                steps::transfer_ownership::run(&ctx, &step, &pk).await?;
            }

            "deploy-gateway" => {
                let pk = resolve_evm_key(&step_name)?;
                let impl_art = resolved_artifact
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--artifact-path required (implementation artifact)"))?;
                let proxy_art = resolved_proxy_artifact
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--proxy-artifact-path required (proxy artifact)"))?;
                steps::deploy_gateway::run(
                    &mut ctx, step_idx, &step, &pk, impl_art, proxy_art,
                )
                .await?;
            }

            "predict-address" => {
                steps::predict_address::run(&mut ctx).await?;
            }

            "config-edit" => {
                steps::config_edit::run(&ctx)?;
            }

            "cosmos-tx" => {
                steps::cosmos_tx::run(&mut ctx, &step, &step_name).await?;
            }

            "cosmos-poll" => {
                steps::cosmos_poll::run(&ctx, &step).await?;
            }

            "cosmos-query" => {
                steps::cosmos_query::run(&ctx).await?;
            }

            "wait-verifier-set" => {
                steps::wait_verifier_set::run(&ctx).await?;
            }

            "deploy-upgradable" => {
                let pk = resolve_evm_key(&step_name)?;
                let impl_art = resolved_artifact
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--artifact-path required (implementation artifact)"))?;
                let proxy_art = resolved_proxy_artifact
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--proxy-artifact-path required (proxy artifact)"))?;
                steps::deploy_upgradable::run(
                    &mut ctx, step_idx, &step, &step_name, &pk, impl_art, proxy_art,
                )
                .await?;
            }

            other => {
                return Err(eyre::eyre!("unknown step kind: {other}"));
            }
        }

        mark_step_completed(&mut ctx.state, step_idx);
        save_state(&ctx.axelar_id, &ctx.state)?;
        println!("step '{step_name}' completed\n");
    }

    Ok(())
}

fn print_completion_message(axelar_id: &str) {
    println!("All steps completed! {axelar_id} EVM deployment is fully done.\n");
    println!("To test GMP (EVM -> {axelar_id}):\n");
    println!("  1. Send a GMP call from another chain:");
    println!("     ts-node evm/gateway.js -n [source-chain] --action callContract \\");
    println!("       --destinationChain {axelar_id} \\");
    println!("       --destination 0xba76c6980428A0b10CFC5d8ccb61949677A61233 --payload 0x1234\n");
    println!("  2. Route via Amplifier:");
    println!("     https://docs.axelar.dev/dev/amplifier/chain-integration/relay-messages\n");
    println!("  3. Submit proof:");
    println!("     ts-node evm/gateway.js -n {axelar_id} --action submitProof \\");
    println!("       --multisigSessionId [session-id]\n");
    println!("  4. Verify approval:");
    println!("     ts-node evm/gateway.js -n {axelar_id} --action isContractCallApproved \\");
    println!(
        "       --commandID [id] --sourceChain [chain] --sourceAddress [addr] \\"
    );
    println!("       --destination [addr] --payloadHash [hash]");
}

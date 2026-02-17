use std::path::PathBuf;
use std::time::Instant;

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use eyre::Result;
use serde_json::{Value, json};

use crate::cli::resolve_axelar_id;
use crate::preflight;
use crate::state::{mark_step_completed, migrate_steps, next_pending_step, read_state, save_state};
use crate::steps;
use crate::ui;
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
    let mut state = read_state(&axelar_id)?;

    // Migrate: append any new steps added since this state was created
    migrate_steps(&mut state);

    // Load ITS config from env vars if not already in state
    if state
        .get("itsDeployerPrivateKey")
        .and_then(|v| v.as_str())
        .is_none()
        && let Ok(pk) = std::env::var("ITS_DEPLOYER_PRIVATE_KEY") {
            state["itsDeployerPrivateKey"] = json!(pk);
            ui::info("loaded ITS_DEPLOYER_PRIVATE_KEY from env");
        }
    if state.get("itsSalt").and_then(|v| v.as_str()).is_none()
        && let Ok(s) = std::env::var("ITS_SALT") {
            state["itsSalt"] = json!(s);
            ui::info(&format!("loaded ITS_SALT from env: {s}"));
        }
    if state.get("itsProxySalt").and_then(|v| v.as_str()).is_none()
        && let Ok(s) = std::env::var("ITS_PROXY_SALT") {
            state["itsProxySalt"] = json!(s);
            ui::info(&format!("loaded ITS_PROXY_SALT from env: {s}"));
        }

    save_state(&axelar_id, &state)?;

    let rpc_url = state["rpcUrl"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no rpcUrl in state"))?
        .to_string();
    let target_json = PathBuf::from(
        state["targetJson"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("no targetJson in state"))?,
    );

    let env = state["env"].as_str().unwrap_or("?");
    let total_steps = state["steps"].as_array().map(|a| a.len()).unwrap_or(0);
    let deploy_start = Instant::now();

    ui::section(&format!("Deploy {axelar_id}"));
    ui::kv("environment", env);
    ui::kv("rpc", &rpc_url);
    ui::kv("steps", &total_steps.to_string());

    let mut ctx = DeployContext {
        axelar_id,
        state,
        rpc_url,
        target_json,
    };

    // --- Pre-flight: check EVM deployer balances ---
    {
        let key_fields: &[(&str, &str)] = &[
            ("deployer", "deployerPrivateKey"),
            ("gateway deployer", "gatewayDeployerPrivateKey"),
            ("gas service deployer", "gasServiceDeployerPrivateKey"),
            ("ITS deployer", "itsDeployerPrivateKey"),
        ];
        let mut wallets: Vec<(&str, Address)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for &(label, state_key) in key_fields {
            if let Some(pk_str) = ctx.state[state_key].as_str()
                && let Ok(signer) = pk_str.parse::<PrivateKeySigner>()
            {
                let addr = signer.address();
                if seen.insert(addr) {
                    wallets.push((label, addr));
                }
            }
        }
        let token_symbol = std::fs::read_to_string(&ctx.target_json)
            .ok()
            .and_then(|c| serde_json::from_str::<Value>(&c).ok())
            .and_then(|root| {
                root.pointer(&format!("/chains/{}/tokenSymbol", ctx.axelar_id))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "ETH".to_string());

        preflight::check_evm_balances(&ctx.rpc_url, &wallets, &token_symbol).await?;
    }

    loop {
        let (step_idx, step) = match next_pending_step(&ctx.state) {
            Some(s) => s,
            None => {
                print_completion_message(&ctx.axelar_id, deploy_start);
                break;
            }
        };

        let step_name = step["name"].as_str().unwrap_or("?").to_string();
        let step_kind = step["kind"].as_str().unwrap_or("?").to_string();
        let step_start = Instant::now();

        ui::step_header(step_idx + 1, total_steps, &step_name);

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
                "DeployInterchainTokenService" => "itsDeployerPrivateKey",
                "AxelarGateway" => "gatewayDeployerPrivateKey",
                "Operators"
                | "RegisterOperators"
                | "TransferOperatorsOwnership"
                | "TransferGatewayOwnership" => "gatewayDeployerPrivateKey",
                "TransferGasServiceOwnership" => "gasServiceDeployerPrivateKey",
                "AxelarGasService" => "gasServiceDeployerPrivateKey",
                _ => return Err(eyre::eyre!("--private-key required for step {step_name}")),
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
                steps::evm_deploy::run(&mut ctx, &step_name, &step_kind, &pk, ap, &salt).await?;
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
                let impl_art = resolved_artifact.as_ref().ok_or_else(|| {
                    eyre::eyre!("--artifact-path required (implementation artifact)")
                })?;
                let proxy_art = resolved_proxy_artifact.as_ref().ok_or_else(|| {
                    eyre::eyre!("--proxy-artifact-path required (proxy artifact)")
                })?;
                steps::deploy_gateway::run(&mut ctx, step_idx, &step, &pk, impl_art, proxy_art)
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
                let impl_art = resolved_artifact.as_ref().ok_or_else(|| {
                    eyre::eyre!("--artifact-path required (implementation artifact)")
                })?;
                let proxy_art = resolved_proxy_artifact.as_ref().ok_or_else(|| {
                    eyre::eyre!("--proxy-artifact-path required (proxy artifact)")
                })?;
                steps::deploy_upgradable::run(
                    &mut ctx, step_idx, &step, &step_name, &pk, impl_art, proxy_art,
                )
                .await?;
            }

            "deploy-its" => {
                let pk = resolve_evm_key(&step_name)?;
                steps::deploy_its::run(&mut ctx, step_idx, &step, &pk).await?;
            }

            other => {
                return Err(eyre::eyre!("unknown step kind: {other}"));
            }
        }

        mark_step_completed(&mut ctx.state, step_idx);
        save_state(&ctx.axelar_id, &ctx.state)?;
        ui::success(&format!(
            "{step_name} completed ({})",
            ui::format_elapsed(step_start)
        ));
    }

    Ok(())
}

fn print_completion_message(axelar_id: &str, deploy_start: Instant) {
    ui::section("Deployment Complete");
    ui::success(&format!(
        "All steps completed for {axelar_id} ({})",
        ui::format_elapsed(deploy_start)
    ));
    println!();
    ui::info(&format!(
        "Run an end-to-end GMP test: cargo run -- test gmp --axelar-id {axelar_id}"
    ));
}

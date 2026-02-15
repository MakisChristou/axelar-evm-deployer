use std::fs;
use std::path::PathBuf;

use eyre::Result;
use serde_json::Value;

use crate::cli::resolve_axelar_id;
use crate::state::{next_pending_step, read_state};

pub fn run(axelar_id: Option<String>) -> Result<()> {
    let axelar_id = resolve_axelar_id(axelar_id)?;
    let state = read_state(&axelar_id)?;
    let steps = state["steps"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("no steps in state"))?;

    let env = state["env"].as_str().unwrap_or("?");
    println!("deployment: {axelar_id} (env: {env})\n");

    // Try to read contract addresses from target json
    let target_json = state["targetJson"].as_str().map(PathBuf::from);
    let read_addr = |contract_name: &str| -> Option<String> {
        let tj = target_json.as_ref()?;
        let content = fs::read_to_string(tj).ok()?;
        let root: Value = serde_json::from_str(&content).ok()?;
        root.pointer(&format!(
            "/chains/{axelar_id}/contracts/{contract_name}/address"
        ))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    };

    for step in steps {
        let name = step["name"].as_str().unwrap_or("?");
        let status = step["status"].as_str().unwrap_or("?");
        let marker = if status == "completed" {
            "[x]"
        } else {
            "[ ]"
        };

        let addr = if status == "completed" {
            match name {
                "ConstAddressDeployer" | "Create3Deployer" | "AxelarGateway" | "Operators"
                | "AxelarGasService" => read_addr(name),
                "PredictGatewayAddress" => state["predictedGatewayAddress"]
                    .as_str()
                    .map(|s| s.to_string()),
                _ => None,
            }
        } else {
            None
        };

        if let Some(a) = addr {
            println!("  {marker} {name} -> {a}");
        } else {
            println!("  {marker} {name}");
        }
    }

    match next_pending_step(&state) {
        Some((_, step)) => println!("\nnext: {}", step["name"].as_str().unwrap_or("?")),
        None => println!("\nall steps completed!"),
    }

    Ok(())
}

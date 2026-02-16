use std::fs;
use std::path::PathBuf;

use comfy_table::{Cell, ContentArrangement, Table};
use eyre::Result;
use owo_colors::OwoColorize;
use serde_json::Value;

use crate::cli::resolve_axelar_id;
use crate::state::{next_pending_step, read_state};
use crate::ui;

pub fn run(axelar_id: Option<String>) -> Result<()> {
    let axelar_id = resolve_axelar_id(axelar_id)?;
    let state = read_state(&axelar_id)?;
    let steps = state["steps"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("no steps in state"))?;

    let env = state["env"].as_str().unwrap_or("?");
    let rpc = state["rpcUrl"].as_str().unwrap_or("?");

    ui::section(&format!("Status: {axelar_id}"));
    ui::kv("environment", env);
    ui::kv("rpc", rpc);

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

    let next_idx = next_pending_step(&state).map(|(idx, _)| idx);

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("#"),
        Cell::new("Step"),
        Cell::new("Status"),
        Cell::new("Address"),
    ]);

    for (i, step) in steps.iter().enumerate() {
        let name = step["name"].as_str().unwrap_or("?");
        let status = step["status"].as_str().unwrap_or("?");
        let is_next = Some(i) == next_idx;

        let status_str = match (status, is_next) {
            ("completed", _) => format!("{}", "+ done".green()),
            (_, true) => format!("{}", "> next".cyan().bold()),
            _ => format!("{}", "  pending".dimmed()),
        };

        let addr = if status == "completed" {
            match name {
                "ConstAddressDeployer"
                | "Create3Deployer"
                | "AxelarGateway"
                | "Operators"
                | "AxelarGasService" => read_addr(name),
                "PredictGatewayAddress" => state["predictedGatewayAddress"]
                    .as_str()
                    .map(|s| s.to_string()),
                _ => None,
            }
        } else {
            None
        };

        let addr_str = addr.unwrap_or_default();

        table.add_row(vec![
            Cell::new(i + 1),
            Cell::new(name),
            Cell::new(status_str),
            Cell::new(addr_str),
        ]);
    }

    println!();
    println!("{table}");

    match next_pending_step(&state) {
        Some((_, step)) => {
            println!();
            ui::kv("next step", step["name"].as_str().unwrap_or("?"));
        }
        None => {
            println!();
            ui::success("all steps completed!");
        }
    }

    Ok(())
}

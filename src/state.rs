use std::fs;
use std::path::PathBuf;

use eyre::Result;
use serde_json::{Value, json};

pub fn data_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .ok_or_else(|| eyre::eyre!("could not determine data directory"))?
        .join("axelar-evm-deployer");
    Ok(dir)
}

pub fn state_path(axelar_id: &str) -> Result<PathBuf> {
    Ok(data_dir()?.join(format!("{axelar_id}.json")))
}

pub fn read_state(axelar_id: &str) -> Result<Value> {
    let path = state_path(axelar_id)?;
    let content = fs::read_to_string(&path)
        .map_err(|e| eyre::eyre!("failed to read state file {}: {e}. Run `init` first.", path.display()))?;
    Ok(serde_json::from_str(&content)?)
}

pub fn save_state(axelar_id: &str, state: &Value) -> Result<()> {
    let path = state_path(axelar_id)?;
    fs::write(&path, serde_json::to_string_pretty(state)? + "\n")?;
    Ok(())
}

pub fn next_pending_step(state: &Value) -> Option<(usize, Value)> {
    let steps = state["steps"].as_array()?;
    for (i, step) in steps.iter().enumerate() {
        if step["status"].as_str() == Some("pending") {
            return Some((i, step.clone()));
        }
    }
    None
}

pub fn mark_step_completed(state: &mut Value, idx: usize) {
    if let Some(step) = state["steps"].as_array_mut().and_then(|a| a.get_mut(idx)) {
        step["status"] = json!("completed");
    }
}

pub fn default_steps() -> Vec<Value> {
    vec![
        json!({ "name": "ConstAddressDeployer", "kind": "deploy-create", "status": "pending" }),
        json!({ "name": "Create3Deployer", "kind": "deploy-create2", "status": "pending" }),
        json!({ "name": "PredictGatewayAddress", "kind": "predict-address", "status": "pending" }),
        json!({ "name": "AddCosmWasmConfig", "kind": "config-edit", "status": "pending" }),
        json!({ "name": "InstantiateChainContracts", "kind": "cosmos-tx", "status": "pending",
                "proposalKey": "instantiate" }),
        json!({ "name": "WaitInstantiateProposal", "kind": "cosmos-poll", "status": "pending",
                "proposalKey": "instantiate" }),
        json!({ "name": "SaveDeployedContracts", "kind": "cosmos-query", "status": "pending" }),
        json!({ "name": "RegisterDeployment", "kind": "cosmos-tx", "status": "pending",
                "proposalKey": "register" }),
        json!({ "name": "WaitRegisterProposal", "kind": "cosmos-poll", "status": "pending",
                "proposalKey": "register" }),
        json!({ "name": "CreateRewardPools", "kind": "cosmos-tx", "status": "pending",
                "proposalKey": "rewardPools" }),
        json!({ "name": "WaitRewardPoolsProposal", "kind": "cosmos-poll", "status": "pending",
                "proposalKey": "rewardPools" }),
        json!({ "name": "AddRewards", "kind": "cosmos-tx", "status": "pending" }),
        json!({ "name": "WaitForVerifierSet", "kind": "wait-verifier-set", "status": "pending" }),
        json!({ "name": "AxelarGateway", "kind": "deploy-gateway", "status": "pending" }),
        json!({ "name": "Operators", "kind": "deploy-create2", "status": "pending" }),
        json!({ "name": "RegisterOperators", "kind": "register-operators", "status": "pending" }),
        json!({ "name": "AxelarGasService", "kind": "deploy-upgradable", "status": "pending" }),
        json!({ "name": "TransferOperatorsOwnership", "kind": "transfer-ownership", "status": "pending",
                "contract": "Operators", "newOwner": "0x49845e5d9985d8dc941462293ed38EEfF18B0eAE" }),
        json!({ "name": "TransferGatewayOwnership", "kind": "transfer-ownership", "status": "pending",
                "contract": "AxelarGateway", "newOwner": "0x49845e5d9985d8dc941462293ed38EEfF18B0eAE" }),
        json!({ "name": "TransferGasServiceOwnership", "kind": "transfer-ownership", "status": "pending",
                "contract": "AxelarGasService", "newOwner": "0x49845e5d9985d8dc941462293ed38EEfF18B0eAE" }),
    ]
}

use eyre::Result;
use serde_json::Value;

use crate::commands::deploy::DeployContext;
use crate::cosmos::{lcd_query_proposal, read_axelar_config};
use crate::ui;

pub async fn run(ctx: &DeployContext, step: &Value) -> Result<()> {
    let proposal_key = step["proposalKey"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no proposalKey in step"))?
        .to_string();
    let proposal_id = ctx
        .state
        .pointer(&format!("/proposals/{proposal_key}"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            eyre::eyre!(
                "no proposal ID for key '{proposal_key}' in state. Was the previous cosmos-tx step completed?"
            )
        })?;

    let (lcd, _, _, _) = read_axelar_config(&ctx.target_json)?;

    let spinner = ui::wait_spinner(&format!("polling proposal {proposal_id}..."));
    loop {
        let proposal = lcd_query_proposal(&lcd, proposal_id).await?;
        let status = proposal["status"].as_str().unwrap_or("UNKNOWN");
        spinner.set_message(format!("proposal {proposal_id}: {status}"));

        match status {
            "PROPOSAL_STATUS_PASSED" => {
                spinner.finish_and_clear();
                ui::success(&format!("proposal {proposal_id} passed!"));
                break;
            }
            "PROPOSAL_STATUS_REJECTED" | "PROPOSAL_STATUS_FAILED" => {
                spinner.finish_and_clear();
                let reason = proposal["failed_reason"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("no reason provided");
                let tally = &proposal["final_tally_result"];
                return Err(eyre::eyre!(
                    "proposal {proposal_id} {status}\n  reason: {reason}\n  tally: yes={} no={} abstain={} no_with_veto={}",
                    tally["yes_count"].as_str().unwrap_or("?"),
                    tally["no_count"].as_str().unwrap_or("?"),
                    tally["abstain_count"].as_str().unwrap_or("?"),
                    tally["no_with_veto_count"].as_str().unwrap_or("?"),
                ));
            }
            _ => {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }

    Ok(())
}

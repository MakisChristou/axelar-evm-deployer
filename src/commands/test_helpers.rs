use eyre::Result;
use serde_json::json;

use crate::cosmos::lcd_cosmwasm_smart_query;
use crate::ui;

/// Extract poll_id from the verify_messages tx response events.
/// Returns None if no poll was created (e.g. message already being verified by active relayers).
pub fn extract_poll_id(tx_resp: &serde_json::Value) -> Option<String> {
    let events = tx_resp
        .pointer("/tx_response/events")
        .and_then(|v| v.as_array())?;

    for event in events {
        let event_type = event["type"].as_str().unwrap_or("");
        if event_type == "wasm" || event_type.starts_with("wasm-") {
            if let Some(attrs) = event["attributes"].as_array() {
                for attr in attrs {
                    let key = attr["key"].as_str().unwrap_or("");
                    if key == "poll_id" {
                        let val = attr["value"].as_str()?;
                        return Some(val.trim_matches('"').to_string());
                    }
                }
            }
        }
    }

    None
}

/// Extract a named attribute from wasm events in a tx response.
pub fn extract_event_attr(tx_resp: &serde_json::Value, attr_name: &str) -> Result<String> {
    let events = tx_resp
        .pointer("/tx_response/events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre::eyre!("no events in tx response"))?;

    for event in events {
        let event_type = event["type"].as_str().unwrap_or("");
        if event_type == "wasm" || event_type.starts_with("wasm-") {
            if let Some(attrs) = event["attributes"].as_array() {
                for attr in attrs {
                    let key = attr["key"].as_str().unwrap_or("");
                    if key == attr_name {
                        let val = attr["value"]
                            .as_str()
                            .ok_or_else(|| eyre::eyre!("{attr_name} attribute has no value"))?;
                        return Ok(val.trim_matches('"').to_string());
                    }
                }
            }
        }
    }

    Err(eyre::eyre!("{attr_name} not found in tx events"))
}

/// Poll the MultisigProver for a proof until it's signed.
pub async fn wait_for_proof(
    lcd: &str,
    multisig_prover: &str,
    session_id: &str,
) -> Result<serde_json::Value> {
    let query = json!({ "proof": { "multisig_session_id": session_id } });
    let spinner = ui::wait_spinner("Waiting for proof signing...");

    for i in 0..120 {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        let resp = lcd_cosmwasm_smart_query(lcd, multisig_prover, &query).await?;
        let resp_str = serde_json::to_string(&resp)?;

        if resp_str.contains("completed") || resp_str.contains("Completed") {
            spinner.finish_and_clear();
            return Ok(resp);
        }

        let status = resp["status"].as_str().unwrap_or("unknown");
        spinner.set_message(format!("Proof status: {status} (attempt {}/120)", i + 1));
    }

    spinner.finish_and_clear();
    Err(eyre::eyre!(
        "proof for session {session_id} timed out after 10 minutes"
    ))
}

/// Wait until the poll has enough SucceededOnChain votes to meet quorum.
pub async fn wait_for_poll_votes(lcd: &str, voting_verifier: &str, poll_id: &str) -> Result<()> {
    let query = json!({ "poll": { "poll_id": poll_id } });
    let spinner = ui::wait_spinner("Waiting for verifier votes...");

    for i in 0..120 {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        let resp = lcd_cosmwasm_smart_query(lcd, voting_verifier, &query).await?;

        let poll = &resp["poll"];
        let quorum: u64 = poll["quorum"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let finished = poll["finished"].as_bool().unwrap_or(false);
        let expires_at: u64 = poll["expires_at"].as_u64().unwrap_or(0);

        if let Some(tallies) = poll["tallies"].as_array() {
            if let Some(tally) = tallies.first() {
                let succeeded: u64 = tally["SucceededOnChain"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let failed: u64 = tally["FailedOnChain"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let not_found: u64 = tally["NotFound"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);

                spinner.set_message(format!(
                    "votes: ok={succeeded} fail={failed} notfound={not_found} (quorum={quorum}, expires={expires_at}, finished={finished})"
                ));

                if quorum > 0 && failed >= quorum {
                    spinner.finish_and_clear();
                    return Err(eyre::eyre!("poll failed: {failed} FailedOnChain votes"));
                }
                if quorum > 0 && not_found >= quorum {
                    spinner.finish_and_clear();
                    return Err(eyre::eyre!("poll failed: {not_found} NotFound votes"));
                }
                if quorum > 0 && succeeded >= quorum {
                    spinner.finish_and_clear();
                    ui::success(&format!("quorum reached ({succeeded}/{quorum})"));
                    return Ok(());
                }
            }
        }
    }

    spinner.finish_and_clear();
    Err(eyre::eyre!("poll {poll_id} timed out after 10 minutes"))
}

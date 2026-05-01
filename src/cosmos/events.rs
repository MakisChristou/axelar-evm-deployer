//! Event-derived queries. These functions parse Tendermint event attributes
//! out of cosmos tx responses (or follow them up with another query) to
//! discover side effects of the amplifier pipeline: proposal IDs, second-leg
//! ITS message metadata, and routing/approval state.

use eyre::Result;
use serde_json::Value;

use super::rpc::{lcd_cosmwasm_smart_query, rpc_tx_search_event};

/// Extract proposal_id from tx response events
pub fn extract_proposal_id(tx_resp: &Value) -> Result<u64> {
    let events = tx_resp
        .pointer("/tx_response/events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre::eyre!("no events in tx response"))?;
    for event in events {
        let event_type = event["type"].as_str().unwrap_or("");
        if (event_type == "submit_proposal" || event_type == "proposal_submitted")
            && let Some(attrs) = event["attributes"].as_array()
        {
            for attr in attrs {
                let key = attr["key"].as_str().unwrap_or("");
                if key == "proposal_id" {
                    let val = attr["value"].as_str().unwrap_or("0");
                    return Ok(val.parse()?);
                }
            }
        }
    }
    Err(eyre::eyre!("proposal_id not found in tx events"))
}

/// Second-leg message info extracted from a hub execution tx that consumed
/// the first-leg message. Set by parsing the `wasm-routing` event.
pub struct SecondLegInfo {
    pub message_id: String,
    pub source_chain: String,
    pub destination_chain: String,
    pub payload_hash: String,
    pub source_address: String,
    pub destination_address: String,
}

/// Discover the second-leg message_id by searching the AxelarnetGateway tx
/// that executed the first-leg message, then extracting `wasm-routing` event
/// attributes. Returns `Ok(None)` if the hub hasn't executed yet.
pub async fn discover_second_leg(
    rpc: &str,
    first_leg_message_id: &str,
) -> Result<Option<SecondLegInfo>> {
    let resp = rpc_tx_search_event(
        rpc,
        "wasm-message_executed.message_id",
        first_leg_message_id,
    )
    .await?;

    let txs = resp
        .pointer("/result/txs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if txs.is_empty() {
        return Ok(None);
    }

    let events = txs[0]
        .pointer("/tx_result/events")
        .and_then(|v| v.as_array());
    let events = match events {
        Some(e) => e,
        None => return Ok(None),
    };

    for event in events {
        let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if event_type != "wasm-routing" {
            continue;
        }

        let attrs = match event.get("attributes").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };

        let get_attr = |key: &str| -> Option<String> {
            attrs.iter().find_map(|a| {
                let k = a.get("key").and_then(|v| v.as_str())?;
                if k == key {
                    a.get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        };

        if let (Some(msg_id), Some(src), Some(dst), Some(ph)) = (
            get_attr("message_id"),
            get_attr("source_chain"),
            get_attr("destination_chain"),
            get_attr("payload_hash"),
        ) {
            // source_address and destination_address are required — they're
            // used downstream by the EVM approval check. An empty fallback
            // would silently make `isContractCallApproved` return false
            // forever. If the wasm-routing event is missing them, fail loud.
            let source_address = get_attr("source_address").ok_or_else(|| {
                eyre::eyre!("wasm-routing event missing 'source_address' attribute")
            })?;
            let destination_address = get_attr("destination_address").ok_or_else(|| {
                eyre::eyre!("wasm-routing event missing 'destination_address' attribute")
            })?;
            return Ok(Some(SecondLegInfo {
                message_id: msg_id,
                source_chain: src,
                destination_chain: dst,
                payload_hash: ph,
                source_address,
                destination_address,
            }));
        }
    }

    Ok(None)
}

/// Check whether a message has been routed onto the destination Cosmos
/// Gateway's `outgoing_messages` table. True once the AxelarnetGateway has
/// published the second-leg message.
pub async fn check_cosmos_routed(
    lcd: &str,
    cosm_gateway: &str,
    source_chain: &str,
    message_id: &str,
) -> Result<bool> {
    let query = serde_json::json!({
        "outgoing_messages": [{
            "source_chain": source_chain,
            "message_id": message_id,
        }]
    });

    let resp = lcd_cosmwasm_smart_query(lcd, cosm_gateway, &query).await?;
    let data = resp.get("data").or_else(|| resp.as_array().map(|_| &resp));
    Ok(match data {
        Some(arr) if arr.is_array() => {
            let items = arr.as_array().unwrap();
            !items.is_empty() && !items.iter().all(|v| v.is_null())
        }
        _ => false,
    })
}

/// Check whether a message is executable on the AxelarnetGateway hub via
/// the `executable_messages` query. True once the hub has been instructed to
/// forward the message (or once it has executed it).
pub async fn check_hub_approved(
    lcd: &str,
    axelarnet_gateway: &str,
    source_chain: &str,
    message_id: &str,
) -> Result<bool> {
    let query = serde_json::json!({
        "executable_messages": {
            "cc_ids": [{
                "source_chain": source_chain,
                "message_id": message_id,
            }]
        }
    });

    let resp = lcd_cosmwasm_smart_query(lcd, axelarnet_gateway, &query).await?;
    let resp_str = serde_json::to_string(&resp)?;
    Ok(!resp_str.contains("null") && resp_str.contains(message_id))
}

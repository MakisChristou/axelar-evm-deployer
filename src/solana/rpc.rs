//! Low-level RPC plumbing: confirmed-commitment client construction and the
//! retry loop that hides testnet RPC lag past `send_and_confirm`. Higher-level
//! flows in `gateway` and `its` reach for `fetch_tx_details` to enrich
//! `TxMetrics` with compute-units / slot, and for `fetch_confirmed_tx` to read
//! logs + inner instructions for message-id and event extraction.

use eyre::Result;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;

/// Solana System Program ID — `11111111111111111111111111111111`. Named here
/// so callers don't sprinkle the base58 literal across the codebase.
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

/// Compute-unit limit applied via ComputeBudget instructions before our own
/// gateway/ITS calls. 400k matches the published per-tx cap and gives our
/// `verify_signature` + `approve_message` step plenty of headroom.
pub(super) const DEFAULT_CU_LIMIT: u32 = 400_000;

/// Max attempts when polling for a confirmed Solana transaction (see
/// `fetch_confirmed_tx`). 15 attempts × exponential backoff capped at 5s
/// per attempt totals ~60s of wait, enough to cover testnet RPC lag past
/// `send_and_confirm`.
const SOL_TX_FETCH_MAX_ATTEMPTS: u32 = 15;

/// Construct an `RpcClient` with the canonical "confirmed" commitment level.
/// Replaces the `RpcClient::new_with_commitment(rpc, CommitmentConfig::confirmed())`
/// boilerplate scattered across 15+ sites.
pub fn rpc_client(rpc_url: &str) -> RpcClient {
    RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed())
}

pub(super) fn fetch_tx_details(
    rpc_client: &RpcClient,
    signature: &Signature,
) -> Result<(Option<u64>, Option<u64>)> {
    let tx = fetch_confirmed_tx(rpc_client, signature)?;
    match tx {
        Some(tx) => {
            let slot = Some(tx.slot);
            let compute_units = tx
                .transaction
                .meta
                .and_then(|m| Option::from(m.compute_units_consumed));
            Ok((compute_units, slot))
        }
        None => Ok((None, None)),
    }
}

/// Fetch a confirmed transaction with retries.
///
/// Used both for best-effort metadata enrichment (compute units, slot — fine
/// to return None) and for the message-id extraction path which actually
/// requires the logs. Testnet RPCs can lag a few seconds beyond
/// `send_and_confirm`, so we retry generously.
pub(super) fn fetch_confirmed_tx(
    rpc_client: &RpcClient,
    signature: &Signature,
) -> Result<Option<solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta>> {
    for i in 0..SOL_TX_FETCH_MAX_ATTEMPTS {
        match rpc_client.get_transaction(signature, UiTransactionEncoding::Json) {
            Ok(tx) => return Ok(Some(tx)),
            Err(_) => {
                // Exponential backoff: 500ms, 1s, 2s, capped at 5s. Total ~60s.
                let delay = std::cmp::min(500 * (1 << i), 5000);
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    Ok(None)
}

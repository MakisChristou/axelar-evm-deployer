use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{keccak256, Address, FixedBytes};
use alloy::providers::Provider;
use eyre::Result;
use futures::future::join_all;
use serde_json::json;
use solana_sdk::pubkey::Pubkey;

use super::metrics::{AmplifierTiming, FailureCategory, TxMetrics, VerificationReport};
use crate::cosmos::{lcd_cosmwasm_smart_query, read_axelar_config, read_axelar_contract_field};
use crate::evm::AxelarAmplifierGateway;
use crate::solana::solana_call_contract_index;
use crate::ui;

/// If no transaction completes a phase for this long, we stop waiting.
/// Resets every time a tx makes progress, so large batches naturally get more time.
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(180);
/// Delay between poll attempts.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Phase tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Voted,
    Routed,
    Approved,
    Executed,
    Done,
}

enum ApprovalResult {
    Approved,
    AlreadyExecuted,
    NotYet,
}

// ---------------------------------------------------------------------------
// Per-tx state
// ---------------------------------------------------------------------------

/// Per-tx state tracked during batch verification.
struct PendingTx {
    idx: usize,
    message_id: String,
    send_instant: Instant,
    source_address: String,
    contract_addr: Address,
    payload_hash: FixedBytes<32>,
    payload_hash_hex: String,
    timing: AmplifierTiming,
    failed: bool,
    fail_reason: Option<String>,
    phase: Phase,
}

// ---------------------------------------------------------------------------
// Destination checker abstraction
// ---------------------------------------------------------------------------

enum DestinationChecker<'a, P: Provider> {
    Evm {
        gw_contract: &'a AxelarAmplifierGateway::AxelarAmplifierGatewayInstance<&'a P>,
    },
    Solana {
        rpc_client: Arc<solana_client::rpc_client::RpcClient>,
        command_ids: Vec<[u8; 32]>,
        _phantom: std::marker::PhantomData<&'a P>,
    },
}

impl<P: Provider> DestinationChecker<'_, P> {
    async fn check_approved(
        &self,
        tx: &PendingTx,
        idx: usize,
        source_chain: &str,
    ) -> Result<ApprovalResult> {
        match self {
            Self::Evm { gw_contract } => {
                let approved = check_evm_is_message_approved(
                    gw_contract,
                    source_chain,
                    &tx.message_id,
                    &tx.source_address,
                    tx.contract_addr,
                    tx.payload_hash,
                )
                .await?;
                if approved {
                    Ok(ApprovalResult::Approved)
                } else {
                    // tx is already routed, so false = already executed
                    Ok(ApprovalResult::AlreadyExecuted)
                }
            }
            Self::Solana {
                rpc_client,
                command_ids,
                ..
            } => {
                let client = rpc_client.clone();
                let cmd_id = command_ids[idx];
                let result = tokio::task::spawn_blocking(move || {
                    check_solana_incoming_message(&client, &cmd_id)
                })
                .await??;
                match result {
                    Some(0) => Ok(ApprovalResult::Approved),
                    Some(_) => Ok(ApprovalResult::AlreadyExecuted),
                    None => Ok(ApprovalResult::NotYet),
                }
            }
        }
    }

    async fn check_executed(
        &self,
        tx: &PendingTx,
        idx: usize,
        source_chain: &str,
    ) -> Result<bool> {
        match self {
            Self::Evm { gw_contract } => {
                let approved = check_evm_is_message_approved(
                    gw_contract,
                    source_chain,
                    &tx.message_id,
                    &tx.source_address,
                    tx.contract_addr,
                    tx.payload_hash,
                )
                .await?;
                // false = approval consumed = executed
                Ok(!approved)
            }
            Self::Solana {
                rpc_client,
                command_ids,
                ..
            } => {
                let client = rpc_client.clone();
                let cmd_id = command_ids[idx];
                let result = tokio::task::spawn_blocking(move || {
                    check_solana_incoming_message(&client, &cmd_id)
                })
                .await??;
                match result {
                    Some(status) if status != 0 => Ok(true),
                    _ => Ok(false),
                }
            }
        }
    }

    fn approval_label(&self) -> &str {
        match self {
            Self::Evm { .. } => "EVM approval",
            Self::Solana { .. } => "Solana approval",
        }
    }

    fn execution_label(&self) -> &str {
        match self {
            Self::Evm { .. } => "EVM execution",
            Self::Solana { .. } => "Solana execution",
        }
    }
}

// ---------------------------------------------------------------------------
// Check outcome — returned from parallel checks, applied to txs afterward
// ---------------------------------------------------------------------------

enum CheckOutcome {
    /// No change (not ready yet, or tx was already terminal).
    NotYet,
    /// Phase completed — record timing and advance.
    PhaseComplete { elapsed: f64 },
    /// Voted phase: no VotingVerifier, just advance to Routed.
    SkipVoting,
    /// Approved check found the tx already executed — skip to Done.
    AlreadyExecuted { elapsed: f64 },
    /// Check returned an error.
    Error(String),
}

// ---------------------------------------------------------------------------
// Unified polling pipeline
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn poll_pipeline<P: Provider>(
    txs: &mut [PendingTx],
    lcd: &str,
    voting_verifier: Option<&str>,
    cosm_gateway: &str,
    source_chain: &str,
    destination_chain: &str,
    destination_address: &str,
    checker: &DestinationChecker<'_, P>,
) {
    let total = txs.len();
    if total == 0 {
        return;
    }

    let spinner = ui::wait_spinner("verifying pipeline (starting)...");
    let mut last_progress = Instant::now();

    loop {
        // Collect indices of non-terminal txs
        let active: Vec<usize> = (0..txs.len())
            .filter(|&i| !txs[i].failed && txs[i].phase != Phase::Done)
            .collect();

        if active.is_empty() {
            break;
        }

        // Fire all checks concurrently
        let futs: Vec<_> = active
            .iter()
            .map(|&i| {
                // Extract data needed for the check (avoids borrowing txs during await)
                let phase = txs[i].phase;
                let message_id = txs[i].message_id.clone();
                let source_address = txs[i].source_address.clone();
                let contract_addr = txs[i].contract_addr;
                let payload_hash = txs[i].payload_hash;
                let payload_hash_hex = txs[i].payload_hash_hex.clone();
                let send_instant = txs[i].send_instant;

                async move {
                    let outcome = match phase {
                        Phase::Voted => {
                            if let Some(vv) = voting_verifier {
                                match check_voting_verifier(
                                    lcd,
                                    vv,
                                    source_chain,
                                    &message_id,
                                    &source_address,
                                    destination_chain,
                                    destination_address,
                                    &payload_hash_hex,
                                )
                                .await
                                {
                                    Ok(true) => CheckOutcome::PhaseComplete {
                                        elapsed: send_instant.elapsed().as_secs_f64(),
                                    },
                                    Ok(false) => CheckOutcome::NotYet,
                                    Err(e) => {
                                        CheckOutcome::Error(format!("VotingVerifier: {e}"))
                                    }
                                }
                            } else {
                                CheckOutcome::SkipVoting
                            }
                        }
                        Phase::Routed => {
                            match check_cosmos_routed(lcd, cosm_gateway, source_chain, &message_id)
                                .await
                            {
                                Ok(true) => CheckOutcome::PhaseComplete {
                                    elapsed: send_instant.elapsed().as_secs_f64(),
                                },
                                Ok(false) => CheckOutcome::NotYet,
                                Err(e) => CheckOutcome::Error(format!("Gateway: {e}")),
                            }
                        }
                        Phase::Approved => {
                            // Build a temporary PendingTx-like view for the checker
                            let tmp = PendingTx {
                                idx: 0,
                                message_id: message_id.clone(),
                                send_instant,
                                source_address,
                                contract_addr,
                                payload_hash,
                                payload_hash_hex,
                                timing: AmplifierTiming::default(),
                                failed: false,
                                fail_reason: None,
                                phase,
                            };
                            match checker.check_approved(&tmp, i, source_chain).await {
                                Ok(ApprovalResult::Approved) => CheckOutcome::PhaseComplete {
                                    elapsed: send_instant.elapsed().as_secs_f64(),
                                },
                                Ok(ApprovalResult::AlreadyExecuted) => {
                                    CheckOutcome::AlreadyExecuted {
                                        elapsed: send_instant.elapsed().as_secs_f64(),
                                    }
                                }
                                Ok(ApprovalResult::NotYet) => CheckOutcome::NotYet,
                                Err(e) => CheckOutcome::Error(format!(
                                    "{}: {e}",
                                    checker.approval_label()
                                )),
                            }
                        }
                        Phase::Executed => {
                            let tmp = PendingTx {
                                idx: 0,
                                message_id: message_id.clone(),
                                send_instant,
                                source_address,
                                contract_addr,
                                payload_hash,
                                payload_hash_hex,
                                timing: AmplifierTiming::default(),
                                failed: false,
                                fail_reason: None,
                                phase,
                            };
                            match checker.check_executed(&tmp, i, source_chain).await {
                                Ok(true) => CheckOutcome::PhaseComplete {
                                    elapsed: send_instant.elapsed().as_secs_f64(),
                                },
                                Ok(false) => CheckOutcome::NotYet,
                                Err(e) => CheckOutcome::Error(format!(
                                    "{}: {e}",
                                    checker.execution_label()
                                )),
                            }
                        }
                        Phase::Done => CheckOutcome::NotYet,
                    };
                    (i, outcome)
                }
            })
            .collect();

        let results = join_all(futs).await;

        // Apply results back to txs
        let mut error_msg = None;
        for (i, outcome) in results {
            match outcome {
                CheckOutcome::NotYet => {}
                CheckOutcome::PhaseComplete { elapsed } => {
                    match txs[i].phase {
                        Phase::Voted => {
                            txs[i].timing.voted_secs = Some(elapsed);
                            txs[i].phase = Phase::Routed;
                        }
                        Phase::Routed => {
                            txs[i].timing.routed_secs = Some(elapsed);
                            txs[i].phase = Phase::Approved;
                        }
                        Phase::Approved => {
                            txs[i].timing.approved_secs = Some(elapsed);
                            txs[i].phase = Phase::Executed;
                        }
                        Phase::Executed => {
                            txs[i].timing.executed_secs = Some(elapsed);
                            txs[i].timing.executed_ok = Some(true);
                            txs[i].phase = Phase::Done;
                        }
                        Phase::Done => {}
                    }
                    last_progress = Instant::now();
                }
                CheckOutcome::SkipVoting => {
                    txs[i].phase = Phase::Routed;
                    last_progress = Instant::now();
                }
                CheckOutcome::AlreadyExecuted { elapsed } => {
                    if txs[i].timing.approved_secs.is_none() {
                        txs[i].timing.approved_secs = Some(elapsed);
                    }
                    txs[i].timing.executed_secs = Some(elapsed);
                    txs[i].timing.executed_ok = Some(true);
                    txs[i].phase = Phase::Done;
                    last_progress = Instant::now();
                }
                CheckOutcome::Error(msg) => {
                    error_msg = Some(msg);
                }
            }
        }

        // Update spinner with multi-phase progress
        let (voted, routed, approved, executed) = phase_counts(txs);
        if let Some(ref err) = error_msg {
            spinner.set_message(format!(
                "voted: {voted}/{total}  routed: {routed}/{total}  approved: {approved}/{total}  executed: {executed}/{total}  (err: {err})"
            ));
        } else {
            spinner.set_message(format!(
                "voted: {voted}/{total}  routed: {routed}/{total}  approved: {approved}/{total}  executed: {executed}/{total}"
            ));
        }

        if last_progress.elapsed() >= INACTIVITY_TIMEOUT {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Mark remaining non-done txs as failed
    for tx in txs.iter_mut() {
        if tx.failed || tx.phase == Phase::Done {
            continue;
        }
        tx.failed = true;
        let label = match tx.phase {
            Phase::Voted => "VotingVerifier",
            Phase::Routed => "cosmos routing",
            Phase::Approved => checker.approval_label(),
            Phase::Executed => checker.execution_label(),
            Phase::Done => unreachable!(),
        };
        if tx.phase == Phase::Executed {
            tx.timing.executed_ok = Some(false);
        }
        tx.fail_reason = Some(format!("{label}: timed out"));
    }

    let (voted, routed, approved, executed) = phase_counts(txs);
    spinner.finish_and_clear();
    ui::success_annotated(
        &format!(
            "voted: {voted}/{total}  routed: {routed}/{total}  approved: {approved}/{total}  executed: {executed}/{total}"
        ),
        destination_chain,
    );
}

/// Count how many txs have reached each phase (cumulative).
fn phase_counts(txs: &[PendingTx]) -> (usize, usize, usize, usize) {
    let mut voted = 0;
    let mut routed = 0;
    let mut approved = 0;
    let mut executed = 0;
    for tx in txs {
        if tx.timing.voted_secs.is_some() {
            voted += 1;
        }
        if tx.timing.routed_secs.is_some() {
            routed += 1;
        }
        if tx.timing.approved_secs.is_some() {
            approved += 1;
        }
        if tx.timing.executed_secs.is_some() {
            executed += 1;
        }
    }
    (voted, routed, approved, executed)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Verify transactions on-chain through 4 Amplifier pipeline checkpoints:
///
/// 1. **Voted** — VotingVerifier verification (source chain)
/// 2. **Routed** — Destination Gateway outgoing_messages
/// 3. **Approved** — EVM gateway isMessageApproved
/// 4. **Executed** — EVM approval consumed
#[allow(clippy::too_many_arguments)]
pub async fn verify_onchain<P: Provider>(
    config: &Path,
    source_chain: &str,
    destination_chain: &str,
    destination_address: &str,
    gateway_addr: Address,
    provider: &P,
    metrics: &mut [TxMetrics],
) -> Result<VerificationReport> {
    let confirmed: Vec<usize> = metrics
        .iter()
        .enumerate()
        .filter(|(_, m)| m.success && !m.signature.is_empty())
        .map(|(i, _)| i)
        .collect();

    let total = confirmed.len();
    if total == 0 {
        ui::warn("no confirmed transactions to verify");
        return Ok(VerificationReport::default());
    }

    let (lcd, _, _, _) = read_axelar_config(config)?;

    let voting_verifier = read_axelar_contract_field(
        config,
        &format!("/axelar/contracts/VotingVerifier/{source_chain}/address"),
    )
    .ok();
    let cosm_gateway = read_axelar_contract_field(
        config,
        &format!("/axelar/contracts/Gateway/{destination_chain}/address"),
    )?;

    let gw_contract = AxelarAmplifierGateway::new(gateway_addr, provider);
    let contract_addr: Address = destination_address.parse()?;

    let initial_phase = if voting_verifier.is_some() {
        Phase::Voted
    } else {
        Phase::Routed
    };

    let mut txs: Vec<PendingTx> = confirmed
        .iter()
        .map(|&idx| {
            let tx = &metrics[idx];
            let payload_hash = parse_payload_hash(&tx.payload_hash).unwrap_or_default();
            PendingTx {
                idx,
                message_id: format!("{}-{}.1", tx.signature, solana_call_contract_index()),
                send_instant: tx.send_instant.unwrap_or_else(Instant::now),
                source_address: tx.source_address.clone(),
                contract_addr,
                payload_hash,
                payload_hash_hex: tx.payload_hash.clone(),
                timing: AmplifierTiming::default(),
                failed: false,
                fail_reason: None,
                phase: initial_phase,
            }
        })
        .collect();

    let checker = DestinationChecker::Evm {
        gw_contract: &gw_contract,
    };

    poll_pipeline(
        &mut txs,
        &lcd,
        voting_verifier.as_deref(),
        &cosm_gateway,
        source_chain,
        destination_chain,
        destination_address,
        &checker,
    )
    .await;

    let report = compute_verification_report(&txs, metrics);
    Ok(report)
}

/// Verify EVM->Solana transactions through the Amplifier pipeline:
///
/// 1. **Voted** — VotingVerifier verification (source EVM chain)
/// 2. **Routed** — Cosmos Gateway outgoing_messages (dest Solana chain)
/// 3. **Approved** — Solana IncomingMessage PDA exists
/// 4. **Executed** — Solana IncomingMessage PDA status = executed
#[allow(clippy::too_many_arguments)]
pub async fn verify_onchain_solana(
    config: &Path,
    source_chain: &str,
    destination_chain: &str,
    destination_address: &str,
    solana_rpc: &str,
    metrics: &mut [TxMetrics],
) -> Result<VerificationReport> {
    let confirmed: Vec<usize> = metrics
        .iter()
        .enumerate()
        .filter(|(_, m)| m.success && !m.signature.is_empty())
        .map(|(i, _)| i)
        .collect();

    let total = confirmed.len();
    if total == 0 {
        ui::warn("no confirmed transactions to verify");
        return Ok(VerificationReport::default());
    }

    let (lcd, _, _, _) = read_axelar_config(config)?;

    let voting_verifier = read_axelar_contract_field(
        config,
        &format!("/axelar/contracts/VotingVerifier/{source_chain}/address"),
    )
    .ok();
    let cosm_gateway = read_axelar_contract_field(
        config,
        &format!("/axelar/contracts/Gateway/{destination_chain}/address"),
    )?;

    let initial_phase = if voting_verifier.is_some() {
        Phase::Voted
    } else {
        Phase::Routed
    };

    let mut txs: Vec<PendingTx> = confirmed
        .iter()
        .map(|&idx| {
            let tx = &metrics[idx];
            let payload_hash = parse_payload_hash(&tx.payload_hash).unwrap_or_default();
            PendingTx {
                idx,
                message_id: tx.signature.clone(),
                send_instant: tx.send_instant.unwrap_or_else(Instant::now),
                source_address: tx.source_address.clone(),
                contract_addr: Address::ZERO,
                payload_hash,
                payload_hash_hex: tx.payload_hash.clone(),
                timing: AmplifierTiming::default(),
                failed: false,
                fail_reason: None,
                phase: initial_phase,
            }
        })
        .collect();

    let command_ids: Vec<[u8; 32]> = confirmed
        .iter()
        .map(|&idx| {
            let message_id = &metrics[idx].signature;
            let input = [source_chain.as_bytes(), b"-", message_id.as_bytes()].concat();
            keccak256(&input).into()
        })
        .collect();

    let rpc_client = Arc::new(solana_client::rpc_client::RpcClient::new_with_commitment(
        solana_rpc,
        solana_commitment_config::CommitmentConfig::confirmed(),
    ));

    let checker: DestinationChecker<'_, alloy::providers::RootProvider> =
        DestinationChecker::Solana {
            rpc_client,
            command_ids,
            _phantom: std::marker::PhantomData,
        };

    poll_pipeline(
        &mut txs,
        &lcd,
        voting_verifier.as_deref(),
        &cosm_gateway,
        source_chain,
        destination_chain,
        destination_address,
        &checker,
    )
    .await;

    let report = compute_verification_report(&txs, metrics);
    Ok(report)
}

// ---------------------------------------------------------------------------
// Single-shot check helpers
// ---------------------------------------------------------------------------

/// Check VotingVerifier `messages_status` for a message.
/// Returns true if status contains "succeeded" (quorum reached).
#[allow(clippy::too_many_arguments)]
async fn check_voting_verifier(
    lcd: &str,
    voting_verifier: &str,
    source_chain: &str,
    message_id: &str,
    source_address: &str,
    destination_chain: &str,
    destination_address: &str,
    payload_hash_hex: &str,
) -> Result<bool> {
    let query = json!({
        "messages_status": [{
            "cc_id": {
                "source_chain": source_chain,
                "message_id": message_id,
            },
            "source_address": source_address,
            "destination_chain": destination_chain,
            "destination_address": destination_address,
            "payload_hash": payload_hash_hex,
        }]
    });

    let resp = lcd_cosmwasm_smart_query(lcd, voting_verifier, &query).await?;
    let resp_str = serde_json::to_string(&resp)?;
    Ok(resp_str.to_lowercase().contains("succeeded"))
}

/// Check if message is routed on destination Cosmos Gateway via `outgoing_messages`.
async fn check_cosmos_routed(
    lcd: &str,
    cosm_gateway: &str,
    source_chain: &str,
    message_id: &str,
) -> Result<bool> {
    let query = json!({
        "outgoing_messages": [{
            "source_chain": source_chain,
            "message_id": message_id,
        }]
    });

    let resp = lcd_cosmwasm_smart_query(lcd, cosm_gateway, &query).await?;
    let data = resp
        .get("data")
        .or_else(|| resp.as_array().map(|_| &resp));
    Ok(match data {
        Some(arr) if arr.is_array() => {
            let items = arr.as_array().unwrap();
            !items.is_empty() && !items.iter().all(|v| v.is_null())
        }
        _ => false,
    })
}

/// Check `isMessageApproved` on the EVM gateway (single attempt).
async fn check_evm_is_message_approved<P: Provider>(
    gw_contract: &AxelarAmplifierGateway::AxelarAmplifierGatewayInstance<&P>,
    source_chain: &str,
    message_id: &str,
    source_address: &str,
    contract_addr: Address,
    payload_hash: FixedBytes<32>,
) -> Result<bool> {
    let approved = gw_contract
        .isMessageApproved(
            source_chain.to_string(),
            message_id.to_string(),
            source_address.to_string(),
            contract_addr,
            payload_hash,
        )
        .call()
        .await?;
    Ok(approved)
}

// ---------------------------------------------------------------------------
// Shared report computation
// ---------------------------------------------------------------------------

/// Compute the `VerificationReport` from pending tx results, writing timings
/// back into the original metrics array.
#[allow(clippy::cast_precision_loss, clippy::float_arithmetic)]
fn compute_verification_report(
    txs: &[PendingTx],
    metrics: &mut [TxMetrics],
) -> VerificationReport {
    let mut successful = 0u64;
    let mut failed = 0u64;
    let mut failure_reasons: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let mut stuck_count = 0u64;
    let mut stuck_phases: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for tx in txs {
        metrics[tx.idx].amplifier_timing = Some(tx.timing.clone());
        if tx.failed {
            failed += 1;
            if let Some(ref reason) = tx.fail_reason {
                *failure_reasons.entry(reason.clone()).or_insert(0) += 1;

                // Categorize stuck txs by the phase they got stuck at
                if reason.contains("timed out") {
                    stuck_count += 1;
                    let phase = stuck_phase(tx);
                    *stuck_phases.entry(phase).or_insert(0) += 1;
                }
            }
        } else if tx.timing.executed_ok == Some(true) {
            successful += 1;
        }
    }

    let total_verified = successful + failed;
    let success_rate = if total_verified > 0 {
        successful as f64 / total_verified as f64
    } else {
        0.0
    };

    let failure_categories: Vec<FailureCategory> = failure_reasons
        .into_iter()
        .map(|(reason, count)| FailureCategory { reason, count })
        .collect();

    let stuck_at: Vec<FailureCategory> = stuck_phases
        .into_iter()
        .map(|(reason, count)| FailureCategory { reason, count })
        .collect();

    let all_timings: Vec<&AmplifierTiming> = txs.iter().map(|t| &t.timing).collect();
    let avg_voted = avg_option(all_timings.iter().filter_map(|t| t.voted_secs));
    let avg_routed = avg_option(all_timings.iter().filter_map(|t| t.routed_secs));
    let avg_approved = avg_option(all_timings.iter().filter_map(|t| t.approved_secs));
    let avg_executed = avg_option(all_timings.iter().filter_map(|t| t.executed_secs));
    let min_executed = min_option(all_timings.iter().filter_map(|t| t.executed_secs));
    let max_executed = max_option(all_timings.iter().filter_map(|t| t.executed_secs));

    VerificationReport {
        total_verified,
        successful,
        pending: 0,
        failed,
        success_rate,
        failure_reasons: failure_categories,
        avg_voted_secs: avg_voted,
        avg_routed_secs: avg_routed,
        avg_approved_secs: avg_approved,
        avg_executed_secs: avg_executed,
        min_executed_secs: min_executed,
        max_executed_secs: max_executed,
        stuck: stuck_count,
        stuck_at,
    }
}

/// Determine which phase a timed-out tx got stuck at (the last phase it didn't complete).
fn stuck_phase(tx: &PendingTx) -> String {
    if tx.timing.voted_secs.is_none() {
        "voted".into()
    } else if tx.timing.routed_secs.is_none() {
        "routed".into()
    } else if tx.timing.approved_secs.is_none() {
        "approved".into()
    } else {
        "executed".into()
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn parse_payload_hash(hex_str: &str) -> Result<FixedBytes<32>> {
    let bytes = alloy::hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
    if bytes.len() != 32 {
        return Err(eyre::eyre!(
            "payload_hash must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(FixedBytes::from_slice(&bytes))
}

#[allow(clippy::float_arithmetic)]
fn avg_option(iter: impl Iterator<Item = f64>) -> Option<f64> {
    let vals: Vec<f64> = iter.collect();
    if vals.is_empty() {
        None
    } else {
        Some(vals.iter().sum::<f64>() / vals.len() as f64)
    }
}

fn min_option(iter: impl Iterator<Item = f64>) -> Option<f64> {
    iter.reduce(f64::min)
}

fn max_option(iter: impl Iterator<Item = f64>) -> Option<f64> {
    iter.reduce(f64::max)
}

// ---------------------------------------------------------------------------
// Solana IncomingMessage PDA check
// ---------------------------------------------------------------------------

/// Incoming message account data offset for the status byte.
/// Layout: 8 (discriminator) + 1 (bump) + 1 (signing_pda_bump) + 3 (pad) = 13
const INCOMING_MESSAGE_STATUS_OFFSET: usize = 13;

/// Check the Solana IncomingMessage PDA for a given command_id.
/// Returns `Some(status_byte)` if the account exists, `None` otherwise.
/// Status: 0 = approved, non-zero = executed.
fn check_solana_incoming_message(
    rpc_client: &solana_client::rpc_client::RpcClient,
    command_id: &[u8; 32],
) -> Result<Option<u8>> {
    let (pda, _bump) = Pubkey::find_program_address(
        &[b"incoming message", command_id],
        &solana_axelar_gateway::id(),
    );

    match rpc_client.get_account_data(&pda) {
        Ok(data) => {
            if data.len() <= INCOMING_MESSAGE_STATUS_OFFSET {
                return Err(eyre::eyre!(
                    "IncomingMessage account too small: {} bytes",
                    data.len()
                ));
            }
            Ok(Some(data[INCOMING_MESSAGE_STATUS_OFFSET]))
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("AccountNotFound")
                || err_str.contains("could not find account")
            {
                Ok(None)
            } else {
                Err(eyre::eyre!("Solana RPC error: {e}"))
            }
        }
    }
}

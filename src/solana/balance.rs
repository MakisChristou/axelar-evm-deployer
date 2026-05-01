//! Solana wallet preflight + the named lamport thresholds for each kind of
//! flow we run. Centralised so callers don't sprinkle magic constants across
//! the codebase and the user gets a clear "fund this address" error before
//! any tx fails on-chain.

use eyre::Result;
use solana_sdk::pubkey::Pubkey;

use super::rpc::rpc_client;
use crate::ui;

/// Default minimum balance for a Solana wallet to send a single GMP-style
/// transaction (call_contract + pay_gas of 0.01 SOL + tx fees + headroom).
pub const MIN_SOL_SEND_LAMPORTS: u64 = 20_000_000; // 0.02 SOL

/// Default minimum balance for a Solana wallet that runs the manual
/// destination-side gateway approval flow (init session + N verify_signature
/// + approve_message + execute) where each tx pays fees and some create rent-exempt PDAs.
pub const MIN_SOL_RELAY_LAMPORTS: u64 = 50_000_000; // 0.05 SOL

/// Minimum balance for the ITS test command: deploy local mint + token manager
/// + ATAs + 2x cross-chain GMP gas, plus fees.
pub const MIN_SOL_ITS_LAMPORTS: u64 = 100_000_000; // 0.1 SOL

/// Preflight: ensure a Solana wallet on the given RPC has at least `min_lamports`.
/// Errors with a clear "fund this address" message if the account is missing or
/// underfunded — replaces the cryptic
/// "Attempt to debit an account but found no record of a prior credit" RPC error.
pub fn check_solana_balance(
    rpc_url: &str,
    label: &str,
    pubkey: &Pubkey,
    min_lamports: u64,
) -> Result<()> {
    let rpc_client = rpc_client(rpc_url);
    let balance = rpc_client.get_balance(pubkey).map_err(|e| {
        eyre::eyre!("failed to query Solana balance for {pubkey} on {rpc_url}: {e}")
    })?;

    #[allow(clippy::cast_precision_loss)]
    let display = balance as f64 / 1_000_000_000.0;
    #[allow(clippy::cast_precision_loss)]
    let min_display = min_lamports as f64 / 1_000_000_000.0;

    if balance < min_lamports {
        ui::error(&format!("{label} Solana wallet underfunded:"));
        ui::error(&format!("  address: {pubkey}"));
        ui::error(&format!("  rpc:     {rpc_url}"));
        ui::error(&format!(
            "  balance: {display:.6} SOL (need >= {min_display:.6})"
        ));
        if balance == 0 {
            ui::error("  account has zero SOL on this network — fund or airdrop before retrying");
            ui::error(&format!("    solana airdrop 2 {pubkey} --url {rpc_url}"));
        }
        return Err(eyre::eyre!(
            "fund {pubkey} with at least {min_display:.6} SOL on {rpc_url} and retry"
        ));
    }

    ui::kv(
        &format!("{label} balance"),
        &format!("{display:.6} SOL (>= {min_display:.6})"),
    );
    Ok(())
}

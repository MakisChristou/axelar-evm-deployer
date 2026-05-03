//! Config-driven test resolution. Three modes:
//!
//! 1. `--test-type` only → auto-detect source and destination chains
//! 2. `--source-chain` + `--destination-chain` only → infer test type
//! 3. All three → validate consistency
//!
//! Also owns the on-disk caches (`load-test-{chain}.json` + the per-pair ITS
//! cache) and the `network-from-filename` heuristic that surfaces a clear
//! error when someone runs a `mainnet` build against `testnet.json`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use eyre::Result;
use serde_json::json;

use super::TestType;
use crate::config::{ChainConfig, ChainsConfig};
use crate::types::ChainType;
use crate::ui;

/// Cache file for storing SenderReceiver address per chain.
fn cache_path(axelar_id: &str) -> PathBuf {
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("axe");
    data_dir.join(format!("load-test-{axelar_id}.json"))
}

pub(super) fn read_cache(axelar_id: &str) -> serde_json::Value {
    let path = cache_path(axelar_id);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

pub(super) fn save_cache(axelar_id: &str, cache: &serde_json::Value) -> Result<()> {
    let path = cache_path(axelar_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(cache)?)?;
    Ok(())
}

/// Look up a chain's `chainType` from the config.
fn chain_type(chains: &HashMap<String, ChainConfig>, chain_id: &str) -> Option<ChainType> {
    chains.get(chain_id)?.chain_type.as_deref()?.parse().ok()
}

/// Find chains by chainType, optionally skipping core-* prefixed chains.
fn find_chains_by_type(
    chains: &HashMap<String, ChainConfig>,
    chain_type_filter: ChainType,
    skip_core: bool,
) -> Vec<String> {
    chains
        .iter()
        .filter(|(k, v)| {
            v.chain_type.as_deref() == Some(chain_type_filter.as_str())
                && !(skip_core && k.starts_with("core-"))
        })
        .map(|(k, _)| k.clone())
        .collect()
}

/// Infer test type from source and destination chain types.
fn infer_test_type(source_type: ChainType, dest_type: ChainType) -> Result<TestType> {
    match (source_type, dest_type) {
        (ChainType::Svm, ChainType::Evm) => Ok(TestType::SolToEvm),
        (ChainType::Evm, ChainType::Svm) => Ok(TestType::EvmToSol),
        (ChainType::Evm, ChainType::Evm) => Ok(TestType::EvmToEvm),
        (ChainType::Svm, ChainType::Svm) => Ok(TestType::SolToSol),
    }
}

/// Resolved configuration from the config JSON.
pub struct ResolvedConfig {
    pub test_type: TestType,
    pub source_chain: String,
    pub destination_chain: String,
    /// The `axelarId` for the source chain — may differ from the JSON key
    /// (e.g. `"Avalanche"` vs `"avalanche"` for consensus chains).
    pub source_axelar_id: String,
    /// The `axelarId` for the destination chain.
    pub destination_axelar_id: String,
    pub source_rpc: String,
    pub destination_rpc: String,
    pub private_key: Option<String>,
}

/// Resolve chains, RPCs, and test type from the config JSON.
///
/// Supports three modes:
/// 1. `--test-type` only → auto-detect source and destination chains
/// 2. `--source-chain` + `--destination-chain` only → infer test type from chainType
/// 3. All three → validate consistency
pub fn resolve_from_config(
    config: &Path,
    test_type_override: Option<TestType>,
    source_chain_override: Option<String>,
    destination_chain_override: Option<String>,
    private_key_override: Option<String>,
    source_rpc_override: Option<String>,
    destination_rpc_override: Option<String>,
) -> Result<ResolvedConfig> {
    let cfg = ChainsConfig::load(config)?;
    let chains = &cfg.chains;

    // --- Resolve test type + chains ---
    let (test_type, source_chain, destination_chain) = match (
        test_type_override,
        source_chain_override,
        destination_chain_override,
    ) {
        // Case 1: Both chains given → infer test type
        (None, Some(src), Some(dst)) => {
            let src_type = chain_type(chains, &src)
                .ok_or_else(|| eyre::eyre!("source chain '{src}' not found in config"))?;
            let dst_type = chain_type(chains, &dst)
                .ok_or_else(|| eyre::eyre!("destination chain '{dst}' not found in config"))?;
            let tt = infer_test_type(src_type, dst_type)?;
            ui::info(&format!("inferred test type: {tt}"));
            (tt, src, dst)
        }
        // Case 2: Test type + optional overrides → auto-detect missing chains
        (Some(tt), src_opt, dst_opt) => {
            let (src, dst) = auto_detect_chains(chains, tt, src_opt, dst_opt)?;
            (tt, src, dst)
        }
        // Case 3: Nothing or partial → try to auto-detect everything
        (None, src_opt, dst_opt) => {
            // Try to find a valid combination from config
            let (tt, src, dst) = auto_detect_all(chains, src_opt, dst_opt)?;
            (tt, src, dst)
        }
    };

    let source_cfg = chains
        .get(&source_chain)
        .ok_or_else(|| eyre::eyre!("source chain '{source_chain}' not found in config"))?;
    let destination_cfg = chains.get(&destination_chain).ok_or_else(|| {
        eyre::eyre!("destination chain '{destination_chain}' not found in config")
    })?;

    // Consensus chains use a capitalised axelarId distinct from the JSON key
    // (e.g. "Avalanche" vs "avalanche"). Lookups use the JSON key; the
    // axelarId is stored for verification queries.
    let source_axelar_id = source_cfg.axelar_id_or(&source_chain);
    let destination_axelar_id = destination_cfg.axelar_id_or(&destination_chain);

    let source_rpc = source_cfg
        .rpc
        .clone()
        .ok_or_else(|| eyre::eyre!("no RPC URL for source chain '{source_chain}' in config"))?;
    let destination_rpc = destination_cfg.rpc.clone().ok_or_else(|| {
        eyre::eyre!("no RPC URL for destination chain '{destination_chain}' in config")
    })?;

    let resolved_source_rpc = source_rpc_override.unwrap_or(source_rpc);
    let resolved_destination_rpc = destination_rpc_override.unwrap_or(destination_rpc);
    ui::kv("source RPC", &resolved_source_rpc);
    ui::kv("destination RPC", &resolved_destination_rpc);

    Ok(ResolvedConfig {
        test_type,
        source_chain,
        destination_chain,
        source_axelar_id,
        destination_axelar_id,
        source_rpc: resolved_source_rpc,
        destination_rpc: resolved_destination_rpc,
        private_key: private_key_override,
    })
}

/// Auto-detect source/destination chains for a known test type.
fn auto_detect_chains(
    chains: &HashMap<String, ChainConfig>,
    test_type: TestType,
    source_override: Option<String>,
    dest_override: Option<String>,
) -> Result<(String, String)> {
    match test_type {
        TestType::SolToEvm => {
            let source = match source_override {
                Some(s) => s,
                None => {
                    let svm = find_chains_by_type(chains, ChainType::Svm, false);
                    match svm.len() {
                        0 => return Err(eyre::eyre!("no SVM (Solana) chain found in config")),
                        1 => {
                            ui::info(&format!("auto-detected source: {}", svm[0]));
                            svm[0].clone()
                        }
                        _ => {
                            return Err(eyre::eyre!(
                                "multiple SVM chains found: {}. Use --source-chain to pick one.",
                                svm.join(", ")
                            ));
                        }
                    }
                }
            };
            let dest = match dest_override {
                Some(d) => d,
                None => {
                    let evm = find_chains_by_type(chains, ChainType::Evm, true);
                    if evm.is_empty() {
                        return Err(eyre::eyre!("no EVM chain found in config"));
                    }
                    ui::info(&format!(
                        "auto-detected destination: {} (use --destination-chain to override)",
                        evm[0]
                    ));
                    evm[0].clone()
                }
            };
            Ok((source, dest))
        }
        TestType::EvmToSol => {
            let source = match source_override {
                Some(s) => s,
                None => {
                    let evm = find_chains_by_type(chains, ChainType::Evm, true);
                    match evm.len() {
                        0 => return Err(eyre::eyre!("no EVM chain found in config")),
                        1 => {
                            ui::info(&format!("auto-detected source: {}", evm[0]));
                            evm[0].clone()
                        }
                        _ => {
                            return Err(eyre::eyre!(
                                "multiple EVM chains found: {}. Use --source-chain to pick one.",
                                evm.join(", ")
                            ));
                        }
                    }
                }
            };
            let dest = match dest_override {
                Some(d) => d,
                None => {
                    let svm = find_chains_by_type(chains, ChainType::Svm, false);
                    if svm.is_empty() {
                        return Err(eyre::eyre!("no SVM (Solana) chain found in config"));
                    }
                    ui::info(&format!(
                        "auto-detected destination: {} (use --destination-chain to override)",
                        svm[0]
                    ));
                    svm[0].clone()
                }
            };
            Ok((source, dest))
        }
        TestType::EvmToEvm => {
            let source = match source_override {
                Some(s) => s,
                None => {
                    let evm = find_chains_by_type(chains, ChainType::Evm, true);
                    if evm.len() < 2 {
                        return Err(eyre::eyre!(
                            "need at least 2 EVM chains in config for evm-to-evm"
                        ));
                    }
                    ui::info(&format!("auto-detected source: {}", evm[0]));
                    evm[0].clone()
                }
            };
            let dest = match dest_override {
                Some(d) => d,
                None => {
                    let evm = find_chains_by_type(chains, ChainType::Evm, true);
                    let picked = evm
                        .iter()
                        .find(|c| **c != source)
                        .ok_or_else(|| eyre::eyre!("need at least 2 EVM chains for evm-to-evm"))?;
                    ui::info(&format!(
                        "auto-detected destination: {} (use --destination-chain to override)",
                        picked
                    ));
                    picked.clone()
                }
            };
            Ok((source, dest))
        }
        TestType::SolToSol => {
            let source = match source_override {
                Some(s) => s,
                None => {
                    let svm = find_chains_by_type(chains, ChainType::Svm, false);
                    if svm.is_empty() {
                        return Err(eyre::eyre!("no SVM (Solana) chain found in config"));
                    }
                    ui::info(&format!("auto-detected source: {}", svm[0]));
                    svm[0].clone()
                }
            };
            let dest = match dest_override {
                Some(d) => d,
                None => {
                    // For sol-to-sol, default to the same chain (loopback)
                    ui::info(&format!(
                        "auto-detected destination: {} (same as source for sol-to-sol)",
                        source
                    ));
                    source.clone()
                }
            };
            Ok((source, dest))
        }
    }
}

/// Auto-detect test type and chains when nothing is specified.
/// Looks at what chain types exist in the config and picks the best match.
fn auto_detect_all(
    chains: &HashMap<String, ChainConfig>,
    source_override: Option<String>,
    dest_override: Option<String>,
) -> Result<(TestType, String, String)> {
    // If one chain is given, figure out the other
    if let Some(ref src) = source_override {
        let src_type = chain_type(chains, src)
            .ok_or_else(|| eyre::eyre!("source chain '{src}' not found in config"))?;
        match src_type {
            ChainType::Svm => {
                let evm = find_chains_by_type(chains, ChainType::Evm, true);
                let dst = dest_override.unwrap_or_else(|| {
                    ui::info(&format!(
                        "auto-detected destination: {} (use --destination-chain to override)",
                        evm[0]
                    ));
                    evm[0].clone()
                });
                ui::info("inferred test type: sol-to-evm");
                return Ok((TestType::SolToEvm, src.clone(), dst));
            }
            ChainType::Evm => {
                let svm = find_chains_by_type(chains, ChainType::Svm, false);
                if svm.is_empty() {
                    return Err(eyre::eyre!(
                        "no SVM chain found in config to pair with EVM source"
                    ));
                }
                let dst = dest_override.unwrap_or_else(|| {
                    ui::info(&format!(
                        "auto-detected destination: {} (use --destination-chain to override)",
                        svm[0]
                    ));
                    svm[0].clone()
                });
                ui::info("inferred test type: evm-to-sol");
                return Ok((TestType::EvmToSol, src.clone(), dst));
            }
        }
    }

    if let Some(ref dst) = dest_override {
        let dst_type = chain_type(chains, dst)
            .ok_or_else(|| eyre::eyre!("destination chain '{dst}' not found in config"))?;
        match dst_type {
            ChainType::Evm => {
                let svm = find_chains_by_type(chains, ChainType::Svm, false);
                if svm.is_empty() {
                    return Err(eyre::eyre!(
                        "no SVM chain found in config to pair with EVM destination"
                    ));
                }
                ui::info(&format!("auto-detected source: {}", svm[0]));
                ui::info("inferred test type: sol-to-evm");
                return Ok((TestType::SolToEvm, svm[0].clone(), dst.clone()));
            }
            ChainType::Svm => {
                let evm = find_chains_by_type(chains, ChainType::Evm, true);
                if evm.is_empty() {
                    return Err(eyre::eyre!(
                        "no EVM chain found in config to pair with SVM destination"
                    ));
                }
                ui::info(&format!("auto-detected source: {}", evm[0]));
                ui::info("inferred test type: evm-to-sol");
                return Ok((TestType::EvmToSol, evm[0].clone(), dst.clone()));
            }
        }
    }

    // Nothing specified — look for valid combinations
    let svm = find_chains_by_type(chains, ChainType::Svm, false);
    let evm = find_chains_by_type(chains, ChainType::Evm, true);

    if !svm.is_empty() && !evm.is_empty() {
        ui::info(&format!(
            "auto-detected: {} -> {} (sol-to-evm)",
            svm[0], evm[0]
        ));
        return Ok((TestType::SolToEvm, svm[0].clone(), evm[0].clone()));
    }

    Err(eyre::eyre!(
        "cannot auto-detect test type from config. Use --test-type, or --source-chain + --destination-chain."
    ))
}

/// ITS cache file for storing token info per chain pair.
fn its_cache_path(src: &str, dst: &str) -> PathBuf {
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("axe");
    data_dir.join(format!("its-load-test-{src}-{dst}.json"))
}

pub(super) fn read_its_cache(src: &str, dst: &str) -> serde_json::Value {
    let path = its_cache_path(src, dst);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

pub(super) fn save_its_cache(src: &str, dst: &str, cache: &serde_json::Value) -> Result<()> {
    let path = its_cache_path(src, dst);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(cache)?)?;
    Ok(())
}

/// Try to detect the target network from the config file path.
/// Looks for known network names in the filename (e.g. "stagenet.json", "devnet-amplifier.json").
pub(super) fn detect_network_from_config(config: &Path) -> Option<crate::types::Network> {
    let name = config.file_stem()?.to_str()?;
    crate::types::Network::ALL
        .iter()
        .copied()
        .find(|n| n.as_str() == name)
}

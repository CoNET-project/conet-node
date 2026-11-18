//! Read-only Epoch reads on CoNET L1 (TS `src/util/localNodeCommand.ts` @215afb18):
//! `currentInfo()` on the epoch-mining-info contract, `restartBlockNumber()` on the node-restart
//! contract, and the `validatorMining` signature check.
//!
//! Nothing in this module writes setup, runs a command, or restarts a service. The TS code runs
//! `sudo systemctl restart conet.service` on a 60 s watchdog, and an upgrade-and-reboot command
//! when a newer restart block is seen. Those actions are not ported. `restart_advice` reports the
//! decision only, and the caller decides what to do with it.
//!
//! Scope of the `validatorMining` port: the message construction and the nodeWallet recovery
//! (TS lines 1354-1355), and the comparison at line 1357 (a mismatch disconnects in TS), which is
//! `validator_matches`. Not in this module, all after line 1358: the nodeDomain routerInfo lookup and
//! table refresh (1366-1397), the nodeInfo.wallet comparison (1398-1404), the validatorWallet check on
//! minerResponseHash (1405-1409), the CurrentEpoch window that refuses an epoch more than 5 behind
//! (1414-1419), the isUser pool branch (1421-1437), the refusal of any epoch behind CurrentEpoch
//! (1438-1441), and the validatorMinerPool.set and response (1443-1445). See
//! `tests/fixtures/epoch_readonly_gen/PROVENANCE.txt`.
use crate::chain::{ChainError, Rpc};
use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};
use serde_json::json;

/// Epoch-mining-info contract (TS `epoch_mining_info_cancun_addr`, lower case in TS).
pub const EPOCH_INFO_ADDR: &str = "0x648f1a17269627c3d465fea40b3c229f7cace5ca";
/// Node-restart contract (TS `nodeRestartEvent_addr`).
pub const NODE_RESTART_ADDR: &str = "0x64c9c9d5caaff0693f324e02fb9b7de907540df1";

sol! {
    function currentInfo() external view returns (uint256 epoch, uint256 totalMiners, uint256 minerRate, uint256 totalUsrs);
    function restartBlockNumber() external view returns (uint256);
}

/// Result of `currentInfo()`. `miner_rate` is in wei (TS formats it with formatEther for logs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentInfo {
    pub epoch: U256,
    pub total_miners: U256,
    pub miner_rate: U256,
    pub total_usrs: U256,
}

/// TS `checkCurrentRate` only records a rate when `epoch > 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentRate {
    pub epoch: U256,
    pub total_miners: U256,
    pub miner_rate: U256,
    pub total_usrs: U256,
}

/// TS `checkCurrentRate` runs on even blocks only (`if (block % 2) return`).
pub fn checks_this_block(block: u64) -> bool {
    block.is_multiple_of(2)
}

pub fn current_rate(info: &CurrentInfo) -> Option<CurrentRate> {
    (info.epoch > U256::ZERO).then_some(CurrentRate {
        epoch: info.epoch,
        total_miners: info.total_miners,
        miner_rate: info.miner_rate,
        total_usrs: info.total_usrs,
    })
}

pub fn decode_current_info(data: &[u8]) -> Result<CurrentInfo, ChainError> {
    let r = currentInfoCall::abi_decode_returns(data).map_err(|e| ChainError(e.to_string()))?;
    Ok(CurrentInfo {
        epoch: r.epoch,
        total_miners: r.totalMiners,
        miner_rate: r.minerRate,
        total_usrs: r.totalUsrs,
    })
}

pub fn decode_restart_block(data: &[u8]) -> Result<U256, ChainError> {
    restartBlockNumberCall::abi_decode_returns(data).map_err(|e| ChainError(e.to_string()))
}

/// `eth_call` of `currentInfo()` on the epoch-mining-info contract.
pub async fn read_current_info(rpc: &Rpc) -> Result<CurrentInfo, ChainError> {
    let raw = rpc
        .eth_call(EPOCH_INFO_ADDR, currentInfoCall {}.abi_encode(), None)
        .await?;
    decode_current_info(&raw)
}

/// TS `getRestart`: when the node-restart contract has no code, there is nothing to read
/// (`None`). Otherwise `restartBlockNumber()` is returned.
pub async fn read_restart_block(rpc: &Rpc) -> Result<Option<U256>, ChainError> {
    let code = rpc
        .call("eth_getCode", json!([NODE_RESTART_ADDR, "latest"]))
        .await?;
    let code = code.as_str().unwrap_or("0x");
    if code == "0x" || code.is_empty() {
        return Ok(None);
    }
    let raw = rpc
        .eth_call(
            NODE_RESTART_ADDR,
            restartBlockNumberCall {}.abi_encode(),
            None,
        )
        .await?;
    decode_restart_block(&raw).map(Some)
}

/// What TS `getRestart` would do with a chain restart block, given the saved setup value.
/// Read-only: the caller never writes setup, runs a command, or reboots from this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartAdvice {
    /// The node-restart contract has no code (TS returns early).
    NoContract,
    /// Nothing to do (no restart scheduled and no stale setup; or a restart already recorded).
    Nothing,
    /// The chain says 0 but the saved setup holds a stale value: TS resets it to 0.
    ClearStaleSetup,
    /// The chain has a newer restart block than the saved setup: TS saves it and runs the
    /// upgrade and reboot command. Not executed here.
    RestartRequired { to: U256 },
}

pub fn restart_advice(setup_block: Option<u64>, chain: Option<U256>) -> RestartAdvice {
    let Some(chain) = chain else {
        return RestartAdvice::NoContract;
    };
    if chain.is_zero() {
        return match setup_block {
            Some(s) if s > 0 => RestartAdvice::ClearStaleSetup,
            _ => RestartAdvice::Nothing,
        };
    }
    match setup_block {
        Some(s) if U256::from(s) < chain => RestartAdvice::RestartRequired { to: chain },
        _ => RestartAdvice::Nothing,
    }
}

/// The TS validator message: `JSON.stringify({ epoch: epoch.toString(), wallet: wallet.toLowerCase() })`.
/// `epoch` must be decimal digits (fail closed on anything else).
pub fn validator_message(epoch: &str, wallet: &str) -> Result<String, ChainError> {
    if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ChainError("epoch is not a decimal number".into()));
    }
    let wallet = wallet.to_ascii_lowercase();
    let wallet_addr: Address = wallet
        .parse()
        .map_err(|_| ChainError("wallet is not an address".into()))?;
    Ok(format!(
        "{{\"epoch\":{},\"wallet\":\"{:#x}\"}}",
        serde_json::to_string(epoch).map_err(|e| ChainError(e.to_string()))?,
        wallet_addr
    ))
}

/// TS `validatorMining`: `ethers.verifyMessage(message, hash).toLowerCase()`.
/// Returns the signer address in lower case.
pub fn validator_signer(epoch: &str, wallet: &str, hash: &str) -> Result<String, ChainError> {
    let message = validator_message(epoch, wallet)?;
    si_crypto::eth::recover_message(&message, hash)
        .map(|a| a.to_ascii_lowercase())
        .map_err(|e| ChainError(e.to_string()))
}

/// True when the signer equals the claimed node wallet (both compared in lower case, as TS does).
pub fn validator_matches(
    epoch: &str,
    wallet: &str,
    hash: &str,
    claimed_node_wallet: &str,
) -> Result<bool, ChainError> {
    Ok(validator_signer(epoch, wallet, hash)? == claimed_node_wallet.to_ascii_lowercase())
}

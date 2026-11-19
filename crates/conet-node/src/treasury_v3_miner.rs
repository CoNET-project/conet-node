//! Read-only `isMiner(address)` on the Treasury V3 contract. The signature is the TS ABI line in
//! CoNET-SI 215afb18 `src/vote/treasuryV3Listen.ts`: `function isMiner(address account) view returns (bool)`.
//! Only an `eth_call` and a strict decode live here. No vote, no transaction, no signer request.
use crate::chain::{ChainError, Rpc};
use alloy_primitives::Address;
use alloy_sol_types::{sol, SolCall};

sol! {
    function isMiner(address account) external view returns (bool);
}

/// The calldata for `isMiner(account)`: the 4-byte selector followed by the padded address.
pub fn encode_is_miner(account: Address) -> Vec<u8> {
    isMinerCall { account }.abi_encode()
}

/// Strict decode: exactly one 32-byte word whose value is 0 or 1. Empty, short, long, or any other
/// value is an error, never `false`. (ethers would accept a longer answer; this reader refuses it.)
pub fn decode_is_miner(data: &[u8]) -> Result<bool, ChainError> {
    if data.len() != 32 {
        return Err(ChainError(format!(
            "isMiner return is {} bytes, expected 32",
            data.len()
        )));
    }
    if data[..31].iter().any(|b| *b != 0) {
        return Err(ChainError("isMiner return is not a bool".into()));
    }
    match data[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ChainError("isMiner return is not a bool".into())),
    }
}

/// `eth_call` of `isMiner(account)` on the Treasury V3 contract at `treasury` (the caller supplies
/// the address; this module does not hard-code or verify a deployment).
pub async fn is_miner(rpc: &Rpc, treasury: &str, account: Address) -> Result<bool, ChainError> {
    let raw = rpc
        .eth_call(treasury, encode_is_miner(account), None)
        .await?;
    decode_is_miner(&raw)
}

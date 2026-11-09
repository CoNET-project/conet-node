//! PROTOTYPE, PLAN ONLY (needs the user's approval of a new SignTx whitelist entry): the main
//! wallet signing `topUp(nodeId)` for AUTO-TOPUP (project decision 2026-11-08).
//!
//! The probe wallet never signs it (`probe_role` refuses every selector but the three votes).
//! The minimal entry for the main wallet:
//! - `to` = the configured registry, type 2, calldata exactly `topUp(own nodeId)`;
//! - `value` = the amount, > 0, <= the missing stake conet-node computed for this term end,
//!   and <= a configured per-transaction cap (the operator sets it, e.g. the full threshold);
//! - only inside the window before the term end that conet-node states;
//! - at most `daily_count` per UTC day and `daily_value` per UTC day.
//!
//! The signer cannot read the chain: the missing amount and the term end come from conet-node
//! and are only as good as it. What the signer itself guarantees, even if conet-node is
//! compromised, are the parts that need no chain: own node id, registry, per-transaction cap and
//! daily caps. A stolen main key is not stopped by this entry.
use si_crypto::eth::keccak256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUpConfig {
    pub registry: String,
    pub own_node_id: u64,
    pub per_tx_cap: u128,
    pub daily_count: u32,
    pub daily_value: u128,
    /// Window before the term end, seconds (same as conet-node's `window_open`).
    pub window: u64,
}

/// What conet-node asks for, with the numbers it read from the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUpRequest {
    pub tx_type: u8,
    pub to: Option<String>,
    pub value: u128,
    pub data: Vec<u8>,
    /// conet-node's `minStakeAt(termEnd) - stakeOf(nodeId)`.
    pub stated_missing: u128,
    pub stated_term_end: u64,
}

/// Already signed today (UTC day of the signer's clock).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Today {
    pub count: u32,
    pub value: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopUpRefuse {
    NotType2,
    WrongTo,
    Creation,
    Selector,
    BadCalldata,
    NotOwnNode,
    ZeroValue,
    AboveMissing,
    AboveCap,
    OutsideWindow,
    DailyCount,
    DailyValue,
}

pub fn topup_selector() -> [u8; 4] {
    let h = keccak256(b"topUp(uint256)");
    [h[0], h[1], h[2], h[3]]
}

pub fn check(
    cfg: &TopUpConfig,
    req: &TopUpRequest,
    today: Today,
    clock: u64,
) -> Result<(), TopUpRefuse> {
    if req.tx_type != 2 {
        return Err(TopUpRefuse::NotType2);
    }
    let to = req.to.as_deref().ok_or(TopUpRefuse::Creation)?;
    if !to.eq_ignore_ascii_case(&cfg.registry) {
        return Err(TopUpRefuse::WrongTo);
    }
    if req.data.len() < 4 || req.data[..4] != topup_selector() {
        return Err(TopUpRefuse::Selector);
    }
    if req.data.len() != 4 + 32 {
        return Err(TopUpRefuse::BadCalldata);
    }
    let id = &req.data[4..];
    if id[..24].iter().any(|&b| b != 0)
        || u64::from_be_bytes(id[24..].try_into().expect("8 bytes")) != cfg.own_node_id
    {
        return Err(TopUpRefuse::NotOwnNode);
    }
    if req.value == 0 {
        return Err(TopUpRefuse::ZeroValue);
    }
    if req.value > req.stated_missing {
        return Err(TopUpRefuse::AboveMissing);
    }
    if req.value > cfg.per_tx_cap {
        return Err(TopUpRefuse::AboveCap);
    }
    if clock >= req.stated_term_end || clock + cfg.window < req.stated_term_end {
        return Err(TopUpRefuse::OutsideWindow);
    }
    if today.count >= cfg.daily_count {
        return Err(TopUpRefuse::DailyCount);
    }
    if today.value.saturating_add(req.value) > cfg.daily_value {
        return Err(TopUpRefuse::DailyValue);
    }
    Ok(())
}

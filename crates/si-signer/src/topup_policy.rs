//! PROTOTYPE, PLAN ONLY (needs the user's approval of a new SignTx whitelist entry): the main
//! (hot) wallet signing `topUp(nodeId)` for AUTO-TOPUP (project decisions 2026-11-08/09: two
//! paths, the operator's web deposit or the node topping up from its main hot wallet; the
//! signer is the main wallet, not a separate deposit wallet). The probe wallet never signs it.
//!
//! Minimal entry (N6 §H.8.24 14.1-14.3, checked byte by byte):
//! - type 2; `to` = the configured registry; calldata exactly `topUp(own nodeId)`;
//! - value <= the per-transaction cap and <= the budget left for this term (operator settings);
//!   conet-node's stated missing amount can only LOWER the value, never raise it;
//! - the window is computed by the signer itself from its own clock and the configured first term
//!   end and term length (not from conet-node);
//! - value 0 only as a same-nonce replacement (to retire our own pending top-up when the web
//!   deposit already covered the gap);
//! - after signing, the wallet must keep a gas reserve (balance stated by conet-node: the signer
//!   cannot read the chain, so this one relies on conet-node).
use si_crypto::eth::keccak256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUpConfig {
    pub registry: String,
    pub own_node_id: u64,
    pub per_tx_cap: u128,
    /// Total the operator allows per term.
    pub term_budget: u128,
    /// First term end and term length (seconds), configured at provisioning.
    pub first_term_end: u64,
    pub term_length: u64,
    /// Window before each term end (seconds).
    pub window: u64,
    pub gas_reserve: u128,
}

impl TopUpConfig {
    /// The term end the signer's clock is in (first_term_end + k x term_length).
    pub fn current_term_end(&self, clock: u64) -> u64 {
        if clock < self.first_term_end || self.term_length == 0 {
            return self.first_term_end;
        }
        let k = (clock - self.first_term_end) / self.term_length + 1;
        self.first_term_end + k * self.term_length
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUpRequest {
    pub tx_type: u8,
    pub to: Option<String>,
    pub value: u128,
    pub data: Vec<u8>,
    /// conet-node's `minStakeAt(termEnd) - stakeOf(nodeId)` (can only lower the value).
    pub stated_missing: u128,
    /// conet-node's reading of the wallet balance before this transaction.
    pub stated_wallet: u128,
    /// Set when this replaces our own pending top-up at the same nonce.
    pub replaces_nonce: Option<u64>,
}

/// Signed so far for the current term (the signer's own ledger, keyed by term end).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TermSpent {
    pub term_end: u64,
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
    AboveBudget,
    OutsideWindow,
    GasReserve,
}

pub fn topup_selector() -> [u8; 4] {
    let h = keccak256(b"topUp(uint256)");
    [h[0], h[1], h[2], h[3]]
}

pub fn check(
    cfg: &TopUpConfig,
    req: &TopUpRequest,
    spent: TermSpent,
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
    if req.value == 0 && req.replaces_nonce.is_none() {
        return Err(TopUpRefuse::ZeroValue);
    }
    if req.value > req.stated_missing {
        return Err(TopUpRefuse::AboveMissing);
    }
    if req.value > cfg.per_tx_cap {
        return Err(TopUpRefuse::AboveCap);
    }
    let end = cfg.current_term_end(clock);
    if clock >= end || clock + cfg.window < end {
        return Err(TopUpRefuse::OutsideWindow);
    }
    let used = if spent.term_end == end {
        spent.value
    } else {
        0
    };
    // A replacement supersedes the pending value it replaces; the caller books the difference.
    if req.replaces_nonce.is_none() && used.saturating_add(req.value) > cfg.term_budget {
        return Err(TopUpRefuse::AboveBudget);
    }
    if req.stated_wallet < req.value.saturating_add(cfg.gas_reserve) {
        return Err(TopUpRefuse::GasReserve);
    }
    Ok(())
}

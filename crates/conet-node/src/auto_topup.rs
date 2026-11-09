//! AUTO-TOPUP (project decision 2026-11-08, "续约比较口径与自动补足"): before the term end the node
//! moves the missing stake from its own wallet into the registry with `topUp(nodeId)`, so the
//! automatic renewal succeeds without anyone clicking.
//!
//! - Renewal compares the whole stake with `minStakeAt(termEnd)`: the full threshold in force at
//!   the end (a DAO raise counts at once; the grace-lagged `effectiveMinStake` and the 80% line
//!   do not).
//! - The wallet balance is NOT stake. Only what the registry holds counts.
//! - Missing = `minStakeAt(termEnd) - stakeOf(nodeId)`, recomputed from the chain on every run.
//! - Send only if the wallet holds missing + a gas reserve, inside the window before the end,
//!   with no top-up of ours still in flight; otherwise an objective obstacle: alert with the
//!   exact amount missing.
//!
//! Pure logic: no RPC, no signing. Sending needs the main wallet's SignTx whitelist entry for
//! `topUp` (not approved: plan only).

/// Chain state for one node, all from one confirmed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainView {
    /// Confirmed block timestamp.
    pub now: u64,
    /// `termOf(nodeId).termEnd` (the archive; renewal state itself comes from `termStateOf`).
    pub term_end: u64,
    /// `termStateOf(nodeId).inTerm`.
    pub in_term: bool,
    /// `termOf(nodeId).stakeStop`: already stopped for lack of stake.
    pub stake_stop: bool,
    /// `stakeOf(nodeId)`: what the registry holds (locks included: renewal does not deduct them).
    pub stake: u128,
    /// `minStakeAt(termEnd)`.
    pub threshold_at_end: u128,
    /// Node wallet balance (`eth_getBalance`), not stake.
    pub wallet: u128,
    /// The wallet's nonce at this confirmed block (transactions mined so far).
    pub wallet_nonce: u64,
}

/// A top-up of ours that was signed and broadcast, as recorded locally before broadcasting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub nonce: u64,
    pub value: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Start trying this long before the term end (seconds).
    pub window_open: u64,
    /// Below this much time left, a transaction cannot be counted on to be mined before the end.
    pub critical: u64,
    /// `topUp` gas limit x worst-case maxFee (vote_price style); value pending measurement.
    pub gas_reserve: u128,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Suggestion: start 7 days before the end (the operator was reminded at 30 / 7 / 1
            // days), keep trying on every run; stop counting on it 1 hour before the end.
            window_open: 7 * 86_400,
            critical: 3_600,
            // Placeholder: 300,000 gas x 1 gwei x 4 (maxFee = 4 x baseFee + tip rule).
            gas_reserve: 300_000u128 * 1_000_000_000 * 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Stake already meets the threshold at the end: renewal will succeed.
    Covered,
    /// Too early: nothing to send yet (the operator reminders still run).
    NotYet { opens_at: u64 },
    /// Our top-up's nonce is not used yet (pending or dropped): only rebroadcast or fee-bump
    /// THAT transaction (same nonce, same content), never a new one.
    Rebroadcast { nonce: u64 },
    /// The other path (the operator's web deposit) moved the chain stake while ours was still
    /// unmined: replace OUR transaction at the same nonce with the remaining gap (0 = a
    /// zero-value top-up that only consumes the nonce), so the two paths never over-fund.
    Replace { nonce: u64, value: u128 },
    /// Send `topUp(nodeId)` with exactly this value.
    Send { value: u128 },
    /// Objective obstacle: the wallet lacks `missing` (top-up plus gas reserve).
    WalletShort { missing: u128, need_stake: u128 },
    /// Not enough time left to count on mining before the end; renewal will fail unless a
    /// transaction already sent lands. After it fails: top up to the latest full threshold plus
    /// locks, then request recovery.
    TooLate { left: u64, need_stake: u128 },
    /// The term already ended (or the node is already stopped): automatic renewal is decided.
    Ended { renewed: bool },
}

/// Decide what to do now. `inflight` = our recorded top-up, if any (recorded before broadcast,
/// persisted, so it survives a restart).
pub fn plan(v: &ChainView, inflight: Option<&InFlight>, cfg: &Config) -> Plan {
    if v.stake_stop {
        return Plan::Ended { renewed: false };
    }
    if v.now >= v.term_end {
        return Plan::Ended { renewed: v.in_term };
    }
    let need = v.threshold_at_end.saturating_sub(v.stake);
    // Idempotence: a recorded top-up whose nonce is not used yet is the only top-up there can
    // be. Once its nonce is used (mined: ours or a replacement), the chain stake already shows
    // it and `need` is recomputed from the chain, so a restart or a repeated run never adds twice.
    if let Some(f) = inflight {
        if v.wallet_nonce <= f.nonce {
            return if need < f.value {
                Plan::Replace {
                    nonce: f.nonce,
                    value: need,
                }
            } else {
                Plan::Rebroadcast { nonce: f.nonce }
            };
        }
    }
    if need == 0 {
        return Plan::Covered;
    }
    let left = v.term_end - v.now;
    if left < cfg.critical {
        return Plan::TooLate {
            left,
            need_stake: need,
        };
    }
    if left > cfg.window_open {
        return Plan::NotYet {
            opens_at: v.term_end - cfg.window_open,
        };
    }
    let required = need.saturating_add(cfg.gas_reserve);
    if v.wallet < required {
        return Plan::WalletShort {
            missing: required - v.wallet,
            need_stake: need,
        };
    }
    Plan::Send { value: need }
}

/// After a failed renewal: what the operator must have in the registry before requesting
/// recovery (N6 §H.8.24: stake minus locked >= the latest full threshold).
pub fn recovery_target(latest_threshold: u128, locked: u128) -> u128 {
    latest_threshold.saturating_add(locked)
}

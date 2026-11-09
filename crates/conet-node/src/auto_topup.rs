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
    /// The wallet's `pending` nonce (mined + sent but not mined, as the node's RPC sees it).
    pub wallet_pending_nonce: u64,
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
    /// A busy wallet this close to the end raises the "use the web page" alert.
    pub busy_alert: u64,
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
            busy_alert: 86_400,
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
    /// unmined and a gap remains: replace OUR transaction at the same nonce with the smaller
    /// remaining gap. If the web deposit covered the whole gap, ours is NOT replaced by a zero
    /// top-up (topUp(0) reverts and only burns gas; not in the approved entry): it lands as is and
    /// the extra stays in the node's stake.
    Replace { nonce: u64, value: u128 },
    /// Send `topUp(nodeId)` with exactly this value.
    Send { value: u128 },
    /// The main wallet has other transactions in flight (N6 second review): wait until they are
    /// mined or dropped, so a top-up never queues behind or races them. "In flight" comes from
    /// conet-node's own RPC, which a hijacked node could report forever (N6 third review): close
    /// to the end (`alert_use_web`) the operator is told to deposit through the web page instead.
    WalletBusy { in_flight: u64, alert_use_web: bool },
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
            return if need > 0 && need < f.value {
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
    if v.wallet_pending_nonce > v.wallet_nonce {
        return Plan::WalletBusy {
            in_flight: v.wallet_pending_nonce - v.wallet_nonce,
            alert_use_web: left <= cfg.busy_alert,
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

/// topUp pricing (N6 engineering advice on the fee caps, 2026-11-09): the first bid keeps both the
/// tip and maxFee at or below ~75% of their signer caps, so at least three +10% replacements still
/// fit under the caps (0.75 x 1.1^3 = 0.998). A first tip equal to the cap could never be replaced
/// and the node would report "busy" forever.
pub const FIRST_BID_SHARE_BPS: u128 = 7_500;

/// First bid: tip = min(wanted, 75% of tip cap); maxFee = min(4 x baseFee + tip, 75% of maxFee
/// cap), and never below the tip.
pub fn first_bid(
    base_fee: u128,
    wanted_tip: u128,
    max_fee_cap: u128,
    tip_cap: u128,
) -> (u128, u128) {
    let tip = wanted_tip.min(tip_cap * FIRST_BID_SHARE_BPS / 10_000);
    let max_fee = (base_fee.saturating_mul(4).saturating_add(tip))
        .min(max_fee_cap * FIRST_BID_SHARE_BPS / 10_000)
        .max(tip);
    (max_fee, tip)
}

/// Next replacement bid: both fees +10% (rounded up, geth's rule), or None if either would pass its
/// cap (then the node stops bumping and, near the end, alerts the operator).
pub fn bump_bid(
    max_fee: u128,
    tip: u128,
    max_fee_cap: u128,
    tip_cap: u128,
) -> Option<(u128, u128)> {
    let up = |v: u128| v + v.div_ceil(10);
    let (m, t) = (up(max_fee), up(tip));
    (m <= max_fee_cap && t <= tip_cap).then_some((m, t))
}

// ---- send flow: pricing wired to the plan (N6 fifth review) ----

/// A top-up of ours that was signed, with the fees of its latest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priced {
    pub nonce: u64,
    pub value: u128,
    pub max_fee: u128,
    pub tip: u128,
}

/// Pricing settings: the signer's caps and the tip the node would like to pay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceConfig {
    pub max_fee_cap: u128,
    pub tip_cap: u128,
    pub wanted_tip: u128,
}

/// What the sender does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendAction {
    /// Ask the signer for this transaction (`replaces` = same-nonce replacement of ours).
    Sign {
        nonce: u64,
        value: u128,
        max_fee: u128,
        tip: u128,
        replaces: Option<u64>,
    },
    /// Broadcast the same signed transaction again.
    Rebroadcast {
        nonce: u64,
    },
    /// Cannot bump any further under the caps: report busy; `alert` close to the end (the operator
    /// should deposit through the web page).
    Busy {
        alert: bool,
    },
    Nothing,
}

/// Turn a [`Plan`] into the next step. `pending` = our latest signed top-up (if its nonce is
/// unused); `priced_out` = it has not been mined for long enough while the base fee moved past it
/// (the caller decides, e.g. N blocks); `left` = seconds to the term end.
#[allow(clippy::too_many_arguments)]
pub fn next_action(
    plan: &Plan,
    pending: Option<&Priced>,
    wallet_nonce: u64,
    base_fee: u128,
    priced_out: bool,
    left: u64,
    p: &PriceConfig,
    cfg: &Config,
) -> SendAction {
    let busy = SendAction::Busy {
        alert: left <= cfg.busy_alert,
    };
    match (plan, pending) {
        (Plan::Send { value }, None) => {
            let (max_fee, tip) = first_bid(base_fee, p.wanted_tip, p.max_fee_cap, p.tip_cap);
            SendAction::Sign {
                nonce: wallet_nonce,
                value: *value,
                max_fee,
                tip,
                replaces: None,
            }
        }
        (Plan::Rebroadcast { nonce }, Some(q)) if q.nonce == *nonce => {
            if !priced_out {
                return SendAction::Rebroadcast { nonce: *nonce };
            }
            match bump_bid(q.max_fee, q.tip, p.max_fee_cap, p.tip_cap) {
                Some((max_fee, tip)) => SendAction::Sign {
                    nonce: q.nonce,
                    value: q.value,
                    max_fee,
                    tip,
                    replaces: Some(q.nonce),
                },
                None => busy,
            }
        }
        (Plan::Replace { nonce, value }, Some(q)) if q.nonce == *nonce => {
            match bump_bid(q.max_fee, q.tip, p.max_fee_cap, p.tip_cap) {
                Some((max_fee, tip)) => SendAction::Sign {
                    nonce: q.nonce,
                    value: *value,
                    max_fee,
                    tip,
                    replaces: Some(q.nonce),
                },
                None => busy,
            }
        }
        (Plan::WalletBusy { alert_use_web, .. }, _) => SendAction::Busy {
            alert: *alert_use_web,
        },
        _ => SendAction::Nothing,
    }
}

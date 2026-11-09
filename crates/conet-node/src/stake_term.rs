//! PROTOTYPE (pure logic, not wired): node side of the stake term rule (project decisions
//! 2026-11-08). Field names are placeholders until the node line publishes its design.
//!
//! The rule:
//! - a term lasts from half a year to three years, both ends allowed, others refused (new nodes
//!   and every new term); exact seconds per the node line;
//! - inside the term a DAO raise does not bite: the serving floor is 80% of the term threshold;
//! - at the term end renewal is automatic: locked effective stake >= the latest full threshold
//!   renews (the node stays online, no transaction from the node: the chain write is
//!   permissionless); below it the renewal fails, the old threshold is not kept, nothing is
//!   topped up automatically;
//! - a stopped node (failed renewal or slashed below the floor) tops up to the latest full
//!   threshold and comes back only through a recovery vote, then starts a new term;
//! - slashing and the 20-vote margin do not change.
//!
//! Everything is read from the chain (confirmed block): term end, term threshold, latest
//! threshold, locked stake, renewal outcome. The node never derives a term end itself; the only
//! local numbers are reminder lead times, which only decide when to tell the operator.
use crate::recovery::OfflineReason;

/// The node's term as the chain reports it (placeholders for the node line's fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermView {
    /// Chain time at which the current term ends (`termEndsAt`). Ended when the confirmed
    /// block's timestamp is at or past it (boundary to confirm with the node line).
    pub term_ends_at: u64,
    /// Threshold this term was approved at (`termThreshold`, "本期核定额").
    pub term_threshold: u128,
    /// Latest full threshold (`minStakeNow`): what renewal and recovery need.
    pub current_threshold: u128,
    /// Locked effective stake ("余额"; excess-stake details pending the node line).
    pub stake: u128,
    pub renewal: Renewal,
}

/// Outcome of the automatic renewal as the chain shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// Not written yet (term running, or ended and nobody has written the outcome yet).
    Pending,
    /// Renewed: the next term starts at the old end (no gap).
    Renewed { next_term_ends_at: u64 },
    /// Renewal failed (stake below the latest full threshold at the end).
    Failed,
}

/// Local reminder settings (operator UX only, never chain state).
#[derive(Debug, Clone)]
pub struct Reminders {
    /// Lead times before the term end, longest first, in seconds.
    pub lead: Vec<u64>,
    /// From here on a shortfall is urgent (a top-up must still land before the end).
    pub last_safe: u64,
}

impl Default for Reminders {
    fn default() -> Self {
        const DAY: u64 = 86_400;
        Self {
            lead: vec![30 * DAY, 14 * DAY, 7 * DAY, 3 * DAY, DAY],
            last_safe: 7 * DAY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advice {
    /// Nothing to do.
    Fine,
    /// Renewed: the term continues without a gap.
    Renewed { next_term_ends_at: u64 },
    /// Remind the operator: top up to `top_up_to` (absolute), `shortfall` missing. A reminder
    /// with no shortfall only says the term ends soon and renewal will be automatic.
    Remind {
        left: u64,
        top_up_to: u128,
        shortfall: u128,
        urgent: bool,
    },
    /// The term ended, the stake meets the latest threshold, the chain has not written the
    /// renewal yet: nothing to send (permissionless write), keep watching.
    RenewalDue,
    /// The renewal failed: the node stops; offline reason for the recovery flow.
    Expired { reason: OfflineReason },
}

/// What to tell the operator now. `chain_now` is the confirmed block's timestamp.
pub fn advise(v: &TermView, chain_now: u64, r: &Reminders) -> Advice {
    match v.renewal {
        Renewal::Renewed { next_term_ends_at } => return Advice::Renewed { next_term_ends_at },
        Renewal::Failed => {
            return Advice::Expired {
                reason: reason_after_expiry(v),
            }
        }
        Renewal::Pending => {}
    }
    if chain_now >= v.term_ends_at {
        return if renews(v.stake, v.current_threshold) {
            Advice::RenewalDue
        } else {
            Advice::Expired {
                reason: reason_after_expiry(v),
            }
        };
    }
    let left = v.term_ends_at - chain_now;
    let shortfall = v.current_threshold.saturating_sub(v.stake);
    if r.lead.iter().any(|&l| left <= l) {
        return Advice::Remind {
            left,
            top_up_to: v.current_threshold,
            shortfall,
            urgent: shortfall > 0 && left <= r.last_safe,
        };
    }
    Advice::Fine
}

/// The automatic renewal rule: locked effective stake >= latest full threshold (equal renews).
pub fn renews(stake: u128, latest_threshold: u128) -> bool {
    stake >= latest_threshold
}

/// After a failed renewal: the existing `StakeShortfall` reason against the latest threshold.
/// `topped_up` is false at failure; it turns true only after a top-up passes
/// [`precheck_recovery`]. The node comes back only through a recovery vote (B7).
pub fn reason_after_expiry(v: &TermView) -> OfflineReason {
    OfflineReason::StakeShortfall {
        topped_up: v.stake >= v.current_threshold,
    }
}

/// Term length precheck when choosing or suggesting a term: half a year to three years, both
/// ends allowed. `min` and `max` in seconds come from the node line's design (not hard-coded).
pub fn term_length_ok(len: u64, min: u64, max: u64) -> Result<(), TermLen> {
    if len < min {
        Err(TermLen::TooShort { min })
    } else if len > max {
        Err(TermLen::TooLong { max })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermLen {
    TooShort { min: u64 },
    TooLong { max: u64 },
}

/// Inside the term, the floor that decides suspension: 80% of the term threshold (board note:
/// "80% 停服线以本期核定额为基数"), not of the current threshold.
pub fn serves_inside_term(v: &TermView, chain_now: u64) -> bool {
    chain_now < v.term_ends_at && v.stake * 10 >= v.term_threshold * 8
}

/// Load of a same-day expiry wave (e.g. the 472 migration nodes): if `failed` nodes all need
/// recovery, each needs `margin` yes votes at `vote_gas`. Returns (vote transactions, gas, full
/// blocks at `block_gas`). Only an estimate for planning.
pub fn wave_load(failed: u64, margin: u64, vote_gas: u64, block_gas: u64) -> (u64, u128, u64) {
    let txs = failed * margin;
    let gas = txs as u128 * vote_gas as u128;
    let blocks = gas.div_ceil(block_gas as u128) as u64;
    (txs, gas, blocks)
}

/// Whether recovery can still pass after a wave: the margin needs at least `margin` eligible
/// voters left serving (the node itself does not count).
pub fn recovery_possible(serving_voters: u64, margin: u64) -> bool {
    serving_voters >= margin
}

/// Why a node stopped serving under the term rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Slashed (or deducted) below 80% of the term threshold while inside the term.
    SlashedInsideTerm,
    /// Term ended without an approved renewal.
    TermEnded,
}

/// What the operator must top up to (absolute stake, not a delta), and how much is missing.
/// Serving inside the term: 80% of the term threshold keeps it serving, but the next term needs
/// the current threshold, so both are reported. Stopped (either way): the full current threshold
/// (project decision 2026-11-08: "恢复要按当时最新的完整质押额补足"; e.g. term 5, now 10, floor
/// 4; slashed below 4 -> top up to 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopUp {
    Serving {
        keep_serving_at: u128,
        renew_at: u128,
        missing_for_renewal: u128,
    },
    Stopped {
        target: u128,
        missing: u128,
    },
}

pub fn top_up(v: &TermView, chain_now: u64) -> TopUp {
    if serves_inside_term(v, chain_now) {
        TopUp::Serving {
            keep_serving_at: v.term_threshold * 8 / 10,
            renew_at: v.current_threshold,
            missing_for_renewal: v.current_threshold.saturating_sub(v.stake),
        }
    } else {
        TopUp::Stopped {
            target: v.current_threshold,
            missing: v.current_threshold.saturating_sub(v.stake),
        }
    }
}

/// Before sending `requestRecovery`: the stake read from the chain must meet the latest full
/// threshold, read from the chain in the same confirmed block. Otherwise do not send (the
/// contract would refuse it or the vote could not lead anywhere).
pub fn precheck_recovery(stake: u128, latest_threshold: u128) -> Result<(), u128> {
    if stake >= latest_threshold {
        Ok(())
    } else {
        Err(latest_threshold - stake)
    }
}

/// The offline reason for a stop: always measured against the latest full threshold.
pub fn reason_for_stop(_why: Stop, stake: u128, latest_threshold: u128) -> OfflineReason {
    OfflineReason::StakeShortfall {
        topped_up: stake >= latest_threshold,
    }
}

//! PROTOTYPE (pure logic, not wired): node side of the stake term rule (project decision
//! 2026-11-08). Field names are placeholders until the node line publishes its design.
//!
//! The rule: each stake term lasts at least half a year. A DAO raise does not touch a node inside
//! its term (it serves under the term's threshold). At the term end the node must pass review at
//! the threshold of that time, or it stops serving and comes back only through a recovery vote.
//! Slashing and the 20-vote margin do not change.
//!
//! Everything here is read from the chain (confirmed block): the term end, the term threshold,
//! the current threshold, the stake, the renewal state. The node never derives a term end from a
//! registration time or adds durations itself; the only local numbers are reminder lead times,
//! which only decide when to tell the operator.
use crate::recovery::OfflineReason;

/// The node's term as the chain reports it (placeholders for the node line's fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermView {
    /// Chain time at which the current term ends (`termEndsAt`, placeholder). Expired when the
    /// confirmed block's timestamp is at or past it (boundary to confirm with the node line).
    pub term_ends_at: u64,
    /// Threshold this term was approved at (`termThreshold`).
    pub term_threshold: u128,
    /// Threshold a renewal must meet now (`minStakeNow`).
    pub current_threshold: u128,
    pub stake: u128,
    pub renewal: Renewal,
}

/// Renewal state on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// Nothing sent yet.
    None,
    /// Sent and under review (if review is a vote); `decided_by` is the chain's deadline.
    UnderReview { decided_by: u64 },
    /// Approved: the next term starts exactly at `term_ends_at` (no gap).
    Approved { next_term_ends_at: u64 },
    /// Review rejected for this term end.
    Rejected,
}

/// Local reminder settings (operator UX only, never chain state).
#[derive(Debug, Clone)]
pub struct Reminders {
    /// Lead times before the term end, longest first, in seconds.
    pub lead: Vec<u64>,
    /// Renewal must be on chain this long before the end, so a slow review or a gas spike
    /// cannot push it past the end.
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
    /// Remind the operator. `shortfall` = what to add so the stake meets the current threshold.
    Remind {
        left: u64,
        shortfall: u128,
        urgent: bool,
    },
    /// Renewal is under review; nothing to send, keep watching.
    Waiting { decided_by: u64 },
    /// The term ended without an approved renewal: the node no longer serves under the old
    /// threshold. Offline reason for the recovery flow.
    Expired { reason: OfflineReason },
}

/// What to tell the operator now. `chain_now` is the confirmed block's timestamp.
pub fn advise(v: &TermView, chain_now: u64, r: &Reminders) -> Advice {
    if let Renewal::Approved { next_term_ends_at } = v.renewal {
        return Advice::Renewed { next_term_ends_at };
    }
    if chain_now >= v.term_ends_at {
        return Advice::Expired {
            reason: reason_after_expiry(v),
        };
    }
    if let Renewal::UnderReview { decided_by } = v.renewal {
        return Advice::Waiting { decided_by };
    }
    let left = v.term_ends_at - chain_now;
    let shortfall = v.current_threshold.saturating_sub(v.stake);
    let due = r.lead.iter().any(|&l| left <= l);
    let rejected = v.renewal == Renewal::Rejected;
    if due || rejected || (shortfall > 0 && left <= r.lead.first().copied().unwrap_or(0)) {
        return Advice::Remind {
            left,
            shortfall,
            urgent: rejected || left <= r.last_safe,
        };
    }
    Advice::Fine
}

/// After an expiry without renewal: the existing `StakeShortfall` reason, measured against the
/// threshold of that time (the old term threshold no longer applies). `topped_up` = the stake
/// already meets it, so the node may request recovery at once; otherwise it tops up first. Either
/// way it comes back only through a recovery vote (B7).
pub fn reason_after_expiry(v: &TermView) -> OfflineReason {
    OfflineReason::StakeShortfall {
        topped_up: v.stake >= v.current_threshold,
    }
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

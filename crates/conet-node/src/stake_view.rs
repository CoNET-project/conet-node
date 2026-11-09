//! Two stake quantities, kept apart by name and in logs (project decision 2026-11-09: reward
//! filling of the stake gap is measured on the node's TOTAL stake):
//!
//! - `total_stake`: what the registry holds for the node (`stakeOf`), temporary vote locks
//!   INCLUDED. Used for: the reward gap and the reward transfer estimate, the AUTO-TOPUP gap
//!   (renewal compares the whole stake), the 80% floor inside a term.
//! - `free_stake`: total minus the temporary vote locks (`voteLocked`). Used only where it was
//!   used before: whether a vote can lock its fine (vote_gate), and recovery eligibility (stake
//!   minus locked >= the latest full threshold, decided rule, unchanged).
//!
//! A lock is not a gap: only an actual fine (which lowers the total) can open one.

/// One node's stake as read from one confirmed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeView {
    /// `stakeOf(nodeId)`: locks included.
    pub total_stake: u128,
    /// `voteLocked`: held by open cases (each case counted once, as the contract books it).
    pub vote_locked: u128,
}

impl StakeView {
    /// Total minus the vote locks.
    pub fn free_stake(&self) -> u128 {
        self.total_stake.saturating_sub(self.vote_locked)
    }

    /// Gap against a target (termBase, or the recovery / renewal requirement), on the TOTAL
    /// stake: locks never create a gap.
    pub fn gap(&self, target: u128) -> u128 {
        target.saturating_sub(self.total_stake)
    }

    /// One log line with both quantities named apart (amounts in wei).
    pub fn log_line(&self, target: u128) -> String {
        format!(
            "stake total_stake={} vote_locked={} free_stake={} target={} gap_on_total={}",
            self.total_stake,
            self.vote_locked,
            self.free_stake(),
            target,
            self.gap(target)
        )
    }
}

/// Estimated split of a reward: first into the node's own stake gap (on the total stake), the
/// rest transferred out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardSplit {
    pub to_stake: u128,
    pub transferred: u128,
}

pub fn estimate_reward_split(s: &StakeView, target: u128, reward: u128) -> RewardSplit {
    let to_stake = reward.min(s.gap(target));
    RewardSplit {
        to_stake,
        transferred: reward - to_stake,
    }
}

/// After an actual fine: the total drops by the fine (the lock that held it is released by the
/// contract, so it is not subtracted a second time).
pub fn after_fine(s: &StakeView, fine: u128, released_lock: u128) -> StakeView {
    StakeView {
        total_stake: s.total_stake.saturating_sub(fine),
        vote_locked: s.vote_locked.saturating_sub(released_lock),
    }
}

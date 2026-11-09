//! Total stake vs free stake (project decision 2026-11-09): the reward gap is measured on the
//! total stake (vote locks included); only an actual fine opens a gap.
use conet_node::stake_view::*;
use conet_node::vote_gate::{VoterView, NEW_REPORT_RATIO_BPS};

const C: u128 = 1_000_000_000_000_000_000;
const MILLI: u128 = C / 1000;

#[test]
fn locks_are_not_a_gap() {
    // Target 10, total 10, 3 locked by open cases: no gap, the whole reward is transferred.
    let s = StakeView {
        total_stake: 10 * C,
        vote_locked: 3 * C,
    };
    assert_eq!(s.free_stake(), 7 * C);
    assert_eq!(s.gap(10 * C), 0);
    assert_eq!(
        estimate_reward_split(&s, 10 * C, 5 * MILLI),
        RewardSplit {
            to_stake: 0,
            transferred: 5 * MILLI
        }
    );
    println!("{}", s.log_line(10 * C));
}

#[test]
fn an_actual_fine_opens_a_gap_on_the_post_fine_total() {
    // 2 locked in one case; the case is lost with a fine of 1: total 9, the lock released.
    let s = StakeView {
        total_stake: 10 * C,
        vote_locked: 2 * C,
    };
    let after = after_fine(&s, C, 2 * C);
    assert_eq!(
        after,
        StakeView {
            total_stake: 9 * C,
            vote_locked: 0
        }
    );
    assert_eq!(after.gap(10 * C), C);
    // A reward of 0.005 goes entirely into the gap; one of 1.5 fills it and transfers 0.5.
    assert_eq!(
        estimate_reward_split(&after, 10 * C, 5 * MILLI),
        RewardSplit {
            to_stake: 5 * MILLI,
            transferred: 0
        }
    );
    assert_eq!(
        estimate_reward_split(&after, 10 * C, 3 * C / 2),
        RewardSplit {
            to_stake: C,
            transferred: C / 2
        }
    );
    println!("{}", after.log_line(10 * C));
}

#[test]
fn other_cases_locks_are_not_subtracted_twice() {
    // Locks in three cases (1 + 1 + 1). One is lost with a fine of 1 and its lock released;
    // the other two stay locked. The gap uses the total only (9 vs 10 = 1), never total - locks.
    let s = StakeView {
        total_stake: 10 * C,
        vote_locked: 3 * C,
    };
    let after = after_fine(&s, C, C);
    assert_eq!(
        after,
        StakeView {
            total_stake: 9 * C,
            vote_locked: 2 * C
        }
    );
    assert_eq!(after.gap(10 * C), C);
    assert_eq!(after.free_stake(), 7 * C);
    // vote_gate keeps using the free stake for locking, subtracting the locks once.
    let v = VoterView {
        node_id: 1,
        active: true,
        services: 0x29,
        stake: after.total_stake,
        locked: after.vote_locked,
        term_base: 5 * C,
        eligible_at: 0,
        open_report_id: 0,
    };
    assert_eq!(v.available(), after.free_stake());
    assert_eq!(v.capacity(NEW_REPORT_RATIO_BPS), 7);
    println!("{}", after.log_line(10 * C));
}

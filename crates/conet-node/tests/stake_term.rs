//! PROTOTYPE stake term rule (2026-11-08 decision), pure logic. Field names are placeholders.
use conet_node::recovery::{Node, OfflineReason, Refused};
use conet_node::stake_term::*;

const DAY: u64 = 86_400;
const C: u128 = 1_000_000_000_000_000_000;
const END: u64 = 1_900_000_000;

fn term(stake: u128, cur: u128, renewal: Renewal) -> TermView {
    TermView {
        term_ends_at: END,
        term_threshold: 100 * C,
        current_threshold: cur,
        stake,
        renewal,
    }
}

#[test]
fn reminders_say_what_to_top_up_to() {
    let r = Reminders::default();
    let t = term(100 * C, 100 * C, Renewal::Pending);
    assert_eq!(advise(&t, END - 60 * DAY, &r), Advice::Fine);
    // Enough stake: a notice only (renewal is automatic), never urgent.
    assert_eq!(
        advise(&t, END - 5 * DAY, &r),
        Advice::Remind {
            left: 5 * DAY,
            top_up_to: 100 * C,
            shortfall: 0,
            urgent: false
        }
    );
    // A DAO raise inside the term: top up to the latest full threshold; urgent in the last 7 days.
    let raised = term(100 * C, 150 * C, Renewal::Pending);
    assert_eq!(
        advise(&raised, END - 25 * DAY, &r),
        Advice::Remind {
            left: 25 * DAY,
            top_up_to: 150 * C,
            shortfall: 50 * C,
            urgent: false
        }
    );
    assert_eq!(
        advise(&raised, END - 2 * DAY, &r),
        Advice::Remind {
            left: 2 * DAY,
            top_up_to: 150 * C,
            shortfall: 50 * C,
            urgent: true
        }
    );
}

#[test]
fn a_raise_inside_the_term_does_not_suspend() {
    // Serving floor inside the term: 80% of the term threshold, whatever the DAO set now.
    let t = term(80 * C, 300 * C, Renewal::Pending);
    assert!(serves_inside_term(&t, END - DAY));
    assert!(!serves_inside_term(
        &term(79 * C, 100 * C, Renewal::Pending),
        END - DAY
    ));
    assert!(!serves_inside_term(&t, END));
}

#[test]
fn automatic_renewal_at_the_end_needs_no_node_transaction() {
    let r = Reminders::default();
    // Equal to the latest threshold renews (>=); one wei less fails.
    assert!(renews(150 * C, 150 * C));
    assert!(!renews(150 * C - 1, 150 * C));
    // Ended, enough stake, chain outcome not written yet: nothing to send, keep watching.
    assert_eq!(
        advise(&term(150 * C, 150 * C, Renewal::Pending), END, &r),
        Advice::RenewalDue
    );
    // Written: renewed without a gap, even past the old end.
    let next = END + 183 * DAY;
    assert_eq!(
        advise(
            &term(
                150 * C,
                150 * C,
                Renewal::Renewed {
                    next_term_ends_at: next
                }
            ),
            END + 1,
            &r
        ),
        Advice::Renewed {
            next_term_ends_at: next
        }
    );
}

#[test]
fn failed_renewal_maps_to_stake_shortfall_and_needs_a_vote() {
    let r = Reminders::default();
    // Below the latest threshold at the end: renewal fails, old threshold not kept.
    for t in [
        term(100 * C, 150 * C, Renewal::Pending),
        term(100 * C, 150 * C, Renewal::Failed),
    ] {
        let Advice::Expired { reason } = advise(&t, END, &r) else {
            panic!()
        };
        assert_eq!(reason, OfflineReason::StakeShortfall { topped_up: false });
    }
    let mut n = Node::offline_because(OfflineReason::StakeShortfall { topped_up: false });
    assert_eq!(n.open([1; 32], [2; 32]), Err(Refused::StakeShort));
    assert!(precheck_recovery(150 * C, 150 * C).is_ok());
    n.stake_topped_up();
    assert!(n.open([1; 32], [2; 32]).is_ok()); // only the right to apply; the vote still decides
}

#[test]
fn term_length_range_both_ends_allowed() {
    // Placeholder seconds (the node line defines them): 182 days and 3 x 365 days.
    let (min, max) = (182 * DAY, 3 * 365 * DAY);
    assert_eq!(term_length_ok(min, min, max), Ok(()));
    assert_eq!(term_length_ok(max, min, max), Ok(()));
    assert_eq!(
        term_length_ok(min - 1, min, max),
        Err(TermLen::TooShort { min })
    );
    assert_eq!(
        term_length_ok(max + 1, min, max),
        Err(TermLen::TooLong { max })
    );
}

#[test]
fn migration_wave_load_and_voter_floor() {
    // 472 nodes expire the same day, all fail: 9,440 votes of about 90,133 gas.
    let (txs, gas, blocks) = wave_load(472, 20, 90_133, 60_000_000);
    assert_eq!(txs, 9_440);
    assert_eq!(gas, 850_855_520);
    assert_eq!(blocks, 15);
    // Recovery needs at least 20 serving voters left.
    assert!(recovery_possible(20, 20));
    assert!(!recovery_possible(19, 20));
}

/// The project's example: term threshold 5, DAO raises to 10; serving floor stays 4; slashed
/// below 4 the node stops and must top up to 10 (full latest), then pass a recovery vote.
#[test]
fn slashed_below_term_floor_tops_up_to_the_latest_full_threshold() {
    let v = |stake: u128| TermView {
        term_ends_at: END,
        term_threshold: 5 * C,
        current_threshold: 10 * C,
        stake,
        renewal: Renewal::Pending,
    };
    let now = END - 30 * DAY;
    // Serving at 4.5: floor 4, renewal needs 10.
    assert!(serves_inside_term(&v(45 * C / 10), now));
    assert_eq!(
        top_up(&v(45 * C / 10), now),
        TopUp::Serving {
            keep_serving_at: 4 * C,
            renew_at: 10 * C,
            missing_for_renewal: 55 * C / 10
        }
    );
    // Slashed to 3.9: stopped; target is 10, not 4 or 5.
    let s = v(39 * C / 10);
    assert!(!serves_inside_term(&s, now));
    assert_eq!(
        top_up(&s, now),
        TopUp::Stopped {
            target: 10 * C,
            missing: 61 * C / 10
        }
    );
    // Topping up to 5 or 9.99 does not allow a recovery request; 10 does (and only that).
    assert_eq!(precheck_recovery(5 * C, 10 * C), Err(5 * C));
    assert!(precheck_recovery(10 * C - 1, 10 * C).is_err());
    assert_eq!(precheck_recovery(10 * C, 10 * C), Ok(()));
    let reason = reason_for_stop(Stop::SlashedInsideTerm, 39 * C / 10, 10 * C);
    assert_eq!(reason, OfflineReason::StakeShortfall { topped_up: false });
    let mut n = Node::offline_because(reason);
    assert_eq!(n.open([1; 32], [2; 32]), Err(Refused::StakeShort));
    n.stake_topped_up(); // caller only does this after precheck_recovery passed
    assert!(n.open([1; 32], [2; 32]).is_ok());
    assert_eq!(n.state, conet_node::recovery::State::Offline); // topping up alone never goes online
}

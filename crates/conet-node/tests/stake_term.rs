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
fn reminders_follow_the_chain_term_end() {
    let r = Reminders::default();
    let t = term(100 * C, 100 * C, Renewal::None);
    assert_eq!(advise(&t, END - 60 * DAY, &r), Advice::Fine);
    assert_eq!(
        advise(&t, END - 20 * DAY, &r),
        Advice::Remind {
            left: 20 * DAY,
            shortfall: 0,
            urgent: false
        }
    );
    assert_eq!(
        advise(&t, END - 5 * DAY, &r),
        Advice::Remind {
            left: 5 * DAY,
            shortfall: 0,
            urgent: true
        }
    );
    // A DAO raise inside the term: the shortfall is against the current threshold.
    let raised = term(100 * C, 150 * C, Renewal::None);
    assert_eq!(
        advise(&raised, END - 25 * DAY, &r),
        Advice::Remind {
            left: 25 * DAY,
            shortfall: 50 * C,
            urgent: false
        }
    );
}

#[test]
fn a_raise_inside_the_term_does_not_suspend() {
    // Serving floor inside the term: 80% of the term threshold, whatever the DAO set now.
    let t = term(80 * C, 300 * C, Renewal::None);
    assert!(serves_inside_term(&t, END - DAY));
    assert!(!serves_inside_term(
        &term(79 * C, 100 * C, Renewal::None),
        END - DAY
    ));
    assert!(!serves_inside_term(&t, END));
}

#[test]
fn renewal_before_the_end_is_seamless() {
    let r = Reminders::default();
    let next = END + 183 * DAY;
    let t = term(
        150 * C,
        150 * C,
        Renewal::Approved {
            next_term_ends_at: next,
        },
    );
    // Approved: no reminder and no expiry, even at or past the old end.
    assert_eq!(
        advise(&t, END - DAY, &r),
        Advice::Renewed {
            next_term_ends_at: next
        }
    );
    assert_eq!(
        advise(&t, END + 1, &r),
        Advice::Renewed {
            next_term_ends_at: next
        }
    );
    let wait = term(
        150 * C,
        150 * C,
        Renewal::UnderReview {
            decided_by: END - 2 * DAY,
        },
    );
    assert_eq!(
        advise(&wait, END - 3 * DAY, &r),
        Advice::Waiting {
            decided_by: END - 2 * DAY
        }
    );
}

#[test]
fn expiry_maps_to_stake_shortfall_and_needs_a_vote() {
    let r = Reminders::default();
    // Stake below the threshold of the expiry time: top up first, then request recovery.
    let short = term(100 * C, 150 * C, Renewal::None);
    let Advice::Expired { reason } = advise(&short, END, &r) else {
        panic!()
    };
    assert_eq!(reason, OfflineReason::StakeShortfall { topped_up: false });
    let mut n = Node::offline_because(reason);
    assert_eq!(n.open([1; 32], [2; 32]), Err(Refused::StakeShort));
    n.stake_topped_up();
    assert!(n.open([1; 32], [2; 32]).is_ok()); // only the right to apply; the vote still decides
                                               // Stake already enough but no renewal (or rejected): may request recovery at once.
    let Advice::Expired { reason } =
        advise(&term(150 * C, 150 * C, Renewal::Rejected), END + 5, &r)
    else {
        panic!()
    };
    assert_eq!(reason, OfflineReason::StakeShortfall { topped_up: true });
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

//! Online votes: 12-hour cooldown, online fee, proposer review, own-case exclusion, rewards.
use conet_node::admission::{EndpointClass, Fail};
use conet_node::ballot::*;
use conet_node::online_gate::*;

const C: u128 = 1_000_000_000_000_000_000;
const T: u64 = 1_900_000_000;

fn rv(now: u64, since: u64, stake: u128, fee: u128) -> RecoveryView {
    RecoveryView {
        now,
        offline_since: since,
        last_rejected_at: 0,
        open_case_opened_at: None,
        stake,
        locked: 0,
        latest_threshold: 10 * C,
        fee_balance: fee,
    }
}

#[test]
fn cooldown_counts_from_the_chain_offline_moment() {
    // Self offline / report / stake stop: outOfServiceSince. Browser: the expired declaration's
    // end if earlier. Later events in the same period do not move it.
    assert_eq!(offline_since(T, None), T);
    assert_eq!(offline_since(T, Some(T - 100)), T - 100);
    assert_eq!(offline_since(T, Some(T + 100)), T);
    assert_eq!(offline_since(0, Some(T)), T);
    // 1 second before 12 h: wait 1 s; at 12 h: may ask.
    let b = precheck_recovery(&rv(T + OFFLINE_COOLDOWN - 1, T, 10 * C, ONLINE_FEE));
    assert_eq!(b.wait, Some(1));
    assert!(precheck_recovery(&rv(T + OFFLINE_COOLDOWN, T, 10 * C, ONLINE_FEE)).clear());
    // Warning before a declared offline.
    assert_eq!(offline_warning(T), T + 43_200);
}

#[test]
fn precheck_lists_every_blocker_with_amounts() {
    let b = precheck_recovery(&RecoveryView {
        locked: 2 * C,
        ..rv(T + 3_600, T, 11 * C, ONLINE_FEE / 2)
    });
    assert_eq!(b.wait, Some(OFFLINE_COOLDOWN - 3_600));
    assert_eq!(b.stake_missing, Some(C)); // 11 - 2 locked < 10 by 1
    assert_eq!(b.fee_missing, Some(ONLINE_FEE / 2));
    assert!(!b.clear());
}

fn direct() -> Attempt {
    Attempt {
        challenge: [1; 32],
        via_anchor: None,
        outcome: Outcome::Verified(EndpointClass::Direct {
            ip: "203.0.113.9".into(),
            port: 443,
        }),
        evidence: None,
    }
}
const P: Policy = Policy {
    node_is_browser: false,
    browser_relay_ok: false,
};

#[test]
fn proposer_reviews_with_the_agree_standard_and_keeps_its_fine() {
    let agree = decide(&[direct()], P);
    assert_eq!(review(&agree, PROPOSER_FINE), ProposeDecision::Propose);
    assert_eq!(
        review(&agree, 0),
        ProposeDecision::CannotCoverFine {
            missing: PROPOSER_FINE
        }
    );
    let unsure = decide(
        &[Attempt {
            outcome: Outcome::Failed(Fail::Expired),
            ..direct()
        }],
        P,
    );
    assert_eq!(review(&unsure, C), ProposeDecision::Decline(Why::Unsure));
    let ev = Evidence {
        challenge: "c".into(),
        reply: "r".into(),
        observed: "o".into(),
    };
    assert_eq!(
        review(&Ballot::Disagree(vec![ev.clone(), ev]), C),
        ProposeDecision::Refuse
    );
}

/// Own proposal: no vote from this node (the probe wallet votes for the same node id, so it is
/// covered by the same check), no execution.
#[test]
fn own_cases_are_skipped() {
    let me = 42;
    let own = CaseView {
        proposer: me,
        applicant: 7,
        voted: false,
        open: true,
    };
    assert_eq!(may_vote_online(me, &own, C), Err(OnlineSkip::OwnProposal));
    let mine = CaseView {
        proposer: 9,
        applicant: me,
        voted: false,
        open: true,
    };
    assert_eq!(
        may_vote_online(me, &mine, C),
        Err(OnlineSkip::OwnApplication)
    );
    let other = CaseView {
        proposer: 9,
        applicant: 7,
        voted: false,
        open: true,
    };
    assert_eq!(may_vote_online(me, &other, C), Ok(()));
    assert_eq!(
        may_vote_online(me, &other, VOTE_STAKE - 1),
        Err(OnlineSkip::NoLock { missing: 1 })
    );
    assert_eq!(
        may_vote_online(
            me,
            &CaseView {
                voted: true,
                ..other
            },
            C
        ),
        Err(OnlineSkip::AlreadyVoted)
    );
    assert!(!executor_worth_it(true, true, 0, 0, 0)); // never executes its own case
}

#[test]
fn economics_win_plus_lose_minus_one_milli() {
    // +0.001 / -0.001: zero at 50%, gas makes even 60% confidence barely positive.
    assert_eq!(vote_expectation(5_000, 0), 0);
    assert!(vote_expectation(6_000, 0) > 0);
    assert!(vote_expectation(6_000, VOTE_STAKE) < 0);
    // Executor strategy (off by default): extra reward 0.004 vs extra gas.
    assert!(!executor_worth_it(false, false, 0, 0, 0));
    let gwei = 1_000_000_000u128;
    assert!(executor_worth_it(true, false, 200_000, gwei, 5_000)); // 0.002 expected vs 0.0002 gas
    assert!(!executor_worth_it(true, false, 1_900_000, 10 * gwei, 5_000)); // 0.019 gas > 0.002
}

/// One valid vote per node per case; the deciding vote closes the case (project decision
/// 2026-11-09): a closed case or an existing vote of this node (any wallet) means no send.
#[test]
fn closed_case_or_existing_vote_means_no_send() {
    let me = 42;
    let c = CaseView {
        proposer: 9,
        applicant: 7,
        voted: false,
        open: true,
    };
    assert_eq!(
        may_vote_online(me, &CaseView { open: false, ..c }, C),
        Err(OnlineSkip::NotOpen)
    );
    assert_eq!(
        may_vote_online(me, &CaseView { voted: true, ..c }, C),
        Err(OnlineSkip::AlreadyVoted)
    );
    // The executor strategy lost the race: expected, no retry, no error.
    assert!(executor_race_lost("AdmissionState"));
    assert!(executor_race_lost("AlreadyVoted"));
    assert!(!executor_race_lost("StakeLocked"));
}

/// Online votes: nothing seals in the first 600 s; voting ends at 7,200 s (project correction
/// 2026-11-09, replacing 5 min / 12 h). Boundaries 599 / 600 / 7,199 / 7,200.
#[test]
fn online_vote_window_600_to_7200() {
    let t0 = 1_900_000_000;
    let yes19 = Tally {
        opened_at: t0,
        agree: 19,
        disagree: 0,
        margin: 20,
    };
    let no19 = Tally {
        opened_at: t0,
        agree: 1,
        disagree: 20,
        margin: 20,
    };
    for (t, side) in [(yes19, true), (no19, false)] {
        assert!(!would_decide(&t, side, t0 + 599));
        assert!(would_decide(&t, side, t0 + 600));
        assert!(would_decide(&t, side, t0 + 7_199));
        assert!(!would_decide(&t, side, t0 + 7_200)); // voting ended
        assert_eq!(decidable_from(&t, side), t0 + 600);
    }
    assert!(voting_open(&yes19, t0 + 7_199));
    assert!(!voting_open(&yes19, t0 + 7_200));
    // Not at the margin: never deciding.
    assert!(!would_decide(
        &Tally { agree: 10, ..yes19 },
        true,
        t0 + 3_600
    ));
}

/// Re-applying after a rejection: a fixed 12 hours from the rejection's sealing moment, however
/// many rejections came before (no doubling).
#[test]
fn after_rejections_always_twelve_hours_from_the_last_seal() {
    let base = rv(0, T, 10 * C, ONLINE_FEE);
    let mut rejected = T + OFFLINE_COOLDOWN + 600;
    for _ in 0..5 {
        let v = RecoveryView {
            now: rejected + 60,
            last_rejected_at: rejected,
            ..base.clone()
        };
        assert_eq!(precheck_recovery(&v).wait, Some(OFFLINE_COOLDOWN - 60));
        let v = RecoveryView {
            now: rejected + OFFLINE_COOLDOWN,
            last_rejected_at: rejected,
            ..base.clone()
        };
        assert!(precheck_recovery(&v).clear());
        rejected += OFFLINE_COOLDOWN + 900; // next rejection, later
    }
    // First offline still counts from the offline moment when there was no rejection.
    assert_eq!(
        precheck_recovery(&RecoveryView {
            now: T + 100,
            ..base
        })
        .wait,
        Some(OFFLINE_COOLDOWN - 100)
    );
}

/// An own recovery case still voting cannot be replaced by a new version before openedAt + 12 h
/// (project decision 2026-11-09); no open case, or a decided one, is not affected.
#[test]
fn open_case_replaceable_only_after_twelve_hours() {
    let opened = T + OFFLINE_COOLDOWN + 100;
    let base = RecoveryView {
        open_case_opened_at: Some(opened),
        ..rv(0, T, 10 * C, ONLINE_FEE)
    };
    let at = |now| {
        precheck_recovery(&RecoveryView {
            now,
            ..base.clone()
        })
    };
    assert_eq!(at(opened + 43_199).replace_at, Some(opened + 43_200));
    assert!(!at(opened + 43_199).clear());
    assert!(at(opened + 43_200).clear());
    // No open case: only the other rules.
    let none = RecoveryView {
        open_case_opened_at: None,
        now: opened + 10,
        ..base.clone()
    };
    assert!(precheck_recovery(&none).clear());
    // A rejection follows its own clock (from the seal), independent of this one.
    let rejected = RecoveryView {
        open_case_opened_at: None,
        last_rejected_at: opened + 50,
        now: opened + 60,
        ..base
    };
    let b = precheck_recovery(&rejected);
    assert_eq!((b.replace_at, b.wait), (None, Some(OFFLINE_COOLDOWN - 10)));
}

/// Project decision 2026-11-09: no holding (votes go out at once, count stays transparent); any
/// address may seal once 600 s passed and the threshold is met; sealing for the executor reward is
/// an optional strategy, off by default; a lost seal race is expected.
#[test]
fn vote_at_once_and_optional_seal_strategy() {
    let t0 = 1_900_000_000;
    let yes19 = Tally {
        opened_at: t0,
        agree: 19,
        disagree: 0,
        margin: 20,
    };
    assert_eq!(vote_timing(&yes19, true, t0 + 120), VoteTiming::Now);
    assert_eq!(vote_timing(&yes19, true, t0 + 7_199), VoteTiming::Now);
    assert_eq!(vote_timing(&yes19, true, t0 + 7_200), VoteTiming::Closed);
    // Threshold met at minute 2: sealable from 600 s, not before, not after the end.
    let yes20 = Tally { agree: 20, ..yes19 };
    assert!(!seal_ready(&yes20, t0 + 599));
    assert!(seal_ready(&yes20, t0 + 600));
    assert!(!seal_ready(&yes20, t0 + 7_200));
    assert!(!seal_ready(&yes19, t0 + 1_000)); // threshold not met
    let no20 = Tally {
        opened_at: t0,
        agree: 1,
        disagree: 21,
        margin: 20,
    };
    assert!(seal_ready(&no20, t0 + 600));
    // Seal strategy (off by default): 0.005 online reward, no stacking, proposer excluded.
    let gwei = 1_000_000_000u128;
    assert!(!seal_worth_it(false, false, EXECUTOR_REWARD, 0, 0, 0, 0));
    assert!(!seal_worth_it(true, true, EXECUTOR_REWARD, 0, 0, 0, 0));
    // Not a voter: 0.005 x 50% = 0.0025 vs 300k gas x 1 gwei = 0.0003: worth it.
    assert!(seal_worth_it(
        true,
        false,
        EXECUTOR_REWARD,
        0,
        300_000,
        gwei,
        5_000
    ));
    // Already a winning voter (0.001): extra 0.004 x 50% = 0.002 vs 300k x 10 gwei = 0.003: not.
    assert!(!seal_worth_it(
        true,
        false,
        EXECUTOR_REWARD,
        VOTE_STAKE,
        300_000,
        10 * gwei,
        5_000
    ));
    // Stagger for seal callers; lost races are expected.
    let case = [9u8; 32];
    assert!(stagger(&case, 101, 60) < 60);
    assert!(executor_race_lost("AdmissionState"));
}

/// First admission rejected: the same applicant waits 12 hours from the seal; changing the
/// endpoint or the proposer does not help (they are not part of the applicant key).
#[test]
fn admission_reapply_after_rejection_twelve_hours() {
    let sealed = 1_900_000_000;
    assert_eq!(
        admission_reapply_at(sealed, sealed + 43_199),
        Some(sealed + 43_200)
    );
    assert_eq!(admission_reapply_at(sealed, sealed + 43_200), None);
    assert_eq!(admission_reapply_at(0, sealed), None); // never rejected
    let mut book = RejectionBook::default();
    // Rejected with endpoint E1 proposed by node 9.
    book.rejected("applicant-wallet-A", sealed);
    // Re-applying with endpoint E2 through proposer 11: same applicant key, still blocked.
    assert_eq!(
        book.reapply_at("applicant-wallet-A", sealed + 43_199),
        Some(sealed + 43_200)
    );
    assert_eq!(book.reapply_at("applicant-wallet-A", sealed + 43_200), None);
    assert_eq!(book.reapply_at("applicant-wallet-B", sealed + 10), None);
    // A later rejection restarts from its own seal, fixed 12 hours (no doubling).
    book.rejected("applicant-wallet-A", sealed + 50_000);
    assert_eq!(
        book.reapply_at("applicant-wallet-A", sealed + 50_001),
        Some(sealed + 50_000 + 43_200)
    );
    // The proposer does not propose while the applicant waits, even if its own challenge passed.
    let agree = Ballot::Agree;
    assert_eq!(
        review_admission(
            &agree,
            C,
            book.reapply_at("applicant-wallet-A", sealed + 60_000)
        ),
        ProposeDecision::ApplicantWaiting {
            until: sealed + 50_000 + 43_200
        }
    );
    assert_eq!(review_admission(&agree, C, None), ProposeDecision::Propose);
}

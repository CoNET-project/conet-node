//! F5 vote gate, pure logic (no chain). The anvil cross-check is in `vote_gate_anvil.rs`.
use conet_node::vote_gate::*;

const CNET: u128 = 1_000_000_000_000_000_000;
const NOW: u64 = 1_800_000_000;

fn voter(id: u64) -> VoterView {
    VoterView {
        node_id: id,
        active: true,
        services: 0x29, // includes the maintenance bit
        stake: 5 * CNET,
        locked: 0,
        term_base: 5 * CNET, // own fine at 20% = 1 CNET
        eligible_at: NOW - 1,
        open_report_id: 0,
    }
}

fn report(rid: u64, target: u64) -> ReportView {
    ReportView {
        rid,
        target,
        reporter: 99,
        opened_at: NOW - 60,
        expires_at: NOW + 7 * 86_400,
        min_open: 300,
        agree: 1,
        disagree: 0,
        margin: 20,
        state: REPORT_OPEN,
        ratio_bps: NEW_REPORT_RATIO_BPS,
        population: None,
    }
}

#[test]
fn fine_is_the_ratio_times_the_voters_own_term_amount() {
    assert_eq!(voter(1).fine_for(NEW_REPORT_RATIO_BPS), CNET);
    let small = VoterView {
        term_base: 1_000,
        ..voter(1)
    };
    assert_eq!(small.fine_for(2_000), 200);
    // Rounding follows the contract: floor(base * ratio / 10000).
    let odd = VoterView {
        term_base: 7,
        ..voter(1)
    };
    assert_eq!(odd.fine_for(2_000), 1);
}

/// User decision 2026-11-08: same case, same ratio, different amounts. A voter approved at 10
/// locks 2 per case and fits half as many cases as one approved at 5 with the same stake.
#[test]
fn each_voter_locks_its_own_fine() {
    let r = report(1, 50);
    let low = VoterView {
        stake: 10 * CNET,
        ..voter(1)
    };
    let high = VoterView {
        stake: 10 * CNET,
        term_base: 10 * CNET,
        ..voter(2)
    };
    assert_eq!(low.capacity(NEW_REPORT_RATIO_BPS), 10);
    assert_eq!(high.capacity(NEW_REPORT_RATIO_BPS), 5);
    let high_full = VoterView {
        locked: 9 * CNET,
        ..high.clone()
    };
    assert_eq!(
        can_vote(&high_full, &r, 0, NOW),
        Err(Skip::NoLockCapacity {
            available: CNET,
            need: 2 * CNET
        })
    );
    let low_same = VoterView {
        locked: 9 * CNET,
        ..low
    };
    assert_eq!(can_vote(&low_same, &r, 0, NOW), Ok(()));
    // pick: the same open cases, different counts.
    let many: Vec<ReportView> = (1..=12).map(|i| report(i, 100 + i)).collect();
    assert_eq!(pick(&high, &many, &[0; 12], NOW).len(), 5);
    assert_eq!(
        pick(
            &VoterView {
                stake: 10 * CNET,
                ..voter(1)
            },
            &many,
            &[0; 12],
            NOW
        )
        .len(),
        10
    );
    // A term amount of 0 (no term yet) gives no capacity, never a division by zero.
    assert_eq!(
        VoterView {
            term_base: 0,
            ..voter(3)
        }
        .capacity(2_000),
        0
    );
}

#[test]
fn can_vote_follows_the_contract_order() {
    let r = report(1, 50);
    assert_eq!(can_vote(&voter(1), &r, 0, NOW), Ok(()));
    // Report state and expiry come first.
    let closed = ReportView {
        state: 2,
        ..r.clone()
    };
    assert_eq!(can_vote(&voter(1), &closed, 0, NOW), Err(Skip::NotOpen));
    assert_eq!(can_vote(&voter(1), &r, 0, r.expires_at), Err(Skip::Expired));
    // Then the voter's own eligibility.
    let inactive = VoterView {
        active: false,
        ..voter(1)
    };
    assert_eq!(can_vote(&inactive, &r, 0, NOW), Err(Skip::NotActive));
    let no_maint = VoterView {
        services: 0x21,
        ..voter(1)
    };
    assert_eq!(can_vote(&no_maint, &r, 0, NOW), Err(Skip::NoMaintBit));
    let cooling = VoterView {
        eligible_at: NOW + 10,
        ..voter(1)
    };
    assert_eq!(
        can_vote(&cooling, &r, 0, NOW),
        Err(Skip::Cooldown { until: NOW + 10 })
    );
    assert_eq!(can_vote(&cooling, &r, 0, NOW + 10), Ok(()));
    // Target, already voted (the reporter is agree #1), lock.
    assert_eq!(can_vote(&voter(50), &r, 0, NOW), Err(Skip::IsTarget));
    assert_eq!(can_vote(&voter(99), &r, 1, NOW), Err(Skip::AlreadyVoted));
    assert_eq!(can_vote(&voter(1), &r, 2, NOW), Err(Skip::AlreadyVoted));
}

#[test]
fn lock_capacity_is_stake_over_fine() {
    // 5 CNET stake, F = 1 CNET: five cases fit, the sixth reverts StakeLocked.
    let mut v = voter(1);
    assert_eq!(v.capacity(NEW_REPORT_RATIO_BPS), 5);
    for i in 0..5 {
        assert_eq!(
            can_vote(&v, &report(10 + i, 50), 0, NOW),
            Ok(()),
            "case {i}"
        );
        v.locked += CNET;
    }
    assert_eq!(v.capacity(NEW_REPORT_RATIO_BPS), 0);
    assert_eq!(
        can_vote(&v, &report(20, 50), 0, NOW),
        Err(Skip::NoLockCapacity {
            available: 0,
            need: CNET
        })
    );
    // A stake cut by offline deductions shrinks the capacity: 4.5 CNET left, 1 locked.
    let cut = VoterView {
        stake: 9 * CNET / 2,
        locked: CNET,
        ..voter(1)
    };
    assert_eq!(cut.capacity(NEW_REPORT_RATIO_BPS), 3);
    // Locked above stake (stake cut after locking) never underflows.
    let over = VoterView {
        stake: CNET,
        locked: 2 * CNET,
        ..voter(1)
    };
    assert_eq!(over.available(), 0);
    assert!(matches!(
        can_vote(&over, &report(21, 50), 0, NOW),
        Err(Skip::NoLockCapacity { .. })
    ));
}

#[test]
fn can_report_rules() {
    assert_eq!(can_report(&voter(1), 50, true, None, NOW), Ok(()));
    assert_eq!(
        can_report(&voter(1), 1, true, None, NOW),
        Err(Skip::IsTarget)
    );
    assert_eq!(
        can_report(&voter(1), 50, false, None, NOW),
        Err(Skip::TargetNotReportable)
    );
    let open = report(7, 50);
    assert_eq!(
        can_report(&voter(1), 50, true, Some(&open), NOW),
        Err(Skip::ReportOpen { rid: 7 })
    );
    // An expired or closed earlier report does not block a new one.
    let expired = ReportView {
        expires_at: NOW,
        ..open.clone()
    };
    assert_eq!(can_report(&voter(1), 50, true, Some(&expired), NOW), Ok(()));
    let closed = ReportView { state: 3, ..open };
    assert_eq!(can_report(&voter(1), 50, true, Some(&closed), NOW), Ok(()));
    // Opening a report locks F like a vote.
    let full = VoterView {
        locked: 5 * CNET,
        ..voter(1)
    };
    assert!(matches!(
        can_report(&full, 50, true, None, NOW),
        Err(Skip::NoLockCapacity { .. })
    ));
    let cooling = VoterView {
        eligible_at: NOW + 1,
        ..voter(1)
    };
    assert!(matches!(
        can_report(&cooling, 50, true, None, NOW),
        Err(Skip::Cooldown { .. })
    ));
}

#[test]
fn pick_orders_by_urgency_then_margin_within_capacity() {
    // Capacity for three cases (3 CNET unlocked, F = 1 CNET each).
    let v = VoterView {
        locked: 2 * CNET,
        ..voter(1)
    };
    let mk = |rid, opened_ago: u64, agree, disagree| ReportView {
        opened_at: NOW - opened_ago,
        agree,
        disagree,
        ..report(rid, 50 + rid)
    };
    let reports = vec![
        mk(1, 10, 1, 0),   // decidable in 290 s
        mk(2, 250, 1, 0),  // decidable in 50 s
        mk(3, 400, 12, 3), // decidable now, 11 votes from the margin
        mk(4, 400, 15, 0), // decidable now, 5 from the margin: most urgent
        mk(5, 400, 1, 0),  // decidable now, 19 from the margin
        report(6, 1),      // the voter is the target: never picked
    ];
    let choices = vec![0, 0, 0, 0, 0, 0];
    assert_eq!(pick(&v, &reports, &choices, NOW), vec![4, 3, 5]);
    // Already voted on 4: the next one moves up, and the decidable-later ones follow.
    let choices = vec![0, 0, 0, 1, 0, 0];
    assert_eq!(pick(&v, &reports, &choices, NOW), vec![3, 5, 2]);
    // No capacity at all: nothing.
    let full = VoterView {
        locked: 5 * CNET,
        ..voter(1)
    };
    assert!(pick(&full, &reports, &[0; 6], NOW).is_empty());
    // A case whose F does not fit stops the list (no skipping ahead to a cheaper one keeps the
    // order of urgency).
    let mut pricey = reports.clone();
    pricey[3].ratio_bps = 8_000; // own fine 4 CNET
    assert!(pick(&v, &pricey, &[0; 6], NOW).is_empty());
}

#[test]
fn node_raw_decoding_checks_the_layout() {
    let mut raw = vec![0u8; NODE_RAW_WORDS * 32];
    let put = |raw: &mut Vec<u8>, i: usize, v: u128| {
        raw[i * 32 + 16..(i + 1) * 32].copy_from_slice(&v.to_be_bytes());
    };
    put(&mut raw, 5, 0x29);
    put(&mut raw, 14, 5 * CNET);
    put(&mut raw, 27, 3);
    put(&mut raw, 36, NOW as u128);
    put(&mut raw, 37, 2 * CNET);
    let v = decode_node_raw(&raw, 9, true, 5 * CNET).unwrap();
    assert_eq!(
        v,
        VoterView {
            node_id: 9,
            active: true,
            services: 0x29,
            stake: 5 * CNET,
            locked: 2 * CNET,
            term_base: 5 * CNET,
            eligible_at: NOW,
            open_report_id: 3,
        }
    );
    // A different struct size is refused instead of misread.
    assert!(decode_node_raw(&raw[..raw.len() - 32], 9, true, 0).is_err());
    let mut longer = raw.clone();
    longer.extend_from_slice(&[0u8; 32]);
    assert!(decode_node_raw(&longer, 9, true, 0).is_err());
    // A value past its type is refused.
    let mut bad = raw.clone();
    bad[37 * 32] = 1;
    assert!(decode_node_raw(&bad, 9, true, 0).is_err());
}

/// "可信集合免冷却" (2026-11-08): eligibility is the chain's voteEligibleAt word as decoded, with
/// no local registration + 7 days. A trusted node whose word equals its registration time votes
/// the same day; a new node or a wallet change (word = change + 7 days) waits for that word.
#[test]
fn eligibility_is_the_chain_word_not_a_local_cooldown() {
    let reg_time = NOW;
    let build = |eligible: u64| {
        let mut raw = vec![0u8; NODE_RAW_WORDS * 32];
        let mut put =
            |i: usize, v: u128| raw[i * 32 + 16..(i + 1) * 32].copy_from_slice(&v.to_be_bytes());
        put(5, 0x29);
        put(14, 5 * CNET);
        put(36, eligible as u128);
        raw
    };
    let r = report(1, 50);
    // Trusted 472, first registration: the contract wrote voteEligibleAt = registration time.
    let trusted = decode_node_raw(&build(reg_time), 1, true, 5 * CNET).unwrap();
    assert_eq!(can_vote(&trusted, &r, 0, reg_time), Ok(()));
    assert_eq!(can_report(&trusted, 77, true, None, reg_time), Ok(()));
    // New node, or the trusted node after a wallet / operator change: the contract wrote +7 days.
    let week = 7 * 24 * 3600;
    let cooling = decode_node_raw(&build(reg_time + week), 1, true, 5 * CNET).unwrap();
    assert_eq!(
        can_vote(&cooling, &r, 0, reg_time),
        Err(Skip::Cooldown {
            until: reg_time + week
        })
    );
    assert_eq!(
        can_report(&cooling, 77, true, None, reg_time),
        Err(Skip::Cooldown {
            until: reg_time + week
        })
    );
    let long = ReportView {
        expires_at: reg_time + week + 60,
        ..r.clone()
    };
    assert_eq!(can_vote(&cooling, &long, 0, reg_time + week), Ok(()));
}

/// Reports follow the same window as every proposal (project correction 2026-11-09): nothing
/// decides before 600 s, voting ends at 7,200 s; times read from the chain's report record.
#[test]
fn report_window_600_to_7200() {
    use conet_node::online_gate::VoteTiming;
    let t0 = NOW;
    let r = ReportView {
        opened_at: t0,
        min_open: 600,
        expires_at: t0 + 7_200,
        agree: 20, // reporter + 19
        disagree: 0,
        ..report(1, 50)
    };
    assert!(!would_decide_report(
        &r,
        true,
        t0 + 599,
        &conet_node::online_gate::MajorityRule::default()
    ));
    assert!(would_decide_report(
        &r,
        true,
        t0 + 600,
        &conet_node::online_gate::MajorityRule::default()
    ));
    assert!(would_decide_report(
        &r,
        true,
        t0 + 7_199,
        &conet_node::online_gate::MajorityRule::default()
    ));
    assert!(!would_decide_report(
        &r,
        true,
        t0 + 7_200,
        &conet_node::online_gate::MajorityRule::default()
    ));
    // Votes go out at once while open (no holding); none after the end; sealable from 600 s.
    assert_eq!(report_vote_timing(&r, t0 + 100), VoteTiming::Now);
    assert_eq!(report_vote_timing(&r, t0 + 7_200), VoteTiming::Closed);
    let st = conet_node::online_gate::SealStrategy::default();
    assert!(!report_seal_ready(&r, t0 + 599, &st));
    assert!(report_seal_ready(&r, t0 + 600, &st));
    assert!(report_seal_ready(&r, t0 + 7_200, &st)); // late sealing, default on
    let off = conet_node::online_gate::SealStrategy {
        seal_after_window: false,
        ..st
    };
    assert!(!report_seal_ready(&r, t0 + 7_200, &off));
    // Disagree side the same.
    let d = ReportView {
        agree: 1,
        disagree: 20,
        ..r.clone()
    };
    assert!(!would_decide_report(
        &d,
        false,
        t0 + 599,
        &conet_node::online_gate::MajorityRule::default()
    ));
    assert!(would_decide_report(
        &d,
        false,
        t0 + 600,
        &conet_node::online_gate::MajorityRule::default()
    ));
    // Not at the margin: vote at once; the case is also not open after expiry for can_vote.
    let few = ReportView {
        agree: 3,
        ..r.clone()
    };
    assert_eq!(report_vote_timing(&few, t0 + 60), VoteTiming::Now);
    assert!(!report_seal_ready(&few, t0 + 600, &st));
    assert_eq!(can_vote(&voter(1), &r, 0, t0 + 7_200), Err(Skip::Expired));
    // Void at 7,200 s: the contract frees the lock; the gate sees capacity again from voteLocked.
    let held = VoterView {
        locked: 5 * CNET,
        ..voter(1)
    };
    assert_eq!(held.capacity(NEW_REPORT_RATIO_BPS), 0);
    let freed = VoterView { locked: 0, ..held };
    assert_eq!(freed.capacity(NEW_REPORT_RATIO_BPS), 5);
}

/// Reports: early seal on turnout over half, late seal / void close after the end.
#[test]
fn report_turnout_and_late_seal() {
    use conet_node::online_gate::{AfterWindow, SealStrategy};
    let t0 = NOW;
    let st = SealStrategy::default();
    let r = ReportView {
        opened_at: t0,
        min_open: 600,
        expires_at: t0 + 7_200,
        agree: 21,
        disagree: 0,
        population: Some(40),
        ..report(1, 50)
    };
    assert!(report_seal_ready(&r, t0 + 60, &st)); // 21 of 40 > half, margin met
    let half = ReportView {
        agree: 20,
        ..r.clone()
    };
    assert!(!report_seal_ready(&half, t0 + 60, &st)); // exactly half
    assert!(would_decide_report(
        &half,
        true,
        t0 + 60,
        &conet_node::online_gate::MajorityRule::default()
    )); // the 21st vote decides
    let short = ReportView {
        agree: 15,
        disagree: 10,
        ..r.clone()
    };
    assert!(!report_seal_ready(&short, t0 + 3_600, &st)); // over half, margin short
    assert_eq!(report_after_window(&r, t0 + 7_199), AfterWindow::StillOpen);
    assert_eq!(report_after_window(&r, t0 + 7_200), AfterWindow::Seal);
    assert_eq!(
        report_after_window(&short, t0 + 7_200),
        AfterWindow::VoidClose
    );
}

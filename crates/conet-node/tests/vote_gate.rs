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
        fine: CNET,
    }
}

#[test]
fn fine_is_twenty_percent_of_threshold() {
    assert_eq!(fine_now(5 * CNET), CNET);
    assert_eq!(fine_now(1_000), 200);
    // Rounding follows the contract: thr - floor(thr * 8000 / 10000).
    assert_eq!(fine_now(7), 7 - 5);
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
    assert_eq!(v.capacity(CNET), 5);
    for i in 0..5 {
        assert_eq!(
            can_vote(&v, &report(10 + i, 50), 0, NOW),
            Ok(()),
            "case {i}"
        );
        v.locked += CNET;
    }
    assert_eq!(v.capacity(CNET), 0);
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
    assert_eq!(cut.capacity(CNET), 3);
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
    let f = CNET;
    assert_eq!(can_report(&voter(1), 50, true, None, f, NOW), Ok(()));
    assert_eq!(
        can_report(&voter(1), 1, true, None, f, NOW),
        Err(Skip::IsTarget)
    );
    assert_eq!(
        can_report(&voter(1), 50, false, None, f, NOW),
        Err(Skip::TargetNotReportable)
    );
    let open = report(7, 50);
    assert_eq!(
        can_report(&voter(1), 50, true, Some(&open), f, NOW),
        Err(Skip::ReportOpen { rid: 7 })
    );
    // An expired or closed earlier report does not block a new one.
    let expired = ReportView {
        expires_at: NOW,
        ..open.clone()
    };
    assert_eq!(
        can_report(&voter(1), 50, true, Some(&expired), f, NOW),
        Ok(())
    );
    let closed = ReportView { state: 3, ..open };
    assert_eq!(
        can_report(&voter(1), 50, true, Some(&closed), f, NOW),
        Ok(())
    );
    // Opening a report locks F like a vote.
    let full = VoterView {
        locked: 5 * CNET,
        ..voter(1)
    };
    assert!(matches!(
        can_report(&full, 50, true, None, f, NOW),
        Err(Skip::NoLockCapacity { .. })
    ));
    let cooling = VoterView {
        eligible_at: NOW + 1,
        ..voter(1)
    };
    assert!(matches!(
        can_report(&cooling, 50, true, None, f, NOW),
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
    pricey[3].fine = 4 * CNET;
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
    let v = decode_node_raw(&raw, 9, true).unwrap();
    assert_eq!(
        v,
        VoterView {
            node_id: 9,
            active: true,
            services: 0x29,
            stake: 5 * CNET,
            locked: 2 * CNET,
            eligible_at: NOW,
            open_report_id: 3,
        }
    );
    // A different struct size is refused instead of misread.
    assert!(decode_node_raw(&raw[..raw.len() - 32], 9, true).is_err());
    let mut longer = raw.clone();
    longer.extend_from_slice(&[0u8; 32]);
    assert!(decode_node_raw(&longer, 9, true).is_err());
    // A value past its type is refused.
    let mut bad = raw.clone();
    bad[37 * 32] = 1;
    assert!(decode_node_raw(&bad, 9, true).is_err());
}

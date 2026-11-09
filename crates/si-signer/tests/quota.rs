//! Quota ledger (§31): counts, gas ceilings, spend, in flight, persistence. TEST keys only.
use si_signer::quota::*;
use std::path::PathBuf;

/// Fixed clock: 2026-11-08 01:00 UTC.
const T0: u64 = 20_400 * 86_400 + 3_600;
const GWEI_TENTH: u64 = 100_000_000;

/// The N6 defaults, to be adjusted field by field in a test.
fn defaults() -> QuotaConfig {
    QuotaConfig::default()
}

fn ledger(dir: &tempfile::TempDir, cfg: QuotaConfig) -> Quota {
    Quota::open(cfg, dir.path().join("quota.json")).unwrap()
}

/// Defaults plus a test gas ceiling for reportOffline (the real one waits for measured gas).
fn with_report_gas() -> QuotaConfig {
    let mut c = defaults();
    c.gas_ceiling.insert(A_REPORT.into(), 500_000);
    c
}

fn report() -> Intent<'static> {
    Intent::tx(A_REPORT, 400_000, GWEI_TENTH)
}

fn vote(agree: bool) -> Intent<'static> {
    let a = if agree { A_VOTE_AGREE } else { A_VOTE_DISAGREE };
    Intent::tx(a, 80_000, GWEI_TENTH)
}

/// Grant and immediately settle at the reserved cost, so in-flight never limits the test.
fn vote_settled(q: &mut Quota, agree: bool, now: u64) -> Result<Grant, QuotaError> {
    settled(q, &vote(agree), now)
}

/// finalizeReport: still a counted, capped action (50 per day by default; values pending).
fn finalize() -> Intent<'static> {
    Intent::tx(A_FINALIZE, 80_000, GWEI_TENTH)
}

fn settled(q: &mut Quota, i: &Intent, now: u64) -> Result<Grant, QuotaError> {
    let g = q.reserve(i, now)?;
    q.settle(g.ticket.unwrap(), i.gas_limit, i.max_fee_wei, now)
        .unwrap();
    Ok(g)
}

#[test]
fn quota_vote_agree_no_daily_limit() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    // Far past the withdrawn 20-per-day proposal: every agree vote goes through.
    for _ in 0..500 {
        let g = vote_settled(&mut q, true, T0).unwrap();
        assert!(g.warnings.is_empty());
    }
    // Recorded, not counted against anything.
    assert_eq!(q.spent(SpendClass::Ballot, T0), 500 * 80_000 * GWEI_TENTH);
    assert_eq!(q.used(A_VOTE_AGREE, T0), 0);
}

#[test]
fn quota_vote_disagree_no_daily_limit() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    // Far past the withdrawn 200-per-day proposal.
    for _ in 0..2_000 {
        vote_settled(&mut q, false, T0).unwrap();
    }
    // Votes do not touch the counted actions either.
    for _ in 0..50 {
        settled(&mut q, &finalize(), T0).unwrap();
    }
    assert!(matches!(
        settled(&mut q, &finalize(), T0),
        Err(QuotaError::Exceeded { .. })
    ));
    vote_settled(&mut q, false, T0).unwrap();
}

#[test]
fn quota_vote_daily_bucket_refused() {
    let d = tempfile::tempdir().unwrap();
    // A daily count for votes cannot be configured: the ledger does not start.
    for b in [A_VOTE_AGREE, A_VOTE_DISAGREE, "voteReport"] {
        let mut c = defaults();
        c.daily.insert(b.into(), 20);
        let err = Quota::open(c, d.path().join("x.json")).err().unwrap();
        assert!(err.contains("unknown bucket"), "{b}: {err}");
    }
    // Neither can a spend cap for votes: the old field name is unknown.
    let mut j = serde_json::to_value(defaults()).unwrap();
    j["spend_vote_wei"] = serde_json::json!(60_000_000_000_000_000u64);
    assert!(serde_json::from_value::<QuotaConfig>(j).is_err());
}

#[test]
fn quota_vote_outside_spend_caps() {
    let gwei = MAX_FEE_HARD_CAP_WEI;
    let d = tempfile::tempdir().unwrap();
    let mut c = defaults();
    c.max_fee_wei = gwei;
    c.gas_ceiling.insert(A_SET_ONLINE.into(), 10_000_000);
    c.max_inflight = 100;
    c.max_inflight_vote = 100;
    let mut q = ledger(&d, c);
    // Fill the upkeep class (0.06 = ten 6M-gas finalizeReport reservations at 1 gwei) ...
    let fin = Intent::tx(A_FINALIZE, 6_000_000, gwei);
    for _ in 0..10 {
        q.reserve(&fin, T0).unwrap();
    }
    assert!(matches!(
        q.reserve(&fin, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.upkeep"
    ));
    // ... and the anchor class (0.04): the total (0.1) is full too.
    let anchor = Intent::tx(A_SET_ONLINE, 10_000_000, gwei);
    for _ in 0..4 {
        q.reserve(&anchor, T0).unwrap();
    }
    assert!(q.reserve(&anchor, T0).is_err());
    // Votes, deciding votes at the 6M ceiling and the 1 gwei cap included, all go through.
    let deciding = Intent::tx(A_VOTE_AGREE, DECIDING_VOTE_GAS_FLOOR, gwei);
    for _ in 0..60 {
        let g = q.reserve(&deciding, T0).unwrap();
        assert!(g.warnings.is_empty(), "no spend warning for votes");
        q.settle(g.ticket.unwrap(), 3_857_848, gwei, T0).unwrap();
    }
    assert_eq!(q.spent(SpendClass::Ballot, T0), 60 * 3_857_848 * gwei);
    // The gas ceiling still applies per transaction; the price follows vote_fee (H812D).
    assert!(matches!(
        q.reserve(
            &Intent::tx(A_VOTE_AGREE, DECIDING_VOTE_GAS_FLOOR + 1, gwei),
            T0
        ),
        Err(QuotaError::GasAboveCeiling { .. })
    ));
    assert!(q
        .reserve(&Intent::tx(A_VOTE_AGREE, 80_000, gwei + 1), T0)
        .is_ok());
}

#[test]
fn quota_vote_inflight_lane_releases() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, with_report_gas());
    // The vote lane bounds only what is in flight at once.
    let t: Vec<u64> = (0..4)
        .map(|_| q.reserve(&vote(true), T0).unwrap().ticket.unwrap())
        .collect();
    assert_eq!(
        q.reserve(&vote(false), T0).unwrap_err(),
        QuotaError::InflightVote { cap: 4 }
    );
    // Other lanes are not affected by a full vote lane, and the other way round.
    let f: Vec<u64> = (0..4)
        .map(|_| q.reserve(&finalize(), T0).unwrap().ticket.unwrap())
        .collect();
    assert_eq!(
        q.reserve(&finalize(), T0).unwrap_err(),
        QuotaError::Inflight { cap: 4 }
    );
    assert!(q.reserve(&report(), T0).is_ok());
    // Settling or cancelling frees a slot at once: thousands of votes over the day, four at a time.
    q.settle(t[0], 80_000, GWEI_TENTH, T0).unwrap();
    q.cancel(t[1], T0).unwrap();
    for _ in 0..1_000 {
        let g = q.reserve(&vote(true), T0).unwrap();
        q.settle(g.ticket.unwrap(), 80_000, GWEI_TENTH, T0).unwrap();
    }
    // The lane does not reset by day: two still in flight carry over midnight and still count.
    let next = T0 + 86_400;
    let a = q.reserve(&vote(true), next).unwrap().ticket.unwrap();
    let b = q.reserve(&vote(true), next).unwrap().ticket.unwrap();
    assert_eq!(
        q.reserve(&vote(true), next).unwrap_err(),
        QuotaError::InflightVote { cap: 4 }
    );
    for x in [t[2], t[3], a, b] {
        q.settle(x, 80_000, GWEI_TENTH, next).unwrap();
    }
    for x in f {
        q.cancel(x, next).unwrap();
    }
    assert!(q.reserve(&vote(true), next).is_ok());
}

#[test]
fn quota_report_offline_own_lane() {
    let gwei = MAX_FEE_HARD_CAP_WEI;
    let d = tempfile::tempdir().unwrap();
    let mut c = with_report_gas();
    c.max_fee_wei = gwei;
    let mut q = ledger(&d, c);
    // Fill the upkeep spend, the other lane and the vote lane.
    let fin = Intent::tx(A_FINALIZE, 6_000_000, gwei);
    let held: Vec<u64> = (0..4)
        .map(|_| q.reserve(&fin, T0).unwrap().ticket.unwrap())
        .collect();
    for _ in 0..4 {
        q.reserve(&vote(false), T0).unwrap();
    }
    assert!(q.reserve(&fin, T0).is_err());
    assert!(q.reserve(&vote(true), T0).is_err());
    // A report still goes through: no count, outside spend caps, its own lane.
    let r = Intent::tx(A_REPORT, 400_000, gwei);
    let g = q.reserve(&r, T0).unwrap();
    assert!(g.warnings.is_empty());
    // The report lane is a concurrency bound only.
    for _ in 0..3 {
        q.reserve(&r, T0).unwrap();
    }
    assert_eq!(
        q.reserve(&r, T0).unwrap_err(),
        QuotaError::InflightReport { cap: 4 }
    );
    q.settle(g.ticket.unwrap(), 300_000, gwei, T0).unwrap();
    assert!(q.reserve(&r, T0).is_ok());
    for t in held {
        q.cancel(t, T0).unwrap();
    }
}

#[test]
fn quota_report_offline_no_daily_limit() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, with_report_gas());
    // 2,000 reports in one UTC day, settled as they go: none is refused.
    for _ in 0..2_000 {
        let t = q.reserve(&report(), T0).unwrap().ticket.unwrap();
        q.settle(t, 400_000, GWEI_TENTH, T0).unwrap();
    }
    // No daily count can be configured for reports.
    let mut c = with_report_gas();
    c.daily.insert(A_REPORT.into(), 3);
    let err = Quota::open(c, d.path().join("x.json")).err().unwrap();
    assert!(err.contains("unknown bucket reportOffline"), "{err}");
    // Default gas ceiling: the node line's measurement x 1.5. Above it is refused (a per-
    // transaction bound, not a count); without the entry a report is refused as unset.
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let at = |g| Intent::tx(A_REPORT, g, GWEI_TENTH);
    let t = q
        .reserve(&at(REPORT_OFFLINE_GAS_DEFAULT), T0)
        .unwrap()
        .ticket
        .unwrap();
    q.cancel(t, T0).unwrap();
    assert_eq!(
        q.reserve(&at(REPORT_OFFLINE_GAS_DEFAULT + 1), T0)
            .unwrap_err(),
        QuotaError::GasAboveCeiling {
            action: A_REPORT.into(),
            ceiling: REPORT_OFFLINE_GAS_DEFAULT
        }
    );
    let mut c = defaults();
    c.gas_ceiling.remove(A_REPORT);
    let d3 = tempfile::tempdir().unwrap();
    let mut q = ledger(&d3, c);
    assert_eq!(
        q.reserve(&report(), T0).unwrap_err(),
        QuotaError::GasCeilingUnset(A_REPORT.into())
    );
}

#[test]
fn quota_vote_gas_ceiling_floor_6m() {
    let d = tempfile::tempdir().unwrap();
    // Defaults: voteReport and finalizeReport allow a deciding vote of up to 6,000,000.
    let mut q = ledger(&d, QuotaConfig::default());
    for a in [A_VOTE_AGREE, A_VOTE_DISAGREE, A_FINALIZE] {
        let g = q
            .reserve(&Intent::tx(a, DECIDING_VOTE_GAS_FLOOR, 1), T0)
            .unwrap();
        q.cancel(g.ticket.unwrap(), T0).unwrap();
        assert_eq!(
            q.reserve(&Intent::tx(a, DECIDING_VOTE_GAS_FLOOR + 1, 1), T0)
                .unwrap_err(),
            QuotaError::GasAboveCeiling {
                action: a.into(),
                ceiling: DECIDING_VOTE_GAS_FLOOR
            }
        );
    }
    // A config below the floor does not start.
    for a in [A_VOTE_AGREE, A_VOTE_DISAGREE, A_FINALIZE] {
        let mut c = defaults();
        c.gas_ceiling.insert(a.into(), 5_999_999);
        let err = Quota::open(c, d.path().join("x.json"))
            .err()
            .expect("below the floor must not start");
        assert!(err.contains("below 6000000"), "{err}");
    }
    // Other transactions have no default ceiling: refused until measured and configured.
    for a in [A_MARK_ONLINE, A_SET_ONLINE, A_EXTEND_ONLINE] {
        assert_eq!(
            q.reserve(&Intent::tx(a, 50_000, 1), T0).unwrap_err(),
            QuotaError::GasCeilingUnset(a.into())
        );
    }
    // maxFee above the configured cap is refused for non-vote calls; a cap above 1 gwei does
    // not start. (Votes follow vote_fee, see quota_vote_fee_* tests.)
    assert_eq!(
        q.reserve(&Intent::tx(A_FINALIZE, 80_000, GWEI_TENTH + 1), T0)
            .unwrap_err(),
        QuotaError::MaxFeeTooHigh { cap: GWEI_TENTH }
    );
    let mut c = defaults();
    c.max_fee_wei = MAX_FEE_HARD_CAP_WEI + 1;
    assert!(Quota::open(c, d.path().join("y.json")).is_err());
}

const GWEI: u64 = 1_000_000_000;

#[test]
fn quota_vote_fee_uncapped_above_old_cap() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    // Base fee 500 gwei (5,000x the old 0.1 gwei cap), maxFee 4x that: signed.
    let v =
        Intent::tx(A_VOTE_AGREE, DECIDING_VOTE_GAS_FLOOR, 2_000 * GWEI).fees(1_000_000, 500 * GWEI);
    let g = q.reserve(&v, T0).unwrap();
    assert_eq!(g.priority_fee_wei, Some(1_000_000));
    // 6M x 2,000 gwei = 12 CNET > 0.01 CNET: a warning, not a refusal.
    assert!(g.warnings.contains(&W_VOTE_COST.to_string()));
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    // Even a price that overflows the cost arithmetic is signed (recorded, saturated).
    let g = q
        .reserve(
            &Intent::tx(A_VOTE_DISAGREE, DECIDING_VOTE_GAS_FLOOR, u64::MAX),
            T0,
        )
        .unwrap();
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    // Only a legacy (non type 2) vote is refused.
    assert_eq!(
        q.reserve(&v.clone().legacy(), T0).unwrap_err(),
        QuotaError::VoteNotType2
    );
}

#[test]
fn quota_vote_tip_lowered_to_cap_and_signed() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let cap = defaults().vote_fee.priority_cap_wei;
    // Requested tip 100x the cap: lowered to the cap, signed, warned.
    let g = q
        .reserve(
            &Intent::tx(A_VOTE_AGREE, 80_000, 1_000 * GWEI).fees(100 * cap, 0),
            T0,
        )
        .unwrap();
    assert_eq!(g.priority_fee_wei, Some(cap));
    assert!(g.warnings.contains(&W_VOTE_TIP_CLAMPED.to_string()));
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    // A tip above maxFee is lowered to maxFee (EIP-1559 requires tip <= maxFee).
    let g = q
        .reserve(&Intent::tx(A_VOTE_AGREE, 80_000, 10).fees(11, 0), T0)
        .unwrap();
    assert_eq!(g.priority_fee_wei, Some(10));
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    // A tip at or under the cap is kept as is, with no warning.
    let g = q
        .reserve(&Intent::tx(A_VOTE_AGREE, 80_000, GWEI).fees(cap, 0), T0)
        .unwrap();
    assert_eq!(g.priority_fee_wei, Some(cap));
    assert!(!g.warnings.contains(&W_VOTE_TIP_CLAMPED.to_string()));
}

#[test]
fn quota_vote_same_nonce_replacements_signed() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let cap = defaults().vote_fee.priority_cap_wei;
    // A stuck vote is replaced: cancel the old ticket, reserve the bumped price. Every bump is
    // signed, however high maxFee goes; the tip never goes over the cap.
    let mut max_fee = 4 * GWEI;
    let mut tip = 60_000_000u64;
    let mut ticket = q
        .reserve(
            &Intent::tx(A_VOTE_AGREE, DECIDING_VOTE_GAS_FLOOR, max_fee).fees(tip, GWEI),
            T0,
        )
        .unwrap()
        .ticket
        .unwrap();
    for step in 1..=8u64 {
        q.cancel(ticket, T0 + 30 * step).unwrap();
        max_fee = max_fee * 112 / 100 * 10; // far faster than any cap would allow
        tip = tip * 112 / 100;
        let g = q
            .reserve(
                &Intent::tx(A_VOTE_AGREE, DECIDING_VOTE_GAS_FLOOR, max_fee).fees(tip, GWEI),
                T0 + 30 * step,
            )
            .unwrap();
        assert!(g.priority_fee_wei.unwrap() <= cap);
        assert_eq!(g.priority_fee_wei.unwrap(), tip.min(cap));
        ticket = g.ticket.unwrap();
    }
    assert_eq!(q.inflight(), 1);
}

#[test]
fn quota_vote_base_fee_jump_warns_only() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let at = |base| Intent::tx(A_VOTE_AGREE, 80_000, 1_000 * GWEI).fees(0, base);
    let g = q.reserve(&at(GWEI), T0).unwrap();
    assert!(!g.warnings.iter().any(|w| w == W_VOTE_BASE_FEE_JUMP));
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    // One CoNET block later (6 s, at most +12.5%): 100x is impossible -> warning, still signed.
    let g = q.reserve(&at(100 * GWEI), T0 + BLOCK_SECS).unwrap();
    assert!(g.warnings.iter().any(|w| w == W_VOTE_BASE_FEE_JUMP));
    q.cancel(g.ticket.unwrap(), T0 + BLOCK_SECS).unwrap();
    // A plausible rise (12% over one block) does not warn.
    let g = q.reserve(&at(112 * GWEI), T0 + 2 * BLOCK_SECS).unwrap();
    assert!(!g.warnings.iter().any(|w| w == W_VOTE_BASE_FEE_JUMP));
}

#[test]
fn quota_other_ops_keep_fixed_max_fee() {
    let d = tempfile::tempdir().unwrap();
    let mut c = with_report_gas();
    c.gas_ceiling.insert(A_MARK_ONLINE.into(), 100_000);
    let cap = c.max_fee_wei;
    let mut q = ledger(&d, c);
    // Votes are uncapped, but every other call keeps the fixed maxFee cap (H812D scope).
    for a in [A_REPORT, A_FINALIZE, A_MARK_ONLINE] {
        assert_eq!(
            q.reserve(&Intent::tx(a, 80_000, cap + 1), T0).unwrap_err(),
            QuotaError::MaxFeeTooHigh { cap },
            "{a}"
        );
    }
    assert!(q
        .reserve(&Intent::tx(A_VOTE_AGREE, 80_000, cap + 1), T0)
        .is_ok());
}

#[test]
fn quota_spend_reserve_then_settle() {
    let d = tempfile::tempdir().unwrap();
    let gwei = MAX_FEE_HARD_CAP_WEI;
    let mut c = defaults();
    c.max_fee_wei = gwei;
    let mut q = ledger(&d, c);
    // A 6M-gas finalizeReport at 1 gwei reserves 0.006 CNET; the upkeep budget is 0.06.
    let big = Intent::tx(A_FINALIZE, 6_000_000, gwei);
    let tickets: Vec<u64> = (0..4)
        .map(|_| q.reserve(&big, T0).unwrap().ticket.unwrap())
        .collect();
    // Receipts cost far less than reserved: 80,000 gas at 0.001 gwei each.
    for t in tickets {
        q.settle(t, 80_000, 1_000_000, T0).unwrap();
    }
    assert_eq!(q.inflight(), 0);
    // So nine more full-cost calls fit (0.054 + 4 x 0.00000008), the tenth does not.
    for _ in 0..9 {
        let t = q.reserve(&big, T0).unwrap().ticket.unwrap();
        q.settle(t, 6_000_000, gwei, T0).unwrap();
    }
    let e = q.reserve(&big, T0).unwrap_err();
    assert!(
        matches!(e, QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.upkeep"),
        "{e}"
    );

    // Cancelling releases the reserved spend, but the count stays used.
    let d = tempfile::tempdir().unwrap();
    let mut c = defaults();
    c.max_fee_wei = gwei;
    c.spend_upkeep_wei = 6_000_000 * gwei; // room for exactly one reservation
    let mut q = ledger(&d, c);
    let t = q.reserve(&big, T0).unwrap().ticket.unwrap();
    assert!(matches!(
        q.reserve(&big, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.upkeep"
    ));
    q.cancel(t, T0).unwrap();
    assert_eq!(q.used(B_FINALIZE, T0), 1);
    assert!(q.reserve(&big, T0).is_ok());
    assert_eq!(q.used(B_FINALIZE, T0), 2);
    assert_eq!(
        q.settle(999, 1, 1, T0).unwrap_err(),
        QuotaError::UnknownTicket
    );
}

#[test]
fn quota_spend_class_caps_independent() {
    let gwei = MAX_FEE_HARD_CAP_WEI;
    let d = tempfile::tempdir().unwrap();
    let mut c = defaults();
    c.max_fee_wei = gwei;
    c.gas_ceiling.insert(A_SET_ONLINE.into(), 10_000_000);
    c.max_inflight = 100;
    let mut q = ledger(&d, c);
    // Anchor class: 0.04 CNET net = four 0.01 CNET reservations.
    let anchor = Intent::tx(A_SET_ONLINE, 10_000_000, gwei);
    for _ in 0..4 {
        q.reserve(&anchor, T0).unwrap();
    }
    assert!(matches!(
        q.reserve(&anchor, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.anchor"
    ));
    // Upkeep class is separate: 0.06 CNET = ten 0.006 CNET reservations.
    let fin = Intent::tx(A_FINALIZE, 6_000_000, gwei);
    for _ in 0..10 {
        q.reserve(&fin, T0).unwrap();
    }
    assert!(matches!(
        q.reserve(&fin, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.upkeep"
    ));
    // Anchor spend counts net of reimbursements; the total caps upkeep + anchor.
    let d2 = tempfile::tempdir().unwrap();
    let mut c = defaults();
    c.max_fee_wei = gwei;
    c.gas_ceiling.insert(A_SET_ONLINE.into(), 10_000_000);
    c.max_inflight = 100;
    c.spend_total_wei = 50_000_000_000_000_000; // tighter total: 0.05
    let mut q = ledger(&d2, c);
    let mut ts = Vec::new();
    for _ in 0..4 {
        ts.push(q.reserve(&anchor, T0).unwrap().ticket.unwrap());
    }
    for t in ts {
        q.settle(t, 10_000_000, gwei, T0).unwrap();
    }
    q.reimbursed(20_000_000_000_000_000, T0).unwrap();
    q.reserve(&anchor, T0).unwrap();
    q.reserve(&anchor, T0).unwrap(); // anchor net 0.04 again
                                     // Upkeep has room (0.06) but the total (0.05) has only 0.01 left: one 0.006 call fits.
    q.reserve(&fin, T0).unwrap();
    assert!(matches!(
        q.reserve(&fin, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.total"
    ));
}

#[test]
fn quota_inflight_cap_4() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let mut t = Vec::new();
    for _ in 0..4 {
        t.push(q.reserve(&finalize(), T0).unwrap().ticket.unwrap());
    }
    assert_eq!(
        q.reserve(&finalize(), T0).unwrap_err(),
        QuotaError::Inflight { cap: 4 }
    );
    // Signatures are not transactions: anchor receipts are not limited by in flight.
    assert!(q.reserve(&Intent::signature(A_ANCHOR_RECEIPT), T0).is_ok());
    q.settle(t[0], 80_000, 1, T0).unwrap();
    assert!(q.reserve(&finalize(), T0).is_ok());
}

#[test]
fn quota_persists_across_restart() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    for _ in 0..50 {
        settled(&mut q, &finalize(), T0).unwrap();
    }
    let held = q.reserve(&vote(false), T0).unwrap().ticket.unwrap();
    drop(q);
    let mut q = ledger(&d, defaults());
    assert_eq!(q.used(B_FINALIZE, T0), 50);
    assert_eq!(q.inflight(), 1);
    assert!(matches!(
        settled(&mut q, &finalize(), T0 + 5),
        Err(QuotaError::Exceeded { .. })
    ));
    // The in-flight ticket from before the restart can still be settled.
    q.settle(held, 80_000, 1, T0 + 5).unwrap();
    assert_eq!(q.inflight(), 0);
    // The file is private to the signer user.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(d.path().join("quota.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn quota_utc_day_rollover() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let last = (T0 / 86_400 + 1) * 86_400 - 1; // 23:59:59 UTC
    for _ in 0..50 {
        settled(&mut q, &finalize(), last).unwrap();
    }
    assert!(settled(&mut q, &finalize(), last).is_err());
    let held = q.reserve(&vote(false), last).unwrap().ticket.unwrap();
    // 00:00:00 UTC: counts start over, the in-flight ticket carries over.
    let midnight = last + 1;
    assert_eq!(q.used(B_FINALIZE, midnight), 0);
    settled(&mut q, &finalize(), midnight).unwrap();
    assert_eq!(q.used(B_FINALIZE, midnight), 1);
    assert_eq!(q.inflight(), 1);
    q.settle(held, 80_000, 1, midnight).unwrap();
}

#[test]
fn quota_corrupt_state_fails_closed() {
    let d = tempfile::tempdir().unwrap();
    let path: PathBuf = d.path().join("quota.json");
    for bad in [
        b"{not json".to_vec(),
        br#"{"v":2,"day":0,"counts":{},"spent_vote_wei":0,"spent_anchor_wei":0,"reimbursed_anchor_wei":0,"inflight":{},"next_ticket":0,"warned":[],"manual_targets":{}}"#.to_vec(),
        b"".to_vec(),
    ] {
        std::fs::write(&path, &bad).unwrap();
        let mut q = Quota::open(QuotaConfig::default(), &path).unwrap();
        assert!(q.broken().is_some());
        for i in [
            Intent::signature(A_ANCHOR_RECEIPT),
            vote(false),
        ] {
            assert!(matches!(
                q.reserve(&i, T0).unwrap_err(),
                QuotaError::StateBroken(_)
            ));
        }
        // The broken file is left as it was for the operator to inspect.
        assert_eq!(std::fs::read(&path).unwrap(), bad);
    }
}

#[test]
fn quota_warn_once_at_80pct() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, defaults());
    let mut warned_at = Vec::new();
    for i in 1..=50 {
        let g = settled(&mut q, &finalize(), T0).unwrap();
        if g.warnings.iter().any(|w| w == B_FINALIZE) {
            warned_at.push(i);
        }
    }
    // 40 of 50 = 80 %: one warning, not repeated at 41..50.
    assert_eq!(warned_at, vec![40]);
    // Next day it can warn again.
    let next = T0 + 86_400;
    let mut again = 0;
    for _ in 0..40 {
        let g = settled(&mut q, &finalize(), next).unwrap();
        again += g.warnings.iter().filter(|w| *w == B_FINALIZE).count();
    }
    assert_eq!(again, 1);
}

#[test]
fn quota_unknown_selector_refused() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, QuotaConfig::default());
    for a in [
        "transfer",
        "registerFor",
        "declareOffline",
        "settleReport",
        "reportOffline.manual",
        "voteReport",
        "",
    ] {
        assert_eq!(
            q.reserve(&Intent::tx(a, 50_000, 1), T0).unwrap_err(),
            QuotaError::UnknownSelector,
            "{a}"
        );
    }
    // Unknown buckets and gas entries in the config do not start.
    let mut c = defaults();
    c.daily.insert("registerFor".into(), 5);
    assert!(Quota::open(c, d.path().join("a.json")).is_err());
    let mut c = defaults();
    c.gas_ceiling.insert("declareOffline".into(), 100_000);
    assert!(Quota::open(c, d.path().join("b.json")).is_err());
    // The example config parses and validates.
    let ex = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/quota.example.json"))
        .unwrap();
    let c: QuotaConfig = serde_json::from_str(&ex).unwrap();
    c.validate().unwrap();
}

mod anchor {
    use super::*;
    use si_signer::keystore;
    use si_signer::proto::{Request, Response};
    use si_signer::server::{Signer, SignerConfig};
    use zeroize::Zeroizing;

    const REGISTRY: &str = "0x00000000000000000000000000000000c0de0001";

    fn cfg(dir: &tempfile::TempDir, quota: bool) -> SignerConfig {
        let g: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/golden.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let kek = [7u8; 32];
        let secrets = keystore::Secrets {
            wallet_hex: g["wallets"]["nodeA"]["privateKey"].as_str().unwrap().into(),
            pgp_armored: g["keys"]["nodeA"]["armoredPrivate"]
                .as_str()
                .unwrap()
                .into(),
            pgp_pass: g["keys"]["nodeA"]["passphrase"].as_str().unwrap().into(),
            previous_pgp_armored: String::new(),
            previous_pgp_pass: String::new(),
        };
        SignerConfig {
            keystore_file: keystore::seal(&kek, &secrets).unwrap(),
            kek: Zeroizing::new(kek),
            verifying_contract: REGISTRY.into(),
            allow_bind: false,
            allow_uid: None,
            anchor_node_id: Some("5".into()),
            quota: quota.then(|| (QuotaConfig::default(), dir.path().join("quota.json"))),
        }
    }

    #[test]
    fn anchor_receipt_daily_cap_1000() {
        let d = tempfile::tempdir().unwrap();
        // Anchor receipts without a ledger do not start.
        assert!(Signer::start(cfg(&d, false)).is_err());

        // Fixed clock (01:00 UTC), so the test never straddles midnight.
        let now = T0 as i64;
        let until = T0 + 3600;
        let req = |seq| Request::SignAnchorReceipt {
            node_id: "12".into(),
            online_seq: seq,
            online_until: until,
        };
        let s = Signer::start(cfg(&d, true)).unwrap();
        for seq in 1..=1000 {
            assert!(
                matches!(s.handle_at(req(seq), now), Response::Ok { .. }),
                "receipt {seq}"
            );
        }
        let refused = |r: Response| match r {
            Response::Refused { reason } => reason,
            Response::Ok { .. } => panic!("signed past the cap"),
        };
        assert_eq!(
            refused(s.handle_at(req(1001), now)),
            "quota_exceeded:anchorReceipt 1000/1000"
        );
        // A bad request is refused on its fields before it touches the ledger.
        assert!(refused(s.handle_at(
            Request::SignAnchorReceipt {
                node_id: "5".into(),
                online_seq: 1,
                online_until: until
            },
            now
        ))
        .contains("anchor_fields"));
        drop(s);
        // Still refused after a restart.
        let s = Signer::start(cfg(&d, true)).unwrap();
        assert_eq!(
            refused(s.handle_at(req(1002), now)),
            "quota_exceeded:anchorReceipt 1000/1000"
        );
        // Other roles keep working.
        assert!(matches!(
            s.handle_at(Request::Address, now),
            Response::Ok { .. }
        ));
    }
}

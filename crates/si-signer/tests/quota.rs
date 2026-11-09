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

fn with_manual(n: u32) -> QuotaConfig {
    let mut c = defaults();
    c.daily.insert(B_MANUAL_REPORT.into(), n);
    c.gas_ceiling.insert(A_MANUAL_REPORT.into(), 500_000);
    c
}

fn vote(agree: bool) -> Intent<'static> {
    let a = if agree { A_VOTE_AGREE } else { A_VOTE_DISAGREE };
    Intent::tx(a, 80_000, GWEI_TENTH)
}

/// Grant and immediately settle at the reserved cost, so in-flight never limits the test.
fn vote_settled(q: &mut Quota, agree: bool, now: u64) -> Result<Grant, QuotaError> {
    let g = q.reserve(&vote(agree), now)?;
    q.settle(g.ticket.unwrap(), 80_000, GWEI_TENTH, now)
        .unwrap();
    Ok(g)
}

#[test]
fn quota_vote_agree_cap_rejects_21st() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, QuotaConfig::default());
    for _ in 0..20 {
        vote_settled(&mut q, true, T0).unwrap();
    }
    let e = vote_settled(&mut q, true, T0).unwrap_err();
    assert_eq!(
        e,
        QuotaError::Exceeded {
            bucket: B_VOTE_AGREE.into(),
            used: 20,
            cap: 20
        }
    );
    // The refusal names bucket and counts only.
    assert_eq!(e.to_string(), "quota_exceeded:voteReport.agree 20/20");
}

#[test]
fn quota_vote_disagree_counted_separately() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, QuotaConfig::default());
    for _ in 0..20 {
        vote_settled(&mut q, true, T0).unwrap();
    }
    assert!(vote_settled(&mut q, true, T0).is_err());
    // Agree budget spent; disagree votes still go through and are counted apart.
    for _ in 0..30 {
        vote_settled(&mut q, false, T0).unwrap();
    }
    assert_eq!(q.used(B_VOTE_AGREE, T0), 20);
    assert_eq!(q.used(B_VOTE_DISAGREE, T0), 30);
}

#[test]
fn quota_manual_report_counts_toward_agree() {
    let d = tempfile::tempdir().unwrap();
    // H8-12 has no default: without a configured count, manual reports are refused.
    let mut off = ledger(&d, QuotaConfig::default());
    let r = Intent {
        target: Some("41"),
        ..Intent::tx(A_MANUAL_REPORT, 400_000, GWEI_TENTH)
    };
    assert_eq!(
        off.reserve(&r, T0).unwrap_err(),
        QuotaError::NotConfigured(B_MANUAL_REPORT.into())
    );
    drop(off);

    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, with_manual(3));
    for _ in 0..19 {
        vote_settled(&mut q, true, T0).unwrap();
    }
    let g = q.reserve(&r, T0).unwrap();
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    assert_eq!(q.used(B_MANUAL_REPORT, T0), 1);
    assert_eq!(q.used(B_VOTE_AGREE, T0), 20);
    // The report used the last agree slot: both another vote and another report are refused.
    assert!(matches!(
        vote_settled(&mut q, true, T0),
        Err(QuotaError::Exceeded { .. })
    ));
    let r2 = Intent {
        target: Some("42"),
        ..r.clone()
    };
    assert_eq!(
        q.reserve(&r2, T0).unwrap_err(),
        QuotaError::Exceeded {
            bucket: B_VOTE_AGREE.into(),
            used: 20,
            cap: 20
        }
    );
    // The manual daily count is its own cap too.
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, with_manual(2));
    for t in ["1", "2"] {
        let g = q
            .reserve(
                &Intent {
                    target: Some(t),
                    ..r.clone()
                },
                T0,
            )
            .unwrap();
        q.cancel(g.ticket.unwrap(), T0).unwrap();
    }
    assert_eq!(
        q.reserve(
            &Intent {
                target: Some("3"),
                ..r.clone()
            },
            T0
        )
        .unwrap_err(),
        QuotaError::Exceeded {
            bucket: B_MANUAL_REPORT.into(),
            used: 2,
            cap: 2
        }
    );
}

#[test]
fn quota_manual_report_same_target_24h() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, with_manual(10));
    let r = |t: &'static str| Intent {
        target: Some(t),
        ..Intent::tx(A_MANUAL_REPORT, 400_000, GWEI_TENTH)
    };
    let g = q.reserve(&r("41"), T0).unwrap();
    q.cancel(g.ticket.unwrap(), T0).unwrap();
    // Same target within 24 h, including just after the UTC day boundary: refused.
    let next_day = (T0 / 86_400 + 1) * 86_400 + 60;
    for at in [T0 + 1, next_day, T0 + 86_399] {
        assert_eq!(
            q.reserve(&r("41"), at).unwrap_err(),
            QuotaError::TargetRecent { window_sec: 86_400 }
        );
    }
    // Another target is fine; the same target after 24 h is fine.
    let g = q.reserve(&r("42"), T0 + 10).unwrap();
    q.cancel(g.ticket.unwrap(), T0 + 10).unwrap();
    let g = q.reserve(&r("41"), T0 + 86_400).unwrap();
    q.cancel(g.ticket.unwrap(), T0 + 86_400).unwrap();
    // A report without a target is refused.
    assert!(q
        .reserve(
            &Intent::tx(A_MANUAL_REPORT, 400_000, GWEI_TENTH),
            T0 + 86_400
        )
        .is_err());
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
    // maxFee above the configured cap is refused; a cap above 1 gwei does not start.
    assert_eq!(
        q.reserve(&Intent::tx(A_VOTE_AGREE, 80_000, GWEI_TENTH + 1), T0)
            .unwrap_err(),
        QuotaError::MaxFeeTooHigh { cap: GWEI_TENTH }
    );
    let mut c = defaults();
    c.max_fee_wei = MAX_FEE_HARD_CAP_WEI + 1;
    assert!(Quota::open(c, d.path().join("y.json")).is_err());
}

#[test]
fn quota_spend_reserve_then_settle() {
    let d = tempfile::tempdir().unwrap();
    let gwei = MAX_FEE_HARD_CAP_WEI;
    let mut c = defaults();
    c.max_fee_wei = gwei;
    let mut q = ledger(&d, c);
    // A 6M-gas vote at 1 gwei reserves 0.006 CNET; the vote budget is 0.06.
    let big = Intent::tx(A_VOTE_AGREE, 6_000_000, gwei);
    let tickets: Vec<u64> = (0..4)
        .map(|_| q.reserve(&big, T0).unwrap().ticket.unwrap())
        .collect();
    // Receipts cost far less than reserved: 80,000 gas at 0.001 gwei each.
    for t in tickets {
        q.settle(t, 80_000, 1_000_000, T0).unwrap();
    }
    assert_eq!(q.inflight(), 0);
    // So nine more full-cost votes fit (0.054 + 4 x 0.00000008), the tenth does not.
    for _ in 0..9 {
        let t = q.reserve(&big, T0).unwrap().ticket.unwrap();
        q.settle(t, 6_000_000, gwei, T0).unwrap();
    }
    let e = q.reserve(&big, T0).unwrap_err();
    assert!(
        matches!(e, QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.vote"),
        "{e}"
    );

    // Cancelling releases the reserved spend, but the count stays used.
    let d = tempfile::tempdir().unwrap();
    let mut c = defaults();
    c.max_fee_wei = gwei;
    c.spend_vote_wei = 6_000_000 * gwei; // room for exactly one reservation
    let mut q = ledger(&d, c);
    let t = q.reserve(&big, T0).unwrap().ticket.unwrap();
    assert!(matches!(
        q.reserve(&big, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.vote"
    ));
    q.cancel(t, T0).unwrap();
    assert_eq!(q.used(B_VOTE_AGREE, T0), 1);
    assert!(q.reserve(&big, T0).is_ok());
    assert_eq!(q.used(B_VOTE_AGREE, T0), 2);
    assert_eq!(
        q.settle(999, 1, 1, T0).unwrap_err(),
        QuotaError::UnknownTicket
    );
}

#[test]
fn quota_spend_class_caps_independent() {
    let d = tempfile::tempdir().unwrap();
    let mut c = defaults();
    c.max_fee_wei = MAX_FEE_HARD_CAP_WEI;
    c.gas_ceiling.insert(A_SET_ONLINE.into(), 10_000_000);
    c.max_inflight = 100;
    let mut q = ledger(&d, c);
    let gwei = MAX_FEE_HARD_CAP_WEI;
    // Anchor class: 0.04 CNET net = four 0.01 CNET reservations.
    let anchor = Intent::tx(A_SET_ONLINE, 10_000_000, gwei);
    for _ in 0..4 {
        q.reserve(&anchor, T0).unwrap();
    }
    assert!(matches!(
        q.reserve(&anchor, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.anchor"
    ));
    // Vote class is separate: 0.06 CNET = ten 0.006 CNET reservations ...
    let v = Intent::tx(A_VOTE_DISAGREE, 6_000_000, gwei);
    for _ in 0..10 {
        q.reserve(&v, T0).unwrap();
    }
    // ... and now the total (0.04 + 0.06 = 0.1) is full as well as the vote class.
    assert!(matches!(
        q.reserve(&v, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.vote"
    ));
    // Anchor spend counts net of reimbursements: settle four at full cost (0.04), get 0.02
    // back, and the anchor class has 0.02 of room again.
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
                                     // Vote class has room (0.06) but the total (0.05) has only 0.01 left: one 0.006 vote fits.
    q.reserve(&v, T0).unwrap();
    assert!(matches!(
        q.reserve(&v, T0).unwrap_err(),
        QuotaError::Exceeded { ref bucket, .. } if bucket == "spend.total"
    ));
}

#[test]
fn quota_inflight_cap_4() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, QuotaConfig::default());
    let mut t = Vec::new();
    for _ in 0..4 {
        t.push(q.reserve(&vote(false), T0).unwrap().ticket.unwrap());
    }
    assert_eq!(
        q.reserve(&vote(false), T0).unwrap_err(),
        QuotaError::Inflight { cap: 4 }
    );
    // Signatures are not transactions: anchor receipts are not limited by in flight.
    assert!(q.reserve(&Intent::signature(A_ANCHOR_RECEIPT), T0).is_ok());
    q.settle(t[0], 80_000, 1, T0).unwrap();
    assert!(q.reserve(&vote(false), T0).is_ok());
}

#[test]
fn quota_persists_across_restart() {
    let d = tempfile::tempdir().unwrap();
    let mut q = ledger(&d, QuotaConfig::default());
    for _ in 0..20 {
        vote_settled(&mut q, true, T0).unwrap();
    }
    let held = q.reserve(&vote(false), T0).unwrap().ticket.unwrap();
    drop(q);
    let mut q = ledger(&d, QuotaConfig::default());
    assert_eq!(q.used(B_VOTE_AGREE, T0), 20);
    assert_eq!(q.inflight(), 1);
    assert!(matches!(
        vote_settled(&mut q, true, T0 + 5),
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
    let mut q = ledger(&d, QuotaConfig::default());
    let last = (T0 / 86_400 + 1) * 86_400 - 1; // 23:59:59 UTC
    for _ in 0..20 {
        vote_settled(&mut q, true, last).unwrap();
    }
    assert!(vote_settled(&mut q, true, last).is_err());
    let held = q.reserve(&vote(false), last).unwrap().ticket.unwrap();
    // 00:00:00 UTC: counts start over, the in-flight ticket carries over.
    let midnight = last + 1;
    assert_eq!(q.used(B_VOTE_AGREE, midnight), 0);
    vote_settled(&mut q, true, midnight).unwrap();
    assert_eq!(q.used(B_VOTE_AGREE, midnight), 1);
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
    let mut q = ledger(&d, QuotaConfig::default());
    let mut warned_at = Vec::new();
    for i in 1..=20 {
        let g = vote_settled(&mut q, true, T0).unwrap();
        if g.warnings.iter().any(|w| w == B_VOTE_AGREE) {
            warned_at.push(i);
        }
    }
    // 16 of 20 = 80 %: one warning, not repeated at 17..20.
    assert_eq!(warned_at, vec![16]);
    // Next day it can warn again.
    let next = T0 + 86_400;
    let mut again = 0;
    for _ in 0..16 {
        let g = vote_settled(&mut q, true, next).unwrap();
        again += g.warnings.iter().filter(|w| *w == B_VOTE_AGREE).count();
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
        "reportOffline",
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

        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let req = |seq| Request::SignAnchorReceipt {
            node_id: "12".into(),
            online_seq: seq,
            online_until: until,
        };
        let s = Signer::start(cfg(&d, true)).unwrap();
        for seq in 1..=1000 {
            assert!(
                matches!(s.handle(req(seq)), Response::Ok { .. }),
                "receipt {seq}"
            );
        }
        let refused = |r: Response| match r {
            Response::Refused { reason } => reason,
            Response::Ok { .. } => panic!("signed past the cap"),
        };
        assert_eq!(
            refused(s.handle(req(1001))),
            "quota_exceeded:anchorReceipt 1000/1000"
        );
        // A bad request is refused on its fields before it touches the ledger.
        assert!(refused(s.handle(Request::SignAnchorReceipt {
            node_id: "5".into(),
            online_seq: 1,
            online_until: until
        }))
        .contains("anchor_fields"));
        drop(s);
        // Still refused after a restart.
        let s = Signer::start(cfg(&d, true)).unwrap();
        assert_eq!(
            refused(s.handle(req(1002))),
            "quota_exceeded:anchorReceipt 1000/1000"
        );
        // Other roles keep working.
        assert!(matches!(s.handle(Request::Address), Response::Ok { .. }));
    }
}

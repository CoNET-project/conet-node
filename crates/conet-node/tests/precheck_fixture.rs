//! Recovery and renewal prechecks against the real contract (node line 45e9c5d0), from
//! `tests/data/precheck-fixture.json` written by `tools/vote-gate/precheck-fixture.test.ts` on a
//! local Hardhat chain (test keys only).
//!
//! Recovery: for every recorded state the view outputs go through the same conversion the reader
//! uses (`recovery_view_from`), and the precheck's first blocker in the contract's order must be
//! exactly the error `requestRecovery` returned ("ok" = no blocker).
//! Renewal: `renews(stake, minStakeAt(termEnd))` must match the event `settleTerms` emitted.
use conet_node::online_gate::{precheck_recovery, recovery_view_from, RecoveryReads, ONLINE_FEE};
use conet_node::stake_term::renews;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("data/precheck-fixture.json")).unwrap()
}
fn n(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn reads(c: &Value) -> RecoveryReads {
    RecoveryReads {
        now: n(&c["now"]) as u64,
        offline_since: n(&c["offlineSince"]) as u64,
        not_before: n(&c["notBefore"]) as u64,
        retry_at: n(&c["retryAt"]) as u64,
        case_state: n(&c["caseState"]) as u8,
        case_opened_at: n(&c["caseOpenedAt"]) as u64,
        case_expires_at: n(&c["caseExpiresAt"]) as u64,
        stake_stop: c["stakeStop"].as_bool().unwrap(),
        in_term: c["inTerm"].as_bool().unwrap(),
        term_base: n(&c["termBase"]),
        stake: n(&c["stake"]),
        free_stake: n(&c["freeStake"]),
        min_stake_now: n(&c["minStakeNow"]),
        suspended: c["suspended"].as_bool().unwrap(),
    }
}

#[test]
fn recovery_precheck_matches_request_recovery() {
    let f = fixture();
    let cases = f["recovery"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    let mut seen = std::collections::BTreeSet::new();
    for c in cases {
        let label = c["label"].as_str().unwrap();
        let b = precheck_recovery(&recovery_view_from(&reads(c), ONLINE_FEE));
        let ours = b.contract_error().unwrap_or("ok");
        assert_eq!(ours, c["answer"].as_str().unwrap(), "{label}: {b:?}");
        seen.insert(ours);
    }
    // Every gate was exercised at least once.
    for e in [
        "ok",
        "InsufficientStake",
        "RecoveryTooSoon",
        "OfflineCooldown",
        "RejectedWait",
        "CaseProtected",
    ] {
        assert!(seen.contains(e), "{e} not covered");
    }
}

/// A node slashed 10% inside its term (above the 80% floor, not stopped) may ask at once after
/// its cooldown: the full latest threshold applies only to a stopped node.
#[test]
fn in_term_floor_vs_stopped_full_threshold() {
    let f = fixture();
    let by = |l: &str| {
        f["recovery"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["label"] == l)
            .unwrap()
            .clone()
    };
    let b = by("B slashed 10% in term");
    let v = recovery_view_from(&reads(&b), ONLINE_FEE);
    assert!(v.in_term && !v.stake_stop && v.stake < v.latest_threshold);
    assert!(precheck_recovery(&v).clear());
    // Stopped C, 1 wei short of the latest full amount: tells the operator exactly 1 wei.
    let c = by("C topped up to full-1wei");
    let p = precheck_recovery(&recovery_view_from(&reads(&c), ONLINE_FEE));
    assert_eq!(p.stake_missing, Some(1));
    assert!(p.suspended);
    // Stopped D after its failed renewal needs the new full amount (10), not 80% of its base.
    let d = by("D after failed renewal");
    let p = precheck_recovery(&recovery_view_from(&reads(&d), ONLINE_FEE));
    assert_eq!(
        p.stake_missing,
        Some(n(&d["minStakeNow"]) - n(&d["freeStake"]))
    );
}

/// The waits the operator is told are the contract's own times.
#[test]
fn waits_are_the_contract_times() {
    let f = fixture();
    for c in f["recovery"].as_array().unwrap() {
        let b = precheck_recovery(&recovery_view_from(&reads(c), ONLINE_FEE));
        let now = n(&c["now"]) as u64;
        match c["answer"].as_str().unwrap() {
            "RecoveryTooSoon" => assert_eq!(b.gap_until, Some(n(&c["notBefore"]) as u64)),
            "RejectedWait" => assert_eq!(b.retry_until, Some(n(&c["retryAt"]) as u64)),
            "OfflineCooldown" => {
                assert_eq!(
                    b.cooldown_until,
                    Some(n(&c["offlineSince"]) as u64 + 43_200)
                )
            }
            "CaseProtected" => assert!(b.replace_at.unwrap() > now),
            _ => {}
        }
        if let Some(w) = b.wait {
            assert!(w > 0);
        }
    }
}

#[test]
fn renewal_matches_settle_terms() {
    let f = fixture();
    let rows = f["renewal"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let mut both = (false, false);
    for r in rows {
        let ok = renews(n(&r["stake"]), n(&r["needAtEnd"]));
        let ev = r["event"].as_str().unwrap();
        assert_eq!(ok, ev == "TermStarted", "{r}");
        if ok {
            // Same term length, no gap; equal stake renews.
            assert_eq!(
                n(&r["termEndAfter"]),
                n(&r["termEnd"]) + n(&r["termLength"])
            );
            assert_eq!(n(&r["stake"]), n(&r["needAtEnd"]));
            assert!(!r["stakeStopAfter"].as_bool().unwrap());
            both.0 = true;
        } else {
            assert!(r["stakeStopAfter"].as_bool().unwrap());
            both.1 = true;
        }
    }
    assert_eq!(both, (true, true));
}

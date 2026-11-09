//! Node line v0.4.2 (a1a13d46) on a local Hardhat chain vs the node side
//! (`tests/data/v042-fixture.json`, from `tools/vote-gate/v042-fixture.test.ts`).
use conet_node::online_gate::{seal_ready, SealStrategy, Tally};
use conet_node::stake_term::suspend_floor;
use conet_node::vote_gate::{report_seal_ready, DueBreakdown, ReportView, REPORT_OPEN};
use serde_json::Value;

fn data() -> Value {
    let p = format!(
        "{}/tests/data/v042-fixture.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn n(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

/// finalizeRecovery / finalizeAdmission / finalizeReport at 599 / 600 / 7,199 / 7,200 s: the node
/// side's seal_ready (online) and report_seal_ready agree with the contract's answer each time.
#[test]
fn seal_window_matches_all_three_finalize_entries() {
    let d = data();
    let st = SealStrategy::default();
    let mut checked = 0;
    for c in d["seal"].as_array().unwrap() {
        let Some(answer) = c["answer"].as_str() else {
            continue; // the sent seal (gas record)
        };
        let opened = n(&c["openedAt"]) as u64;
        let now = n(&c["callTime"]) as u64;
        let ours = match c["kind"].as_str().unwrap() {
            "report" => {
                let r = ReportView {
                    rid: 1,
                    target: 2,
                    reporter: 3,
                    opened_at: opened,
                    expires_at: n(&c["expiresAt"]) as u64,
                    min_open: n(&c["minOpen"]) as u32,
                    agree: n(&c["agree"]) as u32,
                    disagree: n(&c["disagree"]) as u32,
                    margin: n(&c["margin"]) as u16,
                    state: REPORT_OPEN,
                    ratio_bps: 2_000,
                };
                report_seal_ready(&r, now, &st)
            }
            _ => {
                let t = Tally {
                    opened_at: opened,
                    agree: n(&c["agree"]) as u32,
                    disagree: n(&c["disagree"]) as u32,
                    margin: n(&c["margin"]) as u32,
                };
                seal_ready(&t, now, &st)
            }
        };
        assert_eq!(
            ours,
            answer == "ok",
            "{} at +{}: contract {answer}",
            c["kind"],
            c["offset"]
        );
        checked += 1;
    }
    assert_eq!(checked, 12);
}

#[test]
fn finalize_gas_recorded() {
    let d = data();
    for c in d["seal"].as_array().unwrap() {
        if c["offset"] == "600-sent" {
            let gas = n(&c["gasUsed"]);
            assert!(gas > 0 && gas < 6_000_000, "{}: {gas}", c["kind"]);
            println!("{} seal gas {gas}", c["kind"].as_str().unwrap());
        }
    }
}

/// 80% floor: a slash to exactly floor(termBase x 0.8) keeps serving, one bps more stops.
#[test]
fn floor_matches_the_contract() {
    let d = data();
    for f in d["floor"].as_array().unwrap() {
        let ours = n(&f["stake"]) >= suspend_floor(n(&f["termBase"]));
        assert_eq!(ours, f["active"].as_bool().unwrap(), "{f}");
    }
}

/// dueBreakdown: the parts add up, matureUnwithdrawn equals matureUnwithdrawnPrincipal(), and only
/// an exiting node past its unbonding counts (a failed renewal alone does not, in v0.4.2).
#[test]
fn due_breakdown_reading() {
    let d = data();
    let due = d["due"].as_array().unwrap();
    for x in due {
        let b = DueBreakdown {
            mature_unwithdrawn: n(&x["matureUnwithdrawn"]),
            owed: n(&x["owed"]),
        };
        assert_eq!(b.mature_unwithdrawn, n(&x["matureUnwithdrawnPrincipal"]));
        assert_eq!(b.due_unpaid(), b.mature_unwithdrawn + b.owed);
    }
    let by = |l: &str| due.iter().find(|x| x["label"] == l).unwrap();
    assert_eq!(
        n(&by("after the unlock period (no exit requested)")["matureUnwithdrawn"]),
        0
    );
    assert_eq!(
        n(&by("exit requested + unbonding over")["matureUnwithdrawn"]),
        n(&by("exit requested + unbonding over")["node25Stake"])
    );
}

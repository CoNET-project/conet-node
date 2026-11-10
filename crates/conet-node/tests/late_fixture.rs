//! Node line 077c78f7 (late sealing "允许补封" since 45e9c5d0) on a local Hardhat chain vs the node side
//! (`tests/data/late-fixture.json`, from `tools/vote-gate/late-fixture.test.ts`).
use conet_node::online_gate::*;
use conet_node::vote_gate::{report_after_window, report_seal_ready, ReportView, REPORT_OPEN};
use serde_json::Value;

fn data() -> Value {
    let p = format!(
        "{}/tests/data/late-fixture.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn n(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}
fn tally(c: &Value, subject: u32) -> Tally {
    Tally {
        opened_at: n(&c["openedAt"]) as u64,
        agree: n(&c["agree"]) as u32,
        disagree: n(&c["disagree"]) as u32,
        margin: n(&c["margin"]) as u32,
        population: c.get("population").map(|p| n(p) as u32),
        subject,
    }
}

/// After 7,200 s: frozen votes meeting the margin are sealed by the entry (anyone), otherwise the
/// same entry closes the case as void; the node side predicts each outcome.
#[test]
fn late_seal_or_lapse_matches_the_contract() {
    let d = data();
    let st = SealStrategy::default();
    for c in d["cases"].as_array().unwrap() {
        let kind = c["kind"].as_str().unwrap();
        let now = n(&c["now"]) as u64;
        let met = c["met"].as_bool().unwrap();
        assert_eq!(c["result"], "ok", "{kind}: the entry call itself succeeded");
        let ev: Vec<&str> = c["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect();
        let (predicted, ready) = if kind == "report" {
            let r = ReportView {
                rid: 1,
                target: 2,
                reporter: 3,
                opened_at: n(&c["openedAt"]) as u64,
                expires_at: n(&c["expiresAt"]) as u64,
                min_open: n(&c["minOpen"]) as u32,
                agree: n(&c["agree"]) as u32,
                disagree: n(&c["disagree"]) as u32,
                margin: n(&c["margin"]) as u16,
                state: REPORT_OPEN,
                ratio_bps: 2_000,
                population: None,
            };
            (
                report_after_window(&r, now),
                report_seal_ready(&r, now, &st),
            )
        } else {
            let t = tally(c, u32::from(kind == "recovery"));
            (after_window(&t, now), seal_ready(&t, now, &st))
        };
        if met {
            assert_eq!(predicted, AfterWindow::Seal, "{kind}");
            assert!(ready, "{kind}: late sealing (default on) says ready");
            assert!(
                ev.iter().any(|e| e.ends_with("Resolved")),
                "{kind}: sealed, {ev:?}"
            );
        } else {
            assert_eq!(predicted, AfterWindow::VoidClose, "{kind}");
            assert!(!ready, "{kind}");
            assert!(
                ev.contains(&"OnlineCaseLapsed") || ev.contains(&"ReportClosed"),
                "{kind}: closed as void, {ev:?}"
            );
        }
        println!(
            "{kind} {} late entry gas {}",
            if met { "seal" } else { "lapse" },
            c["gasUsed"].as_str().unwrap()
        );
    }
}

/// After 7,200 s votes are refused; with frozen votes meeting the margin, the four paths that would
/// bypass sealing revert; after sealing, settlement works.
#[test]
fn votes_refused_and_bypasses_blocked() {
    let d = data();
    for (k, v) in d["lateVote"].as_object().unwrap() {
        assert_ne!(v, "ok", "late vote {k} must be refused");
    }
    assert_eq!(d["blocked"].as_array().unwrap().len(), 4);
    for b in d["blocked"].as_array().unwrap() {
        assert_ne!(b["answer"], "ok", "{}", b["call"]);
    }
    assert_eq!(d["afterSeal"]["settleReport"], "ok");
}

/// The three early-majority switches, both states, against the contract: exclude_subject at
/// exactly half; min_base and irreversible on the vote that makes it just over half.
#[test]
fn majority_switches_both_states_match_the_contract() {
    let d = data();
    let sw = d["switches"].as_array().unwrap();
    assert_eq!(sw.len(), 5);
    for c in sw {
        assert_eq!(c["setAnswer"], "ok");
        let mut rule = MajorityRule::default();
        for s in c["sets"].as_array().unwrap() {
            match s[0].as_str().unwrap() {
                "mjExcludeSubject" => rule.exclude_subject = true,
                "mjMinBase" => rule.min_base = s[1].as_u64().unwrap() as u32,
                "mjIrreversible" => rule.irreversible = true,
                x => panic!("{x}"),
            }
        }
        let t = tally(c, 1);
        let now = n(&c["now"]) as u64;
        assert!(now < t.opened_at + MIN_OPEN, "before 600 s");
        let label = format!("{} | {}", c["state"], c["switch"]);
        if let Some(answer) = c["answer"].as_str() {
            let st = SealStrategy {
                majority: rule,
                ..SealStrategy::default()
            };
            assert_eq!(
                seal_ready(&t, now, &st),
                answer == "ok",
                "{label}: contract {answer}"
            );
        } else {
            let agree = c["lastVoteAgree"].as_bool().unwrap();
            assert_eq!(
                would_decide(&t, agree, now, &rule),
                c["sealedByLastVote"].as_bool().unwrap(),
                "{label}"
            );
        }
    }
}

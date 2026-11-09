//! AUTO-TOPUP (project decision 2026-11-08): plan logic, partly replayed against the real
//! contract (`tests/data/auto-topup-fixture.json`, from `tools/auto-topup/auto-topup-fixture.test.ts`
//! on the node line's sources, local Hardhat chain).
use conet_node::auto_topup::*;
use conet_node::stake_term::precheck_recovery;
use serde_json::Value;

const C: u128 = 1_000_000_000_000_000_000;
const DAY: u64 = 86_400;
const END: u64 = 1_900_000_000;

fn fixture() -> Value {
    let p = format!(
        "{}/tests/data/auto-topup-fixture.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn n(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}
/// ChainView from a recorded contract state.
fn view(s: &Value) -> ChainView {
    ChainView {
        now: n(&s["now"]) as u64,
        term_end: n(&s["termEnd"]) as u64,
        in_term: s["inTerm"].as_bool().unwrap(),
        stake_stop: s["stakeStop"].as_bool().unwrap(),
        stake: n(&s["stake"]),
        threshold_at_end: n(&s["thresholdAtEnd"]),
        wallet: n(&s["wallet"]),
        wallet_nonce: n(&s["nonce"]) as u64,
        wallet_pending_nonce: n(&s["nonce"]) as u64,
    }
}
fn synthetic(stake: u128, thr: u128, wallet: u128, now: u64) -> ChainView {
    ChainView {
        now,
        term_end: END,
        in_term: true,
        stake_stop: false,
        stake,
        threshold_at_end: thr,
        wallet,
        wallet_nonce: 10,
        wallet_pending_nonce: 10,
    }
}

/// Scenario 1: Funded early -> the plan sends exactly the missing stake -> the real contract renews.
#[test]
fn funded_early_tops_up_and_the_contract_renews() {
    let f = fixture();
    let a = &f["A"];
    let cfg = Config::default();
    let before = view(&a["beforeTopUp"]);
    let p = plan(&before, None, &cfg);
    assert_eq!(
        p,
        Plan::Send {
            value: n(&a["appliedValue"])
        },
        "plan vs the value the contract got"
    );
    // After the top-up was mined: covered, no second one.
    let after = view(&a["afterTopUp"]);
    assert_eq!(
        plan(
            &after,
            Some(&InFlight {
                nonce: before.wallet_nonce,
                value: n(&a["appliedValue"])
            }),
            &cfg
        ),
        Plan::Covered
    );
    // At the end, nobody wrote anything: the contract's read-time state says renewed and active.
    let end = view(&a["afterEnd"]);
    assert_eq!(plan(&end, None, &cfg), Plan::Ended { renewed: true });
    assert!(a["afterEnd"]["active"].as_bool().unwrap());
    // Gas measured for topUp, inside the reserve's gas budget (300,000).
    assert!(n(&f["topupGasUsed"]) < 300_000);
}

/// Scenario 2: Wallet short (top-up plus gas): no transaction, alert with the exact amount missing.
#[test]
fn wallet_short_including_gas_alerts_and_sends_nothing() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    // Missing 5 stake; wallet has exactly 5: not enough once gas is counted.
    assert_eq!(
        plan(&synthetic(5 * C, 10 * C, 5 * C, now), None, &cfg),
        Plan::WalletShort {
            missing: cfg.gas_reserve,
            need_stake: 5 * C
        }
    );
    assert_eq!(
        plan(&synthetic(5 * C, 10 * C, 2 * C, now), None, &cfg),
        Plan::WalletShort {
            missing: 3 * C + cfg.gas_reserve,
            need_stake: 5 * C
        }
    );
    // The wallet balance never counts as stake: a rich wallet with stake 5 is still "missing 5".
    assert_eq!(
        plan(&synthetic(5 * C, 10 * C, 100 * C, now), None, &cfg),
        Plan::Send { value: 5 * C }
    );
}

/// Scenario 3: Too close to the end to count on mining: alert; after the failure, the recovery target.
#[test]
fn critical_moment_alerts_and_recovery_follows_a_failed_renewal() {
    let cfg = Config::default();
    assert_eq!(
        plan(&synthetic(5 * C, 10 * C, 100 * C, END - 1_800), None, &cfg),
        Plan::TooLate {
            left: 1_800,
            need_stake: 5 * C
        }
    );
    assert_eq!(
        plan(
            &synthetic(5 * C, 10 * C, 100 * C, END - 8 * DAY),
            None,
            &cfg
        ),
        Plan::NotYet {
            opens_at: END - 7 * DAY
        }
    );
    // After the end without enough stake: renewal failed; recovery needs latest + locked.
    let failed = ChainView {
        in_term: false,
        ..synthetic(5 * C, 10 * C, 100 * C, END + 1)
    };
    assert_eq!(plan(&failed, None, &cfg), Plan::Ended { renewed: false });
    assert_eq!(recovery_target(10 * C, 2 * C), 12 * C);
    assert_eq!(precheck_recovery(11 * C, 2 * C, 10 * C), Err(C));
    assert_eq!(precheck_recovery(12 * C, 2 * C, 10 * C), Ok(()));
}

/// Scenario 4: Inside the grace period the missing amount uses the full threshold at the end, not
/// effectiveMinStake (recorded: effectiveMin 5, minStakeAt(termEnd) 10).
#[test]
fn grace_period_uses_the_full_threshold() {
    let f = fixture();
    let s = &f["A"]["beforeTopUp"];
    assert_eq!(n(&s["effectiveMin"]), 5 * C);
    assert_eq!(n(&s["thresholdAtEnd"]), 10 * C);
    assert_eq!(
        plan(&view(s), None, &Config::default()),
        Plan::Send { value: 5 * C }
    );
}

/// Scenario 5: Repeated runs and restarts never add twice: a recorded top-up whose nonce is unused can
/// only be rebroadcast; once used, the chain stake decides.
#[test]
fn repeated_runs_and_restarts_are_idempotent() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    let v = synthetic(5 * C, 10 * C, 100 * C, now);
    let Plan::Send { value } = plan(&v, None, &cfg) else {
        panic!()
    };
    let rec = InFlight {
        nonce: v.wallet_nonce,
        value,
    }; // persisted before broadcast
       // Not mined yet (nonce 10 unused): same run again, or after a restart -> rebroadcast only.
    for _ in 0..3 {
        assert_eq!(plan(&v, Some(&rec), &cfg), Plan::Rebroadcast { nonce: 10 });
    }
    // Mined: nonce used, stake 10 -> covered.
    let mined = ChainView {
        stake: 10 * C,
        wallet_nonce: 11,
        wallet: 95 * C,
        ..v.clone()
    };
    assert_eq!(plan(&mined, Some(&rec), &cfg), Plan::Covered);
    // Nonce used by something else (the top-up was replaced or dropped and the nonce reused):
    // recompute from the chain stake, which still shows 5 missing -> a fresh top-up.
    let reused = ChainView {
        wallet_nonce: 11,
        ..v.clone()
    };
    assert_eq!(plan(&reused, Some(&rec), &cfg), Plan::Send { value: 5 * C });
    // A DAO raise after a mined top-up: missing again, by the new difference only.
    let raised = ChainView {
        threshold_at_end: 12 * C,
        ..mined
    };
    assert_eq!(plan(&raised, Some(&rec), &cfg), Plan::Send { value: 2 * C });
}

/// Scenario 6: Failed renewal -> recovery request, against the real contract: refused below
/// latest + locked, accepted after topping up to it.
#[test]
fn failed_renewal_goes_to_recovery_request() {
    let f = fixture();
    let b = &f["B"];
    let end = view(&b["afterEnd"]);
    assert_eq!(
        plan(&end, None, &Config::default()),
        Plan::Ended { renewed: false }
    );
    assert!(!b["afterEnd"]["active"].as_bool().unwrap());
    let latest = n(&b["afterEnd"]["minStakeNow"]);
    let locked = n(&b["afterEnd"]["locked"]);
    assert_eq!(n(&b["recoveryTarget"]), recovery_target(latest, locked));
    // Before: our precheck refuses, and so did the contract.
    assert!(precheck_recovery(end.stake, locked, latest).is_err());
    assert_eq!(b["recoveryBefore"], "InsufficientStake");
    // After topping up to the target: our precheck passes, and the contract accepted.
    let after = view(&b["afterTopUp"]);
    assert_eq!(precheck_recovery(after.stake, locked, latest), Ok(()));
    assert_eq!(b["recoveryAfter"], "ok");
}

/// Two paths (project decision 2026-11-09): the operator's web deposit and the node's own top-up.
#[test]
fn web_deposit_first_then_the_node_does_not_top_up() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    // The web deposit already landed: stake 10 = threshold -> nothing to send.
    assert_eq!(
        plan(&synthetic(10 * C, 10 * C, 100 * C, now), None, &cfg),
        Plan::Covered
    );
    // A partial web deposit: only the rest.
    assert_eq!(
        plan(&synthetic(8 * C, 10 * C, 100 * C, now), None, &cfg),
        Plan::Send { value: 2 * C }
    );
}

#[test]
fn concurrent_paths_and_retries_never_over_fund() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    let v = synthetic(5 * C, 10 * C, 100 * C, now);
    let rec = InFlight {
        nonce: 10,
        value: 5 * C,
    };
    // Ours pending; the web deposit of 5 lands first: no zero-value replacement (topUp(0)
    // reverts); ours is only rebroadcast and lands, the extra 5 stays in the node's stake.
    let web_full = ChainView {
        stake: 10 * C,
        ..v.clone()
    };
    assert_eq!(
        plan(&web_full, Some(&rec), &cfg),
        Plan::Rebroadcast { nonce: 10 }
    );
    // The web deposit of 3 lands first: ours is cut to the remaining 2, same nonce.
    let web_part = ChainView {
        stake: 8 * C,
        ..v.clone()
    };
    assert_eq!(
        plan(&web_part, Some(&rec), &cfg),
        Plan::Replace {
            nonce: 10,
            value: 2 * C
        }
    );
    // Retried many times with nothing changed: rebroadcast only.
    for _ in 0..5 {
        assert_eq!(plan(&v, Some(&rec), &cfg), Plan::Rebroadcast { nonce: 10 });
    }
    // Ours mined first, then the web deposit too: the chain shows 15, the excess is stake of the
    // node (reported, not lost); the node sends nothing more.
    let both = ChainView {
        stake: 15 * C,
        wallet_nonce: 11,
        ..v
    };
    assert_eq!(plan(&both, Some(&rec), &cfg), Plan::Covered);
}

#[test]
fn hot_wallet_short_or_gas_short() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    // Not even the missing stake.
    assert!(matches!(
        plan(&synthetic(5 * C, 10 * C, C, now), None, &cfg),
        Plan::WalletShort { .. }
    ));
    // The stake but not the gas.
    assert_eq!(
        plan(
            &synthetic(5 * C, 10 * C, 5 * C + cfg.gas_reserve - 1, now),
            None,
            &cfg
        ),
        Plan::WalletShort {
            missing: 1,
            need_stake: 5 * C
        }
    );
}

/// Recovery precheck (12-hour cooldown, online fee, stake) against the real contract: for every
/// recorded state our first blocker, in the contract's check order (stake, cooldown, fee), is the
/// error the contract returned, and "no blocker" is exactly when the contract accepted.
#[test]
fn recovery_precheck_matches_the_contract() {
    use conet_node::online_gate::{offline_since, precheck_recovery, RecoveryView};
    let f = fixture();
    let cases = f["B"]["recoveryCases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let label = c["label"].as_str().unwrap();
        let v = RecoveryView {
            // eth_call runs in the next block (latest + 1).
            now: n(&c["now"]) as u64 + 1,
            offline_since: offline_since(n(&c["outOfServiceSince"]) as u64, None),
            last_rejected_at: 0,
            open_case_opened_at: None,
            stake: n(&c["stake"]),
            locked: n(&c["locked"]),
            latest_threshold: n(&c["minStakeNow"]),
            fee_balance: n(&c["feeSent"]),
        };
        let b = precheck_recovery(&v);
        let ours = if b.stake_missing.is_some() {
            "InsufficientStake"
        } else if b.wait.is_some() {
            "OfflineCooldown"
        } else if b.fee_missing.is_some() {
            "OnlineFeeRequired"
        } else {
            "ok"
        };
        assert_eq!(ours, c["answer"].as_str().unwrap(), "{label}: {b:?}");
    }
    // The "5 seconds before" case tells the operator the exact wait.
    let early = &cases[2];
    let b = precheck_recovery(&RecoveryView {
        now: n(&early["now"]) as u64 + 1,
        offline_since: n(&early["outOfServiceSince"]) as u64,
        last_rejected_at: 0,
        open_case_opened_at: None,
        stake: n(&early["stake"]),
        locked: n(&early["locked"]),
        latest_threshold: n(&early["minStakeNow"]),
        fee_balance: n(&early["feeSent"]),
    });
    assert_eq!(b.wait, Some(4));
}

/// Other main-wallet transactions in flight: no top-up until they clear (N6 second review).
#[test]
fn waits_while_the_main_wallet_has_other_transactions_in_flight() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    let busy = ChainView {
        wallet_pending_nonce: 12,
        ..synthetic(5 * C, 10 * C, 100 * C, now)
    };
    assert_eq!(plan(&busy, None, &cfg), Plan::WalletBusy { in_flight: 2 });
    let clear = ChainView {
        wallet_nonce: 12,
        ..busy
    };
    assert_eq!(plan(&clear, None, &cfg), Plan::Send { value: 5 * C });
}

/// Project decision 2026-11-09: rewards first fill the node's own stake gap. The plan reads the
/// chain stake every run, so a reward credited into stake shrinks (or closes) the gap and the node
/// sends only the rest.
#[test]
fn rewards_credited_into_stake_reduce_the_top_up() {
    let cfg = Config::default();
    let now = END - 3 * DAY;
    assert_eq!(
        plan(&synthetic(5 * C, 10 * C, 100 * C, now), None, &cfg),
        Plan::Send { value: 5 * C }
    );
    // 0.011 CNET of rewards landed in stake since the last run.
    let after_reward = synthetic(5 * C + 11 * C / 1000, 10 * C, 100 * C, now);
    assert_eq!(
        plan(&after_reward, None, &cfg),
        Plan::Send {
            value: 5 * C - 11 * C / 1000
        }
    );
    // Rewards covered the whole gap: nothing to send.
    assert_eq!(
        plan(&synthetic(10 * C, 10 * C, 100 * C, now), None, &cfg),
        Plan::Covered
    );
}

/// Stake refilled (by rewards or a top-up) while the node is offline: the precheck only clears the
/// way to REQUEST recovery; the node stays offline until a recovery vote passes.
#[test]
fn refilled_stake_never_means_online() {
    use conet_node::online_gate::{precheck_recovery, RecoveryView};
    use conet_node::recovery::{Node, OfflineReason, State};
    let v = RecoveryView {
        now: END + 50_000,
        offline_since: END,
        last_rejected_at: 0,
        open_case_opened_at: None,
        stake: 10 * C,
        locked: 0,
        latest_threshold: 10 * C,
        fee_balance: C,
    };
    assert!(precheck_recovery(&v).clear());
    let mut n = Node::offline_because(OfflineReason::StakeShortfall { topped_up: false });
    n.stake_topped_up();
    assert_eq!(n.state, State::Offline);
    assert!(n.open([1; 32], [2; 32]).is_ok()); // may request; the vote decides
    assert_eq!(n.state, State::Offline);
    assert_eq!(
        n.mark_online_direct(),
        Err(conet_node::recovery::Refused::RecoveryVoteRequired)
    );
}

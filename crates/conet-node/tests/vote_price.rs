//! Vote pricing and send-loop decisions (H812E, VOTE-MUST): pure logic. The anvil run with real
//! base-fee spikes is in `vote_price_anvil.rs`.
use conet_node::vote_gate::Skip;
use conet_node::vote_price::*;

const GWEI: u64 = 1_000_000_000;
const CNET: u128 = 1_000_000_000_000_000_000;
const GAS: u64 = 6_000_000;
const DAY: u64 = 86_400;

#[test]
fn max_fee_is_4x_base_within_the_votes_share() {
    let c = PriceCfg::default();
    // Today's CoNET: base fee 7 wei, tip 1e6 wei: 4x base + tip, far inside the share.
    let e = estimate(&c, &[7, 7], 1_000_000, GAS, 3 * CNET / 10).unwrap();
    assert_eq!(e.price.max_fee_wei, 4 * 7 + 1_000_000);
    assert_eq!(e.price.tip_wei, 1_000_000);
    assert!(!e.sources_disagree && !e.beyond_share);
    // Sources that disagree: priced on the higher one, flagged.
    let e = estimate(&c, &[GWEI, 3 * GWEI], 1_000_000, GAS, CNET).unwrap();
    assert_eq!(e.base_fee_wei, 3 * GWEI);
    assert_eq!(e.price.max_fee_wei, 12 * GWEI + 1_000_000);
    assert!(e.sources_disagree);
}

#[test]
fn leaves_room_for_the_wallets_other_transactions() {
    let c = PriceCfg::default();
    // 0.3 CNET, base fee 1 gwei: a vote reserves 6M x 4 gwei = 0.024 CNET, so markOnline,
    // reportOffline and further votes still fit (geth checks all pending txs together).
    let mut free = 3 * CNET / 10;
    let mut sent = 0;
    while let Ok(e) = estimate(&c, &[GWEI], 1_000_000, GAS, free) {
        free -= e.price.max_fee_wei as u128 * GAS as u128;
        sent += 1;
        if sent == 10 {
            break;
        }
    }
    assert!(sent >= 4, "{sent}");
    // Base fee 10 gwei: the 4x target (40 gwei) is above the share (12.5 gwei); the vote
    // takes its share, which still covers base + tip, and leaves 3/4 for the others.
    let e = estimate(&c, &[10 * GWEI], 1_000_000, GAS, 3 * CNET / 10).unwrap();
    assert_eq!(e.price.max_fee_wei as u128, 3 * CNET / 10 / 4 / GAS as u128);
    assert!(!e.beyond_share);
    // Base fee 20 gwei: even base + tip is above the share; the vote takes what it needs to be
    // minable now (flagged), never more.
    let e = estimate(&c, &[20 * GWEI], 1_000_000, GAS, 3 * CNET / 10).unwrap();
    assert_eq!(e.price.max_fee_wei, 20 * GWEI + 1_000_000);
    assert!(e.beyond_share);
}

#[test]
fn high_base_fee_vote_still_goes_out() {
    let c = PriceCfg::default();
    // 1,000 gwei base fee: 10,000x the old 0.1 gwei cap. Sent, as long as the wallet can pay.
    let e = estimate(&c, &[1_000 * GWEI], 1_000_000, GAS, 10 * CNET).unwrap();
    assert!(e.price.max_fee_wei >= 1_000 * GWEI);
    // A rise past maxFee: replaced at the new base fee (re-capped by the balance).
    let Step::Replace(next) = on_pending(&c, e.price, 0, 30, 1_600 * GWEI, 10 * CNET, GAS, 7 * DAY)
    else {
        panic!("replace expected");
    };
    assert!(next.max_fee_wei >= 1_600 * GWEI);
    assert!(geth_accepts_replacement(e.price, next, 10));
}

#[test]
fn a_100x_rise_needs_only_a_few_replacements() {
    let c = PriceCfg::default();
    let mut base = GWEI;
    let mut p = estimate(&c, &[base], 1_000_000, GAS, 100 * CNET)
        .unwrap()
        .price;
    let mut replaced = 0;
    let mut t = 1_000;
    // The base fee climbs 12.5% per block until 100x; replace whenever priced out.
    while base < 100 * GWEI {
        base = base * 9 / 8;
        t += 6;
        match on_pending(&c, p, t - 30, t, base, 100 * CNET, GAS, 7 * DAY) {
            Step::Replace(n) => {
                assert!(geth_accepts_replacement(p, n, 10));
                p = n;
                replaced += 1;
            }
            Step::Rebroadcast => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(replaced <= 4, "{replaced}");
}

#[test]
fn objective_obstacles_are_not_refusals() {
    let c = PriceCfg::default();
    // Balance too low for gas x base fee: an obstacle (alert, top up), then sent after top-up.
    let o = estimate(&c, &[1_000 * GWEI], 1_000_000, GAS, 3 * CNET / 10).unwrap_err();
    assert!(matches!(o, Obstacle::Balance { need_wei, .. } if need_wei >= 6 * CNET));
    assert!(estimate(&c, &[1_000 * GWEI], 1_000_000, GAS, 10 * CNET).is_ok());
    // No RPC answered: an obstacle (switch RPC, retry).
    assert_eq!(
        estimate(&c, &[], 1_000_000, GAS, CNET).unwrap_err(),
        Obstacle::Rpc
    );
    // Not a valid vote (contract rules): not sent, reason recorded. Distinct from obstacles.
    let not = decide(Err(Skip::Cooldown { until: 9 }), || unreachable!());
    assert_eq!(not, Decision::NotEligible(Skip::Cooldown { until: 9 }));
    assert!(matches!(
        decide(Ok(()), || estimate(&c, &[], 1, GAS, CNET)),
        Decision::Obstacle(Obstacle::Rpc)
    ));
    assert!(matches!(
        decide(Ok(()), || estimate(&c, &[7], 1, GAS, CNET)),
        Decision::Send(_)
    ));
}

#[test]
fn pending_vote_retried_until_case_expiry() {
    let c = PriceCfg::default();
    let first = estimate(&c, &[7], 1_000_000, GAS, CNET).unwrap().price;
    let (sent_at, expires) = (1_000, 1_000 + 7 * DAY);
    assert_eq!(
        on_pending(&c, first, sent_at, sent_at + 29, 7, CNET, GAS, expires),
        Step::Wait
    );
    // Not mined (e.g. tip competition): rebroadcast every 30 s for the whole 7 days.
    let mut tries = 0u64;
    let mut t = sent_at + c.rebroadcast_secs;
    loop {
        match on_pending(&c, first, t - c.rebroadcast_secs, t, 7, CNET, GAS, expires) {
            Step::Rebroadcast => tries += 1,
            Step::CaseExpiring => break,
            other => panic!("unexpected {other:?} at {t}"),
        }
        t += c.rebroadcast_secs;
    }
    assert!(tries > 20_000, "{tries}");
    assert!(t + c.expiry_margin_secs >= expires && t < expires);
}

#[test]
fn priced_out_vote_replaced_after_top_up_many_times() {
    let c = PriceCfg::default();
    let gas = GAS as u128;
    let mut base = GWEI;
    // Free balance just enough for base + tip: the vote goes out at that price.
    let mut bal = (base as u128 + 1_000_000) * gas;
    let mut p = estimate(&c, &[base], 1_000_000, GAS, bal).unwrap().price;
    for round in 0..30u64 {
        let now = 100 + round * 60;
        base = p.max_fee_wei; // the base fee climbs to the sent maxFee: priced out
                              // Same balance: the +10% replacement does not fit -> obstacle (alert, top up).
        let step = on_pending(&c, p, now - 30, now, base, bal, GAS, 7 * DAY);
        assert!(
            matches!(step, Step::Obstacle(Obstacle::Balance { .. })),
            "{round}: {step:?}"
        );
        // Top-up arrives: replaced with the same nonce; geth's rule holds; tip <= cap.
        bal = base as u128 * gas * 3 / 2;
        let Step::Replace(next) = on_pending(&c, p, now - 30, now, base, bal, GAS, 7 * DAY) else {
            panic!("replace expected in round {round}");
        };
        assert!(geth_accepts_replacement(p, next, 10), "{p:?} -> {next:?}");
        assert!(next.tip_wei <= c.tip_cap_wei);
        assert!(next.max_fee_wei > base);
        p = next;
        bal = p.max_fee_wei as u128 * gas; // spent down to exactly this reservation again
    }
}

#[test]
fn tip_room_and_cap() {
    let c = PriceCfg::default();
    // A hint at the cap is lowered so that reserve_bumps (30) replacements fit under the cap.
    let e = estimate(&c, &[7], c.tip_cap_wei, GAS, CNET).unwrap();
    let mut tip = e.price.tip_wei;
    for _ in 0..c.reserve_bumps {
        tip = (tip as u128 * 110).div_ceil(100) as u64;
    }
    assert!(tip <= c.tip_cap_wei, "{tip}");
    // From today's 1e6 wei tip there is room for far more (about 48).
    let mut t = 1_000_000u64;
    let mut n = 0;
    while (t as u128 * 110).div_ceil(100) as u64 <= c.tip_cap_wei {
        t = (t as u128 * 110).div_ceil(100) as u64;
        n += 1;
    }
    assert!(n >= 45, "{n}");
    // No room left: keep rebroadcasting and alert, never drop.
    let near = Price {
        max_fee_wei: GWEI,
        tip_wei: c.tip_cap_wei,
    };
    assert_eq!(
        on_pending(&c, near, 0, 30, 2 * GWEI, 100 * CNET, GAS, 7 * DAY),
        Step::NoTipRoom
    );
}

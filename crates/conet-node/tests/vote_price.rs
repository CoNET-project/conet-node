//! Vote pricing and send-loop decisions (H812E, VOTE-MUST): pure logic. The anvil run with real
//! base-fee spikes is in `vote_price_anvil.rs`.
use conet_node::vote_gate::Skip;
use conet_node::vote_price::*;

const GWEI: u64 = 1_000_000_000;
const CNET: u128 = 1_000_000_000_000_000_000;
const GAS: u64 = 6_000_000;
const DAY: u64 = 86_400;

#[test]
fn max_fee_is_what_the_wallet_can_prepay() {
    let c = PriceCfg::default();
    // Today's CoNET: base fee 7 wei, tip 1e6 wei; 0.3 CNET free.
    let e = estimate(&c, &[7, 7], 1_000_000, GAS, 3 * CNET / 10).unwrap();
    assert_eq!(e.price.max_fee_wei as u128, 3 * CNET / 10 / GAS as u128); // 50 gwei
    assert_eq!(e.price.tip_wei, 1_000_000);
    assert!(!e.sources_disagree);
    // A second concurrent vote only gets what the first did not reserve.
    let left = 3 * CNET / 10 - e.price.max_fee_wei as u128 * GAS as u128;
    assert!(estimate(&c, &[7], 1_000_000, GAS, left).is_err());
    let e2 = estimate(&c, &[7], 1_000_000, GAS, CNET).unwrap();
    assert!(e2.price.max_fee_wei > e.price.max_fee_wei);
    // Sources that disagree: checked against the higher one, flagged.
    let e = estimate(&c, &[GWEI, 3 * GWEI], 1_000_000, GAS, CNET).unwrap();
    assert_eq!(e.base_fee_wei, 3 * GWEI);
    assert!(e.sources_disagree);
}

#[test]
fn high_base_fee_vote_still_goes_out() {
    let c = PriceCfg::default();
    // 1,000 gwei base fee: 10,000x the old 0.1 gwei cap. Sent, as long as the wallet can pay.
    let e = estimate(&c, &[1_000 * GWEI], 1_000_000, GAS, 10 * CNET).unwrap();
    assert!(e.price.max_fee_wei >= 1_000 * GWEI);
    // The same price survives a further rise to 1,600 gwei with no replacement.
    assert_eq!(
        on_pending(&c, e.price, 0, 30, 1_600 * GWEI, 10 * CNET, GAS, 7 * DAY),
        Step::Rebroadcast
    );
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
    let mut bal = 3 * CNET / 10;
    let mut p = estimate(&c, &[7], 1_000_000, GAS, bal).unwrap().price;
    let mut base = p.max_fee_wei; // the base fee climbs to exactly the sent maxFee
    let mut replaced = 0;
    for round in 0..30u64 {
        let now = 100 + round * 60;
        // Priced out with the same balance: an obstacle (alert, top up), not a refusal.
        let step = on_pending(&c, p, now - 30, now, base, bal, GAS, 7 * DAY);
        assert!(
            matches!(step, Step::Obstacle(Obstacle::Balance { .. })),
            "{step:?}"
        );
        // Top-up arrives: replace with the same nonce; geth's 10% rule holds; tip <= cap.
        bal = base as u128 * gas * 3 / 2 + CNET / 10;
        let Step::Replace(next) = on_pending(&c, p, now - 30, now, base, bal, GAS, 7 * DAY) else {
            panic!("replace expected in round {round}");
        };
        assert!(geth_accepts_replacement(p, next, 10), "{p:?} -> {next:?}");
        assert!(next.tip_wei <= c.tip_cap_wei);
        assert!(next.max_fee_wei > base);
        p = next;
        base = p.max_fee_wei;
        replaced += 1;
    }
    assert_eq!(replaced, 30);
}

#[test]
fn tip_room_and_cap() {
    let c = PriceCfg::default();
    // A hint at the cap is lowered so that reserve_bumps (20) replacements fit under the cap.
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

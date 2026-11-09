//! Vote pricing (H812E): first price, same-nonce replacements under geth's 10% rule.
use conet_node::vote_price::*;

const GWEI: u64 = 1_000_000_000;
const GAS: u64 = 6_000_000;

#[test]
fn estimate_uses_highest_base_fee_and_leaves_tip_room() {
    let c = PriceCfg::default();
    // Today's CoNET: base fee 7 wei, tip 1e6 wei.
    let e = estimate(&c, &[7, 7], 1_000_000, GAS, None).unwrap();
    assert_eq!(e.price.tip_wei, 1_000_000);
    assert_eq!(e.price.max_fee_wei, 4 * 7 + 1_000_000);
    assert!(!e.sources_disagree && !e.balance_limited);
    // Two sources disagree: price on the higher one, and flag it.
    let e = estimate(&c, &[10 * GWEI, 30 * GWEI], 1_000_000, GAS, None).unwrap();
    assert_eq!(e.base_fee_wei, 30 * GWEI);
    assert_eq!(e.price.max_fee_wei, 120 * GWEI + 1_000_000);
    assert!(e.sources_disagree);
    // A tip hint at the cap is lowered so that five 12% bumps still fit under the cap.
    let e = estimate(&c, &[7], c.tip_cap_wei, GAS, None).unwrap();
    let mut tip = e.price.tip_wei;
    assert!(tip < c.tip_cap_wei);
    for _ in 0..c.max_replacements {
        tip = (tip as u128 * 112).div_ceil(100) as u64;
    }
    assert!(tip <= c.tip_cap_wei, "{tip}");
    assert!(estimate(&c, &[], 1, GAS, None).is_none());
}

#[test]
fn estimate_far_above_old_cap_is_not_refused() {
    let c = PriceCfg::default();
    // Base fee 500 gwei: 5,000x the old 0.1 gwei cap. A price is still produced.
    let e = estimate(&c, &[500 * GWEI], 1_000_000, GAS, None).unwrap();
    assert_eq!(e.price.max_fee_wei, 2_000 * GWEI + 1_000_000);
    // With 0.3 CNET the node cannot pre-pay 6M x 2,000 gwei: maxFee drops to balance / gas.
    let bal: u128 = 300_000_000_000_000_000;
    let e = estimate(&c, &[500 * GWEI], 1_000_000, GAS, Some(bal)).unwrap();
    assert_eq!(e.price.max_fee_wei as u128, bal / GAS as u128);
    assert!(e.balance_limited);
    assert!(e.price.tip_wei <= e.price.max_fee_wei);
}

#[test]
fn replacements_follow_geth_rule_count_and_tip_cap() {
    let c = PriceCfg::default();
    let first = estimate(&c, &[7], 1_000_000, GAS, None).unwrap().price;
    let t0 = 1_000;
    // Not due before replace_after_secs.
    assert_eq!(replacement(&c, first, 0, t0, t0 + 29, 7), Replace::Wait);
    let mut prev = first;
    let mut sent = t0;
    for done in 0..c.max_replacements {
        let now = sent + c.replace_after_secs;
        let Replace::Bump(next) = replacement(&c, prev, done, sent, now, 7) else {
            panic!("bump {done} expected");
        };
        assert!(
            geth_accepts_replacement(prev, next, 10),
            "bump {done}: {prev:?} -> {next:?}"
        );
        assert!(next.tip_wei <= c.tip_cap_wei);
        // About 12% each, not more than needed (tip) and at least 12% (maxFee).
        assert_eq!(
            next.tip_wei,
            (prev.tip_wei as u128 * 112).div_ceil(100) as u64
        );
        assert!(next.max_fee_wei >= (prev.max_fee_wei as u128 * 112).div_ceil(100) as u64);
        prev = next;
        sent = now;
    }
    // Count reached: hold (keep waiting), never drop.
    assert_eq!(
        replacement(&c, prev, c.max_replacements, sent, sent + 999, 7),
        Replace::Hold
    );
    // A tip already near the cap cannot be bumped: hold rather than exceed the cap.
    let near = Price {
        max_fee_wei: GWEI,
        tip_wei: c.tip_cap_wei - 1,
    };
    assert_eq!(replacement(&c, near, 0, t0, t0 + 30, 7), Replace::Hold);
}

#[test]
fn replacement_follows_a_rising_base_fee() {
    let c = PriceCfg::default();
    let first = estimate(&c, &[GWEI], 1_000_000, GAS, None).unwrap().price;
    // The base fee jumped to 50 gwei: the bump goes to 4x the new base fee + tip, not just +12%.
    let Replace::Bump(next) = replacement(&c, first, 0, 0, 30, 50 * GWEI) else {
        panic!("bump expected");
    };
    assert_eq!(next.max_fee_wei, 200 * GWEI + next.tip_wei);
    assert!(geth_accepts_replacement(first, next, 10));
}

//! Probe decisions, pure logic (P-04 to P-08, and P-09s).
use conet_node::probe_logic::*;
use Outcome::*;

const T: u64 = 1_800_000_000; // a slot boundary multiple of 60

#[test]
fn fail_counter_three_slots() {
    let c = FailCfg::default();
    let mut f = FailCounter::default();
    // Three failures in three slots, 60 s apart, within 15 minutes: threshold reached.
    assert!(!f.record(&c, Fail(1), T));
    assert!(!f.record(&c, Fail(2), T + 60));
    assert!(f.record(&c, Fail(5), T + 120));
    // Any success resets.
    let mut f = FailCounter::default();
    f.record(&c, Fail(1), T);
    f.record(&c, Fail(1), T + 60);
    assert!(!f.record(&c, Online, T + 90));
    assert_eq!(f.count(), 0);
    // Several failures in one slot (or under 60 s apart) count once.
    let mut f = FailCounter::default();
    for dt in [0, 10, 30, 59] {
        f.record(&c, Fail(1), T + dt);
    }
    assert_eq!(f.count(), 1);
    // 61 s apart but in the next slot counts; 60 s apart across the boundary counts too.
    assert!(!f.record(&c, Fail(1), T + 61));
    assert_eq!(f.count(), 2);
    // Outside the 15-minute window the old ones drop out.
    let mut f = FailCounter::default();
    f.record(&c, Fail(1), T);
    f.record(&c, Fail(1), T + 60);
    assert!(!f.record(&c, Fail(1), T + 15 * 60 + 1));
    assert_eq!(
        f.times(),
        &[T + 60, T + 15 * 60 + 1],
        "only the first one dropped out"
    );
    // Not-counted outcomes (bit0/bit1 replies are Online; format errors, uncertainty) do
    // nothing.
    let mut f = FailCounter::default();
    f.record(&c, Fail(3), T);
    f.record(&c, NotCounted, T + 60);
    f.record(&c, NotCounted, T + 120);
    assert_eq!(f.count(), 1);
}

#[test]
fn online_evidence_resets_failure_count() {
    let c = FailCfg::default();
    let mut f = FailCounter::default();
    f.record(&c, Fail(1), T);
    f.record(&c, Fail(1), T + 60);
    assert!(f.record(&c, Fail(1), T + 120));
    // The pre-report relay check brought back online evidence: start over (§41.4).
    f.reset();
    assert!(!f.record(&c, Fail(1), T + 180));
    assert!(!f.record(&c, Fail(1), T + 240));
    assert!(f.record(&c, Fail(1), T + 300));
    assert_eq!(f.times(), &[T + 180, T + 240, T + 300]);
}

#[test]
fn self_check_gate_blocks_reports() {
    let mut s = SelfCheck::new(60, 16, 80);
    // Too few samples: cannot tell, failures do not count.
    for i in 0..10 {
        s.sample(true, T + i);
    }
    assert!(!s.passes(T + 10));
    assert_eq!(s.gate(Fail(1), T + 10), NotCounted);
    // 16 samples, 13 answered (81%): passes.
    for i in 0..6 {
        s.sample(i < 3, T + 10 + i);
    }
    assert!(s.passes(T + 20));
    assert_eq!(s.gate(Fail(1), T + 20), Fail(1));
    // The prober's own network goes down: most samples fail -> failures stop counting.
    for i in 0..20 {
        s.sample(false, T + 30 + i);
    }
    assert!(!s.passes(T + 55));
    assert_eq!(s.gate(Fail(1), T + 55), NotCounted);
    // Online passes through the gate unchanged.
    assert_eq!(s.gate(Online, T + 55), Online);
    // Old samples expire after the window.
    for i in 0..16 {
        s.sample(true, T + 200 + i);
    }
    assert!(s.passes(T + 220));
}

#[test]
fn batch_assignment_coverage() {
    let nodes: Vec<u64> = (1..=472).collect();
    let seed = [7u8; 32];
    let k = 32;
    let mut hits = std::collections::HashMap::<u64, u32>::new();
    for &p in &nodes {
        let a = assign(&seed, p, &nodes, k);
        assert_eq!(a.len(), k);
        assert!(!a.contains(&p), "never itself");
        assert_eq!(a, assign(&seed, p, &nodes, k), "deterministic");
        for t in a {
            *hits.entry(t).or_default() += 1;
        }
    }
    // Every target is covered by about k probers each round.
    assert_eq!(hits.len(), 472);
    let (min, max) = (*hits.values().min().unwrap(), *hits.values().max().unwrap());
    let mean = hits.values().sum::<u32>() as f64 / 472.0;
    assert!((mean - 32.0).abs() < 0.5, "{mean}");
    assert!(min >= 12 && max <= 56, "{min}..{max}");
    // Chi-square against a uniform 32 per target, 471 degrees of freedom: well under 600.
    let chi: f64 = hits
        .values()
        .map(|h| (*h as f64 - 32.0).powi(2) / 32.0)
        .sum();
    assert!(chi < 600.0, "{chi}");
    // A new seed reshuffles.
    assert_ne!(
        assign(&seed, 1, &nodes, k),
        assign(&[8u8; 32], 1, &nodes, k)
    );
    // Browser and mobile nodes are not in `targets` at all (P-09h is enforced by the caller
    // passing only type-1 active ids).
}

#[test]
fn vote_decision_rule() {
    use Choice::*;
    use RelayResult as R;
    let fail3 = [Fail(1), Fail(1), Fail(5)];
    // Uncertain authorization or stale snapshot: no vote at all.
    assert_eq!(decide(&[Online, Online, Online], &[], true, false), Abstain);
    assert_eq!(
        decide(&fail3, &[R::NoReply, R::NoReply], true, false),
        Abstain
    );
    // Own probes: >= 2 online -> disagree; exactly 1 -> abstain.
    assert_eq!(
        decide(&[Online, Online, Fail(1)], &[], true, true),
        Disagree
    );
    assert_eq!(
        decide(&[Online, Fail(1), Fail(1)], &[], true, true),
        Abstain
    );
    // All three failed but the self-check failed: abstain.
    assert_eq!(
        decide(&fail3, &[R::NoReply, R::NoReply], false, true),
        Abstain
    );
    // Not all three counted (one not counted): abstain.
    assert_eq!(
        decide(
            &[Fail(1), Fail(1), NotCounted],
            &[R::NoReply, R::NoReply],
            true,
            true
        ),
        Abstain
    );
    // Relays: any online evidence -> disagree (partition, not offline).
    assert_eq!(
        decide(&fail3, &[R::NoReply, R::Online], true, true),
        Disagree
    );
    // Two "no reply" -> agree.
    assert_eq!(decide(&fail3, &[R::NoReply, R::NoReply], true, true), Agree);
    assert_eq!(
        decide(
            &fail3,
            &[R::Inconclusive, R::NoReply, R::Inconclusive, R::NoReply],
            true,
            true
        ),
        Agree
    );
    // Refused / busy / timeout are inconclusive, never "no reply": not enough -> abstain.
    assert_eq!(
        decide(
            &fail3,
            &[
                R::Inconclusive,
                R::Inconclusive,
                R::Inconclusive,
                R::NoReply
            ],
            true,
            true
        ),
        Abstain
    );
    assert_eq!(decide(&fail3, &[], true, true), Abstain);
    // Only the first four candidates count.
    assert_eq!(
        decide(
            &fail3,
            &[
                R::Inconclusive,
                R::Inconclusive,
                R::Inconclusive,
                R::NoReply,
                R::NoReply
            ],
            true,
            true
        ),
        Abstain
    );
}

#[test]
fn event_cursor_reorg() {
    let h = |n: u64, fork: u8| {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&n.to_be_bytes());
        x[31] = fork;
        x
    };
    let mut c = Cursor::new(64);
    for n in 100..=110 {
        c.push(n, h(n, 0));
    }
    // Same chain: continue after 110.
    assert_eq!(c.check(|n| Some(h(n, 0))), Resume::After(110));
    // Report 5 seen at block 109, then again (re-delivered log): handled once.
    assert!(c.first_time(5, 109));
    assert!(!c.first_time(5, 109));
    assert!(c.first_time(6, 105));
    // A 3-block reorg: 108..110 replaced. Rewind to 107; the decision made at 109 is void.
    let chain = |n: u64| Some(if n >= 108 { h(n, 1) } else { h(n, 0) });
    assert_eq!(c.check(chain), Resume::Rewind(107));
    assert_eq!(c.last(), Some(107));
    assert!(c.first_time(5, 108), "reprocessed after the reorg");
    assert!(
        !c.first_time(6, 105),
        "below the ancestor: still handled once"
    );
    // Deeper than the ring: full rescan.
    let mut c = Cursor::new(64);
    for n in 0..100 {
        c.push(n, h(n, 0));
    }
    assert_eq!(c.check(|n| Some(h(n, 2))), Resume::FullRescan);
    // Empty cursor (first start): full rescan.
    assert_eq!(Cursor::new(64).check(|_| None), Resume::FullRescan);
}

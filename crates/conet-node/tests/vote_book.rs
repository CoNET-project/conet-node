//! Q117: one vote per node per case, whichever wallet; probe authorization re-checked (pure).
use conet_node::vote_book::*;

const MAIN: &str = "0x9329BB53905b5E07F4AD525C306dF204eE17767e";
const PROBE: &str = "0xc2127c05F2Ecf13C94A0DE44AD131b4E2035cd7b";
const NEW_PROBE: &str = "0xb614156Cd087a94847B70337A425512E83dF0a5C";
const CASE: [u8; 32] = [9; 32];

fn ok(reg: &str) -> ProbeStatus {
    ProbeStatus {
        registered: Some(reg.into()),
        valid: true,
        node_eligible: true,
    }
}

#[test]
fn probe_votes_main_never_also() {
    let mut b = VoteBook::default();
    let w = choose(&ok(PROBE), PROBE, MAIN, true);
    assert_eq!(w, Some(Wallet::Probe(PROBE.into())));
    assert_eq!(
        b.pick(Entry::Report, CASE, false, w.clone()),
        Pick::Send(w.clone().unwrap())
    );
    assert!(b.book(Entry::Report, CASE, w.clone().unwrap(), "0xaa"));
    // The main wallet (or anything else) asking for the same case: already booked.
    let main = Wallet::Main(MAIN.into());
    assert_eq!(
        b.pick(Entry::Report, CASE, false, Some(main.clone())),
        Pick::AlreadyBooked(w.clone().unwrap())
    );
    assert!(!b.book(Entry::Report, CASE, main, "0xbb"));
    // Another entry or another case is independent.
    assert!(matches!(
        b.pick(Entry::Recovery, CASE, false, w.clone()),
        Pick::Send(_)
    ));
    assert!(matches!(
        b.pick(Entry::Report, [1; 32], false, w),
        Pick::Send(_)
    ));
}

#[test]
fn rotation_new_key_does_not_vote_again() {
    let mut b = VoteBook::default();
    // Old probe key sent (in flight).
    b.book(Entry::Admission, CASE, Wallet::Probe(PROBE.into()), "0xaa");
    // Rotation: the chain now registers NEW_PROBE; this host holds NEW_PROBE.
    let w = choose(&ok(NEW_PROBE), NEW_PROBE, MAIN, true);
    assert_eq!(
        b.pick(Entry::Admission, CASE, false, w.clone()),
        Pick::AlreadyBooked(Wallet::Probe(PROBE.into()))
    );
    // The old tx is mined: the chain shows the vote; even a fresh book (e.g. another host
    // after a restore) refuses because of the on-chain record.
    let fresh = VoteBook::default();
    assert_eq!(
        fresh.pick(Entry::Admission, CASE, true, w.clone()),
        Pick::AlreadyOnChain
    );
    // If the old tx was dropped and the chain shows no vote, the booking may be released and the
    // new key votes once.
    assert!(b.release_if_dropped(Entry::Admission, CASE, false));
    assert_eq!(
        b.pick(Entry::Admission, CASE, false, w.clone()),
        Pick::Send(Wallet::Probe(NEW_PROBE.into()))
    );
    // But never released while the chain shows a vote.
    b.book(Entry::Admission, CASE, w.unwrap(), "0xcc");
    assert!(!b.release_if_dropped(Entry::Admission, CASE, true));
}

#[test]
fn replacement_keeps_the_booking_and_wallet() {
    let mut b = VoteBook::default();
    let p = Wallet::Probe(PROBE.into());
    b.book(Entry::Report, CASE, p.clone(), "0xaa");
    assert!(b.replace_tx(Entry::Report, CASE, &p, "0xab"));
    // A replacement from another wallet is not a replacement.
    assert!(!b.replace_tx(Entry::Report, CASE, &Wallet::Main(MAIN.into()), "0xac"));
}

#[test]
fn revoked_or_changed_probe_stops_sending() {
    // Revoked: no registered signer.
    let revoked = ProbeStatus {
        registered: None,
        valid: false,
        node_eligible: true,
    };
    assert!(!probe_may_send(&revoked, PROBE));
    // Replaced by another key (rotation done elsewhere): this host's old key must stop.
    assert!(!probe_may_send(&ok(NEW_PROBE), PROBE));
    // Main wallet changed or expired: the contract reports valid = false.
    let stale = ProbeStatus {
        registered: Some(PROBE.into()),
        valid: false,
        node_eligible: true,
    };
    assert!(!probe_may_send(&stale, PROBE));
    // Node inactive (exit, suspended, cooldown).
    let inactive = ProbeStatus {
        registered: Some(PROBE.into()),
        valid: true,
        node_eligible: false,
    };
    assert!(!probe_may_send(&inactive, PROBE));
    assert!(probe_may_send(&ok(PROBE), PROBE));
    // With no valid probe: main fallback only if configured; never when the node is ineligible.
    assert_eq!(
        choose(&stale, PROBE, MAIN, true),
        Some(Wallet::Main(MAIN.into()))
    );
    assert_eq!(choose(&stale, PROBE, MAIN, false), None);
    assert_eq!(choose(&inactive, PROBE, MAIN, true), None);
    let b = VoteBook::default();
    assert_eq!(
        b.pick(Entry::Report, CASE, false, None),
        Pick::NodeNotEligible
    );
}

/// Main and probe wallet of one node never hold two votes in flight on the same case: the book is
/// per node and case, not per wallet.
#[test]
fn main_and_probe_never_both_in_flight() {
    use conet_node::vote_book::*;
    let mut b = VoteBook::default();
    let case = [7u8; 32];
    let probe = Wallet::Probe("0xprobe".into());
    let main = Wallet::Main("0xmain".into());
    assert_eq!(
        b.pick(Entry::Recovery, case, false, Some(probe.clone())),
        Pick::Send(probe.clone())
    );
    assert!(b.book(Entry::Recovery, case, probe.clone(), "0xtx1"));
    // The main wallet (fallback) is refused for the same case while the probe vote is in flight.
    assert_eq!(
        b.pick(Entry::Recovery, case, false, Some(main.clone())),
        Pick::AlreadyBooked(probe)
    );
    assert!(!b.book(Entry::Recovery, case, main, "0xtx2"));
    // Another case is independent.
    assert!(b.book(
        Entry::Recovery,
        [8u8; 32],
        Wallet::Main("0xmain".into()),
        "0xtx3"
    ));
}

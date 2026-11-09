//! D3 ballot table (2026-11-08): agree / disagree / no vote for admission and recovery.
use conet_node::admission::{EndpointClass, Fail};
use conet_node::ballot::*;

fn direct() -> Attempt {
    Attempt::Verified(EndpointClass::Direct {
        ip: "203.0.113.9".into(),
        port: 443,
    })
}
fn relay() -> Attempt {
    Attempt::Verified(EndpointClass::Relay {
        relay: "turn:relay-1.test:3478".into(),
        relay_ip: "198.51.100.3".into(),
        relay_port: 3478,
    })
}

#[test]
fn agree_only_on_a_verified_challenge() {
    assert_eq!(decide(&[direct()], false), Ballot::Agree);
    // A timeout before a later success does not matter.
    assert_eq!(decide(&[Attempt::NoAnswer, direct()], false), Ballot::Agree);
    // Relay-only: agree only if the operator allows relay-only browsers (pending decision).
    assert_eq!(decide(&[relay()], true), Ballot::Agree);
    assert_eq!(decide(&[relay()], false), Ballot::NoVote(Why::RelayOnly));
}

#[test]
fn timeouts_and_unattributable_failures_are_no_vote() {
    for f in [
        Fail::Decrypt,           // not decryptable: anyone could have sent it
        Fail::ApplicantPgpSig,   // not signed by the applicant's chain key
        Fail::ChallengeMismatch, // a challenge swapped by a man in the middle
        Fail::DtlsFingerprint,   // another certificate on the session: signaling may be redirected
        Fail::WrongEndpoint,     // e.g. a voter behind strict NAT only reaches a relay
        Fail::AddressUnconfirmed,
        Fail::PathChanged,
        Fail::Expired,
        Fail::Replay,
        Fail::WrongApplication, // our own stale request
        Fail::BadField,
    ] {
        let a = vec![
            Attempt::Failed(f.clone()),
            Attempt::Failed(f.clone()),
            Attempt::NoAnswer,
        ];
        assert_eq!(decide(&a, true), Ballot::NoVote(Why::Unsure), "{f:?}");
    }
    assert_eq!(
        decide(&vec![Attempt::NoAnswer; 3], true),
        Ballot::NoVote(Why::Unsure)
    );
    assert_eq!(decide(&[], true), Ballot::NoVote(Why::Unsure));
}

#[test]
fn disagree_only_on_an_attributable_failure_seen_twice() {
    let bad = Attempt::Failed(Fail::SignedDtlsContradicts);
    assert_eq!(
        decide(std::slice::from_ref(&bad), true),
        Ballot::NoVote(Why::NotReproduced)
    );
    assert_eq!(decide(&[bad.clone(), bad.clone()], true), Ballot::Disagree);
    let wallet = Attempt::Failed(Fail::WalletSig);
    assert_eq!(
        decide(&[wallet.clone(), bad.clone()], true),
        Ballot::Disagree
    );
    // Verified once and contradicted once: unsure, no vote.
    assert_eq!(
        decide(&[direct(), bad.clone(), bad], true),
        Ballot::NoVote(Why::Conflicting)
    );
    assert!(attributable(&Fail::WalletSig));
    assert!(!attributable(&Fail::DtlsFingerprint));
}

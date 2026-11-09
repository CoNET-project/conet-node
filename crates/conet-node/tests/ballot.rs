//! D3 ballot table (2026-11-08) with N6 §H.8.25: agree / disagree / no vote for admission and
//! recovery.
use conet_node::admission::{EndpointClass, Fail};
use conet_node::ballot::*;

const BROWSER_RELAY_OK: Policy = Policy {
    node_is_browser: true,
    browser_relay_ok: true,
};
const BROWSER_STRICT: Policy = Policy {
    node_is_browser: true,
    browser_relay_ok: false,
};
const LINUX: Policy = Policy {
    node_is_browser: false,
    browser_relay_ok: true,
};

fn at(ch: u8, outcome: Outcome) -> Attempt {
    Attempt {
        challenge: [ch; 32],
        via_anchor: None,
        outcome,
        evidence: None,
    }
}
fn ev(ch: u8) -> Evidence {
    Evidence {
        challenge: format!("challenge {ch}"),
        reply: format!("reply {ch}"),
        observed: "stats".into(),
    }
}
fn bad(ch: u8) -> Attempt {
    Attempt {
        evidence: Some(ev(ch)),
        ..at(ch, Outcome::Failed(Fail::SignedDtlsContradicts))
    }
}
fn direct() -> Outcome {
    Outcome::Verified(EndpointClass::Direct {
        ip: "203.0.113.9".into(),
        port: 443,
    })
}
fn relay() -> Outcome {
    Outcome::Verified(EndpointClass::Relay {
        relay: "turn:relay-1.test:3478".into(),
        relay_ip: "198.51.100.3".into(),
        relay_port: 3478,
    })
}

#[test]
fn agree_only_on_a_verified_challenge() {
    assert_eq!(decide(&[at(1, direct())], LINUX), Ballot::Agree);
    assert_eq!(
        decide(&[at(1, Outcome::NoAnswer), at(2, direct())], LINUX),
        Ballot::Agree
    );
}

/// Both relay variants (pending): browser through a relay agrees only if allowed; a Linux node
/// never agrees on a relay path.
#[test]
fn relay_policy_both_variants() {
    assert_eq!(decide(&[at(1, relay())], BROWSER_RELAY_OK), Ballot::Agree);
    assert_eq!(
        decide(&[at(1, relay())], BROWSER_STRICT),
        Ballot::NoVote(Why::RelayOnly)
    );
    assert_eq!(
        decide(&[at(1, relay())], LINUX),
        Ballot::NoVote(Why::RelayOnly)
    );
    assert_eq!(decide(&[at(1, direct())], BROWSER_STRICT), Ballot::Agree);
}

#[test]
fn timeouts_version_skew_and_unattributable_failures_are_no_vote() {
    for f in [
        Fail::Decrypt,
        Fail::ApplicantPgpSig,
        Fail::ChallengeMismatch,
        Fail::DtlsFingerprint,
        Fail::WrongEndpoint,
        Fail::AddressUnconfirmed,
        Fail::PathChanged,
        Fail::Expired,
        Fail::Replay,
        Fail::WrongApplication,
        Fail::BadField,        // includes a reply missing its DTLS fields
        Fail::ProtocolVersion, // upgrade in progress
    ] {
        let a = vec![
            at(1, Outcome::Failed(f.clone())),
            at(2, Outcome::Failed(f.clone())),
            at(3, Outcome::NoAnswer),
        ];
        assert_eq!(decide(&a, LINUX), Ballot::NoVote(Why::Unsure), "{f:?}");
    }
    assert_eq!(decide(&[], LINUX), Ballot::NoVote(Why::Unsure));
}

#[test]
fn disagree_needs_two_different_challenges_and_evidence() {
    // The same challenge reported twice counts once.
    assert_eq!(
        decide(&[bad(1), bad(1)], LINUX),
        Ballot::NoVote(Why::NotReproduced)
    );
    assert_eq!(
        decide(&[bad(1), bad(2)], LINUX),
        Ballot::Disagree(vec![ev(1), ev(2)])
    );
    // Without evidence: never disagree.
    let no_ev = Attempt {
        evidence: None,
        ..bad(3)
    };
    assert_eq!(
        decide(&[bad(1), no_ev], LINUX),
        Ballot::NoVote(Why::NoEvidence)
    );
    // Verified once and contradicted twice: conflicting, no vote.
    assert_eq!(
        decide(&[at(9, direct()), bad(1), bad(2)], LINUX),
        Ballot::NoVote(Why::Conflicting)
    );
    // A verified result repeated under the same challenge id as a contradiction: the first wins.
    assert_eq!(decide(&[at(1, direct()), bad(1)], LINUX), Ballot::Agree);
}

#[test]
fn certificate_mismatch_records_the_anchor() {
    let via = |ch: u8, anchor: u64, f: Fail| Attempt {
        via_anchor: Some(anchor),
        ..at(ch, Outcome::Failed(f))
    };
    let a = vec![
        via(1, 7, Fail::DtlsFingerprint),
        via(2, 7, Fail::DtlsFingerprint),
        via(3, 9, Fail::Expired),
        Attempt {
            via_anchor: Some(11),
            ..at(4, direct())
        },
    ];
    assert_eq!(suspect_anchors(&a), vec![7]);
    assert_eq!(decide(&a, BROWSER_STRICT), Ballot::Agree); // retried via anchor 11: verified
}

#[test]
fn schedule_jitter_rounds_and_cap() {
    let s = Schedule::default();
    // Start: random 0..=120 s.
    assert_eq!(s.next(0, true, false, 0), Some(0));
    assert_eq!(s.next(0, true, false, 120), Some(120));
    assert_eq!(s.next(0, true, false, 121), Some(0));
    // Within a round at once, between rounds a gap; six at most.
    assert_eq!(s.next(1, true, false, 5), Some(0));
    assert_eq!(s.next(2, true, false, 5), Some(60));
    assert_eq!(s.next(4, true, false, 5), Some(60));
    assert_eq!(s.next(5, true, false, 5), Some(0));
    assert_eq!(s.next(6, true, false, 5), None);
    // Stop when the vote closed or the voter already decided.
    assert_eq!(s.next(1, false, false, 5), None);
    assert_eq!(s.next(1, true, true, 5), None);
}

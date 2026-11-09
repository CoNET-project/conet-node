//! Ballot choice for admission (first online) and recovery votes, project decision D3
//! (2026-11-08): the chain has only agree and disagree. Probe facts (timeouts, no connection)
//! only help the voter choose; "unsure, do not vote" stays allowed, but not voting is not a
//! ballot. After a valid verdict each winning voter gets 0.01 CNET from the stake pool and each
//! losing voter is fined 0.01 CNET, so a wrong-side vote costs money: vote only on proof.
//!
//! Disagree only when the applicant can be held to it: a reply signed by the applicant's
//! registry-bound key, bound to THIS voter's challenge, whose signed content contradicts the
//! request, seen on two separate challenges (N6: only a provably invalid reply). Everything a
//! network attacker could cause (timeouts, unknown keys answering, swapped challenges, a
//! different certificate on a session a relay or signaling path could redirect) is no vote.
use crate::admission::{EndpointClass, Fail};

/// One challenge attempt as the voter saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// `verify` passed.
    Verified(EndpointClass),
    /// `verify` failed.
    Failed(Fail),
    /// No usable answer: timeout, connection refused, no route, data channel never opened.
    NoAnswer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ballot {
    Agree,
    Disagree,
    /// Not voting (not a ballot). The reason is for the log only.
    NoVote(Why),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Nothing verified and nothing attributable (timeouts, unknown answers, our own errors).
    Unsure,
    /// Verified and attributable failures disagree with each other.
    Conflicting,
    /// An attributable failure seen only once: retry before disagreeing.
    NotReproduced,
    /// Only a relay path proved, and the operator does not allow relay-only browsers (pending).
    RelayOnly,
}

/// Failures the applicant can be held to (its own signed, challenge-bound statement is wrong).
pub fn attributable(f: &Fail) -> bool {
    matches!(f, Fail::SignedDtlsContradicts | Fail::WalletSig)
}

/// The decision table. `attempts` are this voter's attempts on the current request version.
pub fn decide(attempts: &[Attempt], relay_only_allowed: bool) -> Ballot {
    let verified: Vec<&EndpointClass> = attempts
        .iter()
        .filter_map(|a| match a {
            Attempt::Verified(c) => Some(c),
            _ => None,
        })
        .collect();
    let proofs = attempts
        .iter()
        .filter(|a| matches!(a, Attempt::Failed(f) if attributable(f)))
        .count();
    match (verified.is_empty(), proofs) {
        (false, 0) => {
            let direct = verified
                .iter()
                .any(|c| matches!(c, EndpointClass::Direct { .. }));
            if direct || relay_only_allowed {
                Ballot::Agree
            } else {
                Ballot::NoVote(Why::RelayOnly)
            }
        }
        (false, _) => Ballot::NoVote(Why::Conflicting),
        (true, 0) => Ballot::NoVote(Why::Unsure),
        (true, 1) => Ballot::NoVote(Why::NotReproduced),
        (true, _) => Ballot::Disagree,
    }
}

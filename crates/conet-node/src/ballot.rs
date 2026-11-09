//! Ballot choice for admission (first online) and recovery votes, project decision D3
//! (2026-11-08), with N6's review §H.8.25: the chain has only agree and disagree. Probe facts
//! (timeouts, no connection) only help the voter choose; "unsure, do not vote" stays allowed, but
//! not voting is not a ballot. After a valid verdict each winning voter gets 0.01 CNET from the
//! stake pool and each losing voter is fined 0.01 CNET, so a wrong-side vote costs money: vote
//! only on proof.
//!
//! Disagree only when the applicant can be held to it: a reply signed by the applicant's
//! registry-bound key, bound to THIS voter's challenge, whose signed content contradicts the
//! request, seen on two DIFFERENT challenges, with the evidence kept. Everything a network
//! attacker or a version skew could cause is no vote.
use crate::admission::{EndpointClass, Fail};
use std::collections::BTreeSet;

/// Kept for every attributable failure; a disagree vote carries at least two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The armored challenge as sent (signed by this voter, encrypted to the applicant).
    pub challenge: String,
    /// The applicant's armored, signed reply.
    pub reply: String,
    /// This voter's own observation (getStats or TCP peer), serialized.
    pub observed: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `verify` passed.
    Verified(EndpointClass),
    /// `verify` failed.
    Failed(Fail),
    /// No usable answer: timeout, connection refused, no route, data channel never opened.
    NoAnswer,
}

/// One challenge attempt as the voter saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// `Challenge::hash()`: results are counted once per challenge.
    pub challenge: [u8; 32],
    /// Anchor / signaling relay used to reach a browser node, if any.
    pub via_anchor: Option<u64>,
    pub outcome: Outcome,
    /// Required for an attributable failure to count.
    pub evidence: Option<Evidence>,
}

/// Relay policy (pending the project's decision; both variants are supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub node_is_browser: bool,
    /// N6's suggestion: a browser node may be approved through a relay. A Linux node must always
    /// be reached directly.
    pub browser_relay_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ballot {
    Agree,
    /// Disagree, with the evidence of at least two different challenges.
    Disagree(Vec<Evidence>),
    /// Not voting (not a ballot). The reason is for the log only.
    NoVote(Why),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Nothing verified and nothing attributable (timeouts, unknown answers, version skew, our
    /// own errors).
    Unsure,
    /// Verified and attributable failures disagree with each other.
    Conflicting,
    /// An attributable failure seen on only one challenge: retry before disagreeing.
    NotReproduced,
    /// An attributable failure without its evidence: never disagree without it.
    NoEvidence,
    /// Only a relay path proved and the policy does not allow it for this node.
    RelayOnly,
}

/// Failures the applicant can be held to (its own signed, challenge-bound statement is wrong).
pub fn attributable(f: &Fail) -> bool {
    matches!(f, Fail::SignedDtlsContradicts | Fail::WalletSig)
}

/// The first result of each challenge, in order (a challenge's result never counts twice).
fn per_challenge(attempts: &[Attempt]) -> Vec<&Attempt> {
    let mut seen = BTreeSet::new();
    attempts
        .iter()
        .filter(|a| seen.insert(a.challenge))
        .collect()
}

/// The decision table. `attempts` are this voter's attempts on the current request version.
pub fn decide(attempts: &[Attempt], policy: Policy) -> Ballot {
    let uniq = per_challenge(attempts);
    let verified: Vec<&EndpointClass> = uniq
        .iter()
        .filter_map(|a| match &a.outcome {
            Outcome::Verified(c) => Some(c),
            _ => None,
        })
        .collect();
    let proofs: Vec<&&Attempt> = uniq
        .iter()
        .filter(|a| matches!(&a.outcome, Outcome::Failed(f) if attributable(f)))
        .collect();
    match (verified.is_empty(), proofs.len()) {
        (false, 0) => {
            let direct = verified
                .iter()
                .any(|c| matches!(c, EndpointClass::Direct { .. }));
            if direct || (policy.node_is_browser && policy.browser_relay_ok) {
                Ballot::Agree
            } else {
                Ballot::NoVote(Why::RelayOnly)
            }
        }
        (false, _) => Ballot::NoVote(Why::Conflicting),
        (true, 0) => Ballot::NoVote(Why::Unsure),
        (true, 1) => Ballot::NoVote(Why::NotReproduced),
        (true, _) => {
            let ev: Vec<Evidence> = proofs.iter().filter_map(|a| a.evidence.clone()).collect();
            if ev.len() < 2 {
                Ballot::NoVote(Why::NoEvidence)
            } else {
                Ballot::Disagree(ev)
            }
        }
    }
}

/// Anchors through which this voter saw another certificate (N6: retry via another anchor and
/// record the one that misbehaved).
pub fn suspect_anchors(attempts: &[Attempt]) -> Vec<u64> {
    let mut out: Vec<u64> = per_challenge(attempts)
        .iter()
        .filter(|a| a.outcome == Outcome::Failed(Fail::DtlsFingerprint))
        .filter_map(|a| a.via_anchor)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Retry schedule (N6 §H.8.25; values pending): a random start delay, then more rounds while the
/// vote is open, never more than `max_attempts` challenges per request version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Upper bound of the random delay before the first challenge, seconds.
    pub start_jitter: u64,
    /// Challenges per round.
    pub per_round: u32,
    /// Rounds in total (the first plus one or two more while the vote is open).
    pub rounds: u32,
    pub max_attempts: u32,
    /// Gap between rounds, seconds.
    pub round_gap: u64,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            start_jitter: 120,
            per_round: 2,
            rounds: 3,
            max_attempts: 6,
            round_gap: 60,
        }
    }
}

impl Schedule {
    /// Seconds to wait before the next challenge, or `None` to stop. `done` = challenges sent so
    /// far on this request version; `random` = a uniform random value (seed of the jitter).
    pub fn next(&self, done: u32, vote_open: bool, settled: bool, random: u64) -> Option<u64> {
        let cap = self.max_attempts.min(self.per_round * self.rounds);
        if settled || !vote_open || done >= cap {
            return None;
        }
        if done == 0 {
            return Some(random % (self.start_jitter + 1));
        }
        if done.is_multiple_of(self.per_round) {
            Some(self.round_gap)
        } else {
            Some(0)
        }
    }
}

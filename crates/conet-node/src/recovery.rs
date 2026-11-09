//! Offline -> online recovery, node-side model of the rules the chain must enforce
//! (RECOVER-RUST). Used by tests and as the reference for the node line; nothing here touches
//! the chain. Rules (project decision 2026-11-08):
//! - only an offline registered node may recover, and every recovery needs a vote (the 472
//!   initial nodes too; an unchanged address is no exception);
//! - the pending candidate endpoint is never routable and gives no voting right;
//! - votes are bound to the application ID and the endpoint version: a changed endpoint bumps
//!   the version and voids every vote cast so far;
//! - success switches the endpoint and online together; anything else stays offline;
//! - there is no direct "mark online" path.
use crate::admission::EndpointClass;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Online {
        endpoint_hash: [u8; 32],
        class: EndpointClass,
    },
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed; the class the voter's own observation proves.
    Approve(EndpointClass),
    /// Provable impersonation (wrong key, wallet, DTLS, endpoint): evidence kept.
    RejectWithEvidence,
    /// Timeout, no connection, nothing decryptable: not evidence of anything.
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    NotOffline,
    NoPending,
    WrongApplication,
    /// The vote names an older endpoint version.
    StaleVersion,
    AlreadyVoted,
    /// Direct online marking (markOnline-like) without a passed recovery vote.
    RecoveryVoteRequired,
}

/// Pass rule (suggested, pending): at least `min_approve` approvals and, if
/// `veto_on_evidence`, no evidenced rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub min_approve: usize,
    pub veto_on_evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Online,
    StayedOffline,
}

#[derive(Debug, Clone)]
struct Pending {
    app_id: [u8; 32],
    version: u64,
    endpoint_hash: [u8; 32],
    votes: BTreeMap<u64, Verdict>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub state: State,
    pending: Option<Pending>,
}

impl Node {
    pub fn offline() -> Self {
        Self {
            state: State::Offline,
            pending: None,
        }
    }

    /// Open a recovery application for a candidate endpoint. Returns its version.
    pub fn open(&mut self, app_id: [u8; 32], endpoint_hash: [u8; 32]) -> Result<u64, Refused> {
        if self.state != State::Offline {
            return Err(Refused::NotOffline);
        }
        self.pending = Some(Pending {
            app_id,
            version: 1,
            endpoint_hash,
            votes: BTreeMap::new(),
        });
        Ok(1)
    }

    /// The candidate endpoint changed during the vote: new version, all votes void.
    pub fn endpoint_changed(&mut self, endpoint_hash: [u8; 32]) -> Result<u64, Refused> {
        let p = self.pending.as_mut().ok_or(Refused::NoPending)?;
        p.version += 1;
        p.endpoint_hash = endpoint_hash;
        p.votes.clear();
        Ok(p.version)
    }

    pub fn vote(
        &mut self,
        app_id: [u8; 32],
        version: u64,
        voter: u64,
        v: Verdict,
    ) -> Result<(), Refused> {
        let p = self.pending.as_mut().ok_or(Refused::NoPending)?;
        if p.app_id != app_id {
            return Err(Refused::WrongApplication);
        }
        if p.version != version {
            return Err(Refused::StaleVersion);
        }
        if p.votes.contains_key(&voter) {
            return Err(Refused::AlreadyVoted);
        }
        p.votes.insert(voter, v);
        Ok(())
    }

    /// Close the vote. Online (endpoint and state together) only when the rule passes.
    pub fn resolve(&mut self, t: Threshold) -> Result<Outcome, Refused> {
        let p = self.pending.take().ok_or(Refused::NoPending)?;
        let approvals: Vec<&EndpointClass> = p
            .votes
            .values()
            .filter_map(|v| match v {
                Verdict::Approve(c) => Some(c),
                _ => None,
            })
            .collect();
        let evidence = p.votes.values().any(|v| *v == Verdict::RejectWithEvidence);
        if !approvals.is_empty()
            && approvals.len() >= t.min_approve
            && !(t.veto_on_evidence && evidence)
        {
            // A path is Relay as soon as any approving voter only reached a relay.
            let class = approvals
                .iter()
                .find(|c| matches!(c, EndpointClass::Relay { .. }))
                .or(approvals.first())
                .map(|c| (*c).clone())
                .expect("min_approve >= 1");
            self.state = State::Online {
                endpoint_hash: p.endpoint_hash,
                class,
            };
            Ok(Outcome::Online)
        } else {
            Ok(Outcome::StayedOffline)
        }
    }

    /// What the router may use: only an online endpoint, never a pending one.
    pub fn routable(&self) -> Option<[u8; 32]> {
        match &self.state {
            State::Online { endpoint_hash, .. } => Some(*endpoint_hash),
            State::Offline => None,
        }
    }

    /// Voting rights come from being online, not from a pending application.
    pub fn may_vote(&self) -> bool {
        matches!(self.state, State::Online { .. })
    }

    /// The old shortcut (markOnline, setOnline after expiry): refused.
    pub fn mark_online_direct(&mut self) -> Result<(), Refused> {
        Err(Refused::RecoveryVoteRequired)
    }

    pub fn go_offline(&mut self) {
        self.state = State::Offline;
        self.pending = None;
    }
}

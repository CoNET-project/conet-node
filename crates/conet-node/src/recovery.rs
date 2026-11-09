//! Offline -> online recovery, node-side model of the rules the chain must enforce
//! (RECOVER-RUST). Used by tests and as the reference for the node line; nothing here touches
//! the chain. Rules (project decision 2026-11-08):
//! - only an offline registered node may recover, and every recovery needs a vote (the 472
//!   initial nodes too; an unchanged address is no exception);
//! - the pending candidate endpoint is never routable and gives no voting right;
//! - votes are bound to the application ID and the endpoint version: a changed endpoint bumps
//!   the version and voids every vote cast so far;
//! - success switches the endpoint and online together; anything else stays offline;
//! - there is no direct "mark online" path;
//! - a node stopped for lack of stake (slashing, offline deductions, a DAO threshold raise)
//!   only regains the RIGHT TO APPLY when its stake is topped up; going online still needs a
//!   passed recovery vote, and a DAO threshold cut never brings anyone back by itself
//!   (project decision 2026-11-08).
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
    /// Stopped for lack of stake and not topped up yet: may not even apply.
    StakeShort,
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
    /// Operator's call: may a browser node that only voters reaching it through a relay approve
    /// come back online? false = at least one approval must prove a direct path.
    pub relay_only_allowed: bool,
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

/// Why a node is offline. Only `StakeShortfall` blocks applying for recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineReason {
    /// Marked offline by a report verdict.
    Reported,
    /// Declared offline itself.
    SelfDeclared,
    /// Browser/mobile declaration expired or paused.
    DeclarationExpired,
    /// Below the stake floor (slashing, deductions, DAO threshold raise). `topped_up` = the stake
    /// is back above the current floor, so the node may apply (it is still offline).
    StakeShortfall { topped_up: bool },
    /// Wallet unbound, withdrawal requested, or any other cause.
    Other,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub state: State,
    pending: Option<Pending>,
    reason: Option<OfflineReason>,
}

impl Node {
    pub fn offline() -> Self {
        Self::offline_because(OfflineReason::Other)
    }

    pub fn offline_because(reason: OfflineReason) -> Self {
        Self {
            state: State::Offline,
            pending: None,
            reason: Some(reason),
        }
    }

    pub fn reason(&self) -> Option<OfflineReason> {
        self.reason
    }

    /// Stake topped up above the floor: restores the right to apply, nothing more.
    pub fn stake_topped_up(&mut self) {
        if let Some(OfflineReason::StakeShortfall { .. }) = self.reason {
            self.reason = Some(OfflineReason::StakeShortfall { topped_up: true });
        }
    }

    /// The DAO lowered the threshold: no effect on an offline node (no automatic recovery). If
    /// the node's stake is now above the new floor, the caller reports it via
    /// `stake_topped_up` (right to apply), never by marking it online.
    pub fn threshold_lowered(&mut self) {}

    /// Open a recovery application for a candidate endpoint. Returns its version.
    pub fn open(&mut self, app_id: [u8; 32], endpoint_hash: [u8; 32]) -> Result<u64, Refused> {
        if self.state != State::Offline {
            return Err(Refused::NotOffline);
        }
        if let Some(OfflineReason::StakeShortfall { topped_up: false }) = self.reason {
            return Err(Refused::StakeShort);
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
        let any_direct = approvals
            .iter()
            .any(|c| matches!(c, EndpointClass::Direct { .. }));
        if !t.relay_only_allowed && !any_direct {
            return Ok(Outcome::StayedOffline);
        }
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
            self.reason = None;
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
        self.go_offline_because(OfflineReason::Other);
    }

    pub fn go_offline_because(&mut self, reason: OfflineReason) {
        self.state = State::Offline;
        self.pending = None;
        self.reason = Some(reason);
    }
}

//! Which wallet of this node sends a vote, and never twice per case (Q117, Rust line
//! `conet-node-probe-wallet-q117-design-v0.1.md`). Pure logic; nothing here signs or sends.
//!
//! The contract counts one vote per nodeId whichever wallet sends it (main or registered probe
//! wallet) and reverts a second one (`AlreadyVoted`). The node side must not even try: a second
//! attempt burns gas, and during a probe-key rotation an in-flight vote from the old key must not
//! be followed by one from the new key. So votes are booked per (entry, case) for the node, not
//! per wallet, and the probe wallet's authorization is re-checked on chain before every send.

use std::collections::BTreeMap;

/// Vote entry points that accept the probe wallet (contract `voterIdOf(sender, true)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entry {
    Report,
    Admission,
    Recovery,
}

/// Which of this node's wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wallet {
    Main(String),
    Probe(String),
}

/// What the chain says about this node's probe wallet right now (`nodeOfProbeSigner(addr)` on
/// a confirmed block, plus the node's own state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStatus {
    /// The registered probe signer for this node, if any.
    pub registered: Option<String>,
    /// `nodeOfProbeSigner(registered).valid` and it maps back to this node.
    pub valid: bool,
    /// The node itself is active with the maintenance bit and out of cooldown.
    pub node_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    Send(Wallet),
    /// Already booked (sent or mined) for this case: never a second vote.
    AlreadyBooked(Wallet),
    /// The chain already shows this node's vote (sent from anywhere).
    AlreadyOnChain,
    /// The node cannot vote now (inactive, cooldown, ...): record, do not send.
    NodeNotEligible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Booked {
    wallet: Wallet,
    tx: String,
}

/// Per-node vote book. Persist it with the node's state.
#[derive(Debug, Clone, Default)]
pub struct VoteBook {
    booked: BTreeMap<(Entry, [u8; 32]), Booked>,
}

/// Probe wallets vote by default (project decision Q117); the main wallet only when there is no
/// valid probe authorization (`main_fallback`, a setting, pending).
pub fn choose(
    status: &ProbeStatus,
    local_probe: &str,
    main: &str,
    main_fallback: bool,
) -> Option<Wallet> {
    if !status.node_eligible {
        return None;
    }
    let ours = status
        .registered
        .as_deref()
        .is_some_and(|r| r.eq_ignore_ascii_case(local_probe));
    if status.valid && ours {
        Some(Wallet::Probe(local_probe.to_string()))
    } else if main_fallback {
        Some(Wallet::Main(main.to_string()))
    } else {
        None
    }
}

impl VoteBook {
    /// Decide for one case. `on_chain_voted`: the contract's vote record for this nodeId
    /// (`getVote` / `admissionVoteOf` / `recoveryVoteOf`) is non-zero.
    pub fn pick(
        &self,
        entry: Entry,
        case: [u8; 32],
        on_chain_voted: bool,
        wallet: Option<Wallet>,
    ) -> Pick {
        if let Some(b) = self.booked.get(&(entry, case)) {
            return Pick::AlreadyBooked(b.wallet.clone());
        }
        if on_chain_voted {
            return Pick::AlreadyOnChain;
        }
        match wallet {
            Some(w) => Pick::Send(w),
            None => Pick::NodeNotEligible,
        }
    }

    /// Record a sent vote before broadcasting it (so a crash cannot lead to a second one).
    pub fn book(&mut self, entry: Entry, case: [u8; 32], wallet: Wallet, tx: &str) -> bool {
        if self.booked.contains_key(&(entry, case)) {
            return false;
        }
        self.booked.insert(
            (entry, case),
            Booked {
                wallet,
                tx: tx.to_string(),
            },
        );
        true
    }

    /// A same-nonce replacement keeps the booking (same wallet), only the tx hash changes.
    pub fn replace_tx(&mut self, entry: Entry, case: [u8; 32], wallet: &Wallet, tx: &str) -> bool {
        match self.booked.get_mut(&(entry, case)) {
            Some(b) if &b.wallet == wallet => {
                b.tx = tx.to_string();
                true
            }
            _ => false,
        }
    }

    /// The tx was dropped AND the chain shows no vote for this node: the booking may be released
    /// so the case can be voted again (by whichever wallet is valid now).
    pub fn release_if_dropped(
        &mut self,
        entry: Entry,
        case: [u8; 32],
        on_chain_voted: bool,
    ) -> bool {
        if on_chain_voted {
            return false;
        }
        self.booked.remove(&(entry, case)).is_some()
    }
}

/// Before every send with the probe wallet: stop if the authorization is gone (revoked,
/// replaced, main wallet changed, expired, node inactive). The signer process cannot see the
/// chain; conet-node checks, and the contract enforces again.
pub fn probe_may_send(status: &ProbeStatus, local_probe: &str) -> bool {
    status.node_eligible
        && status.valid
        && status
            .registered
            .as_deref()
            .is_some_and(|r| r.eq_ignore_ascii_case(local_probe))
}

//! F5 vote gate, read side only (Rust line §31.3 second item, N6 H8-16).
//!
//! Before a node votes on an offline report (or opens one), decide from chain state whether the
//! contract would accept it, so a vote that must revert (`StakeLocked`, `VoteCooldown`, ...) is
//! never sent and never burns gas. Also picks which open cases to join when the lock capacity
//! is short.
//!
//! The checks mirror `OfflineReportLib.voteReport` / `reportOffline` of the node line's contract
//! (per-case lock: every vote, the report included, locks the case's penalty standard F; a node
//! may hold at most `(stake - locked) / F` more cases). The decisive check is still the contract;
//! a disagreement shows up as a reverted eth_call in tests.
//!
//! Nothing here sends a transaction or signs. Wiring this to a real send path is F5, which is
//! not approved.
use crate::chain::{ChainError, Rpc};
use crate::nr2::NodeRegistryV2;
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolCall;

/// `SUSPEND_BPS / BPS`: below 80% of the threshold a node is suspended; F = threshold - 80%.
pub const SUSPEND_BPS: u128 = 8_000;
pub const BPS: u128 = 10_000;
pub const REPORT_OPEN: u8 = 1;
/// Maintenance service bit: only nodes carrying it may report or vote.
pub const SVC_MAINT: u16 = 1 << 3;

/// What the gate needs to know about a voter (or reporter) node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterView {
    pub node_id: u64,
    /// `isActive(nodeId)`.
    pub active: bool,
    pub services: u16,
    pub stake: u128,
    /// Stake already held by unsettled cases.
    pub locked: u128,
    /// Reporting and voting allowed from this time (7-day cooldown after registration or a
    /// wallet / operator change).
    pub eligible_at: u64,
    /// The open report naming this node as target, 0 = none (used when it is a report target).
    pub open_report_id: u64,
}

impl VoterView {
    /// Stake not yet held by any case.
    pub fn available(&self) -> u128 {
        self.stake.saturating_sub(self.locked)
    }
    /// How many more cases with penalty standard `fine` this node can join.
    pub fn capacity(&self, fine: u128) -> u128 {
        if fine == 0 {
            return u128::MAX;
        }
        self.available() / fine
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportView {
    pub rid: u64,
    pub target: u64,
    pub reporter: u64,
    pub opened_at: u64,
    pub expires_at: u64,
    pub min_open: u32,
    pub agree: u32,
    pub disagree: u32,
    pub margin: u16,
    pub state: u8,
    /// Penalty standard F of this case, fixed when it opened.
    pub fine: u128,
}

impl ReportView {
    /// Votes still needed by the side that is ahead to reach the margin.
    pub fn margin_gap(&self) -> u32 {
        let lead = self.agree.abs_diff(self.disagree);
        (self.margin as u32).saturating_sub(lead)
    }
    /// Earliest time the case can be decided.
    pub fn decidable_at(&self) -> u64 {
        self.opened_at + self.min_open as u64
    }
}

/// Why not to send. Each maps to the contract error the transaction would hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// `ReporterNotEligible`: not active.
    NotActive,
    /// `ReporterNotEligible`: no maintenance bit.
    NoMaintBit,
    /// `VoteCooldown`.
    Cooldown { until: u64 },
    /// `NotReportable`: the voter is the target (or reports itself).
    IsTarget,
    /// `AlreadyVoted` (the reporter counts as the first agree vote).
    AlreadyVoted,
    /// `ReportNotOpen`.
    NotOpen,
    /// `ReportExpired`.
    Expired,
    /// `StakeLocked`: not enough unlocked stake for one more case.
    NoLockCapacity { available: u128, need: u128 },
    /// `NotReportable`: the target cannot be reported (not serving).
    TargetNotReportable,
    /// `ReportOpenAlready`.
    ReportOpen { rid: u64 },
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The contract's voter checks, in its order.
fn eligible(v: &VoterView, now: u64) -> Result<(), Skip> {
    if !v.active {
        return Err(Skip::NotActive);
    }
    if v.services & SVC_MAINT == 0 {
        return Err(Skip::NoMaintBit);
    }
    if now < v.eligible_at {
        return Err(Skip::Cooldown {
            until: v.eligible_at,
        });
    }
    Ok(())
}

fn lock(v: &VoterView, fine: u128) -> Result<(), Skip> {
    if v.stake < v.locked.saturating_add(fine) {
        return Err(Skip::NoLockCapacity {
            available: v.available(),
            need: fine,
        });
    }
    Ok(())
}

/// Would `voteReport(r.rid, _)` from this voter go through at `now`?
/// `my_choice` is `getVote(rid, voter).choice` (0 = not voted).
pub fn can_vote(v: &VoterView, r: &ReportView, my_choice: u8, now: u64) -> Result<(), Skip> {
    if r.state != REPORT_OPEN {
        return Err(Skip::NotOpen);
    }
    if now >= r.expires_at {
        return Err(Skip::Expired);
    }
    eligible(v, now)?;
    if v.node_id == r.target {
        return Err(Skip::IsTarget);
    }
    if my_choice != 0 {
        return Err(Skip::AlreadyVoted);
    }
    lock(v, r.fine)
}

/// Penalty standard a report opened now would fix: threshold - 80% of threshold.
pub fn fine_now(effective_min: u128) -> u128 {
    effective_min - effective_min * SUSPEND_BPS / BPS
}

/// Would `reportOffline(target)` from this reporter go through at `now`?
/// `target_serving` is the contract's `canServe` for the target (for a TCP node the same as
/// `isActive`); `target_open` is the target's open report, if any.
pub fn can_report(
    v: &VoterView,
    target_id: u64,
    target_serving: bool,
    target_open: Option<&ReportView>,
    fine: u128,
    now: u64,
) -> Result<(), Skip> {
    eligible(v, now)?;
    if v.node_id == target_id {
        return Err(Skip::IsTarget);
    }
    if !target_serving {
        return Err(Skip::TargetNotReportable);
    }
    if let Some(o) = target_open {
        if o.state == REPORT_OPEN && now < o.expires_at {
            return Err(Skip::ReportOpen { rid: o.rid });
        }
    }
    lock(v, fine)
}

/// Which of these open cases to join, in order, given the voter's lock capacity (H8-16).
///
/// Only cases the voter can vote on now. Most urgent first: the earliest to become decidable,
/// then the one closest to its margin (where one vote matters most), then the lowest id. Stops
/// when the next case's penalty no longer fits the unlocked stake. `my_choices` gives
/// `getVote(rid, voter).choice` per report, in the same order.
pub fn pick(v: &VoterView, reports: &[ReportView], my_choices: &[u8], now: u64) -> Vec<u64> {
    let mut open: Vec<&ReportView> = reports
        .iter()
        .zip(my_choices.iter().copied().chain(std::iter::repeat(0)))
        .filter(|(r, c)| {
            // Capacity is checked below, cumulatively; here everything else.
            let unlimited = VoterView {
                locked: 0,
                stake: u128::MAX,
                ..v.clone()
            };
            can_vote(&unlimited, r, *c, now).is_ok()
        })
        .map(|(r, _)| r)
        .collect();
    open.sort_by_key(|r| (r.decidable_at().max(now), r.margin_gap(), r.rid));
    let mut left = v.available();
    let mut out = Vec::new();
    for r in open {
        if r.fine > left {
            break;
        }
        left -= r.fine;
        out.push(r.rid);
    }
    out
}

// ---- chain reads ----

/// Words in `getNodeRaw`'s `Node` struct (all static members; `uint32[3] anchors` takes three).
/// Pinned to the node line's contract source set `bee380fd2c26bd66` (abi/README.md).
pub const NODE_RAW_WORDS: usize = 38;
const W_SERVICES: usize = 5;
const W_NODE_WALLET: usize = 10;
const W_STAKE: usize = 14;
const W_OPEN_REPORT: usize = 27;
const W_ELIGIBLE_AT: usize = 36;
const W_LOCKED: usize = 37;

fn ce<E: std::fmt::Display>(e: E) -> ChainError {
    ChainError(e.to_string())
}

fn word_u128(raw: &[u8], i: usize) -> Result<u128, ChainError> {
    let w = &raw[i * 32..(i + 1) * 32];
    if w[..16].iter().any(|b| *b != 0) {
        return Err(ChainError(format!("getNodeRaw word {i} out of range")));
    }
    Ok(u128::from_be_bytes(w[16..].try_into().expect("16 bytes")))
}

/// Decode the voter-relevant members of `getNodeRaw(nodeId)`. The struct is not in the bound ABI
/// (alloy's tuple limit), so the layout is checked by length and by the wallet word.
pub fn decode_node_raw(raw: &[u8], node_id: u64, active: bool) -> Result<VoterView, ChainError> {
    if raw.len() != NODE_RAW_WORDS * 32 {
        return Err(ChainError(format!(
            "getNodeRaw: {} bytes, expected {} (contract layout changed?)",
            raw.len(),
            NODE_RAW_WORDS * 32
        )));
    }
    let services = word_u128(raw, W_SERVICES)?;
    let eligible = word_u128(raw, W_ELIGIBLE_AT)?;
    let open = word_u128(raw, W_OPEN_REPORT)?;
    if services > u16::MAX as u128 || eligible > u64::MAX as u128 || open > u64::MAX as u128 {
        return Err(ChainError("getNodeRaw: field out of range".into()));
    }
    Ok(VoterView {
        node_id,
        active,
        services: services as u16,
        stake: word_u128(raw, W_STAKE)?,
        locked: word_u128(raw, W_LOCKED)?,
        eligible_at: eligible as u64,
        open_report_id: open as u64,
    })
}

/// Reads for the gate. Calls never set `from` and never send.
pub struct VoteReader {
    pub rpc: Rpc,
    pub registry: String,
}

impl VoteReader {
    async fn call<C: SolCall>(&self, c: C) -> Result<C::Return, ChainError> {
        let raw = self
            .rpc
            .eth_call(&self.registry, c.abi_encode(), None)
            .await?;
        C::abi_decode_returns(&raw).map_err(ce)
    }

    pub async fn voter(&self, node_id: u64) -> Result<VoterView, ChainError> {
        let id = U256::from(node_id);
        let active = self
            .call(NodeRegistryV2::isActiveCall { nodeId: id })
            .await?;
        let wallet = self
            .call(NodeRegistryV2::nodeWalletOfCall { nodeId: id })
            .await?;
        let mut data = keccak256(b"getNodeRaw(uint256)")[..4].to_vec();
        data.extend_from_slice(&id.to_be_bytes::<32>());
        let raw = self.rpc.eth_call(&self.registry, data, None).await?;
        let v = decode_node_raw(&raw, node_id, active)?;
        // Layout check: the wallet word must match nodeWalletOf.
        let w = &raw[W_NODE_WALLET * 32 + 12..(W_NODE_WALLET + 1) * 32];
        if w != wallet.as_slice() {
            return Err(ChainError(
                "getNodeRaw: wallet word mismatch (contract layout changed?)".into(),
            ));
        }
        Ok(v)
    }

    pub async fn report(&self, rid: u64) -> Result<ReportView, ChainError> {
        let r = self
            .call(NodeRegistryV2::getReportCall {
                reportId: U256::from(rid),
            })
            .await?;
        Ok(ReportView {
            rid,
            target: r.target,
            reporter: r.reporter,
            opened_at: r.openedAt,
            expires_at: r.expiresAt,
            min_open: r.minOpen,
            agree: r.agree,
            disagree: r.disagree,
            margin: r.margin,
            state: r.state,
            fine: r.fine,
        })
    }

    /// `getVote(rid, voter).choice`; 0 = not voted.
    pub async fn choice(&self, rid: u64, voter: u64) -> Result<u8, ChainError> {
        let v = self
            .call(NodeRegistryV2::getVoteCall {
                reportId: U256::from(rid),
                voterNodeId: U256::from(voter),
            })
            .await?;
        Ok(v.choice)
    }

    /// Penalty standard of a report opened now.
    pub async fn fine_now(&self) -> Result<u128, ChainError> {
        let thr = self.call(NodeRegistryV2::effectiveMinStakeCall {}).await?;
        Ok(fine_now(thr.try_into().map_err(ce)?))
    }

    pub async fn report_count(&self) -> Result<u64, ChainError> {
        let n = self.call(NodeRegistryV2::reportCountCall {}).await?;
        n.try_into().map_err(ce)
    }
}

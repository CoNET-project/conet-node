//! F5 vote gate, read side only (Rust line §31.3 second item, N6 H8-16).
//!
//! Before a node votes on an offline report (or opens one), decide from chain state whether the
//! contract would accept it, so a vote that must revert (`StakeLocked`, `VoteCooldown`, ...) is
//! never sent and never burns gas. Also picks which open cases to join when the lock capacity
//! is short.
//!
//! The checks mirror `OfflineReportLib.voteReport` / `reportOffline` of the node line's contract
//! (per-voter lock, user decision 2026-11-08 "按节点本期核定额"; node line stake-term v0.1 §14-15:
//! a case fixes its penalty RATIO when it opens; every vote, the report included, locks
//! ratio x the voter's OWN read-time term amount (`termState`), fixed at the vote; a node may hold
//! at most `(stake - locked) / own fine` more cases). The decisive check is still the contract; a
//! disagreement shows up as a reverted eth_call in tests.
//!
//! Nothing here sends a transaction or signs. Wiring this to a real send path is F5, which is
//! not approved.
use crate::chain::{ChainError, Rpc};
use crate::nr2::NodeRegistryV2;
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolCall;

/// `SUSPEND_BPS / BPS`: below 80% of the term amount a node is suspended.
pub const SUSPEND_BPS: u128 = 8_000;
pub const BPS: u128 = 10_000;
/// Ratio a report opened now fixes (`BPS - SUSPEND_BPS`, 20%).
pub const NEW_REPORT_RATIO_BPS: u128 = BPS - SUSPEND_BPS;
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
    /// Stake already held by unsettled cases (`voteLocked`).
    pub locked: u128,
    /// The node's approved amount of its current term, read-time (`termStateOf(nodeId).termBase`):
    /// what its own fine is computed from.
    pub term_base: u128,
    /// Reporting and voting allowed from this time: the chain's `voteEligibleAt`, read as is.
    /// Never derived locally (registration + 7 days): the trusted 472 can vote from their first
    /// registration (user decision 2026-11-08), while new nodes and later wallet / operator
    /// changes get the cooldown. Only the contract knows which case applies.
    pub eligible_at: u64,
    /// The open report naming this node as target, 0 = none (used when it is a report target).
    pub open_report_id: u64,
}

impl VoterView {
    /// Stake not yet held by any case.
    pub fn available(&self) -> u128 {
        self.stake.saturating_sub(self.locked)
    }
    /// This node's fine (and lock) for a case of `ratio_bps`, as the contract's `_voterFine`.
    pub fn fine_for(&self, ratio_bps: u128) -> u128 {
        self.term_base * ratio_bps / BPS
    }
    /// How many more cases of `ratio_bps` this node can join (`lockCapacityOf().slotsLeft` for
    /// the 20% ratio).
    pub fn capacity(&self, ratio_bps: u128) -> u128 {
        let f = self.fine_for(ratio_bps);
        if f == 0 {
            return 0;
        }
        self.available() / f
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
    /// Penalty RATIO of this case in BPS, fixed when it opened (`Report.fine`); each voter's
    /// amount is this ratio times its own term amount.
    pub ratio_bps: u128,
    /// Eligible nodes when the report opened (turnout denominator, project decision 2026-11-09);
    /// None until the node line's read exists.
    pub eligible_snapshot: Option<u32>,
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

fn lock(v: &VoterView, ratio_bps: u128) -> Result<(), Skip> {
    let fine = v.fine_for(ratio_bps);
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
    lock(v, r.ratio_bps)
}

/// Would `reportOffline(target)` from this reporter go through at `now`?
/// `target_serving` is the contract's `canServe` for the target (for a TCP node the same as
/// `isActive`); `target_open` is the target's open report, if any. The reporter locks its own
/// fine at [`NEW_REPORT_RATIO_BPS`].
pub fn can_report(
    v: &VoterView,
    target_id: u64,
    target_serving: bool,
    target_open: Option<&ReportView>,
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
    lock(v, NEW_REPORT_RATIO_BPS)
}

/// Which of these open cases to join, in order, given the voter's lock capacity (H8-16).
///
/// Only cases the voter can vote on now. Most urgent first: the earliest to become decidable,
/// then the one closest to its margin (where one vote matters most), then the lowest id. Stops
/// when the voter's own fine for the next case no longer fits its unlocked stake. `my_choices` gives
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
        let f = v.fine_for(r.ratio_bps);
        if f > left {
            break;
        }
        left -= f;
        out.push(r.rid);
    }
    out
}

// ---- chain reads ----

/// Words in `getNodeRaw`'s `Node` struct (all static members; `uint32[3] anchors` takes three).
/// Pinned to the node line's contract source set `a1a13d46` (v0.4.2; abi/README.md): 41 members,
/// the stake-term fields and `offlineSince` appended at the end (earlier word positions unchanged).
pub const NODE_RAW_WORDS: usize = 43;
/// `offlineSince`: chain moment the node's current offline state took effect (recovery cooldown
/// start), v0.4.2.
pub const W_OFFLINE_SINCE: usize = 42;
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
/// `term_base` comes from `termStateOf` (read-time), not from the stored word, which can lag
/// until someone calls `settleTerms`.
pub fn decode_node_raw(
    raw: &[u8],
    node_id: u64,
    active: bool,
    term_base: u128,
) -> Result<VoterView, ChainError> {
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
        term_base,
        eligible_at: eligible as u64,
        open_report_id: open as u64,
    })
}

/// The contract's `lockCapacityOf`: free stake (stake - locked), the fine one new 20% vote would
/// lock now, and how many more such cases fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockCapacity {
    pub free_stake: u128,
    pub fine_per_vote: u128,
    pub slots_left: u128,
}

/// Contract-wide due-but-unpaid amounts (node line v0.4.2, `dueBreakdown()`): principal of exiting
/// nodes whose unbonding is over and nobody withdrew (minus open-case locks), and payouts waiting in
/// `owed`. Their sum is dueUnpaid. Replaces the per-node placeholder kept until the read existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueBreakdown {
    pub mature_unwithdrawn: u128,
    pub owed: u128,
}

impl DueBreakdown {
    pub fn due_unpaid(&self) -> u128 {
        self.mature_unwithdrawn.saturating_add(self.owed)
    }
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
        let term = self
            .call(NodeRegistryV2::termStateOfCall { nodeId: id })
            .await?;
        let v = decode_node_raw(&raw, node_id, active, term.termBase.try_into().map_err(ce)?)?;
        // Layout check: the wallet word must match nodeWalletOf.
        let w = &raw[W_NODE_WALLET * 32 + 12..(W_NODE_WALLET + 1) * 32];
        if w != wallet.as_slice() {
            return Err(ChainError(
                "getNodeRaw: wallet word mismatch (contract layout changed?)".into(),
            ));
        }
        // Cross-check with the contract's own capacity view: free stake and fine per vote.
        let cap = self.lock_capacity(node_id).await?;
        if cap.free_stake != v.available() || cap.fine_per_vote != v.fine_for(NEW_REPORT_RATIO_BPS)
        {
            return Err(ChainError(
                "lockCapacityOf disagrees with getNodeRaw / termStateOf".into(),
            ));
        }
        Ok(v)
    }

    /// `lockCapacityOf(nodeId)`: the contract's view of this node's lock capacity.
    pub async fn lock_capacity(&self, node_id: u64) -> Result<LockCapacity, ChainError> {
        let r = self
            .call(NodeRegistryV2::lockCapacityOfCall {
                nodeId: U256::from(node_id),
            })
            .await?;
        Ok(LockCapacity {
            free_stake: r.freeStake.try_into().map_err(ce)?,
            fine_per_vote: r.finePerVote.try_into().map_err(ce)?,
            slots_left: r.slotsLeft.try_into().map_err(ce)?,
        })
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
            ratio_bps: r.fine,
            eligible_snapshot: None, // pending the node line's read
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

    /// `dueBreakdown()`.
    pub async fn due_breakdown(&self) -> Result<DueBreakdown, ChainError> {
        let r = self.call(NodeRegistryV2::dueBreakdownCall {}).await?;
        Ok(DueBreakdown {
            mature_unwithdrawn: r.matureUnwithdrawn.try_into().map_err(ce)?,
            owed: r.owed.try_into().map_err(ce)?,
        })
    }

    pub async fn report_count(&self) -> Result<u64, ChainError> {
        let n = self.call(NodeRegistryV2::reportCountCall {}).await?;
        n.try_into().map_err(ce)
    }
}

// ---- voting window for reports (project correction 2026-11-09: the 600 s / 7,200 s standard
// applies to every proposal, offline reports included; margin 20, shares and executor rules
// unchanged) ----

/// Would this vote (`agree`) decide the report at `now`: its side reaches the margin, the
/// observation time (`minOpen`, 600 s) has passed and voting has not ended (`expiresAt`, opening +
/// 7,200 s). Both times come from the chain's report record, so the gate follows the contract.
pub fn would_decide_report(r: &ReportView, agree: bool, now: u64) -> bool {
    let (mine, other) = if agree {
        (r.agree + 1, r.disagree)
    } else {
        (r.disagree + 1, r.agree)
    };
    let early =
        crate::online_gate::turnout_over_half(r.agree + r.disagree + 1, r.eligible_snapshot);
    r.state == REPORT_OPEN
        && mine >= other + r.margin as u32
        && (now >= r.decidable_at() || early)
        && now < r.expires_at
}

/// When to send a report vote: at once while voting is open (no holding: anyone can seal through
/// the unified entry once the observation time passed and the threshold is met), none after the
/// end. A report that ends without a verdict is void: no reward, no fine, its locks are freed by
/// the contract (the gate reads `voteLocked` again, so freed capacity shows up by itself).
pub fn report_vote_timing(r: &ReportView, now: u64) -> crate::online_gate::VoteTiming {
    use crate::online_gate::VoteTiming;
    if r.state != REPORT_OPEN || now >= r.expires_at {
        VoteTiming::Closed
    } else {
        VoteTiming::Now
    }
}

/// The report's threshold is met and it can be sealed through the unified entry: after the
/// observation time or with more than half of the eligible nodes voting; after `expiresAt` with
/// the frozen votes when late sealing is on (decided 2026-11-09, default on).
pub fn report_seal_ready(r: &ReportView, now: u64, s: &crate::online_gate::SealStrategy) -> bool {
    let met = r.agree >= r.disagree + r.margin as u32 || r.disagree >= r.agree + r.margin as u32;
    let time_or_turnout = now >= r.decidable_at()
        || crate::online_gate::turnout_over_half(r.agree + r.disagree, r.eligible_snapshot);
    r.state == REPORT_OPEN && met && time_or_turnout && (s.seal_after_window || now < r.expires_at)
}

/// After the report's end the votes are frozen: seal if they meet the margin, else void close.
pub fn report_after_window(r: &ReportView, now: u64) -> crate::online_gate::AfterWindow {
    use crate::online_gate::AfterWindow;
    let met = r.agree >= r.disagree + r.margin as u32 || r.disagree >= r.agree + r.margin as u32;
    if now < r.expires_at {
        AfterWindow::StillOpen
    } else if met {
        AfterWindow::Seal
    } else {
        AfterWindow::VoidClose
    }
}

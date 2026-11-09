//! Online votes (first admission, offline recovery), node side, project decisions 2026-11-08/09
//! ("上线表决防刷" and the reward / proposer decisions that followed):
//!
//! - after the node actually goes offline on chain, no coming back for 12 hours (43,200 s) from the
//!   moment the offline state took effect (self offline, report verdict, expired declaration,
//!   stake stop; wallet or endpoint changes do not reset it; trusted nodes too);
//! - each successful online (first, every recovery) costs the applicant 0.01 CNET: locked when the
//!   case opens, charged once on success, returned on failure or expiry;
//! - the applicant asks ANOTHER node to propose; that proposer reviews (the same challenge checks
//!   as an agree vote) and only then opens the case; the proposal is its agree vote (1:0); it may
//!   not vote again in that case (any of its wallets) and is not the case's executor; a valid
//!   rejection fines the proposer 0.001 once;
//! - voters: winning side +0.001, losing side -0.001 (0.001 locked at the vote), timeout neither;
//!   the node casting the deciding last vote and executing the settlement gets 0.005; one node,
//!   one case: only the highest reward.
//!
//! Lock sources and fee interfaces are not published by the node line yet: the amounts are
//! parameters and the balances are passed in.
use crate::ballot::{Ballot, Why};

pub const OFFLINE_COOLDOWN: u64 = 43_200;
/// An own recovery case still voting can be replaced by a new version only this long after its
/// chain `openedAt` (project decision 2026-11-09).
pub const REPLACE_AFTER: u64 = 43_200;
const MILLI: u128 = 1_000_000_000_000_000; // 0.001 CNET
pub const ONLINE_FEE: u128 = 10 * MILLI; // 0.01
pub const VOTE_STAKE: u128 = MILLI; // +0.001 / -0.001, locked at the vote
pub const PROPOSER_FINE: u128 = MILLI; // on a valid rejection
pub const EXECUTOR_REWARD: u128 = 5 * MILLI; // deciding vote + settlement
pub const PROPOSER_REWARD: u128 = 10 * MILLI; // on approval

/// When the current offline period started, as the contract counts it: `outOfServiceSince`, or
/// the end of an expired browser / mobile declaration, whichever is earlier (OnlineVoteLib
/// `checkCooldown`).
pub fn offline_since(out_of_service_since: u64, expired_declaration_end: Option<u64>) -> u64 {
    match (out_of_service_since, expired_declaration_end) {
        (0, Some(e)) => e,
        (s, Some(e)) if e < s => e,
        (s, _) => s,
    }
}

/// What stops this node from asking for recovery now. Empty = may ask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryBlockers {
    /// Seconds still to wait in the 12-hour cooldown.
    pub wait: Option<u64>,
    /// The open case cannot be replaced by a new version before this chain time.
    pub replace_at: Option<u64>,
    /// Stake still missing (stake - locked must reach the latest full threshold).
    pub stake_missing: Option<u128>,
    /// Online fee still missing in the balance it is paid from (source pending).
    pub fee_missing: Option<u128>,
}

impl RecoveryBlockers {
    pub fn clear(&self) -> bool {
        self.wait.is_none()
            && self.replace_at.is_none()
            && self.stake_missing.is_none()
            && self.fee_missing.is_none()
    }
}

/// Inputs from one confirmed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryView {
    pub now: u64,
    /// [`offline_since`]; 0 = not offline.
    pub offline_since: u64,
    /// Chain time at which the latest valid rejection of this node's recovery sealed its votes;
    /// 0 = never rejected (user decision 2026-11-09). Contract field pending the node line.
    pub last_rejected_at: u64,
    /// This node's own recovery case if it is still voting: its chain `openedAt` (project decision
    /// 2026-11-09: no new version may replace it before openedAt + 43,200). None = no open case
    /// (never opened, or already decided: those follow the other rules).
    pub open_case_opened_at: Option<u64>,
    pub stake: u128,
    pub locked: u128,
    pub latest_threshold: u128,
    /// Balance the online fee is locked from (interface pending).
    pub fee_balance: u128,
}

/// Recovery precheck: all three must hold before asking a proposer; otherwise tell the operator
/// how long to wait and how much is missing. Note for the operator: if the request is rejected,
/// the PROPOSER (another node) is fined 0.001, so proposers will only take honest requests.
pub fn precheck_recovery(v: &RecoveryView) -> RecoveryBlockers {
    let mut b = RecoveryBlockers::default();
    // Always a fixed 12 hours (project correction "重新申请上线都是 12h"; the doubling C17 rule is
    // void): from the actual offline moment, or after a rejection from the moment its verdict
    // sealed the votes. Rejections never add up.
    let start = v.offline_since.max(v.last_rejected_at);
    if start != 0 && v.now < start + OFFLINE_COOLDOWN {
        b.wait = Some(start + OFFLINE_COOLDOWN - v.now);
    }
    // An own case still voting may only be replaced 12 hours after it opened (a separate rule
    // from the post-rejection wait).
    if let Some(opened) = v.open_case_opened_at {
        if v.now < opened + REPLACE_AFTER {
            b.replace_at = Some(opened + REPLACE_AFTER);
        }
    }
    let free = v.stake.saturating_sub(v.locked);
    if free < v.latest_threshold {
        b.stake_missing = Some(v.latest_threshold - free);
    }
    if v.fee_balance < ONLINE_FEE {
        b.fee_missing = Some(ONLINE_FEE - v.fee_balance);
    }
    b
}

/// Shown before a self-declared offline: the node cannot come back before this time.
pub fn offline_warning(now: u64) -> u64 {
    now + OFFLINE_COOLDOWN
}

// ---- this node as the proposer ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposeDecision {
    /// Open the case (the proposal is this node's agree vote).
    Propose,
    /// Do not: the review did not reach the agree standard.
    Decline(Why),
    /// Do not: the applicant's signed reply contradicts the request (keep the evidence).
    Refuse,
    /// Do not: this node cannot carry the possible 0.001 fine.
    CannotCoverFine { missing: u128 },
    /// Do not: the applicant of a first admission is still in its 12-hour wait after a rejection.
    ApplicantWaiting { until: u64 },
}

/// Review standard = the agree standard of [`crate::ballot::decide`], on this node's OWN challenge
/// results only (N6 second review: the applicant's past rejections are not an input): only a verified challenge
/// (direct, or relay where the policy allows) leads to a proposal. The proposer keeps 0.001 free
/// for the fine of a valid rejection (lock interface pending).
pub fn review(ballot: &Ballot, free_balance: u128) -> ProposeDecision {
    match ballot {
        Ballot::Agree if free_balance < PROPOSER_FINE => ProposeDecision::CannotCoverFine {
            missing: PROPOSER_FINE - free_balance,
        },
        Ballot::Agree => ProposeDecision::Propose,
        Ballot::Disagree(_) => ProposeDecision::Refuse,
        Ballot::NoVote(w) => ProposeDecision::Decline(*w),
    }
}

// ---- this node as a voter in someone else's case ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseView {
    /// The case's proposer node id (contract record). Its proposal is its one vote.
    pub proposer: u64,
    /// The applicant node id (0 for a first admission with no node yet).
    pub applicant: u64,
    /// The contract already holds a vote of this node id in the case (any wallet: main, probe,
    /// delegate), or this node has one booked in flight (`vote_book`).
    pub voted: bool,
    /// Still voting: false once the deciding vote locked the verdict (batch settlement after it
    /// never reopens voting).
    pub open: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineSkip {
    /// This node proposed the case: no vote from any of its wallets, no execution.
    OwnProposal,
    /// This node is the applicant.
    OwnApplication,
    AlreadyVoted,
    NotOpen,
    /// Not 0.001 free to lock for the vote.
    NoLock {
        missing: u128,
    },
}

/// May this node vote in an online case at all (before the ballot table)?
pub fn may_vote_online(me: u64, c: &CaseView, free_balance: u128) -> Result<(), OnlineSkip> {
    if !c.open {
        return Err(OnlineSkip::NotOpen);
    }
    if c.proposer == me {
        return Err(OnlineSkip::OwnProposal);
    }
    if c.applicant == me {
        return Err(OnlineSkip::OwnApplication);
    }
    if c.voted {
        return Err(OnlineSkip::AlreadyVoted);
    }
    if free_balance < VOTE_STAKE {
        return Err(OnlineSkip::NoLock {
            missing: VOTE_STAKE - free_balance,
        });
    }
    Ok(())
}

/// Optional strategy, OFF by default: cast the deciding last vote and execute the settlement for
/// 0.005. Worth it only if the extra reward over a plain winning vote (0.005 - 0.001, rewards do
/// not stack) beats the extra gas of the deciding vote plus settlement, AND the node is not the
/// proposer (never executes its own case). Races with other nodes: a losing racer's transaction
/// reverts and still pays gas, so `race_loss_rate` discounts the gain.
pub fn executor_worth_it(
    enabled: bool,
    is_proposer: bool,
    extra_gas: u128,
    gas_price_wei: u128,
    race_loss_rate_bps: u128,
) -> bool {
    if !enabled || is_proposer {
        return false;
    }
    let extra_reward = EXECUTOR_REWARD - VOTE_STAKE;
    let expected = extra_reward * (10_000 - race_loss_rate_bps.min(10_000)) / 10_000;
    let cost = extra_gas.saturating_mul(gas_price_wei);
    expected > cost
}

/// Expected value of one vote in wei-scale CNET for a given confidence (bps) of being on the
/// winning side: +0.001 x p - 0.001 x (1 - p). Below 50% it is negative; with gas it needs more.
pub fn vote_expectation(win_bps: u128, gas_cost: u128) -> i128 {
    let p = win_bps.min(10_000) as i128;
    let s = VOTE_STAKE as i128;
    s * p / 10_000 - s * (10_000 - p) / 10_000 - gas_cost as i128
}

/// Optional seal / executor strategy: an attempt that reverts because the case was sealed in the
/// meantime (someone else sealed it) or this node's vote already counts is an expected race loss:
/// no retry, no second reward, not reported as an error.
pub fn executor_race_lost(revert_name: &str) -> bool {
    matches!(revert_name, "AdmissionState" | "AlreadyVoted")
}

/// Online votes (first admission, recovery), project correction 2026-11-09 (replaces approve 5
/// min / reject 12 h): for the first 600 s votes are taken but nothing seals, even at the margin;
/// voting ends 7,200 s after opening; no verdict by then = void (no reward, no fine, locks freed).
/// Re-applying after a rejection still waits 12 hours; offline reports are unchanged.
pub const MIN_OPEN: u64 = 600;
pub const MAX_OPEN: u64 = 7_200;

/// Tally of an online case as the chain reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub opened_at: u64,
    pub agree: u32,
    pub disagree: u32,
    pub margin: u32,
    /// `population`: nodes registered (not withdrawn) when the case opened, the majority base the
    /// contract stores per case (`s.listed.length` snapshot). Not "eligible" nodes. None = not read
    /// (then only the 600 s rule applies).
    pub population: Option<u32>,
    /// The case's own node in that base: 0 for a first admission, 1 for a recovery (the contract's
    /// `subject`). Only matters with `MajorityRule::exclude_subject`.
    pub subject: u32,
}

/// Participating nodes: agree + disagree. The contract takes one vote per node (a second one
/// reverts), so each vote is a distinct node; [`count_participants`] dedupes local records.
pub fn participants(agree: u32, disagree: u32) -> u32 {
    agree + disagree
}

/// Distinct node ids among recorded votes (a repeated vote of the same node counts once).
pub fn count_participants(voters: &[u64]) -> u32 {
    voters
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u32
}

/// The contract's pending switches for the early (before 600 s) majority seal, mirrored here (all
/// off by default, as in the contract; the node reads them once exposed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MajorityRule {
    /// `mjExcludeSubject` (pending project decision): take the case's own node out of the base.
    pub exclude_subject: bool,
    /// `mjMinBase` (pending, N6): no early seal below this base; 0 = off.
    pub min_base: u32,
    /// `mjIrreversible` (pending, N6): early only if the remaining voters cannot turn the lead.
    pub irreversible: bool,
}

/// The contract's `majorityEarly`: more than half of the base voted (exactly half is not enough),
/// with the pending switches. Turnout never replaces the margin (checked separately).
pub fn majority_early(
    agree: u32,
    disagree: u32,
    population: Option<u32>,
    subject: u32,
    rule: &MajorityRule,
) -> bool {
    let Some(mut base) = population.map(u64::from) else {
        return false;
    };
    if rule.exclude_subject && base >= subject as u64 {
        base -= subject as u64;
    }
    if rule.min_base != 0 && base < rule.min_base as u64 {
        return false;
    }
    let voted = agree as u64 + disagree as u64;
    if voted * 2 <= base {
        return false;
    }
    if rule.irreversible {
        let diff = (agree as u64).abs_diff(disagree as u64);
        let left = base.saturating_sub(voted);
        if diff <= left {
            return false;
        }
    }
    true
}

/// Voting still open at `now` (before opening + 7,200 s).
pub fn voting_open(t: &Tally, now: u64) -> bool {
    now < t.opened_at + MAX_OPEN
}

/// Would this node's vote seal the case at `now` (the contract seals in the transaction that
/// first finds the conditions met, whichever side that vote is for): after it, either side leads
/// by the margin, and either 600 s have passed or more than half of the base has voted (early
/// seal, admission / recovery / report only), and voting has not ended.
pub fn would_decide(t: &Tally, agree: bool, now: u64, rule: &MajorityRule) -> bool {
    let (a, d) = if agree {
        (t.agree + 1, t.disagree)
    } else {
        (t.agree, t.disagree + 1)
    };
    let met = a >= d + t.margin || d >= a + t.margin;
    let early = majority_early(a, d, t.population, t.subject, rule);
    met && (now >= t.opened_at + MIN_OPEN || early) && voting_open(t, now)
}

/// Earliest time any vote could decide the case (same for both sides).
pub fn decidable_from(t: &Tally, _agree: bool) -> u64 {
    t.opened_at + MIN_OPEN
}

/// When to send a vote (project decision 2026-11-09: every proposal can be sealed by anyone through
/// the unified seal entry once 600 s have passed and the threshold is met). Holding votes is no
/// longer needed (the earlier hold-until-600 s candidate is withdrawn): a decided vote goes out at
/// once, which keeps the on-chain count transparent; none after the end (7,200 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteTiming {
    /// Submit now.
    Now,
    /// Voting ended (7,200 s): do not vote.
    Closed,
}

pub fn vote_timing(t: &Tally, _agree: bool, now: u64) -> VoteTiming {
    if voting_open(t, now) {
        VoteTiming::Now
    } else {
        VoteTiming::Closed
    }
}

/// Node-side seal settings. Everything here is a node STRATEGY or a pending project item kept
/// configurable, not a contract rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealStrategy {
    /// Call the unified seal entry for the executor reward. Default off.
    pub enabled: bool,
    /// DECIDED (user 2026-11-09, "允许补封", item 31 for node cases): after 7,200 s the votes are
    /// frozen; anyone may call the unified entry: frozen votes meeting the margin seal (executor
    /// reward paid), otherwise the same entry closes the case as void. Default on.
    pub seal_after_window: bool,
    /// The contract's pending early-majority switches (mirrored; default all off).
    pub majority: MajorityRule,
    /// Strategy choice: do not seal a case this node proposed. Default true.
    pub skip_own_proposal: bool,
    /// Strategy choice: after a lost race (someone else sealed first), do not retry. Default true.
    pub no_retry_after_race_loss: bool,
    /// Executor reward of an online case (wei); decided 0.005 CNET.
    pub online_reward: u128,
    /// PENDING project item 33: report executor reward as a share of the report's pot (bps) and
    /// how it meets "the successful sealer takes the executor reward". Default 700 (7%), kept
    /// configurable.
    pub report_reward_bps: u128,
}

impl Default for SealStrategy {
    fn default() -> Self {
        Self {
            enabled: false,
            seal_after_window: true,
            majority: MajorityRule::default(),
            skip_own_proposal: true,
            no_retry_after_race_loss: true,
            online_reward: EXECUTOR_REWARD,
            report_reward_bps: 700,
        }
    }
}

/// Threshold met on either side.
pub fn threshold_met(t: &Tally) -> bool {
    t.agree >= t.disagree + t.margin || t.disagree >= t.agree + t.margin
}

/// The case can be sealed through the unified entry: threshold met, and either 600 s passed or
/// more than half of the eligible nodes voted; after 7,200 s (frozen votes) only with late sealing.
pub fn seal_ready(t: &Tally, now: u64, s: &SealStrategy) -> bool {
    let time_or_turnout = now >= t.opened_at + MIN_OPEN
        || majority_early(t.agree, t.disagree, t.population, t.subject, &s.majority);
    threshold_met(t) && time_or_turnout && (s.seal_after_window || voting_open(t, now))
}

/// After 7,200 s the votes are frozen: what the unified entry would do (user decision 2026-11-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterWindow {
    /// Voting still open.
    StillOpen,
    /// Frozen votes meet the margin: the entry seals (executor reward paid).
    Seal,
    /// Frozen votes do not: the entry closes the case as void (no reward, no fine, locks freed).
    VoidClose,
}

pub fn after_window(t: &Tally, now: u64) -> AfterWindow {
    if voting_open(t, now) {
        AfterWindow::StillOpen
    } else if threshold_met(t) {
        AfterWindow::Seal
    } else {
        AfterWindow::VoidClose
    }
}

/// Seal for the executor reward? Rewards do not stack per node and case: a node already earning
/// `own_reward` in the case only gains the difference. A losing racer's transaction reverts and
/// still pays gas, discounted by `race_loss_rate_bps`.
pub fn seal_worth_it(
    s: &SealStrategy,
    is_proposer: bool,
    seal_reward: u128,
    own_reward: u128,
    gas: u128,
    gas_price_wei: u128,
    race_loss_rate_bps: u128,
) -> bool {
    if !s.enabled || (is_proposer && s.skip_own_proposal) {
        return false;
    }
    let extra = seal_reward.saturating_sub(own_reward);
    let expected = extra * (10_000 - race_loss_rate_bps.min(10_000)) / 10_000;
    expected > gas.saturating_mul(gas_price_wei)
}

/// Report executor reward under the configured (pending) share.
pub fn report_seal_reward(s: &SealStrategy, pot: u128) -> u128 {
    pot * s.report_reward_bps / 10_000
}

/// After a seal attempt reverted as a lost race: retry only if the strategy says so.
pub fn retry_after_race_loss(s: &SealStrategy, revert_name: &str) -> bool {
    executor_race_lost(revert_name) && !s.no_retry_after_race_loss
}

/// Deterministic per-node stagger in [0, spread) seconds for one case, so nodes running the seal
/// strategy do not all call the seal entry in the same block (only the first one succeeds; the rest
/// revert and count as a lost race: `executor_race_lost`). Derived from the case id and node id.
pub fn stagger(case_id: &[u8; 32], node_id: u64, spread: u64) -> u64 {
    if spread == 0 {
        return 0;
    }
    let mut b = case_id.to_vec();
    b.extend_from_slice(&node_id.to_be_bytes());
    let h = si_crypto::eth::keccak256(&b);
    u64::from_be_bytes(h[..8].try_into().expect("8 bytes")) % spread
}

// ---- first admission after a rejection (project decision 2026-11-09) ----

/// Who "the same applicant" is: pending the node line (main wallet, PGP fingerprint, ...). The
/// endpoint, the request version and the proposer are deliberately NOT part of it, so changing
/// them never bypasses the wait.
pub type ApplicantKey = String;

/// After a valid rejection of a first admission, the same applicant waits a fixed 12 hours from
/// the chain moment the rejection sealed its votes. Returns the time it may apply again, if it
/// still has to wait.
pub fn admission_reapply_at(last_rejected_at: u64, now: u64) -> Option<u64> {
    let at = last_rejected_at.checked_add(OFFLINE_COOLDOWN)?;
    (last_rejected_at != 0 && now < at).then_some(at)
}

/// Rejections seen on chain, by applicant (fed from the contract's events or reads once the node
/// line publishes them).
#[derive(Debug, Clone, Default)]
pub struct RejectionBook {
    last: std::collections::BTreeMap<ApplicantKey, u64>,
}

impl RejectionBook {
    /// Record a rejection sealed at `sealed_at` for this applicant, whatever endpoint, version or
    /// proposer that case had.
    pub fn rejected(&mut self, applicant: &str, sealed_at: u64) {
        let e = self.last.entry(applicant.to_string()).or_insert(0);
        *e = (*e).max(sealed_at);
    }
    pub fn reapply_at(&self, applicant: &str, now: u64) -> Option<u64> {
        admission_reapply_at(*self.last.get(applicant).unwrap_or(&0), now)
    }
}

/// The proposer's review of a first admission: the agree standard, plus no proposal while the
/// applicant is still in its 12-hour wait after a rejection.
pub fn review_admission(
    ballot: &Ballot,
    free_balance: u128,
    applicant_reapply_at: Option<u64>,
) -> ProposeDecision {
    if let Some(until) = applicant_reapply_at {
        return ProposeDecision::ApplicantWaiting { until };
    }
    review(ballot, free_balance)
}

//! Vote pricing and the send loop's decisions (H812E, VOTE-MUST, N6 §H.8.14; Rust line §37,
//! §40). Pure functions; nothing here signs or sends (wiring a real send path is F5, not
//! approved).
//!
//! Rule set: a valid vote is always sent and kept trying until its case expires. No price,
//! daily spend or local threshold stops it. The signer lowers a tip above its cap and signs.
//!
//! - **maxFee target = `base_multiple_percent` x highest base fee + tip** (4x: the vote
//!   survives about 11 full blocks of EIP-1559 rise without a replacement; a 100x jump needs
//!   about 4 replacements). The unused part of maxFee is never charged.
//! - **Leave room for the wallet's other transactions**: geth refuses a transaction when the
//!   balance cannot cover gas limit x maxFee of ALL the account's pending transactions. So the
//!   target is limited to the vote's share, free balance / (gas limit x `shares`), where free
//!   balance = balance minus what the other pending transactions already reserve. Only when
//!   even base fee + tip does not fit the share does the vote take more (up to the whole free
//!   balance), so that it can be mined now; that is flagged.
//! - **Tip**: the fee-history hint, never above the cap, and low enough to leave room for
//!   `reserve_bumps` replacements: geth (CoNET runs Geth 1.17.8) accepts a same-nonce
//!   replacement only if BOTH maxFee and tip rise by at least 10%.
//! - **Pending**: rebroadcast the same transaction every `rebroadcast_secs`, without limit,
//!   until the case expires. Replace only when the base fee has passed the sent maxFee: the
//!   new maxFee follows 4x the latest base fee, re-capped by the free balance at that moment.
//! - **Objective obstacles** (not refusals): the free balance cannot cover base fee + tip, or
//!   a replacement cannot reach +10% (alert, request a top-up; if today's top-up is used, the
//!   next day); no RPC answers (alert, switch RPC, retry); no tip room left (alert, keep
//!   rebroadcasting; mined as soon as the base fee falls back under maxFee).

/// Parameters. Every default is a proposal, PENDING USER CONFIRMATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceCfg {
    /// Tip cap; must equal the signer's `vote_fee.priority_cap_wei`.
    pub tip_cap_wei: u64,
    /// maxFee target = this share of the base fee + tip (400 = 4x).
    pub base_multiple_percent: u64,
    /// The vote's share of the free balance is 1 / `shares`, leaving the rest for the
    /// wallet's other transactions (other votes, markOnline, reportOffline, ...).
    pub shares: u32,
    /// Replacements the first tip leaves room for under the cap (each +10%).
    pub reserve_bumps: u32,
    /// geth's replacement bump (PriceBump), percent.
    pub bump_percent: u64,
    /// Rebroadcast (or reconsider) a pending vote this often (5 CoNET blocks of about 6 s).
    pub rebroadcast_secs: u64,
    /// Stop this long before the case expires (a vote mined after expiry reverts).
    pub expiry_margin_secs: u64,
    /// Alert when the highest reported base fee is more than this share of the lowest.
    pub disagree_percent: u64,
}

impl Default for PriceCfg {
    fn default() -> Self {
        Self {
            tip_cap_wei: 100_000_000,
            base_multiple_percent: 400,
            shares: 4,
            reserve_bumps: 30,
            bump_percent: 10,
            rebroadcast_secs: 30,
            expiry_margin_secs: 60,
            disagree_percent: 200,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    pub max_fee_wei: u64,
    pub tip_wei: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Estimate {
    pub price: Price,
    /// The base fee the price was checked against (the highest reported).
    pub base_fee_wei: u64,
    /// Sources disagree by more than `disagree_percent`: alert.
    pub sources_disagree: bool,
    /// The vote needed more than its share to be minable now: alert (top up).
    pub beyond_share: bool,
}

/// Something outside the vote's validity keeps it from going out now. Alert and retry; never
/// a reason to drop a valid vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Obstacle {
    /// Free balance below gas limit x (base fee + tip): alert, request a top-up, retry.
    Balance { have_wei: u128, need_wei: u128 },
    /// No base fee from any RPC: alert, switch RPC, retry.
    Rpc,
}

fn up(x: u64, percent: u64) -> u64 {
    // ceil(x * (100 + percent) / 100), saturating: always passes geth's floor threshold.
    let v = (x as u128 * (100 + percent) as u128).div_ceil(100);
    v.min(u64::MAX as u128) as u64
}

/// Highest tip that still leaves room for `n` bumps of `percent` under `cap`.
pub fn tip_with_room(cap: u64, percent: u64, n: u32) -> u64 {
    let mut t = cap as u128;
    for _ in 0..n {
        // Inverse of `up`, rounded down, minus 1 for the rounding `up` adds.
        t = (t * 100 / (100 + percent) as u128).saturating_sub(1);
    }
    t as u64
}

fn afford(free_balance_wei: u128, gas_limit: u64) -> u64 {
    (free_balance_wei / gas_limit.max(1) as u128).min(u64::MAX as u128) as u64
}

/// First price for a vote. `base_fees`: latest base fee from each RPC that answered;
/// `free_balance_wei`: balance minus the cost already reserved by this wallet's other pending
/// transactions.
pub fn estimate(
    cfg: &PriceCfg,
    base_fees: &[u64],
    tip_hint_wei: u64,
    gas_limit: u64,
    free_balance_wei: u128,
) -> Result<Estimate, Obstacle> {
    let hi = *base_fees.iter().max().ok_or(Obstacle::Rpc)?;
    let lo = *base_fees.iter().min().ok_or(Obstacle::Rpc)?;
    let sources_disagree = (hi as u128) * 100 > (lo.max(1) as u128) * cfg.disagree_percent as u128;
    let room = tip_with_room(cfg.tip_cap_wei, cfg.bump_percent, cfg.reserve_bumps).max(1);
    let tip = tip_hint_wei.clamp(1, room);
    let (max_fee, beyond_share) = price_within(cfg, hi, tip, gas_limit, free_balance_wei, 0)
        .ok_or_else(|| Obstacle::Balance {
            have_wei: free_balance_wei,
            need_wei: (hi as u128 + tip as u128) * gas_limit as u128,
        })?;
    Ok(Estimate {
        price: Price {
            max_fee_wei: max_fee,
            tip_wei: tip,
        },
        base_fee_wei: hi,
        sources_disagree,
        beyond_share,
    })
}

/// maxFee for base fee `base` and tip `tip`: the 4x target, limited to the vote's share of the
/// free balance, but never below what can be mined now (base + tip) nor below `floor` (the
/// +10% a replacement needs), and never above the whole free balance. None if even the
/// minimum does not fit. Returns (maxFee, took more than the share).
fn price_within(
    cfg: &PriceCfg,
    base: u64,
    tip: u64,
    gas_limit: u64,
    free_balance_wei: u128,
    floor: u64,
) -> Option<(u64, bool)> {
    let target = (base as u128 * cfg.base_multiple_percent as u128 / 100 + tip as u128)
        .min(u64::MAX as u128) as u64;
    let whole = afford(free_balance_wei, gas_limit);
    let share = afford(free_balance_wei / cfg.shares.max(1) as u128, gas_limit);
    let min = (base as u128 + tip as u128).min(u64::MAX as u128) as u64;
    let min = min.max(floor);
    if whole < min {
        return None;
    }
    let max_fee = target.min(share).max(min).min(whole);
    Some((max_fee, max_fee > share))
}

/// Whether to send a vote now. Eligibility first (contract rules, from the vote gate): a vote
/// the contract would refuse is not sent and its reason is recorded. Then the price: an
/// obstacle means alert and retry, never drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Send(Estimate),
    /// Not a valid vote now (cooldown, already voted, no lock capacity, case closed or
    /// expired, ...): do not send, record the reason. Not a price refusal.
    NotEligible(crate::vote_gate::Skip),
    /// Valid vote, objective obstacle: alert, top up or switch RPC, retry.
    Obstacle(Obstacle),
}

pub fn decide(
    gate: Result<(), crate::vote_gate::Skip>,
    price: impl FnOnce() -> Result<Estimate, Obstacle>,
) -> Decision {
    match gate {
        Err(s) => Decision::NotEligible(s),
        Ok(()) => match price() {
            Ok(e) => Decision::Send(e),
            Err(o) => Decision::Obstacle(o),
        },
    }
}

/// Next step for a pending vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Not yet time to look again.
    Wait,
    /// Rebroadcast the same signed transaction (no new signature, no limit on how often).
    Rebroadcast,
    /// Replace with the same nonce at this price (both fields +10% or more).
    Replace(Price),
    /// Priced out and a replacement is not possible now; keep rebroadcasting, alert.
    Obstacle(Obstacle),
    /// No tip room left for a replacement: keep rebroadcasting (mined when the base fee falls
    /// back under maxFee), alert.
    NoTipRoom,
    /// The case expires within the margin: stop and record (the vote would revert).
    CaseExpiring,
}

/// What to do with a vote sent at `sent_at` with `sent`, at `now`. `free_balance_wei` counts
/// this transaction's own reservation as free (a replacement takes its place).
#[allow(clippy::too_many_arguments)]
pub fn on_pending(
    cfg: &PriceCfg,
    sent: Price,
    sent_at: u64,
    now: u64,
    latest_base_fee: u64,
    free_balance_wei: u128,
    gas_limit: u64,
    case_expires_at: u64,
) -> Step {
    if now + cfg.expiry_margin_secs >= case_expires_at {
        return Step::CaseExpiring;
    }
    if now.saturating_sub(sent_at) < cfg.rebroadcast_secs {
        return Step::Wait;
    }
    // Still includable: the base fee is under maxFee. Keep it alive.
    if latest_base_fee < sent.max_fee_wei {
        return Step::Rebroadcast;
    }
    // Priced out. A replacement must raise both fields by 10%; maxFee follows 4x the latest
    // base fee, re-capped by the free balance now (N6 §H.8.14 items 2, 4).
    let tip = up(sent.tip_wei, cfg.bump_percent);
    if tip > cfg.tip_cap_wei {
        return Step::NoTipRoom;
    }
    let floor = up(sent.max_fee_wei, cfg.bump_percent);
    match price_within(
        cfg,
        latest_base_fee,
        tip,
        gas_limit,
        free_balance_wei,
        floor,
    ) {
        Some((max_fee, _)) => Step::Replace(Price {
            max_fee_wei: max_fee,
            tip_wei: tip,
        }),
        None => Step::Obstacle(Obstacle::Balance {
            have_wei: free_balance_wei,
            need_wei: floor.max(latest_base_fee.saturating_add(tip)) as u128 * gas_limit as u128,
        }),
    }
}

/// geth's replacement rule: both maxFee and tip at least `price_bump` percent above the old
/// (geth compares against floor(old * (100 + bump) / 100)).
pub fn geth_accepts_replacement(old: Price, new: Price, price_bump: u64) -> bool {
    let need = |x: u64| x as u128 * (100 + price_bump) as u128 / 100;
    new.max_fee_wei as u128 >= need(old.max_fee_wei) && new.tip_wei as u128 >= need(old.tip_wei)
}

//! Vote pricing and the send loop's decisions (H812E, VOTE-MUST, Rust line §35/§37). Pure
//! functions; nothing here signs or sends (wiring a real send path is F5, not approved).
//!
//! Rule set: a valid vote is always sent and kept trying until its case expires. No price,
//! daily spend or local threshold stops it. The signer lowers a tip above its cap and signs.
//!
//! - **maxFee = what the wallet can pre-pay**: free balance / gas limit, where free balance is
//!   the balance minus what the other pending transactions of this wallet already reserve
//!   (geth refuses a transaction whose cost, together with the account's other pending ones,
//!   exceeds the balance). Under EIP-1559 the unused part of maxFee is never charged, so the
//!   highest affordable maxFee costs nothing extra and survives any base-fee rise the wallet
//!   can pay for, with no replacement needed.
//! - **Tip**: the fee-history hint, never above the cap, and low enough to leave room for
//!   `reserve_bumps` replacements: geth (CoNET runs Geth 1.17.8) accepts a same-nonce
//!   replacement only if BOTH maxFee and tip rise by at least 10%.
//! - **Pending**: rebroadcast the same transaction every `rebroadcast_secs`, without limit,
//!   until the case expires. Replace only when the base fee has passed the sent maxFee and the
//!   wallet can now pay more (for example after a top-up).
//! - **Objective obstacles** (not refusals): the free balance cannot cover gas limit x current
//!   base fee (alert, request a top-up, continue when it arrives); no RPC answers (alert,
//!   switch RPC, retry); no tip room left for a replacement (alert, keep rebroadcasting, the
//!   pending transaction is mined as soon as the base fee falls back under its maxFee).

/// Parameters. Every default is a proposal, PENDING USER CONFIRMATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceCfg {
    /// Tip cap; must equal the signer's `vote_fee.priority_cap_wei`.
    pub tip_cap_wei: u64,
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
            reserve_bumps: 20,
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
    let max_fee = afford(free_balance_wei, gas_limit);
    let need = hi as u128 + tip as u128;
    if (max_fee as u128) < need {
        return Err(Obstacle::Balance {
            have_wei: free_balance_wei,
            need_wei: need * gas_limit as u128,
        });
    }
    Ok(Estimate {
        price: Price {
            max_fee_wei: max_fee,
            tip_wei: tip,
        },
        base_fee_wei: hi,
        sources_disagree,
    })
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
    // Priced out. A replacement must raise both fields by 10%.
    let tip = up(sent.tip_wei, cfg.bump_percent);
    if tip > cfg.tip_cap_wei {
        return Step::NoTipRoom;
    }
    let need = up(sent.max_fee_wei, cfg.bump_percent).max(latest_base_fee.saturating_add(tip));
    let can = afford(free_balance_wei, gas_limit);
    if can < need {
        return Step::Obstacle(Obstacle::Balance {
            have_wei: free_balance_wei,
            need_wei: need as u128 * gas_limit as u128,
        });
    }
    Step::Replace(Price {
        max_fee_wei: can,
        tip_wei: tip,
    })
}

/// geth's replacement rule: both maxFee and tip at least `price_bump` percent above the old
/// (geth compares against floor(old * (100 + bump) / 100)).
pub fn geth_accepts_replacement(old: Price, new: Price, price_bump: u64) -> bool {
    let need = |x: u64| x as u128 * (100 + price_bump) as u128 / 100;
    new.max_fee_wei as u128 >= need(old.max_fee_wei) && new.tip_wei as u128 >= need(old.tip_wei)
}

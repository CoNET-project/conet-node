//! Vote pricing (H812E, Rust line §35): how conet-node prices a `voteReport` and when it replaces
//! a stuck one with the same nonce. Pure functions; nothing here signs or sends (F5 is not
//! approved). The signer never refuses a vote for its price; it only lowers a tip above its cap.
//!
//! - maxFee = `base_multiple_percent` x highest reported base fee + tip, limited by
//!   balance / gas limit (a node rejects a transaction it cannot pre-pay). What a vote really
//!   costs is gas used x min(maxFee, baseFee + tip), so a generous maxFee costs nothing extra.
//! - Replacement: geth's txpool (CoNET runs Geth 1.17.8) accepts a same-nonce replacement only
//!   if BOTH maxFee and the tip rise by at least `PriceBump` (10%). So the first tip leaves room
//!   for `max_replacements` bumps under the cap, and every bump raises both by `bump_percent`.
//!   A bump that would push the tip over the cap is not made: the vote waits (and alerts), it is
//!   never dropped for its price.

/// Pricing parameters. Every default is a proposal, PENDING USER CONFIRMATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceCfg {
    /// Tip cap; must equal the signer's `vote_fee.priority_cap_wei`.
    pub tip_cap_wei: u64,
    /// First maxFee = this share of the base fee + tip (400 = 4x: about 11 full blocks of
    /// EIP-1559 increase before a replacement is needed).
    pub base_multiple_percent: u64,
    /// Raise per replacement; geth needs at least 10, 12 leaves rounding room.
    pub bump_percent: u64,
    /// Replacements per vote.
    pub max_replacements: u32,
    /// Replace when not mined after this long (5 CoNET blocks of about 6 s).
    pub replace_after_secs: u64,
    /// Alert when the highest reported base fee is more than this share of the lowest.
    pub disagree_percent: u64,
}

impl Default for PriceCfg {
    fn default() -> Self {
        Self {
            tip_cap_wei: 100_000_000,
            base_multiple_percent: 400,
            bump_percent: 12,
            max_replacements: 5,
            replace_after_secs: 30,
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
    /// The base fee the price was built on (the highest reported).
    pub base_fee_wei: u64,
    /// Sources disagree by more than `disagree_percent`: alert.
    pub sources_disagree: bool,
    /// maxFee was lowered to balance / gas limit: alert (top up).
    pub balance_limited: bool,
}

fn up(x: u64, percent: u64) -> u64 {
    // ceil(x * (100 + percent) / 100), saturating.
    let v = (x as u128 * (100 + percent) as u128).div_ceil(100);
    v.min(u64::MAX as u128) as u64
}

/// Highest tip that still leaves room for `n` bumps of `percent` under `cap`.
pub fn tip_with_room(cap: u64, percent: u64, n: u32) -> u64 {
    let mut t = cap;
    for _ in 0..n {
        t = (t as u128 * 100 / (100 + percent) as u128) as u64;
    }
    // Rounding up in `up` may add 1 per bump; keep that margin.
    t.saturating_sub(n as u64)
}

/// First price for a vote. `base_fees`: the latest base fee from each RPC source (at least
/// one); `tip_hint`: e.g. the median of eth_feeHistory rewards; `balance_wei`: the node wallet's
/// balance, if known. Returns None with no source.
pub fn estimate(
    cfg: &PriceCfg,
    base_fees: &[u64],
    tip_hint_wei: u64,
    gas_limit: u64,
    balance_wei: Option<u128>,
) -> Option<Estimate> {
    let hi = *base_fees.iter().max()?;
    let lo = *base_fees.iter().min()?;
    let sources_disagree = (hi as u128) * 100 > (lo.max(1) as u128) * cfg.disagree_percent as u128;
    let room = tip_with_room(cfg.tip_cap_wei, cfg.bump_percent, cfg.max_replacements);
    let mut tip = tip_hint_wei.min(room).max(1);
    let mut max_fee = ((hi as u128 * cfg.base_multiple_percent as u128 / 100) + tip as u128)
        .min(u64::MAX as u128) as u64;
    let mut balance_limited = false;
    if let Some(b) = balance_wei {
        let afford = (b / gas_limit.max(1) as u128).min(u64::MAX as u128) as u64;
        if max_fee > afford {
            max_fee = afford;
            tip = tip.min(max_fee);
            balance_limited = true;
        }
    }
    Some(Estimate {
        price: Price {
            max_fee_wei: max_fee,
            tip_wei: tip,
        },
        base_fee_wei: hi,
        sources_disagree,
        balance_limited,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replace {
    /// Not yet due.
    Wait,
    /// Send this with the same nonce.
    Bump(Price),
    /// No further replacement is possible (count reached or the tip would pass its cap):
    /// keep waiting for the pending one, and alert. The vote is not dropped.
    Hold,
}

/// What to do with a vote sent at `sent_at` with `prev`, after `done` replacements, at `now`.
/// `latest_base_fee` lets a bump also follow a base fee that rose past the old maxFee.
pub fn replacement(
    cfg: &PriceCfg,
    prev: Price,
    done: u32,
    sent_at: u64,
    now: u64,
    latest_base_fee: u64,
) -> Replace {
    if now.saturating_sub(sent_at) < cfg.replace_after_secs {
        return Replace::Wait;
    }
    if done >= cfg.max_replacements {
        return Replace::Hold;
    }
    let tip = up(prev.tip_wei, cfg.bump_percent);
    if tip > cfg.tip_cap_wei {
        return Replace::Hold;
    }
    let follow = ((latest_base_fee as u128 * cfg.base_multiple_percent as u128 / 100) + tip as u128)
        .min(u64::MAX as u128) as u64;
    let max_fee = up(prev.max_fee_wei, cfg.bump_percent).max(follow);
    Replace::Bump(Price {
        max_fee_wei: max_fee,
        tip_wei: tip,
    })
}

/// geth's replacement rule: both maxFee and tip at least `price_bump` percent above the old.
pub fn geth_accepts_replacement(old: Price, new: Price, price_bump: u64) -> bool {
    let need = |x: u64| (x as u128 * (100 + price_bump) as u128).div_ceil(100);
    new.max_fee_wei as u128 >= need(old.max_fee_wei) && new.tip_wei as u128 >= need(old.tip_wei)
}

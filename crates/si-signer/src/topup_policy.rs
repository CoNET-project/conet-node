//! Main-wallet `topUp(nodeId)` signing for AUTO-TOPUP. 用户已批准（2026-11-09）: user approval
//! "批准该条目", exactly this entry and nothing else (other SignTx entries, e.g. votes, are
//! approved separately). Revised after N6's pre-review the same day (rolling 24 hours,
//! replacements bound to the signer's own record, no zero-value replacement).
//!
//! The signer builds the transaction itself: `to` = the configured registry, `data` =
//! `topUp(own nodeId)`, type 2, the configured chain id. The caller (conet-node) gives only nonce,
//! fees, gas limit, value, and what it read from the chain (missing stake, wallet balance).
//! Rules (N6 §H.8.24 14.1-14.3 as approved):
//! - value > 0 always (the contract's topUp reverts on 0), <= the stated missing stake (which can
//!   only lower the value), <= the per-transaction cap, and within the per-term budget;
//! - a replacement must match a transaction in the signer's OWN ledger: same nonce, value not above
//!   the original, both fees raised by at least 10% (geth); conet-node's claim alone counts for
//!   nothing. Any signed version of a nonce may still be mined, so the ledger keeps the HIGHEST
//!   value ever signed for that nonce (N6 second review: lowering the booking let a hijacked
//!   conet-node exceed the term budget with an unbroadcast cheap replacement);
//! - the ledger file must exist and be private to the signer account (no group / other bits): a
//!   deleted ledger is never silently restarted from zero; the operator recreates it with
//!   `conet-signer topup-ledger-init` after checking;
//! - only inside the window before the term end, computed by the signer from its own clock and the
//!   configured first term end and term length;
//! - at most `daily_count` transactions and `daily_value` in any rolling 24 hours of the signer's
//!   own clock (not the calendar day: no 4 in a row across midnight);
//! - maxFeePerGas and the tip are capped absolutely (N6 third review): without caps a hijacked
//!   conet-node could burn the whole wallet as fees (or, with a block producer, take it);
//!   a +10% replacement may not pass the caps either;
//! - after signing the wallet keeps a gas reserve. RESIDUAL RISK: the balance is the one conet-node
//!   states; a hijacked conet-node can overstate it, and the signer, offline by design, cannot
//!   check it.
//! - the ledger is written to disk (temp file, fsync, rename) before the signature is released.
use crate::tx1559::{parse_address, Tx1559};
use serde::{Deserialize, Serialize};
use si_crypto::eth::{keccak256, EthKey};
use std::path::PathBuf;

mod dec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// `--topup-config <json>`. Amounts in wei as decimal strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopUpConfig {
    pub registry: String,
    pub chain_id: u64,
    pub own_node_id: u64,
    #[serde(with = "dec")]
    pub per_tx_cap: u128,
    #[serde(with = "dec")]
    pub term_budget: u128,
    pub daily_count: u32,
    #[serde(with = "dec")]
    pub daily_value: u128,
    /// First term end and term length (seconds), configured at provisioning.
    pub first_term_end: u64,
    pub term_length: u64,
    /// Window before each term end (seconds); approved: 7 days.
    pub window: u64,
    /// Wei left in the wallet after value + gas_limit x maxFee.
    #[serde(with = "dec")]
    pub gas_reserve: u128,
    pub max_gas_limit: u64,
    /// Absolute cap on maxFeePerGas (wei).
    #[serde(with = "dec")]
    pub max_fee_cap: u128,
    /// Absolute cap on maxPriorityFeePerGas (wei); the vote tip cap is 1e8.
    #[serde(with = "dec")]
    pub tip_cap: u128,
}

impl TopUpConfig {
    /// The term end the signer's clock is in (first_term_end + k x term_length).
    pub fn current_term_end(&self, clock: u64) -> u64 {
        if clock < self.first_term_end || self.term_length == 0 {
            return self.first_term_end;
        }
        let k = (clock - self.first_term_end) / self.term_length + 1;
        self.first_term_end + k * self.term_length
    }

    pub fn calldata(&self) -> Vec<u8> {
        let mut d = topup_selector().to_vec();
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&self.own_node_id.to_be_bytes());
        d.extend_from_slice(&w);
        d
    }
}

/// What conet-node asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopUpRequest {
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_wei: u128,
    pub priority_fee_wei: u128,
    pub value: u128,
    /// `minStakeAt(termEnd) - stakeOf(nodeId)` as conet-node read it (can only lower the value).
    pub stated_missing: u128,
    /// Wallet balance as conet-node read it, before this transaction.
    pub stated_wallet: u128,
    /// Set when this replaces our own pending top-up at the same nonce.
    pub replaces_nonce: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopUpRefuse {
    /// A replacement above the value the signer booked for that nonce.
    AboveReplaced,
    /// A replacement that does not raise both fees by at least 10%.
    ReplaceFeeBump,
    /// maxFeePerGas or the tip above its absolute cap.
    FeeCap,
    /// No ledger file, or one readable / writable by others: refused until the operator acts.
    LedgerMissing,
    LedgerPerms,
    NotType2,
    WrongTo,
    Creation,
    Selector,
    BadCalldata,
    NotOwnNode,
    ZeroValue,
    AboveMissing,
    AboveCap,
    AboveBudget,
    OutsideWindow,
    DailyCount,
    DailyValue,
    GasReserve,
    GasLimit,
    BadFees,
    ReplaceUnknown,
    State(String),
}

impl std::fmt::Display for TopUpRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "topup:{self:?}")
    }
}

pub fn topup_selector() -> [u8; 4] {
    let h = keccak256(b"topUp(uint256)");
    [h[0], h[1], h[2], h[3]]
}

/// Byte check of a built transaction (defence in depth: the builder can only produce these).
pub fn check_tx_bytes(
    cfg: &TopUpConfig,
    tx_type: u8,
    to: Option<&str>,
    data: &[u8],
) -> Result<(), TopUpRefuse> {
    if tx_type != 2 {
        return Err(TopUpRefuse::NotType2);
    }
    let to = to.ok_or(TopUpRefuse::Creation)?;
    if !to.eq_ignore_ascii_case(&cfg.registry) {
        return Err(TopUpRefuse::WrongTo);
    }
    if data.len() < 4 || data[..4] != topup_selector() {
        return Err(TopUpRefuse::Selector);
    }
    if data.len() != 4 + 32 {
        return Err(TopUpRefuse::BadCalldata);
    }
    let id = &data[4..];
    if id[..24].iter().any(|&b| b != 0)
        || u64::from_be_bytes(id[24..].try_into().expect("8 bytes")) != cfg.own_node_id
    {
        return Err(TopUpRefuse::NotOwnNode);
    }
    Ok(())
}

/// One signed top-up as booked by the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Booked {
    /// Signer clock when first signed (replacements keep it).
    pub at: u64,
    pub nonce: u64,
    /// Highest value ever signed for this nonce (any version may be mined).
    #[serde(with = "dec")]
    pub value: u128,
    /// The term end it was signed for.
    pub term_end: u64,
    /// Fees of the latest signed version (a replacement must exceed them by 10%).
    #[serde(with = "dec")]
    pub max_fee: u128,
    #[serde(with = "dec")]
    pub tip: u128,
}

/// Persistent ledger: the top-ups signed in the current term (with their time, for the rolling
/// 24-hour caps) and the term they belong to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerState {
    pub term_end: u64,
    pub booked: Vec<Booked>,
}

impl LedgerState {
    /// Keep what still matters: this term's entries (budget, replacements) and the last 24 hours
    /// (daily caps).
    fn roll(&mut self, term_end: u64, clock: u64) {
        self.term_end = term_end;
        self.booked
            .retain(|b| b.term_end == term_end || b.at + 86_400 > clock);
    }
    /// Count and value signed in the 24 hours before `clock`.
    pub fn last_24h(&self, clock: u64) -> (u32, u128) {
        self.booked
            .iter()
            .filter(|b| b.at + 86_400 > clock)
            .fold((0, 0), |(n, v), b| (n + 1, v + b.value))
    }
    /// Value booked for the current term.
    pub fn term_value(&self) -> u128 {
        self.booked
            .iter()
            .filter(|b| b.term_end == self.term_end)
            .map(|b| b.value)
            .sum()
    }
    /// Our booked transaction at this nonce in the current term.
    fn find(&self, nonce: u64) -> Option<usize> {
        self.booked
            .iter()
            .position(|b| b.nonce == nonce && b.term_end == self.term_end)
    }
}

/// All rules against a ledger snapshot at `clock`; returns the ledger after booking.
pub fn check(
    cfg: &TopUpConfig,
    req: &TopUpRequest,
    ledger: &LedgerState,
    clock: u64,
) -> Result<LedgerState, TopUpRefuse> {
    check_tx_bytes(cfg, 2, Some(&cfg.registry), &cfg.calldata())?;
    if req.value == 0 {
        return Err(TopUpRefuse::ZeroValue);
    }
    if req.value > req.stated_missing {
        return Err(TopUpRefuse::AboveMissing);
    }
    if req.value > cfg.per_tx_cap {
        return Err(TopUpRefuse::AboveCap);
    }
    let end = cfg.current_term_end(clock);
    if clock >= end || clock + cfg.window < end {
        return Err(TopUpRefuse::OutsideWindow);
    }
    if req.gas_limit == 0 || req.gas_limit > cfg.max_gas_limit {
        return Err(TopUpRefuse::GasLimit);
    }
    if req.priority_fee_wei > req.max_fee_wei || req.max_fee_wei == 0 {
        return Err(TopUpRefuse::BadFees);
    }
    if req.max_fee_wei > cfg.max_fee_cap || req.priority_fee_wei > cfg.tip_cap {
        return Err(TopUpRefuse::FeeCap);
    }
    let gas = (req.gas_limit as u128).saturating_mul(req.max_fee_wei);
    if req.stated_wallet
        < req
            .value
            .saturating_add(gas)
            .saturating_add(cfg.gas_reserve)
    {
        return Err(TopUpRefuse::GasReserve);
    }
    let mut l = ledger.clone();
    l.roll(end, clock);
    match req.replaces_nonce {
        Some(n) => {
            // Must be ours: same nonce, booked by this signer in this term, value not above it.
            let i = match l.find(n) {
                Some(i) if n == req.nonce => i,
                _ => return Err(TopUpRefuse::ReplaceUnknown),
            };
            let b = &mut l.booked[i];
            if req.value > b.value {
                return Err(TopUpRefuse::AboveReplaced);
            }
            let bump = |old: u128| old + old.div_ceil(10);
            if req.max_fee_wei < bump(b.max_fee) || req.priority_fee_wei < bump(b.tip) {
                return Err(TopUpRefuse::ReplaceFeeBump);
            }
            // Booked value stays the highest version (the earlier one may still be mined).
            b.max_fee = req.max_fee_wei;
            b.tip = req.priority_fee_wei;
        }
        None => {
            if l.find(req.nonce).is_some() {
                // A second, different top-up at a nonce already used by ours: only as a replacement.
                return Err(TopUpRefuse::ReplaceUnknown);
            }
            let (n, v) = l.last_24h(clock);
            if n >= cfg.daily_count {
                return Err(TopUpRefuse::DailyCount);
            }
            if v.saturating_add(req.value) > cfg.daily_value {
                return Err(TopUpRefuse::DailyValue);
            }
            if l.term_value().saturating_add(req.value) > cfg.term_budget {
                return Err(TopUpRefuse::AboveBudget);
            }
            l.booked.push(Booked {
                at: clock,
                nonce: req.nonce,
                value: req.value,
                term_end: end,
                max_fee: req.max_fee_wei,
                tip: req.priority_fee_wei,
            });
        }
    }
    Ok(l)
}

/// The ledger on disk.
pub struct TopUpLedger {
    path: PathBuf,
    pub state: LedgerState,
}

impl TopUpLedger {
    /// Open the existing ledger. A missing file or one open to group / others is refused: the
    /// count must never silently restart from zero.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TopUpRefuse> {
        let path = path.into();
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(TopUpRefuse::LedgerMissing)
            }
            Err(e) => return Err(TopUpRefuse::State(e.to_string())),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(TopUpRefuse::LedgerPerms);
            }
        }
        let b = std::fs::read(&path).map_err(|e| TopUpRefuse::State(e.to_string()))?;
        let state =
            serde_json::from_slice(&b).map_err(|e| TopUpRefuse::State(format!("ledger: {e}")))?;
        Ok(Self { path, state })
    }

    /// Create a new, empty ledger (mode 0600); refuses to overwrite an existing file. Run by the
    /// operator (`conet-signer topup-ledger-init`), never automatically.
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, String> {
        use std::io::Write;
        let path = path.into();
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&path).map_err(|e| format!("topup ledger: {e}"))?;
        let state = LedgerState::default();
        f.write_all(&serde_json::to_vec(&state).expect("serializable"))
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("topup ledger: {e}"))?;
        Ok(Self { path, state })
    }

    fn write(&self, s: &LedgerState) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("tmp");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(&serde_json::to_vec(s).expect("serializable"))?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Check, book (written to disk first), then build and sign. Returns the raw transaction.
    pub fn sign(
        &mut self,
        cfg: &TopUpConfig,
        key: &EthKey,
        req: &TopUpRequest,
        clock: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), TopUpRefuse> {
        let next = check(cfg, req, &self.state, clock)?;
        let tx = Tx1559 {
            chain_id: cfg.chain_id,
            nonce: req.nonce,
            max_priority_fee_per_gas: req.priority_fee_wei,
            max_fee_per_gas: req.max_fee_wei,
            gas_limit: req.gas_limit,
            to: parse_address(&cfg.registry).map_err(TopUpRefuse::State)?,
            value: req.value,
            data: cfg.calldata(),
        };
        self.write(&next)
            .map_err(|e| TopUpRefuse::State(e.to_string()))?;
        self.state = next;
        tx.sign(key).map_err(TopUpRefuse::State)
    }
}

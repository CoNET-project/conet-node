//! Main-wallet `topUp(nodeId)` signing for AUTO-TOPUP. APPROVED by the user on 2026-11-09
//! ("批准该条目"), exactly this entry and nothing else (other SignTx entries, e.g. votes, are
//! approved separately).
//!
//! The signer builds the transaction itself: `to` = the configured registry, `data` =
//! `topUp(own nodeId)`, type 2, the configured chain id. The caller (conet-node) gives only nonce,
//! fees, gas limit, value, and what it read from the chain (missing stake, wallet balance).
//! Rules (N6 §H.8.24 14.1-14.3 as approved):
//! - value > 0 (0 only as a same-nonce replacement of our own pending top-up), <= the stated
//!   missing stake (which can only lower the value), <= the per-transaction cap, and within the
//!   per-term budget;
//! - only inside the window before the term end, computed by the signer from its own clock and the
//!   configured first term end and term length;
//! - at most `daily_count` transactions and `daily_value` per UTC day;
//! - after signing the wallet keeps a gas reserve (balance as stated by conet-node: the signer
//!   cannot read the chain);
//! - the ledger is written to disk (temp file, fsync, rename) before the signature is released.
use crate::tx1559::{parse_address, Tx1559};
use serde::{Deserialize, Serialize};
use si_crypto::eth::{keccak256, EthKey};
use std::collections::BTreeMap;
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

/// Persistent ledger: today's count and value, this term's value, and the value booked per nonce
/// (so a same-nonce replacement books only the difference).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerState {
    pub day: u64,
    pub day_count: u32,
    #[serde(with = "dec")]
    pub day_value: u128,
    pub term_end: u64,
    #[serde(with = "dec")]
    pub term_value: u128,
    pub booked: BTreeMap<u64, String>,
}

impl LedgerState {
    fn roll(&mut self, day: u64, term_end: u64) {
        if self.day != day {
            self.day = day;
            self.day_count = 0;
            self.day_value = 0;
        }
        if self.term_end != term_end {
            self.term_end = term_end;
            self.term_value = 0;
            self.booked.clear();
        }
    }
    fn booked(&self, nonce: u64) -> Option<u128> {
        self.booked.get(&nonce).and_then(|v| v.parse().ok())
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
    if req.value == 0 && req.replaces_nonce.is_none() {
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
    l.roll(clock / 86_400, end);
    let previous = match req.replaces_nonce {
        Some(n) => {
            if n != req.nonce {
                return Err(TopUpRefuse::ReplaceUnknown);
            }
            Some(l.booked(n).ok_or(TopUpRefuse::ReplaceUnknown)?)
        }
        None => {
            if l.booked(req.nonce).is_some() {
                // A second, different top-up at a nonce already used by ours: only as a replacement.
                return Err(TopUpRefuse::ReplaceUnknown);
            }
            None
        }
    };
    let prev = previous.unwrap_or(0);
    let add = req.value.saturating_sub(prev);
    if previous.is_none() && l.day_count >= cfg.daily_count {
        return Err(TopUpRefuse::DailyCount);
    }
    if l.day_value.saturating_add(add) > cfg.daily_value {
        return Err(TopUpRefuse::DailyValue);
    }
    if l.term_value.saturating_add(add) > cfg.term_budget {
        return Err(TopUpRefuse::AboveBudget);
    }
    if previous.is_none() {
        l.day_count += 1;
    }
    l.day_value = l.day_value.saturating_add(add);
    l.term_value = (l.term_value + req.value).saturating_sub(prev);
    l.booked.insert(req.nonce, req.value.to_string());
    Ok(l)
}

/// The ledger on disk.
pub struct TopUpLedger {
    path: PathBuf,
    pub state: LedgerState,
}

impl TopUpLedger {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let state = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("topup ledger: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => LedgerState::default(),
            Err(e) => return Err(format!("topup ledger: {e}")),
        };
        Ok(Self { path, state })
    }

    fn write(&self, s: &LedgerState) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
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

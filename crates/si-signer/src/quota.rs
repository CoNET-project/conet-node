//! Quota ledger for registry-wallet actions (N6 §H.8.3–H.8.6, Rust line §31).
//!
//! Pure bookkeeping: it signs nothing and holds no key. The signer asks it before an operation;
//! a refusal means the operation is not signed. Today only `SignAnchorReceipt` (F3) uses it.
//! The transaction actions (voteReport, markOnline, ...) are ledger entries only: there is no
//! `SignTx` role yet, and adding one needs user approval (H8-1, H8-2, H8-7).
//!
//! What it enforces, all as parameters (defaults = N6 proposals, PENDING USER APPROVAL):
//! - daily counts per bucket (UTC day) for markOnline, finalizeReport, anchor submissions and
//!   anchor receipts;
//! - `voteReport` (agree and disagree, the deciding vote included) has NO daily count and NO
//!   spend cap (operator 2026-11-08, H812B; user 2026-11-08, "投票不受花费上限约束", H812C): its
//!   own uncapped spend class (recorded only) and its own in-flight lane;
//! - `reportOffline` has NO daily count of any kind (operator decision H8-12, 2026-11-08):
//!   its own uncapped spend class and its own in-flight lane;
//! - so no other limit can hold a vote or a report back. One vote per case, the per-case lock
//!   and the 7-day cooldown are contract rules, checked by `conet-node`'s vote gate, not here;
//! - per-action gas ceiling; `voteReport` and `finalizeReport` may not go below 6,000,000
//!   (a deciding vote settles the first batch in the same transaction);
//! - daily spend per capped class (upkeep = markOnline + finalizeReport / anchor net of
//!   reimbursements / total of those two; values pending, H8-13): an in-flight transaction
//!   reserves gas ceiling x maxFee, a receipt replaces that with the real cost;
//! - in-flight lanes (other / vote / report): concurrency bounds only, a settled or cancelled
//!   transaction frees its slot at once, nothing resets by day; maxFee cap (all transactions);
//! - a warning once per bucket per day at the warn threshold.
//!
//! State is written to disk (temp file, fsync, rename) before an operation is allowed, so a
//! restart does not reset counts. A state file that does not parse, or has another version,
//! puts the ledger in a broken state that refuses everything until an operator looks at it.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const STATE_VERSION: u32 = 1;
/// Floor for `voteReport` / `finalizeReport` gas ceilings (node line, 2026-11-08).
pub const DECIDING_VOTE_GAS_FLOOR: u64 = 6_000_000;
/// maxFee may never be configured above 1 gwei (H8-7).
pub const MAX_FEE_HARD_CAP_WEI: u64 = 1_000_000_000;
/// reportOffline default gas ceiling: local measurement 256,487 x 1.5 (node line, 2026-11-08).
/// Re-measure on a CoNET fork before deployment.
pub const REPORT_OFFLINE_GAS_DEFAULT: u64 = 384_731;
const DAY: u64 = 86_400;

/// Actions the ledger knows. Anything else is refused as `unknown_selector`.
pub const A_VOTE_AGREE: &str = "voteReport.agree";
pub const A_VOTE_DISAGREE: &str = "voteReport.disagree";
pub const A_MARK_ONLINE: &str = "markOnline";
pub const A_FINALIZE: &str = "finalizeReport";
pub const A_SET_ONLINE: &str = "setOnline";
pub const A_EXTEND_ONLINE: &str = "extendOnline";
pub const A_REPORT: &str = "reportOffline";
pub const A_ANCHOR_RECEIPT: &str = "anchorReceipt";

/// Count buckets. setOnline and extendOnline share one. `voteReport` and `reportOffline` have none.
pub const B_MARK_ONLINE: &str = "markOnline";
pub const B_FINALIZE: &str = "finalizeReport";
pub const B_ANCHOR_TX: &str = "setOnline+extendOnline";
pub const B_ANCHOR_RECEIPT: &str = "anchorReceipt";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpendClass {
    /// Not reimbursed, capped (values pending, H8-13): markOnline, finalizeReport.
    Upkeep,
    /// `voteReport`: recorded for monitoring, never capped (H812C).
    Ballot,
    /// `reportOffline`: recorded for monitoring, never capped (H8-12).
    Report,
    /// Anchor submissions, reimbursed by the subsidy pool; counted net.
    Anchor,
}

struct Action {
    buckets: &'static [&'static str],
    /// None = a signature, not a transaction (no gas, no spend, not in flight).
    class: Option<SpendClass>,
}

fn action(name: &str) -> Option<Action> {
    use SpendClass::*;
    let a = |buckets, class| Some(Action { buckets, class });
    match name {
        // No bucket: votes have no daily count (H812B).
        A_VOTE_AGREE | A_VOTE_DISAGREE => a(&[], Some(Ballot)),
        A_MARK_ONLINE => a(&[B_MARK_ONLINE], Some(Upkeep)),
        A_FINALIZE => a(&[B_FINALIZE], Some(Upkeep)),
        A_SET_ONLINE | A_EXTEND_ONLINE => a(&[B_ANCHOR_TX], Some(Anchor)),
        // No bucket: reports have no daily count (H8-12).
        A_REPORT => a(&[], Some(Report)),
        A_ANCHOR_RECEIPT => a(&[B_ANCHOR_RECEIPT], None),
        _ => None,
    }
}

/// Ledger parameters. Every default is an N6 proposal and is PENDING USER APPROVAL.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    /// Free text for operators (e.g. "defaults pending user approval"); ignored.
    #[serde(default, rename = "_note", skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Daily count per bucket. A bucket that is absent refuses its actions (`not_configured`).
    pub daily: BTreeMap<String, u32>,
    /// Gas ceiling per transaction action. An absent action is refused (`gas_ceiling_unset`).
    pub gas_ceiling: BTreeMap<String, u64>,
    /// markOnline + finalizeReport per day (pending, H8-13). Votes are not in it (H812C); a
    /// config that tries to cap votes does not start (unknown field).
    pub spend_upkeep_wei: u64,
    pub spend_anchor_net_wei: u64,
    pub spend_total_wei: u64,
    pub max_fee_wei: u64,
    pub max_inflight: u32,
    /// Warn once per bucket and day when a count reaches this share of its cap.
    pub warn_percent: u8,
    /// In-flight lane for `reportOffline`, apart from `max_inflight` (suggested, pending).
    /// A concurrency bound only: settled reports free their slot at once; there is no daily count.
    pub max_inflight_report: u32,
    /// In-flight lane for `voteReport` (suggested, pending). A concurrency bound only.
    pub max_inflight_vote: u32,
}

impl Default for QuotaConfig {
    /// N6 proposals (H8-2, H8-7), PENDING USER APPROVAL.
    /// `reportOffline` has no daily count (H8-12, decided); its gas ceiling defaults to the
    /// node line's local measurement x 1.5 (re-measure on a CoNET fork before deployment).
    fn default() -> Self {
        let daily = [
            (B_MARK_ONLINE, 20),
            (B_FINALIZE, 50),
            (B_ANCHOR_TX, 500),
            (B_ANCHOR_RECEIPT, 1_000),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        // voteReport / finalizeReport: the 6,000,000 floor covers the measured worst case x 1.5
        // (deciding vote 3,857,848 -> 5,786,772; finalize 3,781,011 -> 5,671,517).
        // reportOffline: local measurement x 1.5 (256,487 -> 384,731), node line 2026-11-08;
        // re-measure on a CoNET fork before deployment. markOnline / setOnline / extendOnline
        // still wait for measured gas x 1.5.
        let gas_ceiling = [
            (A_VOTE_AGREE, DECIDING_VOTE_GAS_FLOOR),
            (A_VOTE_DISAGREE, DECIDING_VOTE_GAS_FLOOR),
            (A_FINALIZE, DECIDING_VOTE_GAS_FLOOR),
            (A_REPORT, REPORT_OFFLINE_GAS_DEFAULT),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        Self {
            note: None,
            daily,
            gas_ceiling,
            spend_upkeep_wei: 60_000_000_000_000_000, // 0.06 CNET (pending, H8-13)
            spend_anchor_net_wei: 40_000_000_000_000_000, // 0.04 CNET
            spend_total_wei: 100_000_000_000_000_000, // 0.1 CNET
            max_fee_wei: 100_000_000,                 // 0.1 gwei
            max_inflight: 4,
            warn_percent: 80,
            max_inflight_report: 4,
            max_inflight_vote: 4,
        }
    }
}

impl QuotaConfig {
    pub fn validate(&self) -> Result<(), String> {
        for b in self.daily.keys() {
            let known = [B_MARK_ONLINE, B_FINALIZE, B_ANCHOR_TX, B_ANCHOR_RECEIPT];
            if !known.contains(&b.as_str()) {
                return Err(format!("quota config: unknown bucket {b}"));
            }
        }
        for (a, g) in &self.gas_ceiling {
            match action(a) {
                Some(Action { class: Some(_), .. }) => {}
                _ => return Err(format!("quota config: no gas for {a}")),
            }
            let deciding = [A_VOTE_AGREE, A_VOTE_DISAGREE, A_FINALIZE].contains(&a.as_str());
            if deciding && *g < DECIDING_VOTE_GAS_FLOOR {
                return Err(format!(
                    "quota config: {a} gas ceiling {g} below {DECIDING_VOTE_GAS_FLOOR}"
                ));
            }
        }
        if self.max_fee_wei == 0 || self.max_fee_wei > MAX_FEE_HARD_CAP_WEI {
            return Err("quota config: max_fee_wei must be 1..=1 gwei".into());
        }
        if self.max_inflight_report == 0 || self.max_inflight_vote == 0 {
            return Err("quota config: max_inflight_report, max_inflight_vote >= 1".into());
        }
        if self.max_inflight == 0 || !(1..=100).contains(&self.warn_percent) {
            return Err("quota config: max_inflight >= 1, warn_percent 1..=100".into());
        }
        Ok(())
    }
}

/// A refusal. `Display` names the bucket and counts, never request content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaError {
    UnknownSelector,
    NotConfigured(String),
    GasCeilingUnset(String),
    GasAboveCeiling { action: String, ceiling: u64 },
    MaxFeeTooHigh { cap: u64 },
    Exceeded { bucket: String, used: u64, cap: u64 },
    Inflight { cap: u32 },
    InflightReport { cap: u32 },
    InflightVote { cap: u32 },
    UnknownTicket,
    StateBroken(String),
    Write,
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use QuotaError::*;
        match self {
            UnknownSelector => write!(f, "unknown_selector"),
            NotConfigured(b) => write!(f, "not_configured:{b}"),
            GasCeilingUnset(a) => write!(f, "gas_ceiling_unset:{a}"),
            GasAboveCeiling { action, ceiling } => {
                write!(f, "gas_above_ceiling:{action} {ceiling}")
            }
            MaxFeeTooHigh { cap } => write!(f, "max_fee_too_high:{cap}"),
            Exceeded { bucket, used, cap } => write!(f, "quota_exceeded:{bucket} {used}/{cap}"),
            Inflight { cap } => write!(f, "quota_exceeded:inflight {cap}/{cap}"),
            InflightReport { cap } => write!(f, "inflight_report {cap}/{cap}"),
            InflightVote { cap } => write!(f, "inflight_vote {cap}/{cap}"),
            UnknownTicket => write!(f, "unknown_ticket"),
            StateBroken(r) => write!(f, "quota_state_broken:{r}"),
            Write => write!(f, "quota_state_write"),
        }
    }
}

impl std::error::Error for QuotaError {}

/// What the caller wants to do. `gas_limit` and `max_fee_wei` are ignored for signatures.
#[derive(Clone, Debug)]
pub struct Intent<'a> {
    pub action: &'a str,
    pub gas_limit: u64,
    pub max_fee_wei: u64,
}

impl<'a> Intent<'a> {
    pub fn signature(action: &'a str) -> Self {
        Self {
            action,
            gas_limit: 0,
            max_fee_wei: 0,
        }
    }
    pub fn tx(action: &'a str, gas_limit: u64, max_fee_wei: u64) -> Self {
        Self {
            action,
            gas_limit,
            max_fee_wei,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Set for transactions: settle or cancel it when the outcome is known.
    pub ticket: Option<u64>,
    /// Buckets or spend classes that crossed the warn threshold with this grant.
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Inflight {
    action: String,
    reserved_wei: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    v: u32,
    day: u64,
    counts: BTreeMap<String, u64>,
    spent_upkeep_wei: u64,
    spent_anchor_wei: u64,
    reimbursed_anchor_wei: u64,
    inflight: BTreeMap<u64, Inflight>,
    next_ticket: u64,
    warned: Vec<String>,
    /// `reportOffline` gas, monitoring only.
    #[serde(default)]
    spent_report_wei: u64,
    /// `voteReport` gas, monitoring only (H812C).
    #[serde(default)]
    spent_vote_wei: u64,
}

pub struct Quota {
    cfg: QuotaConfig,
    path: PathBuf,
    state: State,
    broken: Option<String>,
}

const W_SPEND_UPKEEP: &str = "spend.upkeep";
const W_SPEND_ANCHOR: &str = "spend.anchor";
const W_SPEND_TOTAL: &str = "spend.total";

impl Quota {
    /// Open the ledger. A missing file starts a fresh ledger; a file that does not parse or has
    /// another version opens a broken ledger that refuses everything.
    pub fn open(cfg: QuotaConfig, path: impl Into<PathBuf>) -> Result<Self, String> {
        cfg.validate()?;
        let path = path.into();
        let (state, broken) = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                State {
                    v: STATE_VERSION,
                    ..State::default()
                },
                None,
            ),
            Err(_) => (State::default(), Some("unreadable".to_string())),
            Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
                Ok(s) if s.v == STATE_VERSION => (s, None),
                Ok(s) => (State::default(), Some(format!("version {}", s.v))),
                Err(_) => (State::default(), Some("unparsable".to_string())),
            },
        };
        Ok(Self {
            cfg,
            path,
            state,
            broken,
        })
    }

    pub fn broken(&self) -> Option<&str> {
        self.broken.as_deref()
    }

    pub fn config(&self) -> &QuotaConfig {
        &self.cfg
    }

    /// Count used today in a bucket.
    pub fn used(&self, bucket: &str, now: u64) -> u64 {
        if self.state.day != now / DAY {
            return 0;
        }
        self.state.counts.get(bucket).copied().unwrap_or(0)
    }

    /// Settled spend today in a class (uncapped classes are recorded too).
    pub fn spent(&self, class: SpendClass, now: u64) -> u64 {
        if self.state.day != now / DAY {
            return 0;
        }
        match class {
            SpendClass::Upkeep => self.state.spent_upkeep_wei,
            SpendClass::Ballot => self.state.spent_vote_wei,
            SpendClass::Report => self.state.spent_report_wei,
            SpendClass::Anchor => self.state.spent_anchor_wei,
        }
    }

    pub fn inflight(&self) -> usize {
        self.state.inflight.len()
    }

    /// Check an intent and, if allowed, record it on disk before returning.
    pub fn reserve(&mut self, intent: &Intent, now: u64) -> Result<Grant, QuotaError> {
        if let Some(r) = &self.broken {
            return Err(QuotaError::StateBroken(r.clone()));
        }
        let Some(act) = action(intent.action) else {
            return Err(QuotaError::UnknownSelector);
        };
        let mut next = self.state.clone();
        roll(&mut next, now);

        // Counts.
        let mut caps = Vec::new();
        for b in act.buckets {
            let Some(cap) = self.cfg.daily.get(*b).copied() else {
                return Err(QuotaError::NotConfigured(b.to_string()));
            };
            let used = next.counts.get(*b).copied().unwrap_or(0);
            if used >= cap as u64 {
                return Err(QuotaError::Exceeded {
                    bucket: b.to_string(),
                    used,
                    cap: cap as u64,
                });
            }
            caps.push((*b, cap as u64));
        }

        // Transactions: gas ceiling, fee cap, in flight, spend.
        let mut ticket = None;
        let mut spend_classes = Vec::new();
        if let Some(class) = act.class {
            let Some(ceiling) = self.cfg.gas_ceiling.get(intent.action).copied() else {
                return Err(QuotaError::GasCeilingUnset(intent.action.to_string()));
            };
            if intent.gas_limit == 0 || intent.gas_limit > ceiling {
                return Err(QuotaError::GasAboveCeiling {
                    action: intent.action.to_string(),
                    ceiling,
                });
            }
            if intent.max_fee_wei == 0 || intent.max_fee_wei > self.cfg.max_fee_wei {
                return Err(QuotaError::MaxFeeTooHigh {
                    cap: self.cfg.max_fee_wei,
                });
            }
            // Three lanes: votes and reports never wait behind each other or behind upkeep and
            // anchors. Counted from what is in flight now; nothing here resets by day.
            let lane = |a: &str| match action(a).and_then(|x| x.class) {
                Some(SpendClass::Report) => 2u8,
                Some(SpendClass::Ballot) => 1,
                _ => 0,
            };
            let mine = lane(intent.action);
            let n = next
                .inflight
                .values()
                .filter(|f| lane(&f.action) == mine)
                .count() as u64;
            let (cap, err) = match mine {
                2 => (
                    self.cfg.max_inflight_report,
                    QuotaError::InflightReport {
                        cap: self.cfg.max_inflight_report,
                    },
                ),
                1 => (
                    self.cfg.max_inflight_vote,
                    QuotaError::InflightVote {
                        cap: self.cfg.max_inflight_vote,
                    },
                ),
                _ => (
                    self.cfg.max_inflight,
                    QuotaError::Inflight {
                        cap: self.cfg.max_inflight,
                    },
                ),
            };
            if n >= cap as u64 {
                return Err(err);
            }
            let cost =
                intent
                    .gas_limit
                    .checked_mul(intent.max_fee_wei)
                    .ok_or(QuotaError::Exceeded {
                        bucket: W_SPEND_TOTAL.into(),
                        used: u64::MAX,
                        cap: self.cfg.spend_total_wei,
                    })?;
            let (vote, anchor) = committed(&next);
            let (cv, ca) = match class {
                SpendClass::Upkeep => (cost, 0),
                SpendClass::Anchor => (0, cost),
                // Votes (H812C) and reports (H8-12) are outside every spend cap.
                SpendClass::Ballot | SpendClass::Report => (0, 0),
            };
            let checks = [
                (W_SPEND_UPKEEP, vote, cv, self.cfg.spend_upkeep_wei),
                (W_SPEND_ANCHOR, anchor, ca, self.cfg.spend_anchor_net_wei),
                (
                    W_SPEND_TOTAL,
                    vote + anchor,
                    cv + ca,
                    self.cfg.spend_total_wei,
                ),
            ];
            for (name, used, add, cap) in checks {
                if add > 0 && used.saturating_add(add) > cap {
                    return Err(QuotaError::Exceeded {
                        bucket: name.into(),
                        used,
                        cap,
                    });
                }
                if add > 0 {
                    spend_classes.push((name, used + add, cap));
                }
            }
            let id = next.next_ticket;
            next.next_ticket += 1;
            next.inflight.insert(
                id,
                Inflight {
                    action: intent.action.to_string(),
                    reserved_wei: cost,
                },
            );
            ticket = Some(id);
        }

        // Record counts and warnings.
        let mut warnings = Vec::new();
        for (b, cap) in caps {
            let c = next.counts.entry(b.to_string()).or_insert(0);
            *c += 1;
            let hit = *c * 100 >= cap * self.cfg.warn_percent as u64;
            if hit && !next.warned.iter().any(|w| w == b) {
                next.warned.push(b.to_string());
                warnings.push(b.to_string());
            }
        }
        for (name, used, cap) in spend_classes {
            let hit = (used as u128) * 100 >= (cap as u128) * self.cfg.warn_percent as u128;
            if hit && !next.warned.iter().any(|w| w == name) {
                next.warned.push(name.to_string());
                warnings.push(name.to_string());
            }
        }

        self.commit(next)?;
        Ok(Grant { ticket, warnings })
    }

    /// A receipt arrived: replace the reservation with the real cost (gas used x price paid).
    pub fn settle(
        &mut self,
        ticket: u64,
        gas_used: u64,
        price_wei: u64,
        now: u64,
    ) -> Result<(), QuotaError> {
        self.finish(ticket, Some(gas_used.saturating_mul(price_wei)), now)
    }

    /// The transaction was never sent or was dropped: release the reservation. The count stays.
    pub fn cancel(&mut self, ticket: u64, now: u64) -> Result<(), QuotaError> {
        self.finish(ticket, None, now)
    }

    /// The subsidy pool paid back anchor gas.
    pub fn reimbursed(&mut self, wei: u64, now: u64) -> Result<(), QuotaError> {
        if let Some(r) = &self.broken {
            return Err(QuotaError::StateBroken(r.clone()));
        }
        let mut next = self.state.clone();
        roll(&mut next, now);
        next.reimbursed_anchor_wei = next.reimbursed_anchor_wei.saturating_add(wei);
        self.commit(next)
    }

    fn finish(&mut self, ticket: u64, cost: Option<u64>, now: u64) -> Result<(), QuotaError> {
        if let Some(r) = &self.broken {
            return Err(QuotaError::StateBroken(r.clone()));
        }
        let mut next = self.state.clone();
        roll(&mut next, now);
        let Some(f) = next.inflight.remove(&ticket) else {
            return Err(QuotaError::UnknownTicket);
        };
        if let Some(cost) = cost {
            match action(&f.action).and_then(|a| a.class) {
                Some(SpendClass::Upkeep) => {
                    next.spent_upkeep_wei = next.spent_upkeep_wei.saturating_add(cost)
                }
                Some(SpendClass::Ballot) => {
                    next.spent_vote_wei = next.spent_vote_wei.saturating_add(cost)
                }
                Some(SpendClass::Anchor) => {
                    next.spent_anchor_wei = next.spent_anchor_wei.saturating_add(cost)
                }
                Some(SpendClass::Report) => {
                    next.spent_report_wei = next.spent_report_wei.saturating_add(cost)
                }
                None => {}
            }
        }
        self.commit(next)
    }

    fn commit(&mut self, next: State) -> Result<(), QuotaError> {
        write_state(&self.path, &next).map_err(|_| QuotaError::Write)?;
        self.state = next;
        Ok(())
    }
}

/// New UTC day: counts, spend and warnings start over. In-flight reservations carry over and
/// keep counting against today's spend until settled.
fn roll(s: &mut State, now: u64) {
    let day = now / DAY;
    if s.day != day {
        s.day = day;
        s.counts.clear();
        s.spent_upkeep_wei = 0;
        s.spent_anchor_wei = 0;
        s.reimbursed_anchor_wei = 0;
        s.spent_report_wei = 0;
        s.spent_vote_wei = 0;
        s.warned.clear();
    }
}

/// Spend committed today per class: settled (anchor net of reimbursements) plus reservations.
fn committed(s: &State) -> (u64, u64) {
    let mut vote = s.spent_upkeep_wei;
    let mut anchor = s.spent_anchor_wei.saturating_sub(s.reimbursed_anchor_wei);
    for f in s.inflight.values() {
        match action(&f.action).and_then(|a| a.class) {
            Some(SpendClass::Upkeep) => vote = vote.saturating_add(f.reserved_wei),
            Some(SpendClass::Anchor) => anchor = anchor.saturating_add(f.reserved_wei),
            Some(SpendClass::Ballot) | Some(SpendClass::Report) | None => {}
        }
    }
    (vote, anchor)
}

fn write_state(path: &Path, s: &State) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = serde_json::to_vec(s).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

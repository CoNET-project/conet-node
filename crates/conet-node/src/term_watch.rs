//! Term watch, read-only: the running node reads its own stake term from the registry and tells
//! the operator (log lines) what the decided rules mean for it. Never sends a transaction and
//! never talks to the signer: renewal is automatic on chain, top-ups go through AUTO-TOPUP or the
//! web page.
//!
//! Every read of one round is pinned to one block (its timestamp is "now"):
//! `termOf` (stored end, base, length, stakeStop), `termStateOf` (read-time inTerm and base),
//! `stakeOf`, `minStakeAt(termEnd)`, `minStakeNow`.
//!
//! What is reported (each once, on change; reminders once per lead time per term end):
//! - before the end, stake short of `minStakeAt(termEnd)`: 30 / 7 / 1-day reminders;
//! - renewed (read-time or written): the next end;
//! - ended without renewal (stakeStop, or read-time not in term): the stop, the latest full
//!   amount to top up to, and the recovery precheck (`VoteReader::recovery_view`).
use crate::chain::{ChainError, Rpc};
use crate::nr2::{NodeRegistryV2, Nr2Reader};
use crate::stake_term::{advise, renewal_precheck, Advice, Reminders, Renewal, TermView};
use alloy_primitives::U256;
use std::time::Duration;
use tracing::{info, warn};

fn ce<E: std::fmt::Display>(e: E) -> ChainError {
    ChainError(e.to_string())
}

/// Raw view outputs of one block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TermReads {
    /// The pinned block's timestamp.
    pub now: u64,
    /// `termOf`: the stored term (a read-time renewal is not written yet).
    pub term_end: u64,
    pub term_base: u128,
    pub term_length: u64,
    pub stake_stop: bool,
    /// `termStateOf`: the contract's read-time view (renewals applied).
    pub in_term: bool,
    pub read_base: u128,
    pub stake: u128,
    /// `minStakeAt(termEnd)`: what the renewal at the stored end compares the whole stake with.
    pub need_at_end: u128,
    /// `minStakeNow()`: what a stopped node tops up to before recovery.
    pub min_stake_now: u128,
}

/// The contract's read-time state as a [`TermView`]:
/// - `stakeStop`, or the stored end passed and the read-time view is not in term: renewal failed
///   (the contract writes it on the next touch; nothing for the node to send);
/// - the stored end passed and the read-time view is in term: renewed, next end = the first
///   stored end + k x length after now;
/// - otherwise pending.
///
/// `current_threshold` is the amount the next step needs: `minStakeAt(termEnd)` while the term
/// runs (renewal rule), the latest full amount once stopped (recovery rule).
pub fn term_view_from(r: &TermReads) -> TermView {
    let ended = r.now >= r.term_end;
    let renewal = if r.stake_stop || (ended && !r.in_term) {
        Renewal::Failed
    } else if ended && r.term_length > 0 {
        let k = (r.now - r.term_end) / r.term_length + 1;
        Renewal::Renewed {
            next_term_ends_at: r.term_end + k * r.term_length,
        }
    } else {
        Renewal::Pending
    };
    let current_threshold = match renewal {
        Renewal::Failed => r.min_stake_now,
        _ => r.need_at_end,
    };
    TermView {
        term_ends_at: r.term_end,
        term_threshold: r.read_base,
        current_threshold,
        stake: r.stake,
        renewal,
    }
}

/// Remembers what was already said, so each fact is logged once.
#[derive(Debug, Default)]
pub struct TermWatch {
    last: Option<Advice>,
    reminded: Option<(u64, u64)>,
}

impl TermWatch {
    /// The line to log for this round, if anything new. Reminders: once per (term end, lead
    /// time); other advice: when it changes. `Fine` is logged only after something else.
    pub fn step(&mut self, v: &TermView, now: u64, r: &Reminders) -> Option<String> {
        let a = advise(v, now, r);
        let line = match &a {
            Advice::Remind {
                left,
                top_up_to,
                shortfall,
                bucket,
            } => {
                if self.reminded == Some((v.term_ends_at, *bucket)) {
                    None
                } else {
                    self.reminded = Some((v.term_ends_at, *bucket));
                    let path = renewal_precheck(v)
                        .err()
                        .map(|p| crate::stake_term::no_renew_log(v, p))
                        .unwrap_or_default();
                    Some(format!(
                        "term: renewal at the current threshold will fail in {left}s unless the whole stake reaches {top_up_to} (missing {shortfall}); {path}"
                    ))
                }
            }
            other if self.last.as_ref() == Some(other) => None,
            Advice::Fine if self.last.is_none() => None,
            Advice::Fine => Some("term: stake meets the renewal threshold".into()),
            Advice::Renewed { next_term_ends_at } => Some(format!(
                "term: renewed automatically, next end {next_term_ends_at}"
            )),
            Advice::RenewalDue => {
                Some("term: ended, stake meets the threshold, renewal pending on chain".into())
            }
            Advice::Expired { .. } => Some(format!(
                "term: renewal failed, node stopped; top up the whole stake to {} and request recovery",
                v.current_threshold
            )),
        };
        self.last = Some(a);
        line
    }
}

/// One round of reads pinned to the latest block.
pub async fn read(r: &Nr2Reader, node_id: u64) -> Result<TermReads, ChainError> {
    let b = r
        .rpc
        .call("eth_getBlockByNumber", serde_json::json!(["latest", false]))
        .await?;
    let hex = |k: &str| -> Result<u64, ChainError> {
        u64::from_str_radix(
            b[k].as_str()
                .ok_or_else(|| ce(format!("block {k}")))?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(ce)
    };
    let (block, now) = (Some(hex("number")?), hex("timestamp")?);
    let id = U256::from(node_id);
    let reg = r.registry.as_str();
    let t = r
        .call(reg, NodeRegistryV2::termOfCall { nodeId: id }, block)
        .await?;
    let s = r
        .call(reg, NodeRegistryV2::termStateOfCall { nodeId: id }, block)
        .await?;
    let stake = r
        .call(reg, NodeRegistryV2::stakeOfCall { nodeId: id }, block)
        .await?;
    let need = r
        .call(reg, NodeRegistryV2::minStakeAtCall { t: t.termEnd }, block)
        .await?;
    let latest = r
        .call(reg, NodeRegistryV2::minStakeNowCall {}, block)
        .await?;
    Ok(TermReads {
        now,
        term_end: t.termEnd,
        term_base: t.termBase,
        term_length: t.termLength as u64,
        stake_stop: t.stakeStop,
        in_term: s.inTerm,
        read_base: s.termBase.try_into().map_err(ce)?,
        stake: stake.try_into().map_err(ce)?,
        need_at_end: need.try_into().map_err(ce)?,
        min_stake_now: latest.try_into().map_err(ce)?,
    })
}

async fn balance(rpc: &Rpc, wallet: &str) -> Result<u128, ChainError> {
    let v = rpc
        .call("eth_getBalance", serde_json::json!([wallet, "latest"]))
        .await?;
    u128::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).map_err(ce)
}

/// The background task: finds this node's id from its wallet, then reads every `every`. A read
/// failure is logged and retried next round; nothing else depends on this task.
pub async fn run(reader: Nr2Reader, wallet: String, every: Duration) {
    let reminders = Reminders::default();
    let mut watch = TermWatch::default();
    let mut node_id = 0u64;
    let mut stopped_said = false;
    loop {
        if node_id == 0 {
            match reader.node_id_of_wallet(&wallet).await {
                Ok(0) => {}
                Ok(id) => node_id = id,
                Err(e) => warn!(%e, "term: node id read failed"),
            }
        }
        if node_id != 0 {
            match read(&reader, node_id).await {
                Ok(r) => {
                    let v = term_view_from(&r);
                    if let Some(line) = watch.step(&v, r.now, &reminders) {
                        info!(node_id, "{line}");
                    }
                    let stopped = v.renewal == Renewal::Failed;
                    if stopped && !stopped_said {
                        recovery_hint(&reader, &wallet, node_id, r.now).await;
                    }
                    stopped_said = stopped;
                }
                Err(e) => warn!(%e, "term: read failed"),
            }
        }
        tokio::time::sleep(every).await;
    }
}

async fn recovery_hint(reader: &Nr2Reader, wallet: &str, node_id: u64, now: u64) {
    let vr = crate::vote_gate::VoteReader {
        rpc: reader.rpc.clone(),
        registry: reader.registry.clone(),
    };
    let fee = balance(&reader.rpc, wallet).await.unwrap_or(0);
    match vr.recovery_view(node_id, now, fee).await {
        Ok(v) => {
            let b = crate::online_gate::precheck_recovery(&v);
            info!(
                node_id,
                "term: recovery precheck clear={} first_contract_error={:?} wait_s={:?} stake_missing={:?} suspended={} fee_missing={:?}",
                b.clear(),
                b.contract_error(),
                b.wait,
                b.stake_missing,
                b.suspended,
                b.fee_missing
            );
        }
        Err(e) => warn!(%e, "term: recovery precheck read failed"),
    }
}

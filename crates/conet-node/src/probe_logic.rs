//! Liveness probe decisions, pure logic (Rust line probe protocol v0.5: P-04 to P-08). No
//! network, no signing, nothing wired into the server yet. All parameters are suggestions,
//! pending (report §33, §36, §38, §41).
use alloy_primitives::keccak256;
use std::collections::{BTreeSet, HashMap, VecDeque};

// ---------- P-04: failure counter ----------

/// One probe outcome as the prober judged it (§33.5, §38.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A valid reply from the target's current, certain authorization (bit0/bit1 do not
    /// matter): online.
    Online,
    /// One of the five fixed failure classes (1 = no reply, 2 = bad signature, 3 = signer not
    /// the current authorization, 4 = requestHash mismatch, 5 = reply too late).
    Fail(u8),
    /// Not counted either way: format error (clock skew), prober's self-check failed, prober's
    /// snapshot stale, target authorization uncertain, grace period.
    NotCounted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailCfg {
    pub slot_secs: u64,
    pub min_gap_secs: u64,
    pub window_secs: u64,
    pub needed: usize,
}

impl Default for FailCfg {
    fn default() -> Self {
        Self {
            slot_secs: 60,
            min_gap_secs: 60,
            window_secs: 15 * 60,
            needed: 3,
        }
    }
}

/// Consecutive failures for one target. Reaching `needed` only allows opening a report (after
/// the pre-report relay check); it is never a verdict.
#[derive(Debug, Clone, Default)]
pub struct FailCounter {
    times: Vec<u64>,
}

impl FailCounter {
    /// Record an outcome at `now`; returns true when the report threshold is reached.
    pub fn record(&mut self, cfg: &FailCfg, o: Outcome, now: u64) -> bool {
        match o {
            Outcome::Online => self.times.clear(),
            Outcome::NotCounted => {}
            Outcome::Fail(class) => {
                debug_assert!((1..=5).contains(&class));
                // Old failures fall out of the window.
                self.times
                    .retain(|t| now.saturating_sub(*t) < cfg.window_secs);
                // Only one failure per slot, and at least min_gap after the previous one.
                let ok = self.times.last().is_none_or(|last| {
                    now >= last + cfg.min_gap_secs && now / cfg.slot_secs != last / cfg.slot_secs
                });
                if ok {
                    self.times.push(now);
                }
            }
        }
        self.times.len() >= cfg.needed
    }
    /// Online evidence from a pre-report relay check: start over (§41.4 item 3).
    pub fn reset(&mut self) {
        self.times.clear();
    }
    pub fn count(&self) -> usize {
        self.times.len()
    }
    /// The failure times, for OfflineEvidence (three distinct slots).
    pub fn times(&self) -> &[u64] {
        &self.times
    }
}

// ---------- P-05: self-check gate ----------

/// The prober's own connectivity (§33.6): in the last `window_secs`, at least `threshold_pct`
/// of a sample of other nodes must have answered for any failure to count. The threshold is
/// the operator's call (fixed 80% or relative to a network baseline).
#[derive(Debug, Clone)]
pub struct SelfCheck {
    pub window_secs: u64,
    pub min_samples: usize,
    pub threshold_pct: u32,
    samples: VecDeque<(u64, bool)>,
}

impl SelfCheck {
    pub fn new(window_secs: u64, min_samples: usize, threshold_pct: u32) -> Self {
        Self {
            window_secs,
            min_samples,
            threshold_pct,
            samples: VecDeque::new(),
        }
    }
    pub fn sample(&mut self, answered: bool, now: u64) {
        self.samples.push_back((now, answered));
        while let Some((t, _)) = self.samples.front() {
            if now.saturating_sub(*t) >= self.window_secs {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
    /// Too few samples is "cannot tell": failures do not count.
    pub fn passes(&self, now: u64) -> bool {
        let live: Vec<bool> = self
            .samples
            .iter()
            .filter(|(t, _)| now.saturating_sub(*t) < self.window_secs)
            .map(|(_, a)| *a)
            .collect();
        if live.len() < self.min_samples {
            return false;
        }
        let ok = live.iter().filter(|a| **a).count();
        ok * 100 >= live.len() * self.threshold_pct as usize
    }
    /// Filter an outcome through the gate.
    pub fn gate(&self, o: Outcome, now: u64) -> Outcome {
        match o {
            Outcome::Fail(_) if !self.passes(now) => Outcome::NotCounted,
            other => other,
        }
    }
}

// ---------- P-06: batch assignment ----------

/// The `k` targets a prober covers this round (§33.1): the smallest
/// keccak256(roundSeed ‖ proberNodeId ‖ targetNodeId), over type-1 active nodes, never itself.
/// Deterministic given the seed, so anyone can recompute it.
pub fn assign(round_seed: &[u8; 32], prober: u64, targets: &[u64], k: usize) -> Vec<u64> {
    let mut keyed: Vec<([u8; 32], u64)> = targets
        .iter()
        .copied()
        .filter(|t| *t != prober)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|t| {
            let mut buf = Vec::with_capacity(32 + 64);
            buf.extend_from_slice(round_seed);
            buf.extend_from_slice(&alloy_primitives::U256::from(prober).to_be_bytes::<32>());
            buf.extend_from_slice(&alloy_primitives::U256::from(t).to_be_bytes::<32>());
            (keccak256(&buf).0, t)
        })
        .collect();
    keyed.sort();
    keyed.into_iter().take(k).map(|(_, t)| t).collect()
}

// ---------- P-07: vote decision ----------

/// What a relay brought back (§36.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayResult {
    /// The relay's own signed request plus the target's reply (authorization certain).
    Online,
    /// The relay's own signed request, no reply from the target.
    NoReply,
    /// Refused, "busy", timed out, nothing or nothing valid handed back.
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Agree,
    Disagree,
    Abstain,
}

/// The voter's decision (§33.8, §36.2, §38.6). `own`: the voter's three probes; `relays`: up
/// to four candidates in order; `self_ok`: the self-check passed; `certain`: the voter's
/// snapshot is fresh and the target's authorization is certain. Uncertain means no vote.
pub fn decide(own: &[Outcome; 3], relays: &[RelayResult], self_ok: bool, certain: bool) -> Choice {
    if !certain {
        return Choice::Abstain;
    }
    let online = own.iter().filter(|o| **o == Outcome::Online).count();
    if online >= 2 {
        return Choice::Disagree;
    }
    if online == 1 {
        return Choice::Abstain;
    }
    let failed = own.iter().filter(|o| matches!(o, Outcome::Fail(_))).count();
    if failed < 3 || !self_ok {
        return Choice::Abstain;
    }
    if relays.contains(&RelayResult::Online) {
        // Reachable elsewhere: partition, not offline.
        return Choice::Disagree;
    }
    let no_reply = relays
        .iter()
        .take(4)
        .filter(|r| **r == RelayResult::NoReply)
        .count();
    if no_reply >= 2 {
        Choice::Agree
    } else {
        Choice::Abstain
    }
}

// ---------- P-08: event cursor and reorgs ----------

/// Where log processing stands (§33.10): the last fully processed block and a ring of recent
/// block hashes for finding a common ancestor after a reorg.
#[derive(Debug, Clone)]
pub struct Cursor {
    pub ring_len: usize,
    ring: VecDeque<(u64, [u8; 32])>,
    processed: HashMap<u64, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resume {
    /// Chain agrees with the cursor: continue after this block.
    After(u64),
    /// Reorg: reprocess from after this common ancestor (decisions above it are void).
    Rewind(u64),
    /// Reorg deeper than the ring (or no ancestor found): rescan all open reports.
    FullRescan,
}

impl Cursor {
    pub fn new(ring_len: usize) -> Self {
        Self {
            ring_len,
            ring: VecDeque::new(),
            processed: HashMap::new(),
        }
    }
    /// Record a processed block.
    pub fn push(&mut self, number: u64, hash: [u8; 32]) {
        self.ring.push_back((number, hash));
        while self.ring.len() > self.ring_len {
            self.ring.pop_front();
        }
    }
    pub fn last(&self) -> Option<u64> {
        self.ring.back().map(|(n, _)| *n)
    }
    /// Before a batch: compare the ring with the chain (`hash_at` = the chain's hash now).
    pub fn check(&mut self, hash_at: impl Fn(u64) -> Option<[u8; 32]>) -> Resume {
        let Some((n, h)) = self.ring.back().copied() else {
            return Resume::FullRescan;
        };
        if hash_at(n) == Some(h) {
            return Resume::After(n);
        }
        while let Some((m, mh)) = self.ring.pop_back() {
            if hash_at(m) == Some(mh) {
                self.ring.push_back((m, mh));
                self.processed.retain(|_, at| *at <= m);
                return Resume::Rewind(m);
            }
        }
        self.processed.clear();
        Resume::FullRescan
    }
    /// Act on a report event once: true the first time `rid` is seen at or below the cursor.
    /// Events are triggers only; the decision re-reads chain state.
    pub fn first_time(&mut self, rid: u64, block: u64) -> bool {
        if self.processed.contains_key(&rid) {
            return false;
        }
        self.processed.insert(rid, block);
        true
    }
}

//! Node table watcher: poll a cheap version, read the full table only when it changed (after
//! random jitter so the fleet does not hit the RPC at once), refuse suspicious shrinkage, and
//! force a full read daily. Mirrors SI `guardianNodes.ts` without its storage-root specifics,
//! which live in the [`NodeSource`] implementation.
use crate::chain::{NodeSource, TableSnapshot};
use crate::route::RouteTable;
use rand_core::{OsRng, RngCore};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct WatchOpts {
    pub poll: Duration,
    pub jitter: Duration,
    pub force_full: Duration,
    /// Forward port for node IPs (SI forwards to :80).
    pub port: u16,
    /// Refuse a new table smaller than this fraction of the current one.
    pub min_keep: f64,
}

impl Default for WatchOpts {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(30),
            jitter: Duration::from_secs(120),
            force_full: Duration::from_secs(24 * 3600),
            port: 80,
            min_keep: 0.8,
        }
    }
}

/// Latest chain block seen (used as the epoch in the mailbox handshake signature).
#[derive(Default)]
pub struct ChainState {
    pub block: AtomicU64,
}

fn rand_below(max: Duration) -> Duration {
    if max.is_zero() {
        return max;
    }
    Duration::from_millis(OsRng.next_u64() % (max.as_millis() as u64).max(1))
}

/// Apply a snapshot unless it shrank suspiciously. Returns true when applied.
pub fn apply(routes: &RouteTable, snap: &TableSnapshot, port: u16, min_keep: f64) -> bool {
    let entries: Vec<(String, SocketAddr, bool)> = snap
        .nodes
        .iter()
        .filter_map(|n| {
            let ip: std::net::IpAddr = n.ip.parse().ok()?;
            Some((
                n.key_id.clone(),
                SocketAddr::new(ip, n.port.unwrap_or(port)),
                n.mailbox,
            ))
        })
        .collect();
    let current = routes.node_count();
    if entries.is_empty() || (current > 10 && (entries.len() as f64) < current as f64 * min_keep) {
        warn!(
            current,
            new = entries.len(),
            "node table shrank too much; keeping the current table"
        );
        return false;
    }
    routes.replace_node_entries(entries, snap.lists_all_active);
    true
}

pub async fn run(
    source: Arc<dyn NodeSource>,
    routes: Arc<RouteTable>,
    chain: Arc<ChainState>,
    opts: WatchOpts,
) {
    let mut applied: Option<(String, Instant)> = None;
    let mut backoff = Duration::from_secs(15);
    loop {
        match source.version().await {
            Ok((version, block)) => {
                chain.block.store(block, Ordering::Relaxed);
                let stale = applied
                    .as_ref()
                    .map(|(v, at)| *v != version || at.elapsed() > opts.force_full)
                    .unwrap_or(true);
                if stale {
                    if applied.is_some() {
                        tokio::time::sleep(rand_below(opts.jitter)).await;
                    }
                    match source.read(block).await {
                        Ok(snap) => {
                            if apply(&routes, &snap, opts.port, opts.min_keep) {
                                info!(
                                    nodes = snap.nodes.len(),
                                    rejected = snap.rejected,
                                    block,
                                    "node table applied"
                                );
                                applied = Some((snap.version, Instant::now()));
                            }
                            backoff = Duration::from_secs(15);
                        }
                        Err(e) => {
                            warn!(%e, "node table read failed");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(900));
                            continue;
                        }
                    }
                }
                tokio::time::sleep(opts.poll).await;
            }
            Err(e) => {
                warn!(%e, "node table version failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(900));
            }
        }
    }
}

//! Node table watcher: poll a cheap version, read the full table only when it changed (after
//! random jitter so the fleet does not hit the RPC at once), refuse suspicious shrinkage, and
//! force a full read daily. Mirrors SI `guardianNodes.ts` without its storage-root specifics,
//! which live in the [`NodeSource`] implementation.
use crate::chain::{NodeSource, TableSnapshot, DEFAULT_NODE_FORWARD_PORT};
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
            port: DEFAULT_NODE_FORWARD_PORT,
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

/// Apply a snapshot unless it is incomplete or an untrusted source shrank suspiciously.
/// NR2 snapshots list every active row and are pinned/validated as complete by the source, so
/// their valid empty set and large real shrink must replace stale routes.
pub fn apply(routes: &RouteTable, snap: &TableSnapshot, port: u16, min_keep: f64) -> bool {
    let entries: Vec<(String, SocketAddr, bool, Option<String>)> = snap
        .nodes
        .iter()
        .filter_map(|n| {
            let ip: std::net::IpAddr = n.ip.parse().ok()?;
            Some((
                n.key_id.clone(),
                SocketAddr::new(ip, n.port.unwrap_or(port)),
                n.mailbox,
                n.wallet.clone(),
            ))
        })
        .collect();
    let current = routes.node_count();
    let complete_active_set = snap.lists_all_active && snap.rejected == 0;
    let incomplete_empty = entries.is_empty() && !complete_active_set;
    let suspicious_untrusted_shrink =
        !complete_active_set && current > 10 && (entries.len() as f64) < current as f64 * min_keep;
    if snap.rejected > 0 || incomplete_empty || suspicious_untrusted_shrink {
        routes.mark_wallet_authority_unavailable();
        warn!(
            current,
            new = entries.len(),
            rejected = snap.rejected,
            complete_active_set,
            "node table snapshot is incomplete or shrank too much; keeping the current table"
        );
        return false;
    }
    routes.replace_node_records(entries, snap.lists_all_active);
    true
}

fn invalidate_wallet_snapshot(routes: &RouteTable, applied: &mut Option<(String, Instant)>) {
    routes.mark_wallet_authority_unavailable();
    // A version that failed to produce a complete snapshot must be read again even if its
    // version string has not changed.
    *applied = None;
}

fn needs_refresh(
    wallet_authority_available: bool,
    applied: Option<&(String, Instant)>,
    version: &str,
    force_full: Duration,
) -> bool {
    !wallet_authority_available
        || applied
            .map(|(applied_version, at)| applied_version != version || at.elapsed() > force_full)
            .unwrap_or(true)
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
                let stale = needs_refresh(
                    routes.wallet_authority_available(),
                    applied.as_ref(),
                    &version,
                    opts.force_full,
                );
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
                            } else {
                                invalidate_wallet_snapshot(&routes, &mut applied);
                            }
                            backoff = Duration::from_secs(15);
                        }
                        Err(e) => {
                            warn!(%e, "node table read failed");
                            invalidate_wallet_snapshot(&routes, &mut applied);
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
                invalidate_wallet_snapshot(&routes, &mut applied);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(900));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainNode;
    use crate::route::{NodeWalletLookup, Resolved};

    fn node(key_id: &str, wallet: Option<&str>) -> ChainNode {
        ChainNode {
            id: 1,
            key_id: key_id.to_string(),
            ip: "127.0.0.1".to_string(),
            pgp_armored: String::new(),
            port: Some(9000),
            services: 1,
            mailbox: true,
            wallet: wallet.map(str::to_string),
        }
    }

    #[test]
    fn rejected_snapshot_invalidates_wallets_but_keeps_routes_and_accept_restores_them() {
        let routes = RouteTable::new("own", Duration::from_secs(60));
        let first = TableSnapshot {
            version: "v1".into(),
            block: 10,
            nodes: vec![node("A1B2", Some("0x01"))],
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &first, 9000, 0.8));
        let addr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(
            routes.node_wallet("A1B2"),
            NodeWalletLookup::Known("0x01".into())
        );

        let rejected = TableSnapshot {
            version: "v2".into(),
            block: 11,
            nodes: vec![],
            rejected: 0,
            lists_all_active: false,
        };
        assert!(!apply(&routes, &rejected, 9000, 0.8));
        assert_eq!(routes.node_wallet("A1B2"), NodeWalletLookup::Unavailable);
        assert_eq!(routes.resolve("A1B2"), Resolved::Remote(addr));

        let recovered = TableSnapshot {
            version: "v2".into(),
            block: 12,
            nodes: vec![node("A1B2", Some("0x02"))],
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &recovered, 9000, 0.8));
        assert_eq!(
            routes.node_wallet("A1B2"),
            NodeWalletLookup::Known("0x02".into())
        );
    }

    #[test]
    fn complete_empty_nr2_snapshot_clears_routes_and_is_available() {
        let routes = RouteTable::new("own", Duration::from_secs(60));
        let first = TableSnapshot {
            version: "v1".into(),
            block: 10,
            nodes: vec![node("A1B2", Some("0x01"))],
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &first, 9000, 0.8));

        // NR2 pagination reaches total == 0 only after a successful complete read. This is
        // distinct from an RPC/read error, which never yields a TableSnapshot.
        let empty = TableSnapshot {
            version: "v2".into(),
            block: 11,
            nodes: vec![],
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &empty, 9000, 0.8));
        assert!(routes.wallet_authority_available());
        assert_eq!(routes.node_count(), 0);
        assert_eq!(routes.node_wallet("A1B2"), NodeWalletLookup::UnknownDomain);
        assert_eq!(routes.resolve("A1B2"), Resolved::NoRoute);
    }

    #[test]
    fn incomplete_or_rejected_empty_snapshot_remains_unavailable_and_keeps_routes() {
        for (lists_all_active, rejected) in [(false, 0), (true, 1)] {
            let routes = RouteTable::new("own", Duration::from_secs(60));
            let first = TableSnapshot {
                version: "v1".into(),
                block: 10,
                nodes: vec![node("A1B2", Some("0x01"))],
                rejected: 0,
                lists_all_active: true,
            };
            assert!(apply(&routes, &first, 9000, 0.8));

            let empty = TableSnapshot {
                version: "v2".into(),
                block: 11,
                nodes: vec![],
                rejected,
                lists_all_active,
            };
            assert!(!apply(&routes, &empty, 9000, 0.8));
            assert!(!routes.wallet_authority_available());
            assert_eq!(routes.node_wallet("A1B2"), NodeWalletLookup::Unavailable);
            assert_eq!(
                routes.resolve("A1B2"),
                Resolved::Remote("127.0.0.1:9000".parse().unwrap())
            );
        }
    }

    #[test]
    fn min_keep_does_not_reject_a_complete_nr2_active_set_shrink() {
        let routes = RouteTable::new("own", Duration::from_secs(60));
        let initial = TableSnapshot {
            version: "v1".into(),
            block: 10,
            nodes: (0..11)
                .map(|i| node(&format!("KEY{i:02}"), Some("0x01")))
                .collect(),
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &initial, 9000, 0.8));
        assert_eq!(routes.node_count(), 11);

        let shrunk = TableSnapshot {
            version: "v2".into(),
            block: 11,
            nodes: vec![node("KEY00", Some("0x02"))],
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &shrunk, 9000, 0.8));
        assert_eq!(routes.node_count(), 1);
        assert_eq!(
            routes.node_wallet("KEY00"),
            NodeWalletLookup::Known("0x02".into())
        );
        assert_eq!(routes.node_wallet("KEY01"), NodeWalletLookup::UnknownDomain);
    }

    #[test]
    fn min_keep_still_rejects_a_large_untrusted_shrink() {
        let routes = RouteTable::new("own", Duration::from_secs(60));
        let initial = TableSnapshot {
            version: "v1".into(),
            block: 10,
            nodes: (0..11)
                .map(|i| node(&format!("KEY{i:02}"), Some("0x01")))
                .collect(),
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &initial, 9000, 0.8));

        let untrusted_shrink = TableSnapshot {
            version: "v2".into(),
            block: 11,
            nodes: vec![node("KEY00", Some("0x02"))],
            rejected: 0,
            lists_all_active: false,
        };
        assert!(!apply(&routes, &untrusted_shrink, 9000, 0.8));
        assert_eq!(routes.node_count(), 11);
        assert_eq!(routes.node_wallet("KEY00"), NodeWalletLookup::Unavailable);
    }

    #[test]
    fn rejected_rows_refuse_v6_shrink_even_when_min_keep_would_allow_it() {
        let routes = RouteTable::new("own", Duration::from_secs(60));
        let initial = TableSnapshot {
            version: "nr2-v1".into(),
            block: 10,
            nodes: (0..11)
                .map(|i| node(&format!("KEY{i:02}"), Some("0x01")))
                .collect(),
            rejected: 0,
            lists_all_active: true,
        };
        assert!(apply(&routes, &initial, 9000, 0.8));
        let retained_addr = "127.0.0.1:9000".parse().unwrap();

        // V6-style partial result: 10 decoded rows plus one rejected row. Ten is above the
        // 80% min_keep threshold, so the rejected-row guard itself must fail closed.
        let partial_v6 = TableSnapshot {
            version: "v6-v2".into(),
            block: 11,
            nodes: (0..10).map(|i| node(&format!("KEY{i:02}"), None)).collect(),
            rejected: 1,
            lists_all_active: false,
        };
        assert!(!apply(&routes, &partial_v6, 9000, 0.8));
        assert_eq!(routes.node_count(), 11);
        assert!(!routes.wallet_authority_available());
        assert_eq!(routes.node_wallet("KEY00"), NodeWalletLookup::Unavailable);
        assert_eq!(routes.resolve("KEY10"), Resolved::Remote(retained_addr));
    }

    #[test]
    fn failed_version_or_read_invalidates_same_version_and_forces_reread() {
        let routes = RouteTable::new("own", Duration::from_secs(60));
        routes.replace_node_records(
            [(
                "A1B2".into(),
                "127.0.0.1:9000".parse().unwrap(),
                true,
                Some("0x01".into()),
            )],
            false,
        );
        let mut applied = Some(("v1".to_string(), Instant::now()));
        assert!(!needs_refresh(
            routes.wallet_authority_available(),
            applied.as_ref(),
            "v1",
            Duration::from_secs(3600)
        ));

        // Both watcher error branches use this invalidation path. The route stays available to
        // forward, while wallet authority is unavailable and the same version must be read again.
        invalidate_wallet_snapshot(&routes, &mut applied);
        assert!(applied.is_none());
        assert_eq!(routes.node_wallet("A1B2"), NodeWalletLookup::Unavailable);
        assert!(needs_refresh(
            routes.wallet_authority_available(),
            applied.as_ref(),
            "v1",
            Duration::from_secs(3600)
        ));
    }
}

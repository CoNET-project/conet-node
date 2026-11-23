//! NodeRegistryV2 v0.1 (node line design v0.1.54), read side (F1):
//!
//! - [`Nr2Source`]: the node table through `NodeRegistryLens.getNodes`, pinned to one block.
//!   Change detection is `tableVersion` plus a log scan of the node events, so endpoint, PGP,
//!   wallet and service changes are picked up even where the contract does not bump the version.
//! - [`Nr2Reader`]: single reads (own node id, egress policy pointer).
//!
//! Nothing here sends a transaction. Calls never set `from`.
use crate::chain::{
    checked_u64, BoxFut, ChainError, ChainNode, NodeSource, Rpc, TableSnapshot,
    DEFAULT_NODE_FORWARD_PORT,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolCall, SolEvent};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use si_proto::node_registry as nr;
use std::sync::Mutex;

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(all_derives)]
    NodeRegistryV2,
    "abi/NodeRegistryV2.json"
);
sol!(
    #[allow(missing_docs)]
    #[sol(all_derives)]
    NodeRegistryLens,
    "abi/NodeRegistryLens.json"
);

fn ce<E: std::fmt::Display>(e: E) -> ChainError {
    ChainError(e.to_string())
}

/// Events after which the cached table must be re-read.
pub fn table_event_topics() -> Vec<B256> {
    use NodeRegistryV2 as R;
    vec![
        R::NodeRegistered::SIGNATURE_HASH,
        R::NodeStatusChanged::SIGNATURE_HASH,
        R::NodeEndpointUpdated::SIGNATURE_HASH,
        R::NodePgpUpdated::SIGNATURE_HASH,
        R::NodeWalletUpdated::SIGNATURE_HASH,
        R::NodeWalletRevoked::SIGNATURE_HASH,
        R::ServicesUpdated::SIGNATURE_HASH,
        R::NodeSuspended::SIGNATURE_HASH,
        // NodeResumed no longer exists (a top-up never resumes a node; recovery is by vote).
        R::TermRenewalFailed::SIGNATURE_HASH,
        R::NodeMarkedOffline::SIGNATURE_HASH,
        R::NodeBackOnline::SIGNATURE_HASH,
        R::NodeSelfOnline::SIGNATURE_HASH,
        R::NodeOnlineExtended::SIGNATURE_HASH,
        R::NodeSelfOffline::SIGNATURE_HASH,
        R::ServiceMaskSet::SIGNATURE_HASH,
        R::ExitRequested::SIGNATURE_HASH,
        R::Withdrawn::SIGNATURE_HASH,
    ]
}

/// Why a listed row did not enter the forwarding table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowSkip {
    /// Not a TCP node (browser and mobile nodes are reached through their anchors).
    NotTcp,
    /// Not active (exiting, withdrawn, suspended, marked offline).
    Inactive,
    /// Malformed: IP not canonical, PGP not decodable, or key ID not the key's first subkey.
    Bad(&'static str),
    /// The ABI returned a node ID that cannot be represented by the forwarding API.
    InvalidNodeId,
}

/// One `NodeView` row → a forwarding entry. Pure, so the rules are unit-tested.
pub fn node_row(v: &NodeRegistryLens::NodeView) -> Result<ChainNode, RowSkip> {
    if v.status != nr::ST_ACTIVE || !v.active || v.suspended {
        return Err(RowSkip::Inactive);
    }
    match v.nodeType {
        nr::TYPE_TCP => {}
        nr::TYPE_BROWSER | nr::TYPE_MOBILE => return Err(RowSkip::NotTcp),
        _ => return Err(RowSkip::Bad("node_type")),
    }
    let ip = nr::check_canonical_ip(&v.ip).map_err(RowSkip::Bad)?;
    let b64 = std::str::from_utf8(&v.pgpBase64).map_err(|_| RowSkip::Bad("pgp_utf8"))?;
    let armored = B64
        .decode(b64.trim())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(RowSkip::Bad("pgp_base64"))?;
    let cert =
        si_crypto::opgp::PublicCert::from_armor(&armored).map_err(|_| RowSkip::Bad("pgp_key"))?;
    let key_id = cert.enc_key_id().ok_or(RowSkip::Bad("pgp_subkey"))?;
    if !key_id.eq_ignore_ascii_case(&hex::encode(v.keyId)) {
        return Err(RowSkip::Bad("key_id"));
    }
    let id =
        checked_u64(v.nodeId, "NodeRegistryV2 row node id").map_err(|_| RowSkip::InvalidNodeId)?;
    Ok(ChainNode {
        id,
        key_id: key_id.to_uppercase(),
        ip: ip.to_string(),
        pgp_armored: armored,
        port: Some(v.tcpPort).filter(|p| *p != 0),
        services: v.services,
        mailbox: v.services & nr::SVC_MAILBOX != 0,
        wallet: Some(format!("{:#x}", v.nodeWallet)),
    })
}

/// Rows of one table read, sorted into the forwarding set and the counters.
pub fn sort_rows(
    rows: &[NodeRegistryLens::NodeView],
) -> Result<(Vec<ChainNode>, usize, usize), ChainError> {
    let (mut nodes, mut skipped) = (vec![], 0);
    let mut seen = std::collections::HashSet::new();
    let mut seen_key_ids = std::collections::HashSet::new();
    for r in rows {
        match node_row(r) {
            Ok(n) => {
                // A key ID is the route domain and may name only one active wallet. Reject the
                // whole snapshot rather than letting RouteTable's map silently choose a row.
                if !seen_key_ids.insert(n.key_id.clone()) {
                    return Err(ChainError(
                        "duplicate NodeRegistryV2 domain/key ID in active rows".into(),
                    ));
                }
                // One endpoint, one node (the contract enforces it; stay safe on a bad read).
                // Dropping an active row would make a partial table look complete to the watcher.
                if !seen.insert((n.ip.clone(), n.port.unwrap_or(DEFAULT_NODE_FORWARD_PORT))) {
                    return Err(ChainError(
                        "duplicate NodeRegistryV2 endpoint in active rows".into(),
                    ));
                }
                nodes.push(n);
            }
            Err(RowSkip::InvalidNodeId) => {
                return Err(ChainError("NodeRegistryV2 row node id exceeds u64".into()));
            }
            Err(RowSkip::Bad(reason)) => {
                return Err(ChainError(format!(
                    "invalid active NodeRegistryV2 row: {reason}"
                )));
            }
            Err(RowSkip::NotTcp | RowSkip::Inactive) => skipped += 1,
        }
    }
    Ok((nodes, 0, skipped))
}

#[derive(Default)]
struct PageProgress {
    total: Option<u64>,
    read: u64,
}

impl PageProgress {
    /// Validate one page without accepting a partial or internally inconsistent table.
    /// Returns true only when exactly `total` rows have been read.
    fn observe(&mut self, total: u64, page_len: usize, page_size: u64) -> Result<bool, ChainError> {
        match self.total {
            Some(expected) if expected != total => {
                return Err(ChainError(
                    "NodeRegistryV2 total changed during the read".into(),
                ));
            }
            None => self.total = Some(total),
            _ => {}
        }
        let page_len = u64::try_from(page_len)
            .map_err(|_| ChainError("NodeRegistryV2 page length exceeds u64".into()))?;
        if page_len > page_size {
            return Err(ChainError(
                "NodeRegistryV2 page exceeds requested size".into(),
            ));
        }
        if self.read > total {
            return Err(ChainError(
                "NodeRegistryV2 rows already exceed total".into(),
            ));
        }
        if page_len == 0 && self.read < total {
            return Err(ChainError(
                "NodeRegistryV2 returned an empty page before total".into(),
            ));
        }
        let next = self
            .read
            .checked_add(page_len)
            .ok_or_else(|| ChainError("NodeRegistryV2 page count overflow".into()))?;
        if next > total {
            return Err(ChainError("NodeRegistryV2 rows exceed total".into()));
        }
        self.read = next;
        Ok(next == total)
    }
}

#[derive(Clone)]
pub struct Nr2Reader {
    pub rpc: Rpc,
    pub registry: String,
}

impl Nr2Reader {
    pub async fn call<C: SolCall>(
        &self,
        to: &str,
        c: C,
        block: Option<u64>,
    ) -> Result<C::Return, ChainError> {
        let raw = self.rpc.eth_call(to, c.abi_encode(), block).await?;
        C::abi_decode_returns(&raw).map_err(ce)
    }

    pub async fn table_version(&self, block: u64) -> Result<U256, ChainError> {
        self.call(
            &self.registry,
            NodeRegistryV2::tableVersionCall {},
            Some(block),
        )
        .await
    }

    /// 0 = this wallet is not a registered node wallet.
    pub async fn node_id_of_wallet(&self, wallet: &str) -> Result<u64, ChainError> {
        let w: Address = wallet.parse().map_err(ce)?;
        let id = self
            .call(
                &self.registry,
                NodeRegistryV2::nodeIdOfNodeWalletCall { nodeWallet: w },
                None,
            )
            .await?;
        checked_u64(id, "NodeRegistryV2 node id")
    }

    /// `(cid bytes, version, updatedAt)`; empty cid = no policy.
    pub async fn egress_policy(&self, node_id: u64) -> Result<(Vec<u8>, u64, u64), ChainError> {
        let r = self
            .call(
                &self.registry,
                NodeRegistryV2::egressPolicyOfCall {
                    nodeId: U256::from(node_id),
                },
                None,
            )
            .await?;
        Ok((r.cid.to_vec(), r.version, r.updatedAt))
    }
}

/// Node table from NodeRegistryV2 through the Lens.
pub struct Nr2Source {
    pub reader: Nr2Reader,
    pub lens: String,
    pub page: u64,
    pub confirmations: u64,
    /// Widest log query; a longer gap counts as a change (forces a read).
    pub max_log_span: u64,
    scan: Mutex<Scan>,
}

#[derive(Default)]
struct Scan {
    /// Last block whose logs were looked at (0 = not started).
    scanned: u64,
    /// Bumped whenever a scan finds a node event; part of the version string.
    changes: u64,
}

impl Nr2Source {
    pub fn new(rpc: Rpc, registry: &str, lens: &str) -> Self {
        Self {
            reader: Nr2Reader {
                rpc,
                registry: registry.to_string(),
            },
            lens: lens.to_string(),
            page: 100,
            confirmations: 2,
            max_log_span: 5_000,
            scan: Mutex::new(Scan::default()),
        }
    }

    async fn node_events_between(&self, from: u64, to: u64) -> Result<bool, ChainError> {
        let topics: Vec<String> = table_event_topics()
            .iter()
            .map(|t| format!("{t:#x}"))
            .collect();
        let v = self
            .reader
            .rpc
            .call(
                "eth_getLogs",
                json!([{
                    "address": self.reader.registry,
                    "fromBlock": format!("0x{from:x}"),
                    "toBlock": format!("0x{to:x}"),
                    "topics": [topics],
                }]),
            )
            .await?;
        has_log_events(&v)
    }
}

fn has_log_events(v: &Value) -> Result<bool, ChainError> {
    let logs = v
        .as_array()
        .ok_or_else(|| ChainError("eth_getLogs result is not an array".into()))?;
    Ok(!logs.is_empty())
}

impl NodeSource for Nr2Source {
    fn version(&self) -> BoxFut<'_, Result<(String, u64), ChainError>> {
        Box::pin(async move {
            let head = self.reader.rpc.block_number().await?;
            let block = head.saturating_sub(self.confirmations);
            let tv = self.reader.table_version(block).await?;
            let from = self.scan.lock().expect("scan").scanned;
            let changed = if from == 0 || block <= from {
                false
            } else if block - from > self.max_log_span {
                true
            } else {
                self.node_events_between(from + 1, block).await?
            };
            let mut s = self.scan.lock().expect("scan");
            if block > s.scanned {
                s.scanned = block;
            }
            if changed {
                s.changes += 1;
            }
            Ok((format!("{tv}/{}", s.changes), block))
        })
    }

    fn read(&self, block: u64) -> BoxFut<'_, Result<TableSnapshot, ChainError>> {
        Box::pin(async move {
            let mut rows = vec![];
            let mut progress = PageProgress::default();
            let mut first_version: Option<U256> = None;
            for _ in 0..10_000 {
                let r = self
                    .reader
                    .call(
                        &self.lens,
                        NodeRegistryLens::getNodesCall {
                            start: U256::from(progress.read),
                            len: U256::from(self.page),
                        },
                        Some(block),
                    )
                    .await?;
                // Pinned to one block, so the version cannot move between pages.
                if *first_version.get_or_insert(r.version) != r.version {
                    return Err(ChainError("tableVersion moved during the read".into()));
                }
                let total = checked_u64(r.total, "NodeRegistryV2 total")?;
                let complete = progress.observe(total, r.out.len(), self.page)?;
                rows.extend(r.out);
                if complete {
                    let (nodes, rejected, _skipped) = sort_rows(&rows)?;
                    let s = self.scan.lock().expect("scan");
                    return Ok(TableSnapshot {
                        version: format!("{}/{}", first_version.unwrap_or_default(), s.changes),
                        block,
                        nodes,
                        rejected,
                        lists_all_active: true,
                    });
                }
            }
            Err(ChainError("getNodes did not end after 10000 pages".into()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use alloy_sol_types::SolStruct;

    #[test]
    fn node_id_conversion_preserves_explicit_zero_and_rejects_overflow() {
        assert_eq!(checked_u64(U256::ZERO, "id").unwrap(), 0);
        assert_eq!(checked_u64(U256::from(7), "id").unwrap(), 7);
        assert!(checked_u64(U256::MAX, "id").is_err());
    }

    #[test]
    fn get_logs_requires_an_array_and_keeps_empty_array_as_no_events() {
        assert!(!has_log_events(&serde_json::json!([])).unwrap());
        assert!(has_log_events(&serde_json::json!([{}])).unwrap());
        for malformed in [
            serde_json::json!(null),
            serde_json::json!(false),
            serde_json::json!(0),
            serde_json::json!({}),
        ] {
            assert!(has_log_events(&malformed).is_err(), "{malformed}");
        }
    }

    fn golden() -> serde_json::Value {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/golden.json"
        );
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn view(armored: &str, key_id: &str) -> NodeRegistryLens::NodeView {
        let id: [u8; 8] = hex::decode(key_id).unwrap().try_into().unwrap();
        NodeRegistryLens::NodeView {
            nodeId: U256::from(7),
            nodeWallet: Address::repeat_byte(0x11),
            status: nr::ST_ACTIVE,
            active: true,
            nodeType: nr::TYPE_TCP,
            services: nr::SVC_ENTRY | nr::SVC_MAILBOX,
            keyId: FixedBytes(id),
            ip: "192.0.2.10".into(),
            tcpPort: 8443,
            pgpBase64: B64.encode(armored).into_bytes().into(),
            ..Default::default()
        }
    }

    #[test]
    fn pagination_requires_stable_total_and_exact_nonempty_progress() {
        let mut progress = PageProgress::default();
        assert!(!progress.observe(4, 2, 2).unwrap());
        assert!(progress.observe(4, 2, 2).unwrap());

        let mut empty_before_total = PageProgress::default();
        assert!(!empty_before_total.observe(3, 1, 2).unwrap());
        assert!(empty_before_total.observe(3, 0, 2).is_err());

        let mut changed_total = PageProgress::default();
        assert!(!changed_total.observe(3, 1, 2).unwrap());
        assert!(changed_total.observe(4, 1, 2).is_err());

        let mut exceeds_total = PageProgress::default();
        assert!(exceeds_total.observe(2, 3, 3).is_err());

        let mut exceeds_page = PageProgress::default();
        assert!(exceeds_page.observe(4, 3, 2).is_err());

        let mut empty_table = PageProgress::default();
        assert!(empty_table.observe(0, 0, 2).unwrap());
    }

    #[test]
    fn duplicate_active_domain_rejects_snapshot_for_same_or_conflicting_wallet() {
        let g = golden();
        let armored = g["keys"]["nodeA"]["armoredPublic"].as_str().unwrap();
        let kid = g["keys"]["nodeA"]["encKeyId"].as_str().unwrap();

        for conflicting_wallet in [false, true] {
            let first = view(armored, kid);
            let mut second = view(armored, kid);
            second.ip = "192.0.2.11".into();
            if conflicting_wallet {
                second.nodeWallet = Address::repeat_byte(0x22);
            }
            assert!(sort_rows(&[first.clone(), second.clone()]).is_err());
            assert!(sort_rows(&[second, first]).is_err());
        }
    }

    #[test]
    fn abi_struct_matches_the_eip712_vectors() {
        assert_eq!(
            NodeRegistryV2::RegisterRequest::eip712_encode_type(),
            nr::REGISTER_REQUEST_TYPE
        );
    }

    #[test]
    fn rows_are_checked() {
        let g = golden();
        let armored = g["keys"]["nodeA"]["armoredPublic"].as_str().unwrap();
        let kid = g["keys"]["nodeA"]["encKeyId"].as_str().unwrap();
        let ok = node_row(&view(armored, kid)).unwrap();
        assert_eq!(ok.key_id, kid.to_uppercase());
        assert_eq!(
            (ok.ip.as_str(), ok.port, ok.mailbox),
            ("192.0.2.10", Some(8443), true)
        );
        assert_eq!(
            ok.wallet.as_deref(),
            Some("0x1111111111111111111111111111111111111111")
        );

        let mut v = view(armored, kid);
        v.services = nr::SVC_ENTRY;
        assert!(!node_row(&v).unwrap().mailbox);
        let mut v = view(armored, kid);
        v.nodeType = nr::TYPE_BROWSER;
        assert_eq!(node_row(&v).unwrap_err(), RowSkip::NotTcp);
        let mut v = view(armored, kid);
        v.nodeType = nr::TYPE_MOBILE;
        assert_eq!(node_row(&v).unwrap_err(), RowSkip::NotTcp);
        for unknown_node_type in [0, 4] {
            let mut v = view(armored, kid);
            v.nodeType = unknown_node_type;
            assert_eq!(node_row(&v), Err(RowSkip::Bad("node_type")));
            assert!(sort_rows(&[v]).is_err());
        }
        for f in [
            |v: &mut NodeRegistryLens::NodeView| v.active = false,
            |v: &mut NodeRegistryLens::NodeView| v.suspended = true,
            |v: &mut NodeRegistryLens::NodeView| v.status = 2,
        ] {
            let mut v = view(armored, kid);
            f(&mut v);
            assert_eq!(node_row(&v).unwrap_err(), RowSkip::Inactive);
        }
        let mut v = view(armored, kid);
        v.ip = "192.000.2.10".into();
        assert!(matches!(node_row(&v), Err(RowSkip::Bad(_))));
        let other = g["keys"]["nodeB"]["encKeyId"].as_str().unwrap();
        assert_eq!(
            node_row(&view(armored, other)).unwrap_err(),
            RowSkip::Bad("key_id")
        );
        let mut v = view(armored, kid);
        v.pgpBase64 = b"not base64!".to_vec().into();
        assert!(matches!(node_row(&v), Err(RowSkip::Bad(_))));
        let mut v = view(armored, kid);
        v.tcpPort = 0;
        assert_eq!(node_row(&v).unwrap().port, None);

        // A duplicate active endpoint with a distinct domain is an incomplete, ambiguous table.
        let other_armored = g["keys"]["nodeB"]["armoredPublic"].as_str().unwrap();
        let other = g["keys"]["nodeB"]["encKeyId"].as_str().unwrap();
        let endpoint_duplicate = vec![view(armored, kid), view(other_armored, other)];
        assert!(sort_rows(&endpoint_duplicate).is_err());

        // Port zero is forwarded on the default port, so it conflicts with an explicit 80.
        let mut default_port = view(armored, kid);
        default_port.tcpPort = 0;
        let mut explicit_default = view(other_armored, other);
        explicit_default.ip = default_port.ip.clone();
        explicit_default.tcpPort = DEFAULT_NODE_FORWARD_PORT;
        assert!(sort_rows(&[default_port, explicit_default]).is_err());

        // Expected non-TCP rows are skipped without turning a healthy snapshot into a failure.
        let rows = vec![view(armored, kid), {
            let mut v = view(armored, kid);
            v.nodeType = nr::TYPE_MOBILE;
            v
        }];
        let (nodes, rejected, skipped) = sort_rows(&rows).unwrap();
        assert_eq!((nodes.len(), rejected, skipped), (1, 0, 1));

        // An active row that cannot be attributed to a verified domain is not silently dropped.
        let mut malformed_active = view(armored, kid);
        malformed_active.ip = "192.000.2.10".into();
        assert!(sort_rows(&[malformed_active]).is_err());

        let mut overflow = view(armored, kid);
        overflow.nodeId = U256::MAX;
        assert_eq!(node_row(&overflow), Err(RowSkip::InvalidNodeId));
        assert!(sort_rows(&[overflow]).is_err());
    }

    #[test]
    fn event_topics_are_distinct() {
        let t = table_event_topics();
        let mut u = t.clone();
        u.sort();
        u.dedup();
        assert_eq!(t.len(), u.len());
        assert_eq!(
            format!("{:#x}", NodeRegistryV2::NodePgpUpdated::SIGNATURE_HASH),
            format!(
                "{:#x}",
                alloy_primitives::keccak256("NodePgpUpdated(uint256,bytes8,bytes8,bytes32)")
            )
        );
    }
}

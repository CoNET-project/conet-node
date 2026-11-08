//! Reads a NodeRegistryV2 deployed on a LOCAL anvil chain (chain id 224422). Runs only when
//! `NR2_RPC`, `NR2_REGISTRY` and `NR2_LENS` are set; CI does not set them, because the contract
//! sources are not committed upstream yet. Expected state (made with `conet-register` + cast):
//! - legacy id 7: golden nodeA key and wallet, 127.0.0.1:18080, services 0x29 (no mailbox);
//! - a sponsored node: golden nodeB key and wallet, 127.0.0.2:18090, services 0x03 (mailbox);
//! - node 7's egress policy pointer = CID of `POLICY` below.
use conet_node::chain::{NodeSource, Rpc};
use conet_node::egress::ChainGate;
use conet_node::nr2::{Nr2Reader, Nr2Source};
use conet_node::register::policy_cid;
use conet_node::route::{Resolved, RouteTable};
use conet_node::watcher;
use serde_json::Value;
use std::time::Duration;

const POLICY: &[u8] = br#"{"version":1,"mode":"allowlist","allow":["example.com"],"ports":[443],"limits":{"maxConnsPerWallet":32}}"#;

fn env() -> Option<(String, String, String)> {
    Some((
        std::env::var("NR2_RPC").ok()?,
        std::env::var("NR2_REGISTRY").ok()?,
        std::env::var("NR2_LENS").ok()?,
    ))
}

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[tokio::test]
async fn table_routes_and_policy_from_a_local_registry() {
    let Some((rpc, registry, lens)) = env() else {
        eprintln!("skipped: NR2_RPC / NR2_REGISTRY / NR2_LENS not set");
        return;
    };
    let g = golden();
    let ka = g["keys"]["nodeA"]["encKeyId"]
        .as_str()
        .unwrap()
        .to_uppercase();
    let kb = g["keys"]["nodeB"]["encKeyId"]
        .as_str()
        .unwrap()
        .to_uppercase();
    let src = Nr2Source::new(Rpc::new(&rpc).unwrap(), &registry, &lens);
    let (v1, block) = src.version().await.unwrap();
    let (v2, _) = src.version().await.unwrap();
    assert_eq!(v1, v2, "no node events between two polls");
    let snap = src.read(block).await.unwrap();
    assert_eq!(snap.rejected, 0);
    assert!(snap.lists_all_active);
    let a = snap.nodes.iter().find(|n| n.key_id == ka).expect("node 7");
    assert_eq!(
        (a.id, a.ip.as_str(), a.port, a.mailbox),
        (7, "127.0.0.1", Some(18080), false)
    );
    let b = snap
        .nodes
        .iter()
        .find(|n| n.key_id == kb)
        .expect("sponsored node");
    assert_eq!(
        (b.ip.as_str(), b.port, b.mailbox),
        ("127.0.0.2", Some(18090), true)
    );
    assert!(b.id >= 572, "new ids start after the migration range");

    // Into a route table, as the watcher does; user routes follow the mailbox bit.
    let routes = RouteTable::new("FFFFFFFFFFFFFFFF", Duration::from_secs(60));
    assert!(watcher::apply(&routes, &snap, 80, 0.8));
    routes.set_user_route("USER1", &kb);
    routes.set_user_route("USER2", &ka);
    assert_eq!(
        routes.resolve("USER1"),
        Resolved::Remote("127.0.0.2:18090".parse().unwrap())
    );
    assert_eq!(
        routes.resolve("USER2"),
        Resolved::NoRoute,
        "node 7 holds no mailboxes"
    );
    assert_eq!(
        routes.resolve(&ka),
        Resolved::Remote("127.0.0.1:18080".parse().unwrap()),
        "still a forwarding target"
    );

    // Egress policy pointer: node id from the wallet, then the 36-byte CID.
    let reader = Nr2Reader {
        rpc: Rpc::new(&rpc).unwrap(),
        registry,
    };
    let wa = g["wallets"]["nodeA"]["address"].as_str().unwrap();
    assert_eq!(reader.node_id_of_wallet(wa).await.unwrap(), 7);
    let (cid, version, _at) = reader.egress_policy(7).await.unwrap();
    assert_eq!(version, 1);
    let gate = ChainGate::new(policy_cid(POLICY).unwrap(), false);
    assert!(gate.update(&cid));
    let other = ChainGate::new(policy_cid(b"{}").unwrap(), true);
    assert!(!other.update(&cid), "another file does not match");
    let wb = g["wallets"]["nodeB"]["address"].as_str().unwrap();
    let id_b = reader.node_id_of_wallet(wb).await.unwrap();
    assert!(reader.egress_policy(id_b).await.unwrap().0.is_empty());
}

/// With `NR2_WAIT_EVENT=1`: poll until a node event (sent by the operator meanwhile, e.g.
/// `updateServices` on node 7) changes the version string, even if `tableVersion` does not.
#[tokio::test]
async fn node_event_changes_the_version() {
    let (Some((rpc, registry, lens)), Ok(_)) = (env(), std::env::var("NR2_WAIT_EVENT")) else {
        eprintln!("skipped: needs NR2_* and NR2_WAIT_EVENT");
        return;
    };
    let mut src = Nr2Source::new(Rpc::new(&rpc).unwrap(), &registry, &lens);
    src.confirmations = 0;
    let (v0, _) = src.version().await.unwrap();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (v, _) = src.version().await.unwrap();
        if v != v0 {
            eprintln!("version {v0} -> {v}");
            return;
        }
    }
    panic!("no change seen");
}

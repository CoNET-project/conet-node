//! F5 vote gate against the node line's contract on a LOCAL anvil (chain 224422). TEST keys only.
//!
//! Runs only with `F5_RPC` and `F5_REGISTRY` set (CI does not: the contract sources are not
//! upstream yet). Expected state, made by `tools/vote-gate/setup.sh` (`conet-register` + cast):
//! node 7 = golden nodeA (maintenance bit), a sponsored golden nodeB (no maintenance bit) and a
//! sponsored golden nodeC (maintenance bit), all freshly registered (in the 7-day vote cooldown).
//!
//! For every state the gate's answer is compared with an `eth_call` of the same transaction from
//! the node wallet: both must agree (accepted, or the matching contract error). Transactions that
//! move the scenario forward (one report, one vote) go through anvil account impersonation:
//! nothing is signed. The test changes time and storage inside an `evm_snapshot` and reverts it
//! at the end, so one setup serves repeated runs (a failed run leaves the chain changed).
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolCall;
use conet_node::chain::Rpc;
use conet_node::nr2::NodeRegistryV2;
use conet_node::vote_gate::*;
use serde_json::{json, Value};

/// `forge inspect NodeRegistryV2 storageLayout` for source set `bee380fd2c26bd66`:
/// `s.nodes` is mapping slot 5; `Node.voteLocked` is member slot 10, offset 0 (16 bytes).
const NODES_SLOT: u64 = 5;
const LOCKED_MEMBER_SLOT: u64 = 10;

struct Chain {
    rpc: Rpc,
    reg: String,
}

impl Chain {
    async fn simulate(&self, from: &str, data: Vec<u8>) -> Result<(), String> {
        let r = self
            .rpc
            .call(
                "eth_call",
                json!([{ "from": from, "to": self.reg, "data": format!("0x{}", hex::encode(data)) }, "latest"]),
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(e) => Err(error_name(&e.0)),
        }
    }

    async fn send(&self, from: &str, data: Vec<u8>) {
        self.rpc
            .call("anvil_impersonateAccount", json!([from]))
            .await
            .unwrap();
        let h = self
            .rpc
            .call(
                "eth_sendTransaction",
                json!([{ "from": from, "to": self.reg, "data": format!("0x{}", hex::encode(data)), "gas": "0x7a1200" }]),
            )
            .await
            .unwrap();
        let mut rc = Value::Null;
        for _ in 0..50 {
            rc = self
                .rpc
                .call("eth_getTransactionReceipt", json!([h]))
                .await
                .unwrap();
            if !rc.is_null() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(rc["status"], "0x1", "transaction failed: {rc}");
        self.rpc
            .call("anvil_stopImpersonatingAccount", json!([from]))
            .await
            .unwrap();
    }

    async fn warp(&self, secs: u64) {
        self.rpc
            .call("evm_increaseTime", json!([secs]))
            .await
            .unwrap();
        self.rpc.call("evm_mine", json!([])).await.unwrap();
    }

    async fn now(&self) -> u64 {
        let b = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await
            .unwrap();
        u64::from_str_radix(
            b["timestamp"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap()
    }

    /// Overwrite `Node.voteLocked` of a node (the low 16 bytes of its slot).
    async fn set_locked(&self, node: u64, locked: u128) {
        let mut key = U256::from(node).to_be_bytes::<32>().to_vec();
        key.extend_from_slice(&U256::from(NODES_SLOT).to_be_bytes::<32>());
        let base = U256::from_be_bytes(keccak256(&key).0);
        let slot = format!("0x{:064x}", base + U256::from(LOCKED_MEMBER_SLOT));
        let cur = self
            .rpc
            .call("eth_getStorageAt", json!([self.reg, slot, "latest"]))
            .await
            .unwrap();
        let mut w = hex::decode(cur.as_str().unwrap().trim_start_matches("0x")).unwrap();
        w.resize(32, 0);
        w[16..].copy_from_slice(&locked.to_be_bytes());
        self.rpc
            .call(
                "anvil_setStorageAt",
                json!([self.reg, slot, format!("0x{}", hex::encode(&w))]),
            )
            .await
            .unwrap();
    }
}

/// Name of the custom error in an eth_call failure, from its 4-byte selector.
fn error_name(err: &str) -> String {
    const NAMES: [&str; 9] = [
        "ReporterNotEligible",
        "VoteCooldown",
        "NotReportable",
        "AlreadyVoted",
        "ReportNotOpen",
        "ReportExpired",
        "StakeLocked",
        "ReportOpenAlready",
        "MinOpenNotPassed",
    ];
    for n in NAMES {
        let sel = hex::encode(&keccak256(format!("{n}()").as_bytes())[..4]);
        if err.contains(&sel) {
            return n.to_string();
        }
    }
    format!("unknown: {err}")
}

/// The contract error a gate refusal predicts.
fn expected(s: &Skip) -> &'static str {
    match s {
        Skip::NotActive | Skip::NoMaintBit => "ReporterNotEligible",
        Skip::Cooldown { .. } => "VoteCooldown",
        Skip::IsTarget | Skip::TargetNotReportable => "NotReportable",
        Skip::AlreadyVoted => "AlreadyVoted",
        Skip::NotOpen => "ReportNotOpen",
        Skip::Expired => "ReportExpired",
        Skip::NoLockCapacity { .. } => "StakeLocked",
        Skip::ReportOpen { .. } => "ReportOpenAlready",
    }
}

fn agree(what: &str, gate: &Result<(), Skip>, chain: &Result<(), String>) {
    match (gate, chain) {
        (Ok(()), Ok(())) => {}
        (Err(s), Err(e)) if expected(s) == e => {}
        _ => panic!("{what}: gate {gate:?} but contract {chain:?}"),
    }
}

fn report_call(target: u64) -> Vec<u8> {
    NodeRegistryV2::reportOfflineCall {
        targetNodeId: U256::from(target),
    }
    .abi_encode()
}

fn vote_call(rid: u64, yes: bool) -> Vec<u8> {
    NodeRegistryV2::voteReportCall {
        reportId: U256::from(rid),
        agree: yes,
    }
    .abi_encode()
}

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[tokio::test]
async fn gate_matches_the_contract_on_local_anvil() {
    let (Ok(url), Ok(reg)) = (std::env::var("F5_RPC"), std::env::var("F5_REGISTRY")) else {
        eprintln!("skipped: F5_RPC / F5_REGISTRY not set");
        return;
    };
    let ch = Chain {
        rpc: Rpc::new(&url).unwrap(),
        reg: reg.clone(),
    };
    // Snapshot now, revert at the end, so one setup serves repeated runs.
    let snap = ch.rpc.call("evm_snapshot", json!([])).await.unwrap();
    let rd = VoteReader {
        rpc: Rpc::new(&url).unwrap(),
        registry: reg.clone(),
    };
    let g = golden();
    let wallet = |n: &str| g["wallets"][n]["address"].as_str().unwrap().to_string();
    let (wa, wb, wc) = (wallet("nodeA"), wallet("nodeB"), wallet("nodeC"));
    let nr = conet_node::nr2::Nr2Reader {
        rpc: Rpc::new(&url).unwrap(),
        registry: reg.clone(),
    };
    let (a, b, c) = (
        nr.node_id_of_wallet(&wa).await.unwrap(),
        nr.node_id_of_wallet(&wb).await.unwrap(),
        nr.node_id_of_wallet(&wc).await.unwrap(),
    );
    assert!(a == 7 && b > 0 && c > 0, "setup: ids {a} {b} {c}");
    let fine = rd.fine_now().await.unwrap();
    assert_eq!(
        fine, 1_000_000_000_000_000_000,
        "F = 20% of a 5 CNET threshold"
    );

    // 1. Freshly registered: everyone is in the 7-day cooldown.
    let now = ch.now().await;
    let va = rd.voter(a).await.unwrap();
    assert!(
        va.eligible_at > now,
        "setup must be fresh (cooldown running)"
    );
    let gate = can_report(&va, b, true, None, fine, now);
    assert!(matches!(gate, Err(Skip::Cooldown { .. })));
    agree(
        "cooldown report",
        &gate,
        &ch.simulate(&wa, report_call(b)).await,
    );

    // 2. After the cooldown.
    ch.warp(7 * 86_400 + 60).await;
    let now = ch.now().await;
    let (va, vb, vc) = (
        rd.voter(a).await.unwrap(),
        rd.voter(b).await.unwrap(),
        rd.voter(c).await.unwrap(),
    );
    assert_eq!(va.locked, 0);
    let cases = [
        ("A reports B", &va, b, &wa),
        ("A reports itself", &va, a, &wa),
        ("B (no maintenance bit) reports A", &vb, a, &wb),
        ("C reports B", &vc, b, &wc),
    ];
    for (what, v, target, w) in cases {
        let gate = can_report(v, target, true, None, fine, now);
        agree(what, &gate, &ch.simulate(w, report_call(target)).await);
    }

    // 3. A opens the report on B (impersonated, not signed).
    ch.send(&wa, report_call(b)).await;
    let rid = rd.report_count().await.unwrap();
    let r = rd.report(rid).await.unwrap();
    assert_eq!((r.target, r.reporter, r.agree, r.fine), (b, a, 1, fine));
    // The reader sees the lock the report took: decoded getNodeRaw matches the contract.
    let va = rd.voter(a).await.unwrap();
    assert_eq!(va.locked, fine);
    assert_eq!(rd.voter(b).await.unwrap().open_report_id, rid);
    let now = ch.now().await;
    for (what, id, w) in [
        ("A votes (reporter)", a, &wa),
        ("B votes (target)", b, &wb),
        ("C votes", c, &wc),
    ] {
        let v = rd.voter(id).await.unwrap();
        let gate = can_vote(&v, &r, rd.choice(rid, id).await.unwrap(), now);
        agree(what, &gate, &ch.simulate(w, vote_call(rid, false)).await);
    }
    let open = Some(&r);
    let gate = can_report(&rd.voter(c).await.unwrap(), b, true, open, fine, now);
    assert!(matches!(gate, Err(Skip::ReportOpen { .. })));
    agree(
        "C reports B again",
        &gate,
        &ch.simulate(&wc, report_call(b)).await,
    );

    // 4. Lock capacity at the boundary: locked = stake, stake - F, stake - F + 1.
    let stake = rd.voter(c).await.unwrap().stake;
    for (what, locked) in [
        ("C fully locked", stake),
        ("C exactly one F free", stake - fine),
        ("C one wei short", stake - fine + 1),
    ] {
        ch.set_locked(c, locked).await;
        let v = rd.voter(c).await.unwrap();
        assert_eq!(v.locked, locked);
        let gate = can_vote(&v, &r, 0, now);
        agree(what, &gate, &ch.simulate(&wc, vote_call(rid, false)).await);
        assert_eq!(
            pick(&v, std::slice::from_ref(&r), &[0], now).len(),
            gate.is_ok() as usize
        );
    }
    ch.set_locked(c, 0).await;

    // 5. C votes; its lock goes up by F, and a second vote is refused by both.
    ch.send(&wc, vote_call(rid, false)).await;
    let vc = rd.voter(c).await.unwrap();
    assert_eq!(vc.locked, fine);
    assert_eq!(rd.choice(rid, c).await.unwrap(), 2);
    let r = rd.report(rid).await.unwrap();
    assert_eq!((r.agree, r.disagree), (1, 1));
    let gate = can_vote(&vc, &r, 2, ch.now().await);
    agree(
        "C votes twice",
        &gate,
        &ch.simulate(&wc, vote_call(rid, true)).await,
    );
    assert!(pick(&vc, std::slice::from_ref(&r), &[2], ch.now().await).is_empty());

    // 6. After expiry both refuse.
    ch.warp(7 * 86_400).await;
    let now = ch.now().await;
    let gate = can_vote(&rd.voter(c).await.unwrap(), &r, 0, now);
    assert_eq!(gate, Err(Skip::Expired));
    // C already voted, but expiry is checked first by both.
    agree(
        "vote after expiry",
        &gate,
        &ch.simulate(&wc, vote_call(rid, true)).await,
    );

    assert_eq!(
        ch.rpc.call("evm_revert", json!([snap])).await.unwrap(),
        json!(true)
    );
}

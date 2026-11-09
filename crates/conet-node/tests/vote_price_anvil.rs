//! Votes under base-fee spikes on a LOCAL anvil (chain 224422), TEST keys only (VOTE-MUST).
//!
//! Runs only with `F5_RPC` and `F5_REGISTRY` (state from `tools/vote-gate/setup.sh`). The vote
//! is priced with `vote_price::estimate`, then anvil raises the next block's base fee to 20x,
//! 100x and to 1,000 gwei: the send loop's replacement (`on_pending`) gets it mined, and the
//! wallet pays base fee + tip, not maxFee. A balance too low for the base fee is an obstacle;
//! after a top-up the vote goes out. Transactions go through anvil impersonation (nothing is signed); every
//! scenario runs inside `evm_snapshot` / `evm_revert`.
use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use conet_node::chain::Rpc;
use conet_node::nr2::{NodeRegistryV2, Nr2Reader};
use conet_node::vote_gate::{can_vote, VoteReader};
use conet_node::vote_price::*;
use serde_json::{json, Value};

const GWEI: u64 = 1_000_000_000;
const CNET: u128 = 1_000_000_000_000_000_000;
const GAS: u64 = 6_000_000;

fn hexu(v: &Value) -> u128 {
    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

struct A {
    rpc: Rpc,
    reg: String,
}

impl A {
    async fn call(&self, m: &str, p: Value) -> Value {
        self.rpc
            .call(m, p)
            .await
            .unwrap_or_else(|e| panic!("{m}: {}", e.0))
    }
    async fn base_fee(&self) -> u64 {
        let b = self
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await;
        hexu(&b["baseFeePerGas"]) as u64
    }
    async fn balance(&self, w: &str) -> u128 {
        hexu(&self.call("eth_getBalance", json!([w, "latest"])).await)
    }
    async fn set_balance(&self, w: &str, v: u128) {
        self.call("anvil_setBalance", json!([w, format!("0x{v:x}")]))
            .await;
    }
    async fn next_base_fee(&self, v: u64) {
        self.call(
            "anvil_setNextBlockBaseFeePerGas",
            json!([format!("0x{v:x}")]),
        )
        .await;
    }
    /// Send a type 2 transaction from `from` (impersonated); returns the receipt.
    async fn send(&self, from: &str, data: Vec<u8>, p: Price) -> Value {
        self.call("anvil_impersonateAccount", json!([from])).await;
        let h = self
            .call(
                "eth_sendTransaction",
                json!([{
                    "from": from, "to": self.reg, "type": "0x2",
                    "data": format!("0x{}", hex::encode(data)),
                    "gas": format!("0x{GAS:x}"),
                    "maxFeePerGas": format!("0x{:x}", p.max_fee_wei),
                    "maxPriorityFeePerGas": format!("0x{:x}", p.tip_wei),
                }]),
            )
            .await;
        let mut rc = Value::Null;
        for _ in 0..50 {
            rc = self.call("eth_getTransactionReceipt", json!([h])).await;
            if !rc.is_null() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        self.call("anvil_stopImpersonatingAccount", json!([from]))
            .await;
        rc
    }
}

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[tokio::test]
async fn votes_go_out_through_base_fee_spikes() {
    let (Ok(url), Ok(reg)) = (std::env::var("F5_RPC"), std::env::var("F5_REGISTRY")) else {
        eprintln!("skipped: F5_RPC / F5_REGISTRY not set");
        return;
    };
    let a = A {
        rpc: Rpc::new(&url).unwrap(),
        reg: reg.clone(),
    };
    let top = a.call("evm_snapshot", json!([])).await;
    let g = golden();
    let w = |n: &str| g["wallets"][n]["address"].as_str().unwrap().to_string();
    let (wa, wb, wc) = (w("nodeA"), w("nodeB"), w("nodeC"));
    let nr = Nr2Reader {
        rpc: Rpc::new(&url).unwrap(),
        registry: reg.clone(),
    };
    let rd = VoteReader {
        rpc: Rpc::new(&url).unwrap(),
        registry: reg.clone(),
    };
    let b = nr.node_id_of_wallet(&wb).await.unwrap();
    let c = nr.node_id_of_wallet(&wc).await.unwrap();

    // Past the cooldown, A opens a report on B (impersonated, priced normally).
    a.call("evm_increaseTime", json!([7 * 86_400 + 60])).await;
    a.call("evm_mine", json!([])).await;
    let cfg = PriceCfg::default();
    let report = NodeRegistryV2::reportOfflineCall {
        targetNodeId: U256::from(b),
    }
    .abi_encode();
    let p = estimate(
        &cfg,
        &[a.base_fee().await],
        1_000_000,
        GAS,
        a.balance(&wa).await,
    )
    .unwrap()
    .price;
    let rc = a.send(&wa, report, p).await;
    assert_eq!(rc["status"], "0x1", "report: {rc}");
    let rid = rd.report_count().await.unwrap();
    let vote = NodeRegistryV2::voteReportCall {
        reportId: U256::from(rid),
        agree: false,
    }
    .abi_encode();
    let after_report = a.call("evm_snapshot", json!([])).await;

    // C is a valid voter (vote gate), with 10 CNET.
    let now = hexu(
        &a.call("eth_getBlockByNumber", json!(["latest", false]))
            .await["timestamp"],
    ) as u64;
    let r = rd.report(rid).await.unwrap();
    assert_eq!(can_vote(&rd.voter(c).await.unwrap(), &r, 0, now), Ok(()));

    let mut snap = after_report;
    for (what, spike) in [("20x", 20u64), ("100x", 100), ("1,000 gwei", 0)] {
        a.set_balance(&wc, 10 * CNET).await;
        // Price the vote at a 1 gwei base fee (10x the old 0.1 gwei cap already) ...
        a.next_base_fee(GWEI).await;
        a.call("evm_mine", json!([])).await;
        let base0 = a.base_fee().await;
        let e = estimate(&cfg, &[base0], 1_000_000, GAS, 10 * CNET).unwrap();
        // ... then the base fee jumps before the vote is mined.
        let spiked = if spike == 0 {
            1_000 * GWEI
        } else {
            base0 * spike
        };
        a.next_base_fee(spiked).await;
        let before = a.balance(&wc).await;
        // The price made at the old base fee no longer fits: anvil refuses it outright (geth
        // would keep it pending). The send loop treats both as "priced out" and replaces at
        // the latest base fee.
        let price = match on_pending(&cfg, e.price, 0, 30, spiked, 10 * CNET, GAS, u64::MAX) {
            Step::Replace(p) => p,
            Step::Rebroadcast => e.price,
            other => panic!("{what}: {other:?}"),
        };
        let rc = a.send(&wc, vote.clone(), price).await;
        assert_eq!(rc["status"], "0x1", "{what}: {rc}");
        let paid = before - a.balance(&wc).await;
        let used = hexu(&rc["gasUsed"]);
        let eff = hexu(&rc["effectiveGasPrice"]);
        // Charged base fee + tip, never maxFee.
        assert_eq!(eff, spiked as u128 + price.tip_wei as u128, "{what}");
        assert_eq!(paid, used * eff, "{what}");
        assert!(paid <= GAS as u128 * price.max_fee_wei as u128);
        assert_eq!(rd.choice(rid, c).await.unwrap(), 2, "{what}: vote recorded");
        assert_eq!(a.call("evm_revert", json!([snap])).await, json!(true));
        snap = a.call("evm_snapshot", json!([])).await;
    }

    // Balance too low for a 1,000 gwei base fee: an obstacle; after a top-up the vote goes out.
    a.set_balance(&wc, 3 * CNET / 10).await;
    let o = estimate(&cfg, &[1_000 * GWEI], 1_000_000, GAS, 3 * CNET / 10).unwrap_err();
    assert!(matches!(o, Obstacle::Balance { .. }));
    a.set_balance(&wc, 10 * CNET).await;
    let e = estimate(&cfg, &[1_000 * GWEI], 1_000_000, GAS, a.balance(&wc).await).unwrap();
    a.next_base_fee(1_000 * GWEI).await;
    let rc = a.send(&wc, vote.clone(), e.price).await;
    assert_eq!(rc["status"], "0x1", "after top-up: {rc}");

    assert_eq!(a.call("evm_revert", json!([top])).await, json!(true));
    let _ = snap;
}

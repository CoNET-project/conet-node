//! Smart-wallet compatibility against the REAL BeamioAccount (fork 4's verbatim fixture 0f8ad23, source 8cf6a697),
//! recorded on a local Hardhat chain by `tools/service-order/beamio-wallet-fixture.test.ts` (test keys only) into
//! `data/beamio-wallet-fixture.json`.
//!
//! For each case the node runs its own path (`service_order::verify_signature`: ECDSA first, then the code-hash gate,
//! then `isValidSignature(digest, sig)` with its gas cap) against a local JSON-RPC that serves the account's recorded
//! runtime code and the account's own recorded answer for exactly the calldata the node builds. A calldata the fixture
//! did not record fails the test, so the node's request must equal the one the real contract answered. The node's
//! verdict must equal the contract's in every case, including after the managers or the threshold changed.
use alloy_primitives::{Address, B256, U256};
use conet_node::service_order::draft::{self, SettlementOrder};
use conet_node::service_order::*;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod common;

fn fixture() -> Value {
    serde_json::from_str(include_str!("data/beamio-wallet-fixture.json")).unwrap()
}
fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}
fn order(o: &Value) -> SettlementOrder {
    let s = |k: &str| o[k].as_str().unwrap();
    SettlementOrder {
        pool: s("pool").parse().unwrap(),
        user: s("user").parse().unwrap(),
        nodeId: s("nodeId").parse().unwrap(),
        nodeWallet: s("nodeWallet").parse().unwrap(),
        minNodeGb: U256::from_str(s("minNodeGb")).unwrap(),
        maxUserPay: U256::from_str(s("maxUserPay")).unwrap(),
        gbBaseVersion: s("gbBaseVersion").parse().unwrap(),
        markupVersion: s("markupVersion").parse().unwrap(),
        freeExchangeVersion: s("freeExchangeVersion").parse().unwrap(),
        freePoolVersion: s("freePoolVersion").parse().unwrap(),
        serviceBit: s("serviceBit").parse().unwrap(),
        deadline: s("deadline").parse().unwrap(),
        nonce: s("nonce").parse().unwrap(),
    }
}

/// Local JSON-RPC serving one case's recorded code and answers; counts eth_call.
async fn replay(c: &Value) -> (conet_node::chain::Rpc, Arc<AtomicUsize>) {
    let code = c["code"].as_str().unwrap().to_string();
    let rpc = c["rpc"].as_object().unwrap().clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let url = common::serve(Arc::new(move |m: &str, p: &Value| match m {
        "eth_getCode" => json!(code),
        "eth_call" => {
            n.fetch_add(1, Ordering::SeqCst);
            let data = p[0]["data"].as_str().unwrap().to_lowercase();
            rpc.get(&data).cloned().unwrap_or_else(|| {
                panic!("the node sent a call the real contract was not asked: {data}")
            })
        }
        m => panic!("unexpected {m}"),
    }))
    .await;
    (conet_node::chain::Rpc::new(&url).unwrap(), calls)
}

#[tokio::test(flavor = "multi_thread")]
async fn node_verdict_equals_the_real_beamio_account() {
    let f = fixture();
    let o = order(&f["order"]);
    let token: Address = f["token"].as_str().unwrap().parse().unwrap();
    // The order is fork 5's draft layout: the node's digest equals the one the wallet was asked about.
    let d = draft::digest(&o, token);
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    let hash: B256 = cases[0]["codeHash"].as_str().unwrap().parse().unwrap();
    let policy = WalletPolicy {
        accepted_code_hashes: vec![hash],
        gas_cap: 200_000,
        timeout: Duration::from_secs(10),
    };
    let (mut ok, mut refused) = (0, 0);
    for c in cases {
        let label = c["label"].as_str().unwrap();
        assert_eq!(c["digest"].as_str().unwrap(), format!("{d:#x}"), "{label}");
        // Policy changes do not change the runtime code: one code hash for the account.
        assert_eq!(
            c["codeHash"].as_str().unwrap(),
            format!("{hash:#x}"),
            "{label}"
        );
        let user: Address = c["account"].as_str().unwrap().parse().unwrap();
        assert_eq!(user, o.user);
        let (rpc, calls) = replay(c).await;
        let got = verify_signature(
            &rpc,
            d,
            &hexb(c["signature"].as_str().unwrap()),
            user,
            &policy,
        )
        .await;
        let want = c["valid"].as_bool().unwrap();
        assert_eq!(got.is_ok(), want, "{label}: {got:?}");
        if !want {
            assert_eq!(
                got,
                Err(Refuse::BadSignature("ERC-1271 rejected")),
                "{label}"
            );
        }
        // The verdict came from the wallet's own answer: exactly one isValidSignature call.
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{label}");
        if want {
            ok += 1
        } else {
            refused += 1
        }
    }
    assert_eq!((ok, refused), (5, 6));
}

/// The code-hash list only decides whether the node calls the wallet: an account whose code is not listed is refused
/// without any call, even with a signature the wallet itself would accept.
#[tokio::test(flavor = "multi_thread")]
async fn unlisted_code_is_not_called() {
    let f = fixture();
    let c = &f["cases"][0]; // owner eth-sign, valid on chain
    assert!(c["valid"].as_bool().unwrap());
    let (rpc, calls) = replay(c).await;
    let policy = WalletPolicy {
        accepted_code_hashes: vec![B256::repeat_byte(1)],
        ..WalletPolicy::default()
    };
    let d: B256 = c["digest"].as_str().unwrap().parse().unwrap();
    let user: Address = c["account"].as_str().unwrap().parse().unwrap();
    let got = verify_signature(
        &rpc,
        d,
        &hexb(c["signature"].as_str().unwrap()),
        user,
        &policy,
    )
    .await;
    assert!(matches!(got, Err(Refuse::WalletNotAccepted(_))), "{got:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

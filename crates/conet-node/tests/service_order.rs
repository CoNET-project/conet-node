//! Service orders (local prototype on fork 5's DRAFT fields, 8e43083c): type string and digest
//! against ethers (`conformance/vectors/settlement-order.json`, test key), strict ECDSA, the
//! ERC-1271 call mechanics against a local mock JSON-RPC (code-hash allowlist, gas cap, timeout;
//! not a Beamio compatibility test, which waits for a real BeamioAccount fixture), nonce
//! book, deadline by chain time, the ordered precheck, and the settle simulation's error names.
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolError, SolStruct};
use conet_node::service_order::draft::{self, SettlementConfig, SettlementOrder};
use conet_node::service_order::*;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;

fn vectors() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/settlement-order.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn u(v: &Value) -> U256 {
    U256::from_str(v.as_str().unwrap()).unwrap()
}
fn order_of(o: &Value) -> SettlementOrder {
    SettlementOrder {
        pool: o["pool"].as_str().unwrap().parse().unwrap(),
        user: o["user"].as_str().unwrap().parse().unwrap(),
        nodeId: o["nodeId"].as_str().unwrap().parse().unwrap(),
        nodeWallet: o["nodeWallet"].as_str().unwrap().parse().unwrap(),
        minNodeGb: u(&o["minNodeGb"]),
        maxUserPay: u(&o["maxUserPay"]),
        gbBaseVersion: o["gbBaseVersion"].as_str().unwrap().parse().unwrap(),
        markupVersion: o["markupVersion"].as_str().unwrap().parse().unwrap(),
        freeExchangeVersion: o["freeExchangeVersion"].as_str().unwrap().parse().unwrap(),
        freePoolVersion: o["freePoolVersion"].as_str().unwrap().parse().unwrap(),
        serviceBit: o["serviceBit"].as_str().unwrap().parse().unwrap(),
        deadline: o["deadline"].as_str().unwrap().parse().unwrap(),
        nonce: o["nonce"].as_str().unwrap().parse().unwrap(),
    }
}
fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}

#[test]
fn type_string_and_digest_match_the_draft_and_ethers() {
    assert_eq!(SettlementOrder::eip712_encode_type(), draft::TYPE_STRING);
    for v in vectors().as_array().unwrap() {
        assert_eq!(v["typeString"].as_str().unwrap(), draft::TYPE_STRING);
        let o = order_of(&v["order"]);
        let token: Address = v["token"].as_str().unwrap().parse().unwrap();
        let d = draft::digest(&o, token);
        assert_eq!(format!("{d:#x}"), v["digest"].as_str().unwrap());
        verify_eoa(d, &hexb(v["signature"].as_str().unwrap()), o.user).unwrap();
        // Another token (domain) or another field: the signature no longer fits.
        let other = draft::digest(&o, Address::repeat_byte(9));
        assert!(verify_eoa(other, &hexb(v["signature"].as_str().unwrap()), o.user).is_err());
        let mut o2 = o.clone();
        o2.minNodeGb += U256::from(1);
        assert!(verify_eoa(
            draft::digest(&o2, token),
            &hexb(v["signature"].as_str().unwrap()),
            o.user
        )
        .is_err());
    }
}

#[test]
fn ecdsa_is_strict() {
    let v = &vectors()[0];
    let o = order_of(&v["order"]);
    let d = draft::digest(&o, v["token"].as_str().unwrap().parse().unwrap());
    let sig = hexb(v["signature"].as_str().unwrap());
    // v = 0/1 refused (contract ecrecover needs 27/28).
    let mut s = sig.clone();
    s[64] -= 27;
    assert_eq!(verify_eoa(d, &s, o.user), Err(Refuse::BadSignature("v")));
    // High s refused (malleable twin).
    let n = U256::from_str("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        .unwrap();
    let s_val = U256::from_be_slice(&sig[32..64]);
    let mut s = sig.clone();
    s[32..64].copy_from_slice(&(n - s_val).to_be_bytes::<32>());
    s[64] = if sig[64] == 27 { 28 } else { 27 };
    assert_eq!(
        verify_eoa(d, &s, o.user),
        Err(Refuse::BadSignature("high s"))
    );
    assert_eq!(
        verify_eoa(d, &sig[..64], o.user),
        Err(Refuse::BadSignature("length"))
    );
    assert_eq!(
        verify_eoa(d, &sig, Address::repeat_byte(1)),
        Err(Refuse::BadSignature("not the user"))
    );
}

#[test]
fn domain_check() {
    let token = Address::repeat_byte(0xc2);
    let allow = TokenAllowlist(vec![token]);
    assert!(check_domain(&draft::domain(token), token, &allow).is_ok());
    assert_eq!(
        check_domain(&draft::domain(token), Address::repeat_byte(1), &allow),
        Err(Refuse::TokenNotAllowed(Address::repeat_byte(1)))
    );
    let mut d = draft::domain(token);
    d.chain_id = Some(U256::from(1));
    assert_eq!(
        check_domain(&d, token, &allow),
        Err(Refuse::Domain("chainId"))
    );
    let mut d = draft::domain(token);
    d.version = Some("2".into());
    assert_eq!(
        check_domain(&d, token, &allow),
        Err(Refuse::Domain("version"))
    );
    let mut d = draft::domain(token);
    d.salt = Some(B256::repeat_byte(1));
    assert_eq!(check_domain(&d, token, &allow), Err(Refuse::Domain("salt")));
}

/// Mock wallet chain: `code` at every address, `answer` for eth_call, optional delay; records
/// the eth_call gas and counts the calls.
async fn wallet_rpc(
    code: &str,
    answer: &str,
    delay: Duration,
) -> (
    conet_node::chain::Rpc,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<String>>>,
) {
    wallet_rpc_values(json!(code), json!(answer), delay).await
}

async fn wallet_rpc_values(
    code: Value,
    answer: Value,
    delay: Duration,
) -> (
    conet_node::chain::Rpc,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<String>>>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let gas = Arc::new(Mutex::new(vec![]));
    let (c, g) = (calls.clone(), gas.clone());
    let url = common::serve(Arc::new(move |m: &str, p: &Value| match m {
        "eth_getCode" => code.clone(),
        "eth_call" => {
            c.fetch_add(1, Ordering::SeqCst);
            g.lock()
                .unwrap()
                .push(p[0]["gas"].as_str().unwrap_or("").to_string());
            std::thread::sleep(delay);
            answer.clone()
        }
        m => panic!("unexpected {m}"),
    }))
    .await;
    (conet_node::chain::Rpc::new(&url).unwrap(), calls, gas)
}

#[tokio::test]
async fn malformed_code_and_erc1271_results_remain_rpc_failures() {
    let code = "0x6080604052";
    let code_hash = alloy_primitives::keccak256(hexb(code));
    let user = Address::repeat_byte(0xbe);
    let policy = WalletPolicy {
        accepted_code_hashes: vec![code_hash],
        gas_cap: 150_000,
        timeout: Duration::from_secs(2),
    };
    let d = B256::repeat_byte(7);
    let sig = vec![1u8; 130];

    let (rpc, _, _) = wallet_rpc_values(json!(null), json!(MAGIC), Duration::ZERO).await;
    assert!(matches!(
        verify_1271(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::WalletCallFailed(message)) if message.contains("eth_getCode")
    ));

    let (rpc, _, _) = wallet_rpc_values(
        json!({ "__omit_result": true }),
        json!(MAGIC),
        Duration::ZERO,
    )
    .await;
    assert!(matches!(
        verify_1271(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::WalletCallFailed(message))
            if message.contains("JSON-RPC response has neither result nor error")
    ));

    let (rpc, _, _) = wallet_rpc_values(json!(code), json!(null), Duration::ZERO).await;
    assert!(matches!(
        verify_1271(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::WalletCallFailed(message)) if message.contains("eth_call")
    ));

    let (rpc, _, _) = wallet_rpc_values(
        json!(code),
        json!({ "__omit_result": true }),
        Duration::ZERO,
    )
    .await;
    assert!(matches!(
        verify_1271(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::WalletCallFailed(message))
            if message.contains("JSON-RPC response has neither result nor error")
    ));

    let (rpc, _, _) = wallet_rpc_values(json!("0x"), json!(MAGIC), Duration::ZERO).await;
    assert_eq!(
        verify_1271(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::BadSignature(
            "no code (undeployed wallets are refused)"
        ))
    );
}

/// Mock wallet chain whose `eth_call` never answers: the connection is held open without a
/// response, so only the policy timeout can end the call. `eth_getCode` answers normally. Nothing
/// blocks a runtime thread, so the timeout fires at the same point under any load.
async fn hold_wallet_rpc(code: &str) -> (conet_node::chain::Rpc, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let (c, code) = (calls.clone(), code.to_string());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (c, code) = (c.clone(), code.clone());
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let body = loop {
                    let k = match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => k,
                    };
                    buf.extend_from_slice(&tmp[..k]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text[..h]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= h + 4 + len {
                            break buf[h + 4..h + 4 + len].to_vec();
                        }
                    }
                };
                let req: Value = serde_json::from_slice(&body).unwrap();
                match req["method"].as_str().unwrap_or("") {
                    "eth_call" => {
                        c.fetch_add(1, Ordering::SeqCst);
                        // Hold the socket open and never answer.
                        std::future::pending::<()>().await;
                    }
                    "eth_getCode" => {
                        let out = json!({ "jsonrpc": "2.0", "id": 1, "result": code }).to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                            out.len()
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                    }
                    m => panic!("unexpected {m}"),
                }
            });
        }
    });
    (conet_node::chain::Rpc::new(&url).unwrap(), calls)
}

const MAGIC: &str = "0x1626ba7e00000000000000000000000000000000000000000000000000000000";

/// Node-side call mechanics of the ERC-1271 path only (allowlist before the call, gas cap,
/// timeout, magic value) against a mock JSON-RPC. This is NOT a Beamio compatibility test: that
/// one needs a real BeamioAccount fixture (requested from fork 4 through the PM) on a local chain.
#[tokio::test(flavor = "multi_thread")]
async fn erc1271_path() {
    let code = "0x6080604052";
    let h = alloy_primitives::keccak256(hexb(code));
    let user = Address::repeat_byte(0xbe);
    let d = B256::repeat_byte(7);
    let sig = vec![1u8; 130]; // two managers' signatures: opaque to the node
    let policy = WalletPolicy {
        accepted_code_hashes: vec![h],
        gas_cap: 150_000,
        // Generous for the passing cases (a loaded machine right after a build once failed
        // this test once, cause not reproduced in 83 reruns); the timeout case below sets its own.
        timeout: Duration::from_secs(10),
    };
    // Accepted wallet, magic value: ok; the call carries the gas cap.
    let (rpc, calls, gas) = wallet_rpc(code, MAGIC, Duration::ZERO).await;
    verify_signature(&rpc, d, &sig, user, &policy)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(gas.lock().unwrap()[0], "0x249f0");
    // Wrong answer: refused.
    let (rpc, _, _) = wallet_rpc(
        code,
        "0xffffffff00000000000000000000000000000000000000000000000000000000",
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        verify_signature(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::BadSignature("ERC-1271 rejected"))
    );
    // Not a listed Beamio wallet: refused before calling it.
    let (rpc, calls, _) = wallet_rpc("0x60016002", MAGIC, Duration::ZERO).await;
    assert!(matches!(
        verify_signature(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::WalletNotAccepted(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // No code (EOA, or an undeployed wallet): the ECDSA reason is reported.
    let (rpc, calls, _) = wallet_rpc("0x", MAGIC, Duration::ZERO).await;
    assert_eq!(
        verify_signature(&rpc, d, &sig, user, &policy).await,
        Err(Refuse::BadSignature("length"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // A slow wallet: timeout.
    let slow = WalletPolicy {
        timeout: Duration::from_millis(200),
        ..policy.clone()
    };
    let (rpc, calls) = hold_wallet_rpc(code).await;
    assert_eq!(
        verify_signature(&rpc, d, &sig, user, &slow).await,
        Err(Refuse::WalletCallFailed("timeout".into()))
    );
    // The timeout came from the eth_call itself, not from the code read.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn nonce_book() {
    let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
    let n = B256::repeat_byte(3);
    let mut book = NonceBook::default();
    book.hold(a, n, 100).unwrap();
    assert_eq!(book.hold(a, n, 100), Err(Refuse::NonceUsed));
    book.hold(b, n, 100).unwrap(); // per user
    book.release(a, n); // failed: may come again
    book.hold(a, n, 100).unwrap();
    book.settled(a, n);
    book.release(a, n); // settled stays used
    assert_eq!(book.hold(a, n, 100), Err(Refuse::NonceUsed));
    book.prune(100);
    assert_eq!(book.len(), 2);
    book.prune(101);
    assert!(book.is_empty());
}

#[test]
fn deadline_by_chain_time() {
    let p = DeadlinePolicy {
        min_left: 60,
        max_ahead: 3_600,
    };
    assert_eq!(check_deadline(1_000, 1_001, p), Err(Refuse::OrderExpired));
    assert_eq!(
        check_deadline(1_000, 941, p),
        Err(Refuse::TooCloseToDeadline)
    );
    assert!(check_deadline(1_000, 940, p).is_ok());
    assert!(check_deadline(4_600, 1_000, p).is_ok());
    assert_eq!(check_deadline(4_601, 1_000, p), Err(Refuse::DeadlineTooFar));
}

fn tok() -> Address {
    "0x00000000000000000000000000000000000c0de2"
        .parse()
        .unwrap()
}

fn me() -> Me {
    Me {
        node_id: 101,
        node_wallet: "0x00000000000000000000000000000000000a0001"
            .parse()
            .unwrap(),
        services: B256::left_padding_from(&[0x0f]),
    }
}
fn view(now: u64) -> TokenView {
    TokenView {
        now,
        config: SettlementConfig {
            freePoolOn: true,
            freePoolVersion: 9,
            freeExchangeOn: true,
            freeExchangeVersion: 5,
            markupVersion: 2,
            gbBaseVersion: 3,
        },
        paid_balance: U256::from(10_000_000u64),
        free_balance: U256::from(10_000_000u64),
        inventory_gb: U256::from(1_000_000_000u64),
        price: None,
        free_closed_mode: draft::FreeClosedMode::Freeze,
    }
}

#[test]
fn precheck_follows_the_draft_rules() {
    let v = vectors();
    let paid = order_of(&v[0]["order"]); // pool PAID, versions 3/2, free versions 0
    let now = paid.deadline - 600;
    let p = DeadlinePolicy::default();
    let mut book = NonceBook::default();
    precheck(&paid, &me(), &view(now), None, tok(), p, &mut book).unwrap();
    // Same order again: nonce held.
    assert_eq!(
        precheck(&paid, &me(), &view(now), None, tok(), p, &mut book),
        Err(Refuse::NonceUsed)
    );
    let fresh = NonceBook::default;

    // PAID ignores the free-pool switches and their versions.
    let mut t = view(now);
    t.config.freePoolOn = false;
    t.config.freeExchangeOn = false;
    t.config.freePoolVersion = 99;
    precheck(&paid, &me(), &t, None, tok(), p, &mut fresh()).unwrap();
    // A bound version moved: refused, by name.
    let mut t = view(now);
    t.config.markupVersion = 3;
    assert_eq!(
        precheck(&paid, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::VersionMismatch {
            item: "markupVersion",
            active: 3,
            signed: 2
        })
    );

    // FREE: switches first, then all four versions; never falls back to PAID.
    let mut free = paid.clone();
    free.pool = draft::POOL_FREE;
    free.freeExchangeVersion = 5;
    free.freePoolVersion = 9;
    precheck(&free, &me(), &view(now), None, tok(), p, &mut fresh()).unwrap();
    let mut t = view(now);
    t.config.freePoolOn = false;
    assert_eq!(
        precheck(&free, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::PoolDisabled)
    );
    let mut t = view(now);
    t.config.freeExchangeOn = false;
    assert_eq!(
        precheck(&free, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::FreeExchangeOff)
    );
    let mut t = view(now);
    t.config.freePoolVersion = 10;
    assert!(matches!(
        precheck(&free, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::VersionMismatch {
            item: "freePoolVersion",
            ..
        })
    ));

    // Node, service, fields.
    let mut o = paid.clone();
    o.nodeId = 102;
    assert_eq!(
        precheck(&o, &me(), &view(now), None, tok(), p, &mut fresh()),
        Err(Refuse::NotForThisNode)
    );
    let mut o = paid.clone();
    o.serviceBit = B256::left_padding_from(&[0x10]);
    assert_eq!(
        precheck(&o, &me(), &view(now), None, tok(), p, &mut fresh()),
        Err(Refuse::ServiceMissing)
    );
    let mut o = paid.clone();
    o.minNodeGb = U256::ZERO;
    assert_eq!(
        precheck(&o, &me(), &view(now), None, tok(), p, &mut fresh()),
        Err(Refuse::BadField("zero amount"))
    );

    // Amount with known prices: G = 0.5 GB, pBase = 2,000,000 U units / GB, m = 2.5%:
    // pay = ceil(0.5e9 x 2e6 x 10250 / 1e13) = 1,025,000 <= maxUserPay 1,234,567.
    assert_eq!(
        draft::user_pay(paid.minNodeGb, U256::from(2_000_000u64), 250),
        U256::from(1_025_000u64)
    );
    let mut t = view(now);
    t.price = Some((U256::from(2_000_000u64), 250));
    precheck(&paid, &me(), &t, None, tok(), p, &mut fresh()).unwrap();
    t.price = Some((U256::from(2_500_000u64), 250));
    assert!(matches!(
        precheck(&paid, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::ExceedsMaxPay { .. })
    ));
    let mut t = view(now);
    t.price = Some((U256::from(2_000_000u64), 250));
    t.paid_balance = U256::from(1_024_999u64);
    assert!(matches!(
        precheck(&paid, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::BalanceShort { .. })
    ));
    // Inventory short: whole order refused (the contract would revert without burning).
    let mut t = view(now);
    t.inventory_gb = paid.minNodeGb - U256::from(1);
    assert!(matches!(
        precheck(&paid, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::InsufficientInventory { .. })
    ));
    // Refusals carry the matching draft contract error name.
    assert_eq!(Refuse::PoolDisabled.contract_error(), Some("PoolDisabled"));
    assert_eq!(Refuse::DeadlineTooFar.contract_error(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn settle_simulation_names_the_revert() {
    let v = vectors();
    let o = order_of(&v[0]["order"]);
    let auth = hexb(v[0]["signature"].as_str().unwrap());
    let token: Address = v[0]["token"].as_str().unwrap().parse().unwrap();
    let revert = draft::IThirdPartyStableLedger::InsufficientInventory {
        have: U256::from(1),
        need: U256::from(2),
    }
    .abi_encode();
    let ok = [
        U256::from(1_025_000u64).to_be_bytes::<32>(),
        U256::from(500_000_000u64).to_be_bytes::<32>(),
    ]
    .concat();
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let mode = Arc::new(AtomicUsize::new(0));
    let m2 = mode.clone();
    let (revert_hex, ok_hex) = (
        format!("0x{}", hex::encode(&revert)),
        format!("0x{}", hex::encode(&ok)),
    );
    let url = common::serve(Arc::new(move |m: &str, p: &Value| {
        assert_eq!(m, "eth_call");
        s2.lock().unwrap().push(p[0].clone());
        match m2.load(Ordering::SeqCst) {
            0 => json!({ "__rpc_error": { "code": 3, "message": "execution reverted", "data": revert_hex } }),
            1 => json!(ok_hex),
            2 => json!(null),
            _ => json!({ "__omit_result": true }),
        }
    }))
    .await;
    let rpc = conet_node::chain::Rpc::new(&url).unwrap();
    let from = me().node_wallet;
    // Revert: named with the draft errors.
    assert_eq!(
        simulate_settle(&rpc, token, from, &o, &auth).await,
        Err(Refuse::Simulated("InsufficientInventory".into()))
    );
    let call = seen.lock().unwrap()[0].clone();
    assert_eq!(
        call["data"].as_str().unwrap(),
        format!("0x{}", hex::encode(settle_calldata(&o, &auth)))
    );
    assert_eq!(
        call["from"].as_str().unwrap().to_lowercase(),
        format!("{from:#x}")
    );
    // Success: (userPaid, gbSent) decoded.
    mode.store(1, Ordering::SeqCst);
    assert_eq!(
        simulate_settle(&rpc, token, from, &o, &auth).await,
        Ok((U256::from(1_025_000u64), U256::from(500_000_000u64)))
    );
    mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        simulate_settle(&rpc, token, from, &o, &auth).await,
        Err(Refuse::Simulated(message)) if message.contains("eth_call result is not a hex data string")
    ));
    mode.store(3, Ordering::SeqCst);
    assert!(matches!(
        simulate_settle(&rpc, token, from, &o, &auth).await,
        Err(Refuse::Simulated(message))
            if message.contains("JSON-RPC response has neither result nor error")
    ));
    assert_eq!(draft::error_name(&[0xde, 0xad, 0xbe, 0xef]), None);
}

/// Payment sources (decided 2026-11-10): ordinary FREE under the creator's close mode, and the
/// subscription receipt, independent of the free pool and binding none of its versions.
#[test]
fn payment_sources() {
    let v = vectors();
    let paid = order_of(&v[0]["order"]);
    let now = paid.deadline - 600;
    let p = DeadlinePolicy::default();
    let fresh = NonceBook::default;
    let mut free = paid.clone();
    free.pool = draft::POOL_FREE;
    free.freeExchangeVersion = 5;
    free.freePoolVersion = 9;
    // Free pool closed: A (freeze) refuses, B (keep usable) goes on.
    let mut t = view(now);
    t.config.freePoolOn = false;
    assert_eq!(
        precheck(&free, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::PoolDisabled)
    );
    t.free_closed_mode = draft::FreeClosedMode::KeepUsable;
    precheck(&free, &me(), &t, None, tok(), p, &mut fresh()).unwrap();
    // ... but the exchange switch and the free versions still apply under B.
    let mut t2 = t.clone();
    t2.config.freeExchangeOn = false;
    assert_eq!(
        precheck(&free, &me(), &t2, None, tok(), p, &mut fresh()),
        Err(Refuse::FreeExchangeOff)
    );
    assert_eq!(
        precheck(&paid, &me(), &t2, None, tok(), p, &mut fresh()),
        Ok(())
    );

    // Receipt orders.
    let mut rec = paid.clone();
    rec.pool = draft::POOL_RECEIPT;
    rec.gbBaseVersion = 0; // binds no ordinary-pool version (what it binds is pending v0.4)
    rec.markupVersion = 0;
    let r = draft::ReceiptView {
        receipt_id: U256::from(77),
        token: tok(),
        holder_balance: U256::from(1),
        valid_from: now - 100,
        valid_until: now + 86_400,
        quota: Some(U256::from(2_000_000u64)),
        used: U256::from(500_000u64),
    };
    // Free pool closed and frozen, free versions moved: no effect on a receipt order.
    let mut t = view(now);
    t.config.freePoolOn = false;
    t.config.freeExchangeOn = false;
    t.config.freePoolVersion = 99;
    precheck(&rec, &me(), &t, Some(&r), tok(), p, &mut fresh()).unwrap();
    assert!(draft::bound_versions(&rec, &t.config).is_empty());
    // No receipt, another token's receipt, transferred away: not held.
    assert_eq!(
        precheck(&rec, &me(), &t, None, tok(), p, &mut fresh()),
        Err(Refuse::ReceiptNotHeld)
    );
    let other = draft::ReceiptView {
        token: Address::repeat_byte(5),
        ..r.clone()
    };
    assert_eq!(
        precheck(&rec, &me(), &t, Some(&other), tok(), p, &mut fresh()),
        Err(Refuse::ReceiptNotHeld)
    );
    let gone = draft::ReceiptView {
        holder_balance: U256::ZERO,
        ..r.clone()
    };
    assert_eq!(
        precheck(&rec, &me(), &t, Some(&gone), tok(), p, &mut fresh()),
        Err(Refuse::ReceiptNotHeld)
    );
    // Validity by chain time, both ends inclusive.
    let late = draft::ReceiptView {
        valid_until: now - 1,
        ..r.clone()
    };
    assert_eq!(
        precheck(&rec, &me(), &t, Some(&late), tok(), p, &mut fresh()),
        Err(Refuse::ReceiptExpired)
    );
    let edge = draft::ReceiptView {
        valid_until: now,
        ..r.clone()
    };
    precheck(&rec, &me(), &t, Some(&edge), tok(), p, &mut fresh()).unwrap();
    // Quota in the stable token: pay 1,025,000 against 1,500,000 left passes; 1,024,999 left fails.
    t.price = Some((U256::from(2_000_000u64), 250));
    precheck(&rec, &me(), &t, Some(&r), tok(), p, &mut fresh()).unwrap();
    let short = draft::ReceiptView {
        used: U256::from(975_001u64),
        ..r.clone()
    };
    assert_eq!(
        precheck(&rec, &me(), &t, Some(&short), tok(), p, &mut fresh()),
        Err(Refuse::ReceiptQuotaShort {
            left: U256::from(1_024_999u64),
            need: U256::from(1_025_000u64)
        })
    );
    // Unlimited: only the issuer's GB inventory limits it.
    let unlimited = draft::ReceiptView {
        quota: None,
        used: U256::from(10u64).pow(U256::from(30)),
        ..r.clone()
    };
    precheck(&rec, &me(), &t, Some(&unlimited), tok(), p, &mut fresh()).unwrap();
    t.inventory_gb = rec.minNodeGb - U256::from(1);
    assert!(matches!(
        precheck(&rec, &me(), &t, Some(&unlimited), tok(), p, &mut fresh()),
        Err(Refuse::InsufficientInventory { .. })
    ));
}

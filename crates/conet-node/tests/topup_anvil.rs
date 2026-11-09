//! AUTO-TOPUP send flow end to end on a LOCAL anvil (N6 fifth review): first bid -> +10%
//! replacements -> stop at the caps (busy) -> alert near the end; the signer process signs every
//! version (approved entry). TEST keys only. Starts its own anvil (no automine, chain 224422);
//! #[ignore] by default: run with `--include-ignored` (needs `anvil` on PATH).
use conet_node::auto_topup::*;
use conet_node::chain::Rpc;
use serde_json::{json, Value};
use si_signer::keystore;
use si_signer::proto::{Request, Response};
use si_signer::server::{Signer, SignerConfig};
use si_signer::topup_policy::{TopUpConfig, TopUpLedger};
use std::process::{Child, Command, Stdio};
use zeroize::Zeroizing;

const REG: &str = "0x00000000000000000000000000000000c0de0001";
const C: u128 = 1_000_000_000_000_000_000;
const GWEI: u128 = 1_000_000_000;

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn hex_u128(v: &Value) -> u128 {
    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[tokio::test]
#[ignore = "starts a local anvil; run with --include-ignored"]
async fn first_bid_bump_cap_alert_on_anvil() {
    let port = 18_745;
    let child = Command::new("anvil")
        .args([
            "--chain-id",
            "224422",
            "--port",
            &port.to_string(),
            "--no-mining",
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil on PATH");
    let _anvil = Anvil(child);
    let rpc = Rpc::new(&format!("http://127.0.0.1:{port}")).unwrap();
    for _ in 0..100 {
        if rpc.call("eth_chainId", json!([])).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Signer with the approved entry; its clock is pinned 3 days before the term end.
    let g: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/golden.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let wallet = g["wallets"]["nodeA"]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let clock: u64 = 1_900_000_000;
    let term_end = clock + 3 * 86_400;
    let tc = TopUpConfig {
        registry: REG.into(),
        chain_id: 224422,
        own_node_id: 573,
        per_tx_cap: 10 * C,
        term_budget: 10 * C,
        daily_count: 2,
        daily_value: 10 * C,
        first_term_end: term_end,
        term_length: 15_768_000,
        window: 7 * 86_400,
        gas_reserve: C / 100,
        max_gas_limit: 300_000,
        max_fee_cap: 50 * GWEI,
        tip_cap: 100_000_000,
    };
    let d = tempfile::tempdir().unwrap();
    let ledger = d.path().join("topup.json");
    TopUpLedger::create(&ledger).unwrap();
    let kek = [7u8; 32];
    let secrets = keystore::Secrets {
        wallet_hex: g["wallets"]["nodeA"]["privateKey"].as_str().unwrap().into(),
        pgp_armored: g["keys"]["nodeA"]["armoredPrivate"]
            .as_str()
            .unwrap()
            .into(),
        pgp_pass: g["keys"]["nodeA"]["passphrase"].as_str().unwrap().into(),
        previous_pgp_armored: String::new(),
        previous_pgp_pass: String::new(),
    };
    let signer = Signer::start(SignerConfig {
        keystore_file: keystore::seal(&kek, &secrets).unwrap(),
        kek: Zeroizing::new(kek),
        verifying_contract: REG.into(),
        allow_bind: false,
        allow_uid: None,
        anchor_node_id: None,
        quota: None,
        topup: Some((tc.clone(), ledger)),
    })
    .unwrap();
    rpc.call(
        "anvil_setBalance",
        json!([wallet, format!("0x{:x}", 100 * C)]),
    )
    .await
    .unwrap();

    let block = rpc
        .call("eth_getBlockByNumber", json!(["latest", false]))
        .await
        .unwrap();
    let base_fee = hex_u128(&block["baseFeePerGas"]);
    let price = PriceConfig {
        max_fee_cap: tc.max_fee_cap,
        tip_cap: tc.tip_cap,
        wanted_tip: 100_000_000,
    };
    let cfg = Config::default();
    let value = 5 * C;
    let sign = |a: SendAction| -> (Priced, String) {
        let SendAction::Sign {
            nonce,
            value,
            max_fee,
            tip,
            replaces,
        } = a
        else {
            panic!("{a:?}")
        };
        let r = signer.handle_at(
            Request::SignTopUp {
                nonce,
                gas_limit: 200_000,
                max_fee_wei: max_fee.to_string(),
                priority_fee_wei: tip.to_string(),
                value: value.to_string(),
                stated_missing: (5 * C).to_string(),
                stated_wallet: (100 * C).to_string(),
                replaces_nonce: replaces,
            },
            clock as i64,
        );
        let Response::Ok { value: raw } = r else {
            panic!("signer refused: {r:?}")
        };
        (
            Priced {
                nonce,
                value,
                max_fee,
                tip,
            },
            raw,
        )
    };
    let mut log = Vec::new();

    // 1. First bid at <= 75% of the caps, broadcast, pending (no automine).
    let a = next_action(
        &Plan::Send { value },
        None,
        0,
        base_fee,
        false,
        term_end - clock,
        &price,
        &cfg,
    );
    let (mut pending, raw) = sign(a);
    assert_eq!(pending.tip, 75_000_000);
    let mut hash = rpc
        .call("eth_sendRawTransaction", json!([raw]))
        .await
        .unwrap();
    log.push(format!(
        "first bid nonce={} max_fee={} tip={} hash={}",
        pending.nonce, pending.max_fee, pending.tip, hash
    ));

    // 2. Not priced out: rebroadcast only.
    let plan = Plan::Rebroadcast { nonce: 0 };
    assert_eq!(
        next_action(
            &plan,
            Some(&pending),
            0,
            base_fee,
            false,
            term_end - clock,
            &price,
            &cfg
        ),
        SendAction::Rebroadcast { nonce: 0 }
    );

    // 3. Priced out: +10% replacements, each accepted by anvil (it replaces ours in the pool).
    let mut bumps = 0;
    loop {
        let a = next_action(
            &plan,
            Some(&pending),
            0,
            base_fee,
            true,
            term_end - clock,
            &price,
            &cfg,
        );
        if let SendAction::Busy { alert } = a {
            assert!(!alert, "far from the end: busy, no alert yet");
            log.push(format!("caps reached after {bumps} replacements: busy"));
            break;
        }
        let (next, raw) = sign(a);
        let new_hash = rpc
            .call("eth_sendRawTransaction", json!([raw]))
            .await
            .unwrap();
        let old = rpc
            .call("eth_getTransactionByHash", json!([hash]))
            .await
            .unwrap();
        assert!(old.is_null(), "the replaced version left the pool");
        log.push(format!(
            "replacement {} max_fee={} tip={} hash={}",
            bumps + 1,
            next.max_fee,
            next.tip,
            new_hash
        ));
        pending = next;
        hash = new_hash;
        bumps += 1;
        assert!(bumps <= 5);
    }
    assert!(bumps >= 3, "at least three replacements under the caps");

    // 4. Near the end (< 1 day) still unable to bump: busy with the alert.
    let near = next_action(
        &plan,
        Some(&pending),
        0,
        base_fee,
        true,
        3_600,
        &price,
        &cfg,
    );
    assert_eq!(near, SendAction::Busy { alert: true });
    log.push("one hour before the end: busy + alert (deposit through the web page)".into());

    // 5. Mine: exactly one version lands, the value arrives once.
    rpc.call("evm_mine", json!([])).await.unwrap();
    let rc = rpc
        .call("eth_getTransactionReceipt", json!([hash]))
        .await
        .unwrap();
    assert_eq!(rc["status"], "0x1");
    let bal = rpc
        .call("eth_getBalance", json!([REG, "latest"]))
        .await
        .unwrap();
    assert_eq!(hex_u128(&bal), value);
    let nonce = rpc
        .call("eth_getTransactionCount", json!([wallet, "latest"]))
        .await
        .unwrap();
    assert_eq!(hex_u128(&nonce), 1);
    log.push(format!(
        "mined: status=1 value_received={} wallet_nonce=1",
        hex_u128(&bal)
    ));
    for l in log {
        println!("{l}");
    }
}

//! AUTO-TOPUP main-wallet SignTx entry (用户已批准 2026-11-09, revised after N6's pre-review).
//! TEST keys only, no network.
use si_crypto::eth::EthKey;
use si_signer::keystore;
use si_signer::probe_role::{self, Origin, ProbeRole, Refuse};
use si_signer::proto::{Request, Response};
use si_signer::server::{Signer, SignerConfig};
use si_signer::topup_policy::*;
use si_signer::tx1559::{parse_address, Tx1559};
use zeroize::Zeroizing;

const REG: &str = "0x00000000000000000000000000000000c0de0001";
const C: u128 = 1_000_000_000_000_000_000;
const GWEI: u128 = 1_000_000_000;
/// First term end: 2030-03-17-ish; the window opens 7 days before.
const END: u64 = 1_900_000_000;
const IN_WINDOW: u64 = END - 3 * 86_400;

fn cfg() -> TopUpConfig {
    TopUpConfig {
        registry: REG.into(),
        chain_id: 224422,
        own_node_id: 573,
        per_tx_cap: 10 * C,
        term_budget: 12 * C,
        daily_count: 2,
        daily_value: 10 * C,
        first_term_end: END,
        term_length: 15_768_000,
        window: 7 * 86_400,
        gas_reserve: C / 100,
        max_gas_limit: 300_000,
    }
}
fn req(nonce: u64, value: u128) -> TopUpRequest {
    TopUpRequest {
        nonce,
        gas_limit: 200_000,
        max_fee_wei: 4 * GWEI,
        priority_fee_wei: GWEI / 10,
        value,
        stated_missing: 5 * C,
        stated_wallet: 100 * C,
        replaces_nonce: None,
    }
}
fn data(id: u64) -> Vec<u8> {
    let mut d = topup_selector().to_vec();
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&id.to_be_bytes());
    d.extend_from_slice(&w);
    d
}
fn fresh() -> LedgerState {
    LedgerState::default()
}

#[test]
fn builds_only_own_topup_to_the_registry() {
    let c = cfg();
    assert_eq!(c.calldata(), data(573));
    assert_eq!(check_tx_bytes(&c, 2, Some(REG), &data(573)), Ok(()));
    // Another node, another contract, contract creation, another selector, extra bytes, type 0.
    assert_eq!(
        check_tx_bytes(&c, 2, Some(REG), &data(574)),
        Err(TopUpRefuse::NotOwnNode)
    );
    assert_eq!(
        check_tx_bytes(
            &c,
            2,
            Some("0x00000000000000000000000000000000000000bb"),
            &data(573)
        ),
        Err(TopUpRefuse::WrongTo)
    );
    assert_eq!(
        check_tx_bytes(&c, 2, None, &data(573)),
        Err(TopUpRefuse::Creation)
    );
    let mut w = probe_role::selector("withdraw(uint256)").to_vec();
    w.extend_from_slice(&data(573)[4..]);
    assert_eq!(
        check_tx_bytes(&c, 2, Some(REG), &w),
        Err(TopUpRefuse::Selector)
    );
    let mut long = data(573);
    long.push(0);
    assert_eq!(
        check_tx_bytes(&c, 2, Some(REG), &long),
        Err(TopUpRefuse::BadCalldata)
    );
    assert_eq!(
        check_tx_bytes(&c, 0, Some(REG), &data(573)),
        Err(TopUpRefuse::NotType2)
    );
}

#[test]
fn amount_window_gas_rules() {
    let c = cfg();
    let l = fresh();
    assert!(check(&c, &req(1, 5 * C), &l, IN_WINDOW).is_ok());
    // Above the stated missing amount (it only lowers), above the per-tx cap, zero.
    assert_eq!(
        check(&c, &req(1, 5 * C + 1), &l, IN_WINDOW),
        Err(TopUpRefuse::AboveMissing)
    );
    let big = TopUpRequest {
        stated_missing: 50 * C,
        ..req(1, 11 * C)
    };
    assert_eq!(check(&c, &big, &l, IN_WINDOW), Err(TopUpRefuse::AboveCap));
    assert_eq!(
        check(&c, &req(1, 0), &l, IN_WINDOW),
        Err(TopUpRefuse::ZeroValue)
    );
    // Window: computed by the signer from its clock and the configured schedule.
    assert_eq!(
        check(&c, &req(1, C), &l, END - 8 * 86_400),
        Err(TopUpRefuse::OutsideWindow)
    );
    assert_eq!(
        check(&c, &req(1, C), &l, END),
        Err(TopUpRefuse::OutsideWindow)
    ); // next term, far
    assert!(check(&c, &req(1, C), &l, END + 15_768_000 - 86_400).is_ok()); // next term's window
                                                                           // Gas: wallet must keep value + gas_limit x maxFee + reserve.
    let need = 5 * C + 200_000 * 4 * GWEI + C / 100;
    assert!(check(
        &c,
        &TopUpRequest {
            stated_wallet: need,
            ..req(1, 5 * C)
        },
        &l,
        IN_WINDOW
    )
    .is_ok());
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                stated_wallet: need - 1,
                ..req(1, 5 * C)
            },
            &l,
            IN_WINDOW
        ),
        Err(TopUpRefuse::GasReserve)
    );
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                gas_limit: 300_001,
                ..req(1, C)
            },
            &l,
            IN_WINDOW
        ),
        Err(TopUpRefuse::GasLimit)
    );
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                priority_fee_wei: 5 * GWEI,
                ..req(1, C)
            },
            &l,
            IN_WINDOW
        ),
        Err(TopUpRefuse::BadFees)
    );
}

#[test]
fn rolling_24h_caps_term_budget_and_replacement() {
    let c = cfg();
    let r = |n, v| TopUpRequest {
        stated_missing: 10 * C,
        ..req(n, v)
    };
    let l1 = check(&c, &r(1, 4 * C), &fresh(), IN_WINDOW).unwrap();
    let l2 = check(&c, &r(2, 4 * C), &l1, IN_WINDOW).unwrap();
    // Third within 24 hours: refused. Daily value: 4 + 7 > 10.
    assert_eq!(
        check(&c, &r(3, C), &l2, IN_WINDOW),
        Err(TopUpRefuse::DailyCount)
    );
    assert_eq!(
        check(&c, &r(2, 7 * C), &l1, IN_WINDOW),
        Err(TopUpRefuse::DailyValue)
    );
    // Rolling, not calendar: two just before midnight, then just after midnight still refused.
    let midnight = (IN_WINDOW / 86_400 + 1) * 86_400;
    let a = check(&c, &r(11, C), &fresh(), midnight - 60).unwrap();
    let b = check(&c, &r(12, C), &a, midnight - 30).unwrap();
    assert_eq!(
        check(&c, &r(13, C), &b, midnight + 30),
        Err(TopUpRefuse::DailyCount)
    );
    assert!(check(&c, &r(13, C), &b, midnight - 60 + 86_400).is_ok()); // 24 h after the first
                                                                       // The term budget (12) holds across days: 8 + 5 > 12.
    let later = IN_WINDOW + 86_400;
    assert_eq!(
        check(&c, &r(3, 5 * C), &l2, later),
        Err(TopUpRefuse::AboveBudget)
    );
    assert!(check(&c, &r(3, 4 * C), &l2, later).is_ok());
    // Replacement: must be our own booked nonce, value not above the original; lowers the booking.
    let rep = TopUpRequest {
        replaces_nonce: Some(2),
        ..r(2, C)
    };
    let l3 = check(&c, &rep, &l2, IN_WINDOW).unwrap();
    assert_eq!(l3.last_24h(IN_WINDOW), (2, 5 * C));
    assert_eq!(l3.term_value(), 5 * C);
    let up = TopUpRequest {
        replaces_nonce: Some(2),
        ..r(2, 4 * C + 1)
    };
    assert_eq!(
        check(&c, &up, &l2, IN_WINDOW),
        Err(TopUpRefuse::AboveReplaced)
    );
    // A claimed replacement of a nonce the signer never signed: refused (no budget bypass).
    let fake = TopUpRequest {
        replaces_nonce: Some(9),
        ..r(9, 4 * C)
    };
    assert_eq!(
        check(&c, &fake, &l2, IN_WINDOW),
        Err(TopUpRefuse::ReplaceUnknown)
    );
    // Mismatched nonce in the claim.
    let odd = TopUpRequest {
        replaces_nonce: Some(1),
        ..r(5, C)
    };
    assert_eq!(
        check(&c, &odd, &l2, IN_WINDOW),
        Err(TopUpRefuse::ReplaceUnknown)
    );
    // Zero value: refused, also as a replacement (topUp(0) reverts; let the original land).
    let zero = TopUpRequest {
        replaces_nonce: Some(2),
        stated_missing: 0,
        ..req(2, 0)
    };
    assert_eq!(
        check(&c, &zero, &l2, IN_WINDOW),
        Err(TopUpRefuse::ZeroValue)
    );
    // A different top-up at one of our nonces without claiming replacement: refused.
    assert_eq!(
        check(&c, &r(2, C), &l2, later),
        Err(TopUpRefuse::ReplaceUnknown)
    );
}

#[test]
fn ledger_persists_across_restart() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("topup.json");
    let key = EthKey::from_hex(&format!("0x{}", "22".repeat(32))).unwrap();
    let c = cfg();
    let mut l = TopUpLedger::open(&path).unwrap();
    l.sign(&c, &key, &req(1, 2 * C), IN_WINDOW).unwrap();
    l.sign(&c, &key, &req(2, 2 * C), IN_WINDOW).unwrap();
    drop(l);
    // Restarted: the day's two are remembered, a third is refused.
    let mut l = TopUpLedger::open(&path).unwrap();
    assert_eq!(l.state.last_24h(IN_WINDOW).0, 2);
    assert_eq!(
        l.sign(&c, &key, &req(3, C), IN_WINDOW),
        Err(TopUpRefuse::DailyCount)
    );
    // A refused request leaves the ledger as it was.
    assert_eq!(TopUpLedger::open(&path).unwrap().state.booked.len(), 2);
}

fn signer(dir: &tempfile::TempDir, topup: bool) -> Signer {
    let g: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/golden.json"
        ))
        .unwrap(),
    )
    .unwrap();
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
    Signer::start(SignerConfig {
        keystore_file: keystore::seal(&kek, &secrets).unwrap(),
        kek: Zeroizing::new(kek),
        verifying_contract: REG.into(),
        allow_bind: false,
        allow_uid: None,
        anchor_node_id: None,
        quota: None,
        topup: topup.then(|| (cfg(), dir.path().join("topup.json"))),
    })
    .unwrap()
}

fn wire(nonce: u64, value: &str, wallet: &str) -> Request {
    Request::SignTopUp {
        nonce,
        gas_limit: 200_000,
        max_fee_wei: (4 * GWEI).to_string(),
        priority_fee_wei: (GWEI / 10).to_string(),
        value: value.into(),
        stated_missing: (5 * C).to_string(),
        stated_wallet: wallet.into(),
        replaces_nonce: None,
    }
}

/// Through the signer service: a valid request returns the raw transaction the signer built
/// (own node, registry, type 2); everything outside the entry is refused by name.
#[test]
fn signer_service_end_to_end() {
    let d = tempfile::tempdir().unwrap();
    let s = signer(&d, true);
    let g: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/golden.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let key = EthKey::from_hex(g["wallets"]["nodeA"]["privateKey"].as_str().unwrap()).unwrap();
    let Response::Ok { value: raw } = s.handle_at(
        wire(7, &(5 * C).to_string(), &(100 * C).to_string()),
        IN_WINDOW as i64,
    ) else {
        panic!("refused")
    };
    let expect = Tx1559 {
        chain_id: 224422,
        nonce: 7,
        max_priority_fee_per_gas: GWEI / 10,
        max_fee_per_gas: 4 * GWEI,
        gas_limit: 200_000,
        to: parse_address(REG).unwrap(),
        value: 5 * C,
        data: data(573),
    }
    .sign(&key)
    .unwrap()
    .0;
    assert_eq!(raw, format!("0x{}", hex::encode(expect)));
    let refused = |r: Response| match r {
        Response::Refused { reason } => reason,
        Response::Ok { .. } => panic!("signed"),
    };
    // Above the gap, outside the window, gas short, daily count, malformed amount.
    assert_eq!(
        refused(s.handle_at(
            wire(8, &(6 * C).to_string(), &(100 * C).to_string()),
            IN_WINDOW as i64
        )),
        "topup:AboveMissing"
    );
    assert_eq!(
        refused(s.handle_at(
            wire(8, &C.to_string(), &(100 * C).to_string()),
            (END - 8 * 86_400) as i64
        )),
        "topup:OutsideWindow"
    );
    assert_eq!(
        refused(s.handle_at(wire(8, &C.to_string(), &C.to_string()), IN_WINDOW as i64)),
        "topup:GasReserve"
    );
    let _ = s.handle_at(
        wire(8, &C.to_string(), &(100 * C).to_string()),
        IN_WINDOW as i64,
    );
    assert_eq!(
        refused(s.handle_at(
            wire(9, &C.to_string(), &(100 * C).to_string()),
            IN_WINDOW as i64
        )),
        "topup:DailyCount"
    );
    assert_eq!(
        refused(s.handle_at(wire(9, "1e18", "1"), IN_WINDOW as i64)),
        "topup_fields"
    );
    // Not configured: refused.
    let d2 = tempfile::tempdir().unwrap();
    assert_eq!(
        refused(signer(&d2, false).handle_at(wire(1, "1", "1"), IN_WINDOW as i64)),
        "topup_disabled"
    );
}

/// The probe wallet never signs a top-up, whatever channel it comes from.
#[test]
fn probe_wallet_refuses_topup() {
    let k = EthKey::from_hex(&format!("0x{}", "22".repeat(32))).unwrap();
    let r = ProbeRole {
        key: &k,
        domain: si_core::probe::ProbeDomain::new(REG).unwrap(),
        registry: REG.into(),
    };
    let tx = probe_role::TxRequest {
        tx_type: 2,
        to: Some(REG.into()),
        value: C,
        data: data(573),
    };
    assert!(matches!(
        r.handle(Origin::LocalVoteGate, probe_role::Request::SignVoteTx(tx)),
        Err(Refuse::HasValue) | Err(Refuse::Selector(_))
    ));
}

#[test]
fn example_config_parses() {
    let s = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/topup.example.json"))
        .unwrap();
    let c: TopUpConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(c.window, 7 * 86_400);
    assert_eq!(c.daily_count, 2);
    assert!(serde_json::from_str::<TopUpConfig>(
        &s.replace("\"window\"", "\"extra\": 1, \"window\"")
    )
    .is_err());
}

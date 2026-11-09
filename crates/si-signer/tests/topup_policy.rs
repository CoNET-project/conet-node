//! AUTO-TOPUP main-wallet SignTx entry (用户已批准 2026-11-09, revised after N6's two reviews).
//! TEST keys only, no network.
use si_crypto::eth::EthKey;
use si_signer::keystore;
use si_signer::probe_role::{self, Origin, ProbeRole, Refuse};
use si_signer::proto::{Request, Response};
use si_signer::server::{Signer, SignerConfig};
use si_signer::topup_policy::*;
use si_signer::tx1559::{parse_address, Tx1559};
use std::path::PathBuf;
use zeroize::Zeroizing;

const REG: &str = "0x00000000000000000000000000000000c0de0001";
const C: u128 = 1_000_000_000_000_000_000;
const GWEI: u128 = 1_000_000_000;
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
        max_fee_cap: 50 * GWEI,
        tip_cap: GWEI,
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
/// A same-nonce replacement with both fees raised by 10%.
fn replacement(nonce: u64, value: u128) -> TopUpRequest {
    TopUpRequest {
        replaces_nonce: Some(nonce),
        max_fee_wei: 4 * GWEI * 11 / 10,
        priority_fee_wei: GWEI / 10 * 11 / 10,
        stated_missing: 10 * C,
        ..req(nonce, value)
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
fn golden_key() -> (keystore::Secrets, EthKey) {
    let g: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/golden.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let wallet = g["wallets"]["nodeA"]["privateKey"].as_str().unwrap();
    (
        keystore::Secrets {
            wallet_hex: wallet.into(),
            pgp_armored: g["keys"]["nodeA"]["armoredPrivate"]
                .as_str()
                .unwrap()
                .into(),
            pgp_pass: g["keys"]["nodeA"]["passphrase"].as_str().unwrap().into(),
            previous_pgp_armored: String::new(),
            previous_pgp_pass: String::new(),
        },
        EthKey::from_hex(wallet).unwrap(),
    )
}
fn signer(topup: Option<PathBuf>) -> Signer {
    let kek = [7u8; 32];
    let (secrets, _) = golden_key();
    Signer::start(SignerConfig {
        keystore_file: keystore::seal(&kek, &secrets).unwrap(),
        kek: Zeroizing::new(kek),
        verifying_contract: REG.into(),
        allow_bind: false,
        allow_uid: None,
        anchor_node_id: None,
        quota: None,
        topup: topup.map(|p| (cfg(), p)),
    })
    .unwrap()
}
fn wire(nonce: u64, value: u128, wallet: u128) -> Request {
    Request::SignTopUp {
        nonce,
        gas_limit: 200_000,
        max_fee_wei: (4 * GWEI).to_string(),
        priority_fee_wei: (GWEI / 10).to_string(),
        value: value.to_string(),
        stated_missing: (5 * C).to_string(),
        stated_wallet: wallet.to_string(),
        replaces_nonce: None,
    }
}
fn refused(r: Response) -> String {
    match r {
        Response::Refused { reason } => reason,
        Response::Ok { .. } => panic!("signed"),
    }
}

#[test]
fn builds_only_own_topup_to_the_registry() {
    let c = cfg();
    assert_eq!(c.calldata(), data(573));
    assert_eq!(check_tx_bytes(&c, 2, Some(REG), &data(573)), Ok(()));
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
    assert_eq!(
        check(&c, &req(1, C), &l, END - 8 * 86_400),
        Err(TopUpRefuse::OutsideWindow)
    );
    assert_eq!(
        check(&c, &req(1, C), &l, END),
        Err(TopUpRefuse::OutsideWindow)
    );
    assert!(check(&c, &req(1, C), &l, END + 15_768_000 - 86_400).is_ok());
    let need = 5 * C + 200_000 * 4 * GWEI + C / 100;
    let w = |stated_wallet| TopUpRequest {
        stated_wallet,
        ..req(1, 5 * C)
    };
    assert!(check(&c, &w(need), &l, IN_WINDOW).is_ok());
    assert_eq!(
        check(&c, &w(need - 1), &l, IN_WINDOW),
        Err(TopUpRefuse::GasReserve)
    );
    let g = TopUpRequest {
        gas_limit: 300_001,
        ..req(1, C)
    };
    assert_eq!(check(&c, &g, &l, IN_WINDOW), Err(TopUpRefuse::GasLimit));
    let f = TopUpRequest {
        priority_fee_wei: 5 * GWEI,
        ..req(1, C)
    };
    assert_eq!(check(&c, &f, &l, IN_WINDOW), Err(TopUpRefuse::BadFees));
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
    assert_eq!(
        check(&c, &r(3, C), &l2, IN_WINDOW),
        Err(TopUpRefuse::DailyCount)
    );
    assert_eq!(
        check(&c, &r(2, 7 * C), &l1, IN_WINDOW),
        Err(TopUpRefuse::DailyValue)
    );
    // Rolling, not calendar: two just before midnight, the third just after is still refused.
    let midnight = (IN_WINDOW / 86_400 + 1) * 86_400;
    let a = check(&c, &r(11, C), &fresh(), midnight - 60).unwrap();
    let b = check(&c, &r(12, C), &a, midnight - 30).unwrap();
    assert_eq!(
        check(&c, &r(13, C), &b, midnight + 30),
        Err(TopUpRefuse::DailyCount)
    );
    assert!(check(&c, &r(13, C), &b, midnight - 60 + 86_400).is_ok());
    // Term budget across days.
    let later = IN_WINDOW + 86_400;
    assert_eq!(
        check(&c, &r(3, 5 * C), &l2, later),
        Err(TopUpRefuse::AboveBudget)
    );
    assert!(check(&c, &r(3, 4 * C), &l2, later).is_ok());
    // Replacement: own nonce, value not above, fees +10%; the booking keeps the highest version.
    let l3 = check(&c, &replacement(2, C), &l2, IN_WINDOW).unwrap();
    assert_eq!(l3.last_24h(IN_WINDOW), (2, 8 * C));
    assert_eq!(l3.term_value(), 8 * C);
    let cheap = TopUpRequest {
        replaces_nonce: Some(2),
        ..r(2, C)
    };
    assert_eq!(
        check(&c, &cheap, &l2, IN_WINDOW),
        Err(TopUpRefuse::ReplaceFeeBump)
    );
    assert_eq!(
        check(&c, &replacement(2, 4 * C + 1), &l2, IN_WINDOW),
        Err(TopUpRefuse::AboveReplaced)
    );
    // A claimed replacement of a nonce the signer never signed, or a mismatched nonce.
    assert_eq!(
        check(&c, &replacement(9, 4 * C), &l2, IN_WINDOW),
        Err(TopUpRefuse::ReplaceUnknown)
    );
    let odd = TopUpRequest {
        replaces_nonce: Some(1),
        ..r(5, C)
    };
    assert_eq!(
        check(&c, &odd, &l2, IN_WINDOW),
        Err(TopUpRefuse::ReplaceUnknown)
    );
    // Zero value: refused, also as a replacement.
    assert_eq!(
        check(&c, &replacement(2, 0), &l2, IN_WINDOW),
        Err(TopUpRefuse::ZeroValue)
    );
    // Another top-up at one of our nonces without claiming replacement.
    assert_eq!(
        check(&c, &r(2, C), &l2, later),
        Err(TopUpRefuse::ReplaceUnknown)
    );
}

/// N6 second review: sign 4, then an unbroadcast cheaper replacement of 1 at the same nonce, then
/// another 4: both 4s could be mined. With the booking at the highest version, refused.
#[test]
fn cheap_unbroadcast_replacement_does_not_free_budget() {
    let c = TopUpConfig {
        term_budget: 5 * C,
        daily_value: 20 * C,
        daily_count: 5,
        ..cfg()
    };
    let r = |n, v| TopUpRequest {
        stated_missing: 10 * C,
        ..req(n, v)
    };
    let l1 = check(&c, &r(1, 4 * C), &fresh(), IN_WINDOW).unwrap();
    let l2 = check(&c, &replacement(1, C), &l1, IN_WINDOW).unwrap();
    assert_eq!(l2.term_value(), 4 * C);
    assert_eq!(
        check(&c, &r(2, 4 * C), &l2, IN_WINDOW),
        Err(TopUpRefuse::AboveBudget)
    );
    assert!(check(&c, &r(2, C), &l2, IN_WINDOW).is_ok());
}

#[test]
fn ledger_persists_across_restart() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("topup.json");
    let key = EthKey::from_hex(&format!("0x{}", "22".repeat(32))).unwrap();
    let c = cfg();
    let mut l = TopUpLedger::create(&path).unwrap();
    l.sign(&c, &key, &req(1, 2 * C), IN_WINDOW).unwrap();
    l.sign(&c, &key, &req(2, 2 * C), IN_WINDOW).unwrap();
    drop(l);
    let mut l = TopUpLedger::open(&path).unwrap();
    assert_eq!(l.state.last_24h(IN_WINDOW).0, 2);
    assert_eq!(
        l.sign(&c, &key, &req(3, C), IN_WINDOW),
        Err(TopUpRefuse::DailyCount)
    );
    assert_eq!(TopUpLedger::open(&path).unwrap().state.booked.len(), 2);
}

/// A missing or non-private ledger refuses every topUp; the operator recreates it explicitly.
#[test]
fn missing_or_open_ledger_refuses() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("topup.json");
    assert_eq!(
        TopUpLedger::open(&p).err(),
        Some(TopUpRefuse::LedgerMissing)
    );
    TopUpLedger::create(&p).unwrap();
    assert!(TopUpLedger::create(&p).is_err());
    assert!(TopUpLedger::open(&p).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(TopUpLedger::open(&p).err(), Some(TopUpRefuse::LedgerPerms));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Deleted, then the signer restarts: topUp refused, never restarted from zero.
    std::fs::remove_file(&p).unwrap();
    let s = signer(Some(p));
    assert_eq!(
        refused(s.handle_at(wire(1, C, 100 * C), IN_WINDOW as i64)),
        "topup:LedgerMissing"
    );
}

#[test]
fn signer_service_end_to_end() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("topup.json");
    TopUpLedger::create(&p).unwrap();
    let s = signer(Some(p));
    let (_, key) = golden_key();
    let Response::Ok { value: raw } = s.handle_at(wire(7, 5 * C, 100 * C), IN_WINDOW as i64) else {
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
    let at = |r| refused(s.handle_at(r, IN_WINDOW as i64));
    assert_eq!(at(wire(8, 6 * C, 100 * C)), "topup:AboveMissing");
    assert_eq!(
        refused(s.handle_at(wire(8, C, 100 * C), (END - 8 * 86_400) as i64)),
        "topup:OutsideWindow"
    );
    assert_eq!(at(wire(8, C, C)), "topup:GasReserve");
    let _ = s.handle_at(wire(8, C, 100 * C), IN_WINDOW as i64);
    assert_eq!(at(wire(9, C, 100 * C)), "topup:DailyCount");
    let bad = Request::SignTopUp {
        nonce: 9,
        gas_limit: 1,
        max_fee_wei: "x".into(),
        priority_fee_wei: "1".into(),
        value: "1e18".into(),
        stated_missing: "1".into(),
        stated_wallet: "1".into(),
        replaces_nonce: None,
    };
    assert_eq!(at(bad), "topup_fields");
    assert_eq!(
        refused(signer(None).handle_at(wire(1, 1, 1), IN_WINDOW as i64)),
        "topup_disabled"
    );
}

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

/// N6 third review: absolute caps on maxFee and the tip; a hijacked conet-node cannot burn the
/// wallet as fees. A +10% replacement may not pass the caps either.
#[test]
fn fee_caps_are_absolute() {
    let c = TopUpConfig {
        tip_cap: 100_000_000,
        ..cfg()
    };
    let l = fresh();
    // N6's request: 1 CNET per gas as maxFee and tip.
    let burn = TopUpRequest {
        max_fee_wei: C,
        priority_fee_wei: C,
        stated_wallet: u128::MAX / 4,
        ..req(1, C)
    };
    assert_eq!(check(&c, &burn, &l, IN_WINDOW), Err(TopUpRefuse::FeeCap));
    let over_max = TopUpRequest {
        max_fee_wei: 50 * GWEI + 1,
        ..req(1, C)
    };
    assert_eq!(
        check(&c, &over_max, &l, IN_WINDOW),
        Err(TopUpRefuse::FeeCap)
    );
    let over_tip = TopUpRequest {
        priority_fee_wei: 100_000_001,
        ..req(1, C)
    };
    assert_eq!(
        check(&c, &over_tip, &l, IN_WINDOW),
        Err(TopUpRefuse::FeeCap)
    );
    // At the caps: fine.
    let at = TopUpRequest {
        max_fee_wei: 50 * GWEI,
        priority_fee_wei: 100_000_000,
        ..req(1, C)
    };
    let l1 = check(&c, &at, &l, IN_WINDOW).unwrap();
    // Replacing it needs +10% on both fees, which would pass the caps: refused.
    let bump = TopUpRequest {
        replaces_nonce: Some(1),
        max_fee_wei: 55 * GWEI,
        priority_fee_wei: 110_000_000,
        ..req(1, C)
    };
    assert_eq!(check(&c, &bump, &l1, IN_WINDOW), Err(TopUpRefuse::FeeCap));
}

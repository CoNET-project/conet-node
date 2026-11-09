//! AUTO-TOPUP SignTx whitelist entry for the main wallet (PROTOTYPE, PLAN ONLY: needs approval).
use si_signer::probe_role::{self, Origin, ProbeRole, Refuse};
use si_signer::topup_policy::*;

const REG: &str = "0x00000000000000000000000000000000c0de0001";
const C: u128 = 1_000_000_000_000_000_000;
const END: u64 = 1_900_000_000;

fn cfg() -> TopUpConfig {
    TopUpConfig {
        registry: REG.into(),
        own_node_id: 573,
        per_tx_cap: 10 * C,
        term_budget: 10 * C,
        first_term_end: END,
        term_length: 15_768_000,
        window: 7 * 86_400,
        gas_reserve: C / 100,
    }
}
fn data(id: u64) -> Vec<u8> {
    let mut d = topup_selector().to_vec();
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&id.to_be_bytes());
    d.extend_from_slice(&w);
    d
}
fn req(value: u128) -> TopUpRequest {
    TopUpRequest {
        tx_type: 2,
        to: Some(REG.into()),
        value,
        data: data(573),
        stated_missing: 5 * C,
        stated_wallet: 100 * C,
        replaces_nonce: None,
    }
}

#[test]
fn minimal_entry_byte_checks_caps_window_and_gas() {
    let c = cfg();
    let s = TermSpent::default();
    let now = END - 3 * 86_400;
    assert_eq!(check(&c, &req(5 * C), s, now), Ok(()));
    // The stated missing amount only lowers: above it is refused.
    assert_eq!(
        check(&c, &req(5 * C + 1), s, now),
        Err(TopUpRefuse::AboveMissing)
    );
    assert_eq!(check(&c, &req(0), s, now), Err(TopUpRefuse::ZeroValue));
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                data: data(574),
                ..req(C)
            },
            s,
            now
        ),
        Err(TopUpRefuse::NotOwnNode)
    );
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                tx_type: 0,
                ..req(C)
            },
            s,
            now
        ),
        Err(TopUpRefuse::NotType2)
    );
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                to: Some("0x00000000000000000000000000000000000000bb".into()),
                ..req(C)
            },
            s,
            now
        ),
        Err(TopUpRefuse::WrongTo)
    );
    let mut other = probe_role::selector("withdraw(uint256)").to_vec();
    other.extend_from_slice(&data(573)[4..]);
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                data: other,
                ..req(C)
            },
            s,
            now
        ),
        Err(TopUpRefuse::Selector)
    );
    let mut long = data(573);
    long.push(0);
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                data: long,
                ..req(C)
            },
            s,
            now
        ),
        Err(TopUpRefuse::BadCalldata)
    );
    // Window from the signer's own clock + configured first end and length.
    assert_eq!(
        check(&c, &req(C), s, END - 8 * 86_400),
        Err(TopUpRefuse::OutsideWindow)
    );
    let second_end = END + 15_768_000;
    assert_eq!(c.current_term_end(END + 1), second_end);
    assert_eq!(check(&c, &req(C), s, second_end - 86_400), Ok(())); // next term's window
    assert_eq!(
        check(&c, &req(C), s, END + 86_400),
        Err(TopUpRefuse::OutsideWindow)
    );
    // Caps.
    let big = TopUpRequest {
        stated_missing: 50 * C,
        ..req(11 * C)
    };
    assert_eq!(check(&c, &big, s, now), Err(TopUpRefuse::AboveCap));
    let spent = TermSpent {
        term_end: END,
        value: 9 * C,
    };
    assert_eq!(
        check(&c, &req(2 * C), spent, now),
        Err(TopUpRefuse::AboveBudget)
    );
    // Budget is per term: last term's spending does not count.
    assert_eq!(
        check(
            &c,
            &req(2 * C),
            TermSpent {
                term_end: END - 15_768_000,
                value: 9 * C
            },
            now
        ),
        Ok(())
    );
    // Gas left after signing.
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                stated_wallet: 5 * C,
                ..req(5 * C)
            },
            s,
            now
        ),
        Err(TopUpRefuse::GasReserve)
    );
    // A zero-value same-nonce replacement is allowed (retires our pending top-up).
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                replaces_nonce: Some(10),
                stated_missing: 0,
                ..req(0)
            },
            s,
            now
        ),
        Ok(())
    );
}

/// The probe wallet never signs a top-up, whatever channel it comes from.
#[test]
fn probe_wallet_refuses_topup() {
    let k = si_crypto::eth::EthKey::from_hex(&format!("0x{}", "22".repeat(32))).unwrap();
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

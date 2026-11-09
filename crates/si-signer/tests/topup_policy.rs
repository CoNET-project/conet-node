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
        daily_count: 2,
        daily_value: 10 * C,
        window: 7 * 86_400,
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
        stated_term_end: END,
    }
}

#[test]
fn minimal_entry_accepts_only_own_topup_up_to_the_missing_amount_in_the_window() {
    let c = cfg();
    let t = Today::default();
    let now = END - 3 * 86_400;
    assert_eq!(check(&c, &req(5 * C), t, now), Ok(()));
    assert_eq!(
        check(&c, &req(5 * C + 1), t, now),
        Err(TopUpRefuse::AboveMissing)
    );
    assert_eq!(check(&c, &req(0), t, now), Err(TopUpRefuse::ZeroValue));
    assert_eq!(
        check(
            &c,
            &TopUpRequest {
                data: data(574),
                ..req(C)
            },
            t,
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
            t,
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
            t,
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
            t,
            now
        ),
        Err(TopUpRefuse::Selector)
    );
    // Window: not before end - 7 days, not at or after the end.
    assert_eq!(
        check(&c, &req(C), t, END - 8 * 86_400),
        Err(TopUpRefuse::OutsideWindow)
    );
    assert_eq!(check(&c, &req(C), t, END), Err(TopUpRefuse::OutsideWindow));
    // Caps that need no chain view.
    let big = TopUpRequest {
        stated_missing: 50 * C,
        ..req(11 * C)
    };
    assert_eq!(check(&c, &big, t, now), Err(TopUpRefuse::AboveCap));
    assert_eq!(
        check(&c, &req(C), Today { count: 2, value: 0 }, now),
        Err(TopUpRefuse::DailyCount)
    );
    assert_eq!(
        check(
            &c,
            &req(2 * C),
            Today {
                count: 1,
                value: 9 * C
            },
            now
        ),
        Err(TopUpRefuse::DailyValue)
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

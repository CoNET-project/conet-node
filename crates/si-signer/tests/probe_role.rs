//! Q117 probe-wallet role policy (prototype), N6 §H.8.19 cases Q14 and Q15. TEST KEY ONLY.
use si_core::probe::{ProbeDomain, ProbeRequest};
use si_crypto::eip712 as e7;
use si_crypto::eth::{recover_digest, EthKey};
use si_signer::probe_role::*;

const REG: &str = "0x00000000000000000000000000000000c0de0001";

fn word(n: u64) -> [u8; 32] {
    e7::u64_word(n)
}
fn call(sig: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut d = selector(sig).to_vec();
    for w in words {
        d.extend_from_slice(w);
    }
    d
}
fn tx(data: Vec<u8>) -> TxRequest {
    TxRequest {
        tx_type: 2,
        to: Some(REG.into()),
        value: 0,
        data,
    }
}
fn role(key: &EthKey) -> ProbeRole<'_> {
    ProbeRole {
        key,
        domain: ProbeDomain::new(REG).unwrap(),
        registry: REG.into(),
    }
}
fn key() -> EthKey {
    EthKey::from_hex(&format!("0x{}", "22".repeat(32))).unwrap()
}

#[test]
fn positive_control_votes_from_the_vote_gate_pass() {
    let k = key();
    let r = role(&k);
    for (sig, first, e) in [
        ("voteReport(uint256,bool)", word(7), VoteEntry::Report),
        (
            "voteAdmission(bytes32,bool)",
            [9u8; 32],
            VoteEntry::Admission,
        ),
        ("voteRecovery(bytes32,bool)", [8u8; 32], VoteEntry::Recovery),
    ] {
        let d = call(sig, &[first, word(1)]);
        assert_eq!(
            r.handle(Origin::LocalVoteGate, Request::SignVoteTx(tx(d.clone()))),
            Ok(Signed::VoteApproved { entry: e, data: d })
        );
    }
}

/// Q14: reportOffline, markOnline, topUp, withdraw, updateNodeWallet, setProbeSigner, a value
/// transaction, a type 0 transaction: all refused, even on the vote-gate channel.
#[test]
fn q14_everything_outside_the_three_votes_is_refused() {
    let k = key();
    let r = role(&k);
    let gate = |t: TxRequest| r.handle(Origin::LocalVoteGate, Request::SignVoteTx(t));
    let addr = e7::address_word("0x00000000000000000000000000000000000000aa").unwrap();
    for (sig, words) in [
        ("reportOffline(uint256)", vec![word(5)]),
        ("markOnline(uint256)", vec![word(5)]),
        ("topUp(uint256)", vec![word(5)]),
        ("withdraw(uint256)", vec![word(5)]),
        (
            "updateNodeWallet(uint256,address,uint256,bytes)",
            vec![word(5), addr, word(9), word(128), word(0)],
        ),
        (
            "setProbeSigner(uint256,address,uint48,bytes)",
            vec![word(5), addr, word(9), word(128), word(0)],
        ),
        ("revokeProbeSigner(uint256)", vec![word(5)]),
        ("finalizeReport(uint256)", vec![word(5)]),
        ("finalizeAdmission(bytes32)", vec![[1u8; 32]]),
        ("finalizeRecovery(bytes32)", vec![[1u8; 32]]),
    ] {
        let got = gate(tx(call(sig, &words)));
        assert_eq!(
            got,
            Err(Refuse::Selector(hex::encode(selector(sig)))),
            "{sig}"
        );
    }
    let vote = call("voteRecovery(bytes32,bool)", &[[8u8; 32], word(1)]);
    // value
    assert_eq!(
        gate(TxRequest {
            value: 1,
            ..tx(vote.clone())
        }),
        Err(Refuse::HasValue)
    );
    // type 0
    assert_eq!(
        gate(TxRequest {
            tx_type: 0,
            ..tx(vote.clone())
        }),
        Err(Refuse::NotType2)
    );
    // another contract, contract creation
    assert_eq!(
        gate(TxRequest {
            to: Some("0x00000000000000000000000000000000000000bb".into()),
            ..tx(vote.clone())
        }),
        Err(Refuse::WrongTo)
    );
    assert_eq!(
        gate(TxRequest {
            to: None,
            ..tx(vote.clone())
        }),
        Err(Refuse::Creation)
    );
    // calldata shape: extra word, bool not 0/1
    let mut long = vote.clone();
    long.extend_from_slice(&word(0));
    assert_eq!(gate(tx(long)), Err(Refuse::BadCalldata));
    assert_eq!(
        gate(tx(call(
            "voteRecovery(bytes32,bool)",
            &[[8u8; 32], word(2)]
        ))),
        Err(Refuse::BadCalldata)
    );
    // generic transactions and the consent are never served by this role
    assert_eq!(
        r.handle(Origin::LocalVoteGate, Request::SignTx(tx(vote))),
        Err(Refuse::NotThisRole)
    );
    assert_eq!(
        r.handle(Origin::LocalVoteGate, Request::SignProbeSignerAccept),
        Err(Refuse::ConsentNotServed)
    );
}

/// Q15: network traffic cannot reach the vote entry. A probe request whose fields carry vote
/// calldata yields only a probe-domain signature; a vote request on the probe channel is refused.
#[test]
fn q15_network_cannot_trigger_a_vote() {
    let k = key();
    let r = role(&k);
    let vote = call("voteRecovery(bytes32,bool)", &[[8u8; 32], word(1)]);
    let mut nonce = [0u8; 32];
    nonce[..4].copy_from_slice(&vote[..4]);
    let crafted = ProbeRequest {
        version: 1,
        prober_node_id: word(7),
        prober_wallet: e7::address_word(REG).unwrap(), // registry address planted as a field
        target_node_id: [8u8; 32],
        target_wallet: e7::address_word(&k.address()).unwrap(),
        target_ip_hash: word(1),
        target_port: 443,
        nonce,
        issued_at: 1,
        expires_at: 2,
    };
    let out = r
        .handle(
            Origin::ProbeChannel,
            Request::SignProbeRequest(crafted.clone()),
        )
        .unwrap();
    let Signed::ProbeSignature { digest, sig } = out else {
        panic!("a probe request produced something other than a probe signature")
    };
    assert_eq!(digest, crafted.digest(&ProbeDomain::new(REG).unwrap()));
    assert!(recover_digest(&digest, &sig)
        .unwrap()
        .eq_ignore_ascii_case(&k.address()));
    // A well-formed vote on the probe channel: refused before the whitelist is even consulted.
    assert_eq!(
        r.handle(Origin::ProbeChannel, Request::SignVoteTx(tx(vote))),
        Err(Refuse::NotFromVoteGate)
    );
}

#[test]
fn selectors_match_the_design_table() {
    assert_eq!(
        hex::encode(selector("voteReport(uint256,bool)")),
        "a7a17ad2"
    );
    assert_eq!(
        hex::encode(selector("voteAdmission(bytes32,bool)")),
        "ada285b1"
    );
    assert_eq!(
        hex::encode(selector("voteRecovery(bytes32,bool)")),
        "2964b390"
    );
}

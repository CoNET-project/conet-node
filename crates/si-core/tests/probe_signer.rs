//! ProbeSignerAccept (Q117 乙, N6 §H.8.20) against the ethers 6 vector
//! (conformance/vectors/probe-signer.json): own domain `CoNET-NodeProbeSigner`.
use serde_json::Value;
use si_core::probe::{ProbeDomain, DOMAIN_NAME as PROBE_MSG_DOMAIN};
use si_core::probe_signer::*;
use si_crypto::{eip712 as e7, eth};

fn vector() -> Value {
    let p = format!(
        "{}/../../conformance/vectors/probe-signer.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn accept_matches_ethers_and_recovers_the_probe_signer() {
    let v = vector();
    let val = &v["value"];
    let reg = v["domain"]["verifyingContract"].as_str().unwrap();
    let d = ProbeSignerDomain::new(reg).unwrap();
    let a = ProbeSignerAccept {
        node_id: e7::u256_dec(val["nodeId"].as_str().unwrap()).unwrap(),
        node_wallet: e7::address_word(val["nodeWallet"].as_str().unwrap()).unwrap(),
        probe_signer: e7::address_word(val["probeSigner"].as_str().unwrap()).unwrap(),
    };
    assert_eq!(
        e7::to_hex(&d.separator()),
        v["domainSeparator"].as_str().unwrap()
    );
    assert_eq!(
        e7::to_hex(&a.struct_hash()),
        v["structHash"].as_str().unwrap()
    );
    assert_eq!(e7::to_hex(&a.digest(&d)), v["digest"].as_str().unwrap());
    assert_eq!(
        e7::to_hex(&eth::keccak256(PURPOSE.as_bytes())),
        val["purpose"].as_str().unwrap()
    );
    let who = eth::recover_digest(&a.digest(&d), v["signature"].as_str().unwrap()).unwrap();
    assert!(who.eq_ignore_ascii_case(val["probeSigner"].as_str().unwrap()));
}

/// The same consent struct in the probe-message domain gives another digest, so a consent can
/// never be taken from a probe-message signature or the other way round (the contract refuses a
/// consent signed in `CoNET-NodeProbe`).
#[test]
fn consent_and_probe_message_domains_differ() {
    let v = vector();
    let reg = v["domain"]["verifyingContract"].as_str().unwrap();
    assert_ne!(DOMAIN_NAME, PROBE_MSG_DOMAIN);
    let consent = ProbeSignerDomain::new(reg).unwrap();
    let probe = ProbeDomain::new(reg).unwrap();
    assert_ne!(consent.separator(), probe.separator);
    let val = &v["value"];
    let a = ProbeSignerAccept {
        node_id: e7::u256_dec(val["nodeId"].as_str().unwrap()).unwrap(),
        node_wallet: e7::address_word(val["nodeWallet"].as_str().unwrap()).unwrap(),
        probe_signer: e7::address_word(val["probeSigner"].as_str().unwrap()).unwrap(),
    };
    let in_probe = probe.digest(&a.struct_hash());
    assert_eq!(
        e7::to_hex(&in_probe),
        v["digestInProbeMessageDomain"].as_str().unwrap()
    );
    assert_ne!(in_probe, a.digest(&consent));
}

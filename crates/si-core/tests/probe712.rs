//! P-01: the four probe message types against ethers 6 vectors (conformance/vectors/probe712.json).
use serde_json::Value;
use si_core::probe::*;
use si_crypto::{eip712 as e7, eth};

fn load(name: &str) -> Value {
    let p = format!(
        "{}/../../conformance/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k}"))
}
fn n(v: &Value, k: &str) -> u64 {
    match &v[k] {
        Value::Number(x) => x.as_u64().unwrap(),
        Value::String(t) => t.parse().unwrap(),
        _ => panic!("{k}"),
    }
}
fn w(v: &Value, k: &str) -> e7::Word {
    e7::u256_dec(s(v, k)).unwrap()
}
fn a(v: &Value, k: &str) -> e7::Word {
    e7::address_word(s(v, k)).unwrap()
}
fn b(v: &Value, k: &str) -> e7::Word {
    e7::bytes32(s(v, k)).unwrap()
}

/// (type string, struct hash, digest) computed by si-core for one vector.
fn compute(input: &Value, d: &ProbeDomain) -> (&'static str, e7::Word, e7::Word) {
    let v = &input["value"];
    match s(input, "primaryType") {
        "ProbeRequest" => {
            let r = ProbeRequest {
                version: n(v, "version") as u16,
                prober_node_id: w(v, "proberNodeId"),
                prober_wallet: a(v, "proberWallet"),
                target_node_id: w(v, "targetNodeId"),
                target_wallet: a(v, "targetWallet"),
                target_ip_hash: b(v, "targetIpHash"),
                target_port: n(v, "targetPort") as u16,
                nonce: b(v, "nonce"),
                issued_at: n(v, "issuedAt"),
                expires_at: n(v, "expiresAt"),
            };
            (PROBE_REQUEST_TYPE, r.struct_hash(), r.digest(d))
        }
        "ProbeReply" => {
            let r = ProbeReply {
                request_hash: b(v, "requestHash"),
                replier_node_id: w(v, "replierNodeId"),
                replier_wallet: a(v, "replierWallet"),
                replied_at: n(v, "repliedAt"),
                expires_at: n(v, "expiresAt"),
                flags: n(v, "flags") as u8,
                registry_block: n(v, "registryBlock"),
            };
            (PROBE_REPLY_TYPE, r.struct_hash(), r.digest(d))
        }
        "ProbeDelegation" => {
            let r = ProbeDelegation {
                voter_node_id: w(v, "voterNodeId"),
                voter_wallet: a(v, "voterWallet"),
                relay_node_id: w(v, "relayNodeId"),
                target_node_id: w(v, "targetNodeId"),
                report_id: w(v, "reportId"),
                challenge: b(v, "challenge"),
                issued_at: n(v, "issuedAt"),
                expires_at: n(v, "expiresAt"),
            };
            (PROBE_DELEGATION_TYPE, r.struct_hash(), r.digest(d))
        }
        "OfflineEvidence" => {
            let hs: Vec<e7::Word> = v["requestHashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| e7::bytes32(x.as_str().unwrap()).unwrap())
                .collect();
            let ats: Vec<u64> = v["issuedAts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().parse().unwrap())
                .collect();
            let r = OfflineEvidence {
                reporter_node_id: w(v, "reporterNodeId"),
                reporter_wallet: a(v, "reporterWallet"),
                target_node_id: w(v, "targetNodeId"),
                request_hashes: [hs[0], hs[1], hs[2]],
                issued_ats: [ats[0], ats[1], ats[2]],
                published_at: n(v, "publishedAt"),
            };
            (OFFLINE_EVIDENCE_TYPE, r.struct_hash(), r.digest(d))
        }
        other => panic!("{other}"),
    }
}

#[test]
fn probe_typed_data_golden() {
    let file = load("probe712.json");
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 7);
    let mut kinds = std::collections::BTreeSet::new();
    for vec in vectors {
        let (id, input, exp) = (s(vec, "id"), &vec["input"], &vec["expect"]);
        let dom = &input["domain"];
        assert_eq!(
            (s(dom, "name"), s(dom, "version")),
            (DOMAIN_NAME, DOMAIN_VERSION),
            "{id}"
        );
        assert_eq!(dom["chainId"].as_u64(), Some(224_422), "{id}");
        let d = ProbeDomain::new(s(dom, "verifyingContract")).unwrap();
        assert_eq!(e7::to_hex(&d.separator), s(exp, "domainSeparator"), "{id}");
        let (t, sh, dg) = compute(input, &d);
        kinds.insert(t);
        assert_eq!(t, s(exp, "typeString"), "{id}: type string");
        assert_eq!(e7::to_hex(&e7::type_hash(t)), s(exp, "typeHash"), "{id}");
        assert_eq!(e7::to_hex(&sh), s(exp, "structHash"), "{id}");
        assert_eq!(e7::to_hex(&dg), s(exp, "digest"), "{id}");
        // The ethers signature recovers the golden wallet over the same digest.
        let who = eth::recover_digest(&dg, s(exp, "signature")).unwrap();
        assert!(who.eq_ignore_ascii_case(s(exp, "address")), "{id}");
    }
    assert_eq!(kinds.len(), 4, "all four types covered");
}

#[test]
fn probe_domain_is_not_the_registry_domain() {
    let file = load("probe712.json");
    let vec = &file["vectors"][0];
    let contract = s(&vec["input"]["domain"], "verifyingContract");
    let probe = ProbeDomain::new(contract).unwrap();
    // Same struct under the registry's own domain, another chain or another registry.
    for other in [
        ProbeDomain::with("CoNETNodeRegistry", "1", 224_422, contract).unwrap(),
        ProbeDomain::with(DOMAIN_NAME, DOMAIN_VERSION, 1, contract).unwrap(),
        ProbeDomain::with(
            DOMAIN_NAME,
            DOMAIN_VERSION,
            224_422,
            "0x00000000000000000000000000000000c0de0002",
        )
        .unwrap(),
    ] {
        let (_, sh, dg) = compute(&vec["input"], &probe);
        assert_ne!(other.digest(&sh), dg);
    }
}

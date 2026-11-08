//! Operator registration data (F7): typed data, digests and calldata for NodeRegistryV2 v0.1.
//! Builds data only; it never sends a transaction (the operator's own wallet does that).
//!
//! - Sponsored registration (`registerFor`): the operator signs `RegisterRequest` (typed data
//!   for `eth_signTypedData_v4`), prestakes against its digest, the node wallet signs a
//!   `BindNode` with nodeId 0 and the request's nonce and deadline (signer `SignBind`).
//! - Migration (`registerReserved`): the reserved operator sends it with the stake; the node
//!   wallet signs a `BindNode` with nodeId = legacy id and its current bind nonce. Migrated
//!   nodes may not carry the mailbox bit (Q94).
//! - Egress policy pointer (`setEgressPolicy`, W59): 36-byte CIDv1/raw/sha2-256 of the policy
//!   file, at most 256 KiB.
use crate::nr2::NodeRegistryV2 as R;
use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::SolCall;
use serde_json::{json, Value};
use si_core::statement::{pgp_field, Domain};
use si_crypto::eip712::Word;
use si_proto::node_registry as nr;

/// Policy files above this size mean "no policy" (W59).
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
/// CIDv1, raw codec, sha2-256, 32-byte digest.
pub const CID_PREFIX: [u8; 4] = [0x01, 0x55, 0x12, 0x20];

#[derive(Debug, PartialEq, Eq)]
pub struct BuildError(pub String);

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for BuildError {}

fn be(s: impl Into<String>) -> BuildError {
    BuildError(s.into())
}

/// The route key ID (first subkey) of an armored public key, as the contract's `bytes8`.
pub fn key_id_of(armored_public: &str) -> Result<FixedBytes<8>, BuildError> {
    let cert = si_crypto::opgp::PublicCert::from_armor(armored_public)
        .map_err(|_| be("not an armored public key"))?;
    let id = cert.enc_key_id().ok_or_else(|| be("key has no subkey"))?;
    let b: [u8; 8] = hex::decode(id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| be("key id"))?;
    Ok(FixedBytes(b))
}

/// Things the operator must see before signing.
pub fn warnings(node_type: u8, services: u16) -> Vec<&'static str> {
    let mut w = vec![];
    if services & nr::SVC_MAILBOX != 0 {
        w.push("mailbox bit: chosen once at registration; it can only be switched off (fine 0.5 CNET, re-enable after 7 days); changing the node wallet or PGP key costs 0.5 CNET each and a PGP change invalidates every user route to this mailbox at once (users must re-sign); exit only after 30 days out of service, with declareOffline first");
        if node_type != nr::TYPE_TCP {
            w.push("only TCP (Linux) nodes may hold mailboxes: the contract will refuse this");
        }
    }
    if services & (nr::SVC_EGRESS_TCP | nr::SVC_EGRESS_HTTP) != 0 {
        w.push("egress bits: the exit stays closed until setEgressPolicy points at the same policy file the node loads");
    }
    w
}

pub struct RegisterInput {
    pub operator: Address,
    pub beneficiary: Address,
    pub node_wallet: Address,
    pub node_type: u8,
    pub ip: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub armored_public: String,
    pub services: u16,
    pub sponsor_node_id: U256,
    pub nonce: U256,
    pub deadline: U256,
}

/// A prepared sponsored registration.
pub struct Prepared {
    pub request: R::RegisterRequest,
    /// Contract PGP field (base64 of the armor); goes into `registerFor` as `pgp`.
    pub pgp: String,
    /// EIP-712 digest = the contract's `requestHash` (prestake key).
    pub request_hash: B256,
}

fn word(b: B256) -> Word {
    b.0
}

fn u256_word(v: U256) -> Word {
    v.to_be_bytes::<32>()
}

fn addr_word(a: Address) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a.as_slice());
    w
}

fn key_word(k: FixedBytes<8>) -> Word {
    let mut w = [0u8; 32];
    w[..8].copy_from_slice(k.as_slice());
    w
}

pub fn prepare_register(inp: &RegisterInput, registry: &str) -> Result<Prepared, BuildError> {
    let ip_hash = if inp.node_type == nr::TYPE_TCP {
        let ip = nr::check_canonical_ip(&inp.ip).map_err(be)?;
        B256::from(si_core::statement::ip_hash_of(ip).map_err(be)?)
    } else {
        if !inp.ip.is_empty() {
            return Err(be("browser and mobile nodes register no IP"));
        }
        B256::ZERO
    };
    let key_id = key_id_of(&inp.armored_public)?;
    let pgp = pgp_field(&inp.armored_public);
    let pgp_hash = B256::from(si_core::statement::pgp_hash(&inp.armored_public));
    let request = R::RegisterRequest {
        operator: inp.operator,
        beneficiary: inp.beneficiary,
        nodeWallet: inp.node_wallet,
        nodeType: inp.node_type,
        ipHash: ip_hash,
        tcpPort: inp.tcp_port,
        udpPort: inp.udp_port,
        pgpHash: pgp_hash,
        keyId: key_id,
        services: inp.services,
        sponsorNodeId: inp.sponsor_node_id,
        nonce: inp.nonce,
        deadline: inp.deadline,
    };
    let domain = Domain::new(registry).map_err(|e| be(e.to_string()))?;
    let digest = si_core::statement::RegisterRequest {
        operator: addr_word(inp.operator),
        beneficiary: addr_word(inp.beneficiary),
        node_wallet: addr_word(inp.node_wallet),
        node_type: inp.node_type,
        ip_hash: word(ip_hash),
        tcp_port: inp.tcp_port,
        udp_port: inp.udp_port,
        pgp_hash: word(pgp_hash),
        key_id: key_word(key_id),
        services: inp.services,
        sponsor_node_id: u256_word(inp.sponsor_node_id),
        nonce: u256_word(inp.nonce),
        deadline: u256_word(inp.deadline),
    }
    .digest(&domain);
    Ok(Prepared {
        request,
        pgp,
        request_hash: B256::from(digest),
    })
}

/// `eth_signTypedData_v4` payload for the operator's wallet.
pub fn typed_data(r: &R::RegisterRequest, registry: &str) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "RegisterRequest": [
                {"name": "operator", "type": "address"},
                {"name": "beneficiary", "type": "address"},
                {"name": "nodeWallet", "type": "address"},
                {"name": "nodeType", "type": "uint8"},
                {"name": "ipHash", "type": "bytes32"},
                {"name": "tcpPort", "type": "uint16"},
                {"name": "udpPort", "type": "uint16"},
                {"name": "pgpHash", "type": "bytes32"},
                {"name": "keyId", "type": "bytes8"},
                {"name": "services", "type": "uint16"},
                {"name": "sponsorNodeId", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"}
            ]
        },
        "primaryType": "RegisterRequest",
        "domain": {
            "name": nr::DOMAIN_NAME,
            "version": nr::DOMAIN_VERSION,
            "chainId": nr::CHAIN_ID,
            "verifyingContract": registry.to_lowercase(),
        },
        "message": {
            "operator": format!("{:#x}", r.operator),
            "beneficiary": format!("{:#x}", r.beneficiary),
            "nodeWallet": format!("{:#x}", r.nodeWallet),
            "nodeType": r.nodeType,
            "ipHash": format!("{:#x}", r.ipHash),
            "tcpPort": r.tcpPort,
            "udpPort": r.udpPort,
            "pgpHash": format!("{:#x}", r.pgpHash),
            "keyId": format!("{:#x}", r.keyId),
            "services": r.services,
            "sponsorNodeId": r.sponsorNodeId.to_string(),
            "nonce": r.nonce.to_string(),
            "deadline": r.deadline.to_string(),
        }
    })
}

/// Fields of the signer's `SignBind` request (JSON as the signer protocol spells it).
pub fn bind_request(
    operator: Address,
    node_id: U256,
    ip_hash: B256,
    key_id: FixedBytes<8>,
    pgp_hash: B256,
    nonce: U256,
    deadline: U256,
) -> Value {
    json!({
        "op": "sign_bind",
        "operator": format!("{operator:#x}"),
        "nodeId": node_id.to_string(),
        "ipHash": format!("{ip_hash:#x}"),
        "keyId": format!("{key_id:#x}"),
        "pgpHash": format!("{pgp_hash:#x}"),
        "nonce": nonce.to_string(),
        "deadline": deadline.to_string(),
    })
}

fn sig_bytes(hex_sig: &str) -> Result<Bytes, BuildError> {
    let b =
        hex::decode(hex_sig.trim().trim_start_matches("0x")).map_err(|_| be("signature hex"))?;
    if b.len() != 65 {
        return Err(be("signature must be 65 bytes"));
    }
    Ok(b.into())
}

pub fn prestake_calldata(request_hash: B256) -> Vec<u8> {
    R::prestakeCall {
        requestHash: request_hash,
    }
    .abi_encode()
}

pub fn register_for_calldata(
    p: &Prepared,
    ip: &str,
    operator_sig: &str,
    node_sig: &str,
) -> Result<Vec<u8>, BuildError> {
    Ok(R::registerForCall {
        r: p.request.clone(),
        ip: ip.to_string(),
        pgp: p.pgp.clone().into_bytes().into(),
        operatorSig: sig_bytes(operator_sig)?,
        nodeWalletSig: sig_bytes(node_sig)?,
    }
    .abi_encode())
}

pub struct ReservedInput {
    pub legacy_id: U256,
    pub operator: Address,
    pub ip: String,
    pub udp_port: u16,
    pub node_wallet: Address,
    pub deadline: U256,
    pub armored_public: String,
    pub services: u16,
    /// The node wallet's current `bindNonceOf`.
    pub bind_nonce: U256,
}

/// The node's `SignBind` request for a reserved (migrated) registration.
pub fn reserved_bind(inp: &ReservedInput) -> Result<Value, BuildError> {
    if inp.services & nr::SVC_MAILBOX != 0 {
        return Err(be("migrated nodes carry no mailbox bit (Q94)"));
    }
    let ip = nr::check_canonical_ip(&inp.ip).map_err(be)?;
    let ip_hash = B256::from(si_core::statement::ip_hash_of(ip).map_err(be)?);
    Ok(bind_request(
        inp.operator,
        inp.legacy_id,
        ip_hash,
        key_id_of(&inp.armored_public)?,
        B256::from(si_core::statement::pgp_hash(&inp.armored_public)),
        inp.bind_nonce,
        inp.deadline,
    ))
}

pub fn register_reserved_calldata(
    inp: &ReservedInput,
    bind_sig: &str,
) -> Result<Vec<u8>, BuildError> {
    reserved_bind(inp)?;
    Ok(R::registerReservedCall {
        legacyId: inp.legacy_id,
        ip: inp.ip.clone(),
        udpPort: inp.udp_port,
        nodeWallet: inp.node_wallet,
        deadline: inp.deadline,
        bindSig: sig_bytes(bind_sig)?,
        pgp: pgp_field(&inp.armored_public).into_bytes().into(),
        services: inp.services,
    }
    .abi_encode())
}

/// 36-byte binary CID of a policy file (CIDv1, raw, sha2-256). Over 256 KiB → error.
pub fn policy_cid(file: &[u8]) -> Result<[u8; 36], BuildError> {
    if file.len() > MAX_POLICY_BYTES {
        return Err(be("policy file over 256 KiB"));
    }
    let mut cid = [0u8; 36];
    cid[..4].copy_from_slice(&CID_PREFIX);
    use sha2::Digest;
    cid[4..].copy_from_slice(&sha2::Sha256::digest(file));
    Ok(cid)
}

/// Text form (multibase base32 lower, `b` prefix): `bafkrei…`. For display and IPFS only;
/// the contract takes the 36 bytes.
pub fn cid_text(cid: &[u8]) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::from("b");
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in cid {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn set_egress_policy_calldata(node_id: U256, cid: Option<&[u8; 36]>) -> Vec<u8> {
    R::setEgressPolicyCall {
        nodeId: node_id,
        cid: cid.map(|c| c.to_vec()).unwrap_or_default().into(),
    }
    .abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::{eip712_domain, SolStruct};

    const REGISTRY: &str = "0x00000000000000000000000000000000c0de0001";

    fn golden() -> Value {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/golden.json"
        );
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn vector(g: &Value, id: &str) -> Value {
        g["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap()
            .clone()
    }

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    /// The golden `nr2-register-tcp` vector rebuilt through this module.
    #[test]
    fn register_request_matches_golden_vector() {
        let g = golden();
        let v = vector(&g, "nr2-register-tcp");
        let m = &v["input"]["value"];
        let inp = RegisterInput {
            operator: addr(m["operator"].as_str().unwrap()),
            beneficiary: addr(m["beneficiary"].as_str().unwrap()),
            node_wallet: addr(m["nodeWallet"].as_str().unwrap()),
            node_type: 1,
            ip: "192.0.2.10".into(),
            tcp_port: 8443,
            udp_port: 18443,
            armored_public: g["keys"]["nodeA"]["armoredPublic"].as_str().unwrap().into(),
            services: 0b1011,
            sponsor_node_id: U256::from(7),
            nonce: U256::from(1),
            deadline: U256::from(1_800_000_000u64),
        };
        let p = prepare_register(&inp, REGISTRY).unwrap();
        assert_eq!(
            format!("{:#x}", p.request_hash),
            v["expect"]["digest"].as_str().unwrap()
        );
        // alloy's EIP-712 over the ABI-generated struct agrees (ABI ↔ vectors).
        let domain = eip712_domain! {
            name: "CoNETNodeRegistry",
            version: "1",
            chain_id: 224422,
            verifying_contract: addr(REGISTRY),
        };
        assert_eq!(p.request.eip712_signing_hash(&domain), p.request_hash);
        // The operator's golden signature recovers through the typed data.
        let sig = v["expect"]["signature"].as_str().unwrap();
        let who = si_crypto::eth::recover_digest(&p.request_hash.0, sig).unwrap();
        assert_eq!(
            who.to_lowercase(),
            m["operator"].as_str().unwrap().to_lowercase()
        );
        let td = typed_data(&p.request, REGISTRY);
        assert_eq!(td["message"]["keyId"], m["keyId"]);
        assert_eq!(td["message"]["pgpHash"], m["pgpHash"]);

        let data = register_for_calldata(&p, "192.0.2.10", sig, sig).unwrap();
        let back = R::registerForCall::abi_decode(&data).unwrap();
        assert_eq!(back.r, p.request);
        assert_eq!(back.pgp.as_ref(), p.pgp.as_bytes());
        assert!(register_for_calldata(&p, "192.0.2.10", "0x12", sig).is_err());
        assert_eq!(
            &prestake_calldata(p.request_hash)[..4],
            &R::prestakeCall::SELECTOR
        );
    }

    #[test]
    fn register_input_checks() {
        let g = golden();
        let mut inp = RegisterInput {
            operator: Address::repeat_byte(1),
            beneficiary: Address::repeat_byte(1),
            node_wallet: Address::repeat_byte(2),
            node_type: 1,
            ip: "192.000.2.10".into(),
            tcp_port: 8443,
            udp_port: 0,
            armored_public: g["keys"]["nodeA"]["armoredPublic"].as_str().unwrap().into(),
            services: 1,
            sponsor_node_id: U256::from(1),
            nonce: U256::from(1),
            deadline: U256::from(1),
        };
        assert!(
            prepare_register(&inp, REGISTRY).is_err(),
            "non-canonical IP"
        );
        inp.ip = "192.0.2.10".into();
        inp.armored_public = "junk".into();
        assert!(prepare_register(&inp, REGISTRY).is_err(), "bad key");
    }

    #[test]
    fn reserved_registration() {
        let g = golden();
        let mut inp = ReservedInput {
            legacy_id: U256::from(42),
            operator: Address::repeat_byte(1),
            ip: "192.0.2.10".into(),
            udp_port: 0,
            node_wallet: Address::repeat_byte(2),
            deadline: U256::from(1_800_000_000u64),
            armored_public: g["keys"]["nodeA"]["armoredPublic"].as_str().unwrap().into(),
            services: nr::SVC_ENTRY | nr::SVC_MAILBOX,
            bind_nonce: U256::ZERO,
        };
        assert!(reserved_bind(&inp).unwrap_err().0.contains("Q94"));
        inp.services = nr::SVC_ENTRY;
        let b = reserved_bind(&inp).unwrap();
        assert_eq!(b["nodeId"], "42");
        assert_eq!(
            b["keyId"],
            format!(
                "0x{}",
                g["keys"]["nodeA"]["encKeyId"]
                    .as_str()
                    .unwrap()
                    .to_lowercase()
            )
        );
        let sig = format!("0x{}", "11".repeat(65));
        let data = register_reserved_calldata(&inp, &sig).unwrap();
        let back = R::registerReservedCall::abi_decode(&data).unwrap();
        assert_eq!(back.legacyId, U256::from(42));
        assert_eq!(back.services, nr::SVC_ENTRY);
    }

    #[test]
    fn policy_cid_and_text() {
        // `ipfs add --cid-version 1 --raw-leaves` of an empty file.
        let cid = policy_cid(b"").unwrap();
        assert_eq!(
            cid_text(&cid),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
        assert_eq!(&cid[..4], &CID_PREFIX);
        assert!(policy_cid(&vec![0u8; MAX_POLICY_BYTES]).is_ok());
        assert!(policy_cid(&vec![0u8; MAX_POLICY_BYTES + 1]).is_err());
        let data = set_egress_policy_calldata(U256::from(9), Some(&cid));
        let back = R::setEgressPolicyCall::abi_decode(&data).unwrap();
        assert_eq!(back.cid.as_ref(), &cid[..]);
        let clear =
            R::setEgressPolicyCall::abi_decode(&set_egress_policy_calldata(U256::from(9), None))
                .unwrap();
        assert!(clear.cid.is_empty());
    }

    #[test]
    fn mailbox_warning() {
        assert!(warnings(nr::TYPE_TCP, nr::SVC_MAILBOX)[0].contains("0.5 CNET"));
        assert_eq!(warnings(nr::TYPE_BROWSER, nr::SVC_MAILBOX).len(), 2);
        assert!(warnings(nr::TYPE_TCP, nr::SVC_ENTRY).is_empty());
    }
}

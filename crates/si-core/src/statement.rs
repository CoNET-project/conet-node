//! NodeRegistryV2 v0.1 EIP-712 typed builders (node line, Q77), byte-compatible with the
//! contract (`NodeRegistryTypes.sol`) and ethers `TypedDataEncoder`, plus the field encodings the
//! contract fixes: `ipHash` (canonical IP text), `pgpHash` (base64 armor) and `anchorsHash`.
//! v0.1 has no NodeStatement (node line v0.1.47 §8.4.38): online state is expressed by the
//! Online, Extend and Pause declarations.
use si_crypto::eip712::{self, Word};
use si_crypto::eth::keccak256;
use si_proto::node_registry as nr;

pub struct Domain {
    pub separator: Word,
}

impl Domain {
    pub fn new(verifying_contract: &str) -> si_crypto::Result<Self> {
        Ok(Self {
            separator: eip712::domain_separator(
                nr::DOMAIN_NAME,
                nr::DOMAIN_VERSION,
                nr::CHAIN_ID,
                verifying_contract,
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BindNode {
    pub operator: Word,
    pub node_id: Word,
    pub ip_hash: Word,
    pub key_id: Word,
    pub pgp_hash: Word,
    pub nonce: Word,
    pub deadline: Word,
}

impl BindNode {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            nr::BIND_NODE_TYPE,
            &[
                self.operator,
                self.node_id,
                self.ip_hash,
                self.key_id,
                self.pgp_hash,
                self.nonce,
                self.deadline,
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

/// NodeRegistryV2 v0.1 `RegisterRequest`, signed by the operator (sponsored registration). The
/// node wallet's consent is a `BindNode` with nodeId 0 and the request's nonce and deadline.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisterRequest {
    pub operator: Word,
    pub beneficiary: Word,
    pub node_wallet: Word,
    pub node_type: u8,
    pub ip_hash: Word,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub pgp_hash: Word,
    pub key_id: Word,
    pub services: u16,
    pub sponsor_node_id: Word,
    pub nonce: Word,
    pub deadline: Word,
}

impl RegisterRequest {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            nr::REGISTER_REQUEST_TYPE,
            &[
                self.operator,
                self.beneficiary,
                self.node_wallet,
                eip712::u64_word(self.node_type as u64),
                self.ip_hash,
                eip712::u64_word(self.tcp_port as u64),
                eip712::u64_word(self.udp_port as u64),
                self.pgp_hash,
                self.key_id,
                eip712::u64_word(self.services as u64),
                self.sponsor_node_id,
                self.nonce,
                self.deadline,
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

/// `keccak256(abi.encodePacked(uint256[] anchorNodeIds))`, in the order passed to `setOnline`.
pub fn anchors_hash(anchor_node_ids: &[Word]) -> Word {
    keccak256(&anchor_node_ids.concat())
}

/// The contract's PGP field: canonical base64 (standard alphabet, padded) of the armored
/// public key; `pgpHash` is keccak256 of that field's bytes, not of the armor.
pub fn pgp_field(armored_public: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(armored_public.as_bytes())
}

/// `ipHash` = keccak256(canonical IP text). Refuses text that is not already canonical.
pub fn ip_hash(text: &str) -> Result<Word, &'static str> {
    nr::check_canonical_ip(text)?;
    Ok(keccak256(text.as_bytes()))
}

/// `ipHash` of an address the node knows as a value (its own public IP, a peer's address).
pub fn ip_hash_of(ip: std::net::IpAddr) -> Result<Word, &'static str> {
    Ok(keccak256(nr::canonical_ip(ip)?.as_bytes()))
}

pub fn pgp_hash(armored_public: &str) -> Word {
    keccak256(pgp_field(armored_public).as_bytes())
}

/// Browser or mobile node's online declaration, signed by its node wallet.
#[derive(Debug, Clone, PartialEq)]
pub struct OnlineDeclaration {
    pub node_id: Word,
    pub mode: u8,
    pub anchors_hash: Word,
    pub services_now: u16,
    pub online_until: u64,
    pub online_seq: u64,
    pub deadline: Word,
}

impl OnlineDeclaration {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            nr::ONLINE_DECLARATION_TYPE,
            &[
                self.node_id,
                eip712::u64_word(self.mode as u64),
                self.anchors_hash,
                eip712::u64_word(self.services_now as u64),
                eip712::u64_word(self.online_until),
                eip712::u64_word(self.online_seq),
                self.deadline,
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

/// Signed by each anchor (a TCP node) other than the one submitting `setOnline`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorReceipt {
    pub node_id: Word,
    pub anchor_node_id: Word,
    pub online_seq: u64,
    pub online_until: u64,
}

impl AnchorReceipt {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            nr::ANCHOR_RECEIPT_TYPE,
            &[
                self.node_id,
                self.anchor_node_id,
                eip712::u64_word(self.online_seq),
                eip712::u64_word(self.online_until),
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

/// `ExtendDeclaration` (`at` = newUntil) and `PauseDeclaration` (`at` = pauseAt): same shape.
#[derive(Debug, Clone, PartialEq)]
pub struct SeqDeclaration {
    pub type_string: &'static str,
    pub node_id: Word,
    pub online_seq: u64,
    pub at: u64,
    pub deadline: Word,
}

impl SeqDeclaration {
    pub fn extend(node_id: Word, online_seq: u64, new_until: u64, deadline: Word) -> Self {
        Self {
            type_string: nr::EXTEND_DECLARATION_TYPE,
            node_id,
            online_seq,
            at: new_until,
            deadline,
        }
    }
    pub fn pause(node_id: Word, online_seq: u64, pause_at: u64, deadline: Word) -> Self {
        Self {
            type_string: nr::PAUSE_DECLARATION_TYPE,
            node_id,
            online_seq,
            at: pause_at,
            deadline,
        }
    }
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            self.type_string,
            &[
                self.node_id,
                eip712::u64_word(self.online_seq),
                eip712::u64_word(self.at),
                self.deadline,
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typehashes_match_spec() {
        for (t, h) in [
            (nr::REGISTER_REQUEST_TYPE, nr::REGISTER_REQUEST_TYPEHASH),
            (nr::ONLINE_DECLARATION_TYPE, nr::ONLINE_DECLARATION_TYPEHASH),
            (nr::ANCHOR_RECEIPT_TYPE, nr::ANCHOR_RECEIPT_TYPEHASH),
            (nr::EXTEND_DECLARATION_TYPE, nr::EXTEND_DECLARATION_TYPEHASH),
            (nr::PAUSE_DECLARATION_TYPE, nr::PAUSE_DECLARATION_TYPEHASH),
        ] {
            assert_eq!(eip712::to_hex(&eip712::type_hash(t)), h, "{t}");
        }
        assert_eq!(
            eip712::to_hex(&eip712::type_hash(nr::BIND_NODE_TYPE)),
            nr::BIND_NODE_TYPEHASH
        );
    }
}

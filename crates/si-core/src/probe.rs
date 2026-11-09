//! Liveness probe messages (Rust line probe protocol v0.5, P-01): the four EIP-712 types the
//! probe key signs, in their own domain `CoNET-NodeProbe` (never the registry's
//! `CoNETNodeRegistry`, so the contract can never take a probe signature for one of its own).
//! Checked byte for byte against ethers vectors in `conformance/vectors/probe712.json`.
use si_crypto::eip712::{self, Word};
use si_proto::node_registry as nr;

pub const DOMAIN_NAME: &str = "CoNET-NodeProbe";
pub const DOMAIN_VERSION: &str = "1";

pub const PROBE_REQUEST_TYPE: &str = "ProbeRequest(uint16 version,uint256 proberNodeId,address proberWallet,uint256 targetNodeId,address targetWallet,bytes32 targetIpHash,uint16 targetPort,bytes32 nonce,uint64 issuedAt,uint64 expiresAt)";
pub const PROBE_REPLY_TYPE: &str = "ProbeReply(bytes32 requestHash,uint256 replierNodeId,address replierWallet,uint64 repliedAt,uint64 expiresAt,uint8 flags,uint64 registryBlock)";
pub const PROBE_DELEGATION_TYPE: &str = "ProbeDelegation(uint256 voterNodeId,address voterWallet,uint256 relayNodeId,uint256 targetNodeId,uint256 reportId,bytes32 challenge,uint64 issuedAt,uint64 expiresAt)";
pub const OFFLINE_EVIDENCE_TYPE: &str = "OfflineEvidence(uint256 reporterNodeId,address reporterWallet,uint256 targetNodeId,bytes32[3] requestHashes,uint64[3] issuedAts,uint64 publishedAt)";

/// Reply flag bits.
pub const FLAG_DEGRADED: u8 = 1;
pub const FLAG_CLOCK_SKEW: u8 = 2;

/// `CoNET-NodeProbe` domain bound to one registry deployment on CoNET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeDomain {
    pub separator: Word,
}

impl ProbeDomain {
    pub fn new(verifying_contract: &str) -> si_crypto::Result<Self> {
        Ok(Self {
            separator: eip712::domain_separator(
                DOMAIN_NAME,
                DOMAIN_VERSION,
                nr::CHAIN_ID,
                verifying_contract,
            )?,
        })
    }
    /// Any other domain (tests: the registry's own) with the same struct.
    pub fn with(
        name: &str,
        version: &str,
        chain_id: u64,
        contract: &str,
    ) -> si_crypto::Result<Self> {
        Ok(Self {
            separator: eip712::domain_separator(name, version, chain_id, contract)?,
        })
    }
    pub fn digest(&self, struct_hash: &Word) -> Word {
        eip712::digest(&self.separator, struct_hash)
    }
}

/// EIP-712 encoding of a fixed array of atomic values: keccak256 of the concatenated words.
fn array(words: &[Word]) -> Word {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for w in words {
        buf.extend_from_slice(w);
    }
    si_crypto::eth::keccak256(&buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    pub version: u16,
    pub prober_node_id: Word,
    pub prober_wallet: Word,
    pub target_node_id: Word,
    pub target_wallet: Word,
    pub target_ip_hash: Word,
    pub target_port: u16,
    pub nonce: Word,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ProbeRequest {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            PROBE_REQUEST_TYPE,
            &[
                eip712::u64_word(self.version as u64),
                self.prober_node_id,
                self.prober_wallet,
                self.target_node_id,
                self.target_wallet,
                self.target_ip_hash,
                eip712::u64_word(self.target_port as u64),
                self.nonce,
                eip712::u64_word(self.issued_at),
                eip712::u64_word(self.expires_at),
            ],
        )
    }
    /// The digest a reply carries back as `requestHash`.
    pub fn digest(&self, d: &ProbeDomain) -> Word {
        d.digest(&self.struct_hash())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReply {
    pub request_hash: Word,
    pub replier_node_id: Word,
    pub replier_wallet: Word,
    pub replied_at: u64,
    pub expires_at: u64,
    pub flags: u8,
    pub registry_block: u64,
}

impl ProbeReply {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            PROBE_REPLY_TYPE,
            &[
                self.request_hash,
                self.replier_node_id,
                self.replier_wallet,
                eip712::u64_word(self.replied_at),
                eip712::u64_word(self.expires_at),
                eip712::u64_word(self.flags as u64),
                eip712::u64_word(self.registry_block),
            ],
        )
    }
    pub fn digest(&self, d: &ProbeDomain) -> Word {
        d.digest(&self.struct_hash())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeDelegation {
    pub voter_node_id: Word,
    pub voter_wallet: Word,
    pub relay_node_id: Word,
    pub target_node_id: Word,
    /// 0 = check before a report (pre-report).
    pub report_id: Word,
    pub challenge: Word,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ProbeDelegation {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            PROBE_DELEGATION_TYPE,
            &[
                self.voter_node_id,
                self.voter_wallet,
                self.relay_node_id,
                self.target_node_id,
                self.report_id,
                self.challenge,
                eip712::u64_word(self.issued_at),
                eip712::u64_word(self.expires_at),
            ],
        )
    }
    pub fn digest(&self, d: &ProbeDomain) -> Word {
        d.digest(&self.struct_hash())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineEvidence {
    pub reporter_node_id: Word,
    pub reporter_wallet: Word,
    pub target_node_id: Word,
    pub request_hashes: [Word; 3],
    pub issued_ats: [u64; 3],
    pub published_at: u64,
}

impl OfflineEvidence {
    pub fn struct_hash(&self) -> Word {
        let ats = self.issued_ats.map(eip712::u64_word);
        eip712::hash_words(
            OFFLINE_EVIDENCE_TYPE,
            &[
                self.reporter_node_id,
                self.reporter_wallet,
                self.target_node_id,
                array(&self.request_hashes),
                array(&ats),
                eip712::u64_word(self.published_at),
            ],
        )
    }
    pub fn digest(&self, d: &ProbeDomain) -> Word {
        d.digest(&self.struct_hash())
    }
}

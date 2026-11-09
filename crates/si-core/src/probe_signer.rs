//! Probe signer consent (Q117 乙, N6 §H.8.20): the probe wallet proves it holds its key and
//! agrees to serve one node, by signing `ProbeSignerAccept` once, when `setProbeSigner` is sent.
//!
//! It has its own domain, `CoNET-NodeProbeSigner`, apart from the four probe messages
//! (`CoNET-NodeProbe`, see [`crate::probe`]), the registry (`CoNETNodeRegistry`) and the
//! admission / recovery challenges (`CoNET-NodeAdmission`). A separate Rust type keeps a consent
//! digest from ever being built in another domain: the signer process gets more than a type hash
//! to tell them apart. Checked against ethers 6 (`conformance/vectors/probe-signer.json`), which
//! the node line's contract accepts.
use si_crypto::eip712::{self, Word};
use si_crypto::eth::keccak256;
use si_proto::node_registry as nr;

pub const DOMAIN_NAME: &str = "CoNET-NodeProbeSigner";
pub const DOMAIN_VERSION: &str = "1";
pub const ACCEPT_TYPE: &str =
    "ProbeSignerAccept(uint256 nodeId,address nodeWallet,address probeSigner,bytes32 purpose)";
/// The contract's `PROBE_PURPOSE` preimage.
pub const PURPOSE: &str = "conet.node-probe.v1";

/// `CoNET-NodeProbeSigner` domain bound to one registry deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSignerDomain {
    separator: Word,
}

impl ProbeSignerDomain {
    pub fn new(verifying_contract: &str) -> si_crypto::Result<Self> {
        Self::on_chain(nr::CHAIN_ID, verifying_contract)
    }
    /// Another chain id (local test chains).
    pub fn on_chain(chain_id: u64, verifying_contract: &str) -> si_crypto::Result<Self> {
        Ok(Self {
            separator: eip712::domain_separator(
                DOMAIN_NAME,
                DOMAIN_VERSION,
                chain_id,
                verifying_contract,
            )?,
        })
    }
    pub fn separator(&self) -> Word {
        self.separator
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSignerAccept {
    pub node_id: Word,
    /// The node's main wallet, which sends `setProbeSigner`.
    pub node_wallet: Word,
    pub probe_signer: Word,
}

impl ProbeSignerAccept {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            ACCEPT_TYPE,
            &[
                self.node_id,
                self.node_wallet,
                self.probe_signer,
                keccak256(PURPOSE.as_bytes()),
            ],
        )
    }
    /// What the probe key signs (only in this domain).
    pub fn digest(&self, d: &ProbeSignerDomain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

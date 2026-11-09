//! PROTOTYPE (pure logic, not served yet): what the signer signs for the probe-wallet role
//! (Q117 乙; Rust line `conet-node-probe-wallet-q117-design-v0.1.md` §2, N6 §H.8.19 Q14/Q15,
//! §H.8.20 domains and whitelist).
//!
//! - Probe messages: EIP-712 only, in `CoNET-NodeProbe`; the output is a signature, never a
//!   transaction, whatever the (network-supplied) fields contain.
//! - Vote transactions: only `voteReport` / `voteAdmission` / `voteRecovery` to the registry,
//!   type 2, value 0, exact calldata; and only when the request came in on the local vote-gate
//!   channel. The origin is set by the server from the listener that accepted the connection,
//!   never read from the request (it has no `Deserialize`).
//! - Everything else is refused: other selectors (`reportOffline`, `markOnline`, `topUp`,
//!   `withdraw`, `updateNodeWallet`, `setProbeSigner`, any `finalize*` / settle), value, type 0,
//!   another `to`, contract creation, and the `ProbeSignerAccept` consent (signed once by the
//!   provisioning command, not by `serve --role probe`).
use si_core::probe::{ProbeDomain, ProbeRequest};
use si_crypto::eth::{keccak256, EthKey};

/// Where a request came from. Set by the server per listener; not deserializable on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The vote gate's own socket (peer credential checked by the server).
    LocalVoteGate,
    /// The probe socket: requests built from network traffic (probe exchange).
    ProbeChannel,
}

/// An unsigned transaction as the caller describes it (the signer encodes it itself later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRequest {
    /// 0 = legacy, 2 = EIP-1559.
    pub tx_type: u8,
    /// `None` = contract creation.
    pub to: Option<String>,
    pub value: u128,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Request {
    SignProbeRequest(ProbeRequest),
    SignVoteTx(TxRequest),
    /// Any other transaction.
    SignTx(TxRequest),
    /// The setProbeSigner consent.
    SignProbeSignerAccept,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    /// 65-byte EIP-712 signature (hex) over the probe-domain digest.
    ProbeSignature { digest: [u8; 32], sig: String },
    /// The vote call that passed the policy; the encoder signs exactly this.
    VoteApproved { entry: VoteEntry, data: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteEntry {
    Report,
    Admission,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refuse {
    NotFromVoteGate,
    NotType2,
    HasValue,
    Creation,
    WrongTo,
    /// Selector outside the three vote entry points (hex, for the log).
    Selector(String),
    BadCalldata,
    /// Generic transactions are never signed by this role.
    NotThisRole,
    /// The consent is signed only by the provisioning command.
    ConsentNotServed,
    Sign,
}

pub fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn entry_of(sel: [u8; 4]) -> Option<VoteEntry> {
    [
        ("voteReport(uint256,bool)", VoteEntry::Report),
        ("voteAdmission(bytes32,bool)", VoteEntry::Admission),
        ("voteRecovery(bytes32,bool)", VoteEntry::Recovery),
    ]
    .into_iter()
    .find(|(s, _)| selector(s) == sel)
    .map(|(_, e)| e)
}

/// The vote whitelist (§2.2). `registry` is the configured registry address.
pub fn check_vote_tx(registry: &str, tx: &TxRequest) -> Result<VoteEntry, Refuse> {
    if tx.tx_type != 2 {
        return Err(Refuse::NotType2);
    }
    if tx.value != 0 {
        return Err(Refuse::HasValue);
    }
    let to = tx.to.as_deref().ok_or(Refuse::Creation)?;
    if !to.eq_ignore_ascii_case(registry) {
        return Err(Refuse::WrongTo);
    }
    if tx.data.len() < 4 {
        return Err(Refuse::BadCalldata);
    }
    let sel = [tx.data[0], tx.data[1], tx.data[2], tx.data[3]];
    let entry = entry_of(sel).ok_or_else(|| Refuse::Selector(hex::encode(sel)))?;
    // Exactly two words; the bool word must be 0 or 1.
    if tx.data.len() != 4 + 64 {
        return Err(Refuse::BadCalldata);
    }
    let b = &tx.data[36..68];
    if b[..31].iter().any(|&x| x != 0) || b[31] > 1 {
        return Err(Refuse::BadCalldata);
    }
    Ok(entry)
}

pub struct ProbeRole<'a> {
    pub key: &'a EthKey,
    pub domain: ProbeDomain,
    pub registry: String,
}

impl ProbeRole<'_> {
    pub fn handle(&self, origin: Origin, req: Request) -> Result<Signed, Refuse> {
        match req {
            Request::SignProbeRequest(r) => {
                let digest = r.digest(&self.domain);
                let sig = self.key.sign_digest(&digest).map_err(|_| Refuse::Sign)?;
                Ok(Signed::ProbeSignature { digest, sig })
            }
            Request::SignVoteTx(tx) => {
                if origin != Origin::LocalVoteGate {
                    return Err(Refuse::NotFromVoteGate);
                }
                let entry = check_vote_tx(&self.registry, &tx)?;
                Ok(Signed::VoteApproved {
                    entry,
                    data: tx.data,
                })
            }
            Request::SignTx(_) => Err(Refuse::NotThisRole),
            Request::SignProbeSignerAccept => Err(Refuse::ConsentNotServed),
        }
    }
}

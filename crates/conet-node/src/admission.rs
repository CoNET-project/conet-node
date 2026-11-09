//! Vote admission challenge (ADMIT-RUST): first admission of a new node and recovery of a
//! registered node, node side. Pure protocol for local simulation: nothing here sends a
//! transaction, opens a socket or is wired into the server. Design: pm-notes report
//! `conet-node-admission-design-v0.1.md`.
//!
//! Flow per voter:
//! 1. The voter builds a one-time `Challenge` (random nonce, 60 s, bound to the application ID,
//!    kind, endpoint version, voter, applicant wallet and full PGP fingerprint, IP hash, port,
//!    chain and registry), PGP-signs it with its registered route key and encrypts it to the
//!    applicant's PGP key. It POSTs it straight to the declared IP and port.
//! 2. The applicant checks the voter's PGP signature against the voter's registered key, every
//!    binding, expiry and one-time use; signs `AdmissionResponse` (EIP-712, domain
//!    `CoNET-NodeAdmission`) with its main wallet; PGP-signs the reply with its own key and
//!    encrypts it to the voter.
//! 3. The voter checks the applicant key's FULL fingerprint (the key ID only identifies), the
//!    PGP signature, the wallet signature, the challenge hash (one-time), expiry, and that the
//!    reply came from the declared address it connected to.
//!
//! The main wallet signs (registry role), not the probe key: admission is not one of the probe
//! key's four message types, so it gets its own domain.
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use si_crypto::eip712 as e7;
use si_crypto::eth::{self, EthKey};
use si_crypto::opgp::{self, EncryptOpts, PublicCert, SecretCert};

pub const DOMAIN_NAME: &str = "CoNET-NodeAdmission";
pub const DOMAIN_VERSION: &str = "1";
/// Challenge lifetime (suggested, pending).
pub const CHALLENGE_TTL_SEC: u64 = 60;
/// Allowed clock difference (suggested, pending).
pub const CLOCK_SKEW_SEC: u64 = 30;

const RESPONSE_TYPE: &str = "AdmissionResponse(bytes32 appId,uint8 kind,uint256 nodeId,address applicantWallet,bytes20 pgpFingerprint,bytes32 ipHash,uint16 tcpPort,uint64 endpointVersion,uint256 voterNodeId,bytes32 challengeHash,uint64 expiresAt)";
const APPLICATION_TYPE: &str = "AdmissionApplication(bytes32 appId,uint8 kind,uint256 nodeId,address applicantWallet,bytes20 pgpFingerprint,bytes32 ipHash,uint16 tcpPort,uint64 endpointVersion,uint256 proposerNodeId,uint64 expiresAt)";

/// First admission of a new node, or recovery (offline -> online) of a registered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Kind {
    First = 1,
    Recovery = 2,
}

/// Chain context, bound into every signed structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctx {
    pub chain_id: u64,
    pub registry: String,
}

impl Ctx {
    fn domain(&self) -> Result<e7::Word, Fail> {
        e7::domain_separator(DOMAIN_NAME, DOMAIN_VERSION, self.chain_id, &self.registry)
            .map_err(|_| Fail::BadField)
    }
}

/// The application as the chain records it (fields the node side needs). `node_id` is 0 for a
/// first admission. `ip` is canonical text; `pgp_fingerprint` is the full v4 fingerprint (40
/// hex); `main_sig` is the applicant main wallet's signature over `AdmissionApplication`
/// (first admission) or over the candidate endpoint (recovery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    pub app_id: [u8; 32],
    pub kind: Kind,
    pub node_id: u64,
    pub applicant_wallet: String,
    pub pgp_fingerprint: String,
    pub ip: String,
    pub tcp_port: u16,
    pub endpoint_version: u64,
    pub proposer_node_id: u64,
    pub expires_at: u64,
}

/// What a voter POSTs (inside PGP sign + encrypt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub v: u8,
    pub app_id: String,
    pub kind: Kind,
    pub node_id: u64,
    pub endpoint_version: u64,
    pub voter_node_id: u64,
    pub voter_fingerprint: String,
    pub applicant_wallet: String,
    pub applicant_fingerprint: String,
    pub ip_hash: String,
    pub tcp_port: u16,
    pub chain_id: u64,
    pub registry: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Challenge {
    /// keccak256 of the exact JSON the voter signed.
    pub fn hash(&self) -> [u8; 32] {
        eth::keccak256(&serde_json::to_vec(self).expect("serializable"))
    }
}

/// What the applicant returns (inside PGP sign + encrypt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub challenge_hash: String,
    pub wallet_sig: String,
}

/// The voter's memory of a challenge it sent; consumed by the first reply.
#[derive(Debug, Clone)]
pub struct Outstanding {
    pub challenge: Challenge,
    pub hash: [u8; 32],
}

/// Why a step failed. Each is a reason not to answer (applicant) or not to approve (voter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    Decrypt,
    BadField,
    /// The voter's PGP signature does not verify against its registered key, or the voter is
    /// not registered.
    VoterSig,
    /// Application ID, kind, node, endpoint version or applicant identity differ.
    WrongApplication,
    /// IP hash or port differ from the declared endpoint (or from where the voter connected).
    WrongEndpoint,
    /// Chain ID or registry differ.
    WrongContext,
    Expired,
    Replay,
    /// The applicant key's full fingerprint differs from the application's.
    Fingerprint,
    /// The applicant's PGP signature on the reply is missing or invalid.
    ApplicantPgpSig,
    /// The wallet signature does not recover the applicant main wallet.
    WalletSig,
    /// The reply is for another challenge (or another voter).
    ChallengeMismatch,
}

fn fp_norm(s: &str) -> String {
    s.trim_start_matches("0x").to_ascii_uppercase()
}

fn word_fp(fp: &str) -> Result<e7::Word, Fail> {
    e7::fixed_bytes_word(&format!("0x{}", fp_norm(fp)), 20).map_err(|_| Fail::BadField)
}

fn ip_hash_word(ip: &str) -> Result<e7::Word, Fail> {
    si_core::statement::ip_hash(ip).map_err(|_| Fail::BadField)
}

/// EIP-712 digest the applicant main wallet signs over its application (first admission).
pub fn application_digest(ctx: &Ctx, a: &Application) -> Result<[u8; 32], Fail> {
    let s = e7::hash_words(
        APPLICATION_TYPE,
        &[
            a.app_id,
            e7::u64_word(a.kind as u64),
            e7::u64_word(a.node_id),
            e7::address_word(&a.applicant_wallet).map_err(|_| Fail::BadField)?,
            word_fp(&a.pgp_fingerprint)?,
            ip_hash_word(&a.ip)?,
            e7::u64_word(a.tcp_port as u64),
            e7::u64_word(a.endpoint_version),
            e7::u64_word(a.proposer_node_id),
            e7::u64_word(a.expires_at),
        ],
    );
    Ok(e7::digest(&ctx.domain()?, &s))
}

/// EIP-712 digest of the applicant's answer to one challenge.
pub fn response_digest(
    ctx: &Ctx,
    a: &Application,
    c: &Challenge,
    challenge_hash: &[u8; 32],
) -> Result<[u8; 32], Fail> {
    let s = e7::hash_words(
        RESPONSE_TYPE,
        &[
            a.app_id,
            e7::u64_word(a.kind as u64),
            e7::u64_word(a.node_id),
            e7::address_word(&a.applicant_wallet).map_err(|_| Fail::BadField)?,
            word_fp(&a.pgp_fingerprint)?,
            ip_hash_word(&a.ip)?,
            e7::u64_word(a.tcp_port as u64),
            e7::u64_word(a.endpoint_version),
            e7::u64_word(c.voter_node_id),
            *challenge_hash,
            e7::u64_word(c.expires_at),
        ],
    );
    Ok(e7::digest(&ctx.domain()?, &s))
}

/// Proposer side: the application must carry the applicant main wallet's signature, and the
/// presented PGP key must match the full fingerprint (not just the key ID).
pub fn check_application(
    ctx: &Ctx,
    a: &Application,
    main_sig: &str,
    applicant_key: &PublicCert,
    now: u64,
) -> Result<(), Fail> {
    if fp_norm(&applicant_key.fingerprint()) != fp_norm(&a.pgp_fingerprint) {
        return Err(Fail::Fingerprint);
    }
    if now > a.expires_at {
        return Err(Fail::Expired);
    }
    let d = application_digest(ctx, a)?;
    match eth::recover_digest(&d, main_sig) {
        Ok(w) if w.eq_ignore_ascii_case(&a.applicant_wallet) => Ok(()),
        _ => Err(Fail::WalletSig),
    }
}

/// Voter: a fresh one-time challenge, PGP-signed by the voter and encrypted to the applicant.
pub fn make_challenge<R: RngCore + CryptoRng>(
    mut rng: R,
    ctx: &Ctx,
    a: &Application,
    voter_node_id: u64,
    voter_key: &SecretCert,
    applicant_key: &PublicCert,
    now: u64,
) -> Result<(Outstanding, String), Fail> {
    if fp_norm(&applicant_key.fingerprint()) != fp_norm(&a.pgp_fingerprint) {
        return Err(Fail::Fingerprint);
    }
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let c = Challenge {
        v: 1,
        app_id: hex::encode(a.app_id),
        kind: a.kind,
        node_id: a.node_id,
        endpoint_version: a.endpoint_version,
        voter_node_id,
        voter_fingerprint: fp_norm(&voter_key.public().fingerprint()),
        applicant_wallet: a.applicant_wallet.to_lowercase(),
        applicant_fingerprint: fp_norm(&a.pgp_fingerprint),
        ip_hash: hex::encode(ip_hash_word(&a.ip)?),
        tcp_port: a.tcp_port,
        chain_id: ctx.chain_id,
        registry: ctx.registry.to_lowercase(),
        nonce: hex::encode(nonce),
        issued_at: now,
        expires_at: now + CHALLENGE_TTL_SEC,
    };
    let body = serde_json::to_vec(&c).map_err(|_| Fail::BadField)?;
    let armored = opgp::encrypt(
        &mut rng,
        &body,
        applicant_key,
        EncryptOpts {
            text: false,
            zlib: false,
            sign_with: Some(voter_key),
        },
    )
    .map_err(|_| Fail::BadField)?;
    let hash = c.hash();
    Ok((Outstanding { challenge: c, hash }, armored))
}

/// Applicant: answer one challenge. `voter_key_of` looks up a voter's registered PGP key by
/// node id (None = not a registered, active node). `seen` holds nonces already answered.
#[allow(clippy::too_many_arguments)]
pub fn answer<R: RngCore + CryptoRng>(
    mut rng: R,
    ctx: &Ctx,
    me: &Application,
    my_key: &SecretCert,
    my_wallet: &EthKey,
    armored: &str,
    voter_key_of: impl Fn(u64) -> Option<PublicCert>,
    seen: &mut std::collections::HashSet<String>,
    now: u64,
) -> Result<String, Fail> {
    // First pass: read who claims to have sent it; second pass: verify that voter's signature.
    let plain = opgp::decrypt(armored, my_key, None).map_err(|_| Fail::Decrypt)?;
    let c: Challenge = serde_json::from_slice(&plain.data).map_err(|_| Fail::BadField)?;
    let voter = voter_key_of(c.voter_node_id).ok_or(Fail::VoterSig)?;
    if fp_norm(&voter.fingerprint()) != c.voter_fingerprint {
        return Err(Fail::VoterSig);
    }
    let checked = opgp::decrypt(armored, my_key, Some(&voter)).map_err(|_| Fail::Decrypt)?;
    if checked.verified != Some(true) || checked.data != plain.data {
        return Err(Fail::VoterSig);
    }
    if c.chain_id != ctx.chain_id || !c.registry.eq_ignore_ascii_case(&ctx.registry) {
        return Err(Fail::WrongContext);
    }
    if c.app_id != hex::encode(me.app_id)
        || c.kind != me.kind
        || c.node_id != me.node_id
        || c.endpoint_version != me.endpoint_version
        || !c
            .applicant_wallet
            .eq_ignore_ascii_case(&me.applicant_wallet)
        || c.applicant_fingerprint != fp_norm(&me.pgp_fingerprint)
        || fp_norm(&my_key.public().fingerprint()) != fp_norm(&me.pgp_fingerprint)
    {
        return Err(Fail::WrongApplication);
    }
    if c.ip_hash != hex::encode(ip_hash_word(&me.ip)?) || c.tcp_port != me.tcp_port {
        return Err(Fail::WrongEndpoint);
    }
    if c.expires_at < c.issued_at
        || c.expires_at - c.issued_at > CHALLENGE_TTL_SEC
        || now > c.expires_at + CLOCK_SKEW_SEC
        || now + CLOCK_SKEW_SEC < c.issued_at
    {
        return Err(Fail::Expired);
    }
    if !seen.insert(format!("{}:{}", c.voter_node_id, c.nonce)) {
        return Err(Fail::Replay);
    }
    let h = c.hash();
    let sig = my_wallet
        .sign_digest(&response_digest(ctx, me, &c, &h)?)
        .map_err(|_| Fail::WalletSig)?;
    let reply = Reply {
        challenge_hash: hex::encode(h),
        wallet_sig: sig,
    };
    let body = serde_json::to_vec(&reply).map_err(|_| Fail::BadField)?;
    opgp::encrypt(
        &mut rng,
        &body,
        &voter,
        EncryptOpts {
            text: false,
            zlib: false,
            sign_with: Some(my_key),
        },
    )
    .map_err(|_| Fail::BadField)
}

/// Voter: verify a reply to `outstanding`, received from `connected` (the address it POSTed
/// to). On success the challenge is used up (the caller drops `outstanding`).
#[allow(clippy::too_many_arguments)]
pub fn verify(
    ctx: &Ctx,
    a: &Application,
    outstanding: &Outstanding,
    voter_key: &SecretCert,
    applicant_key: &PublicCert,
    armored_reply: &str,
    connected: (&str, u16),
    now: u64,
) -> Result<(), Fail> {
    if fp_norm(&applicant_key.fingerprint()) != fp_norm(&a.pgp_fingerprint) {
        return Err(Fail::Fingerprint);
    }
    if connected.0 != a.ip || connected.1 != a.tcp_port {
        return Err(Fail::WrongEndpoint);
    }
    if now > outstanding.challenge.expires_at + CLOCK_SKEW_SEC {
        return Err(Fail::Expired);
    }
    let d =
        opgp::decrypt(armored_reply, voter_key, Some(applicant_key)).map_err(|_| Fail::Decrypt)?;
    if d.verified != Some(true) {
        return Err(Fail::ApplicantPgpSig);
    }
    let r: Reply = serde_json::from_slice(&d.data).map_err(|_| Fail::BadField)?;
    if r.challenge_hash != hex::encode(outstanding.hash) {
        return Err(Fail::ChallengeMismatch);
    }
    // The application the vote is about must be the one the challenge was made for.
    let c = &outstanding.challenge;
    if c.app_id != hex::encode(a.app_id)
        || c.kind != a.kind
        || c.node_id != a.node_id
        || c.endpoint_version != a.endpoint_version
        || !c.applicant_wallet.eq_ignore_ascii_case(&a.applicant_wallet)
        || c.applicant_fingerprint != fp_norm(&a.pgp_fingerprint)
        || c.ip_hash != hex::encode(ip_hash_word(&a.ip)?)
        || c.tcp_port != a.tcp_port
    {
        return Err(Fail::WrongApplication);
    }
    let digest = response_digest(ctx, a, c, &outstanding.hash)?;
    match eth::recover_digest(&digest, &r.wallet_sig) {
        Ok(w) if w.eq_ignore_ascii_case(&a.applicant_wallet) => Ok(()),
        _ => Err(Fail::WalletSig),
    }
}

/// The fixed set of nodes the project initialised (472), exempt from FIRST admission only.
/// The node line defines the set's format (snapshot root and proofs); until then this is the
/// interface the node side calls. Never decided from self-reports or counts.
pub trait TrustedInitialSet {
    /// Some(true/false) when membership can be proven or disproven against the pinned root;
    /// None when it cannot be decided (no proof, root unknown).
    fn contains(&self, node_id: u64, main_wallet: &str) -> Option<bool>;
}

/// Whether an application still needs the admission vote.
pub fn needs_vote(kind: Kind, node_id: u64, wallet: &str, set: &dyn TrustedInitialSet) -> bool {
    match kind {
        // Recovery always needs a vote, the initial 472 included.
        Kind::Recovery => true,
        // Exempt only with a positive proof of membership.
        Kind::First => set.contains(node_id, wallet) != Some(true),
    }
}

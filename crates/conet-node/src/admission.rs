//! Vote admission and recovery challenge (ADMIT-RUST, RECOVER-RUST), node side. Pure protocol
//! for local simulation: nothing here sends a transaction, opens a socket or is wired into the
//! server. Designs: pm-notes `conet-node-admission-design-v0.1.md`,
//! `conet-node-recovery-design-v0.1.md`.
//!
//! Flow per voter:
//! 1. The voter looks at the path it actually has to the candidate (`Observed`): for a TCP node
//!    the address it connected to; for a browser node the WebRTC candidate pair its OWN stack
//!    selected (remote address, port, candidate type, relay identity) and the remote DTLS
//!    fingerprint. Never what the candidate claims in SDP or signaling.
//! 2. It builds a one-time `Challenge` (random nonce, 60 s) bound to the application ID, kind,
//!    node, endpoint version, the candidate endpoint (incl. type), its observation, the voter
//!    and its full fingerprint, the applicant wallet and full PGP fingerprint, chain and
//!    registry; PGP-signs it with its registered key and encrypts it to the applicant.
//! 3. The applicant checks the voter against its registered key and every binding (for a
//!    browser: both sides see the same two DTLS certificates), answers once and encrypts to the
//!    voter. First admission: signs `AdmissionResponse` (EIP-712, domain `CoNET-NodeAdmission`)
//!    with its main wallet and PGP-signs the reply. Recovery: the main wallet authorized the
//!    candidate endpoint once in the application; each reply is PGP-signed only. Every
//!    PGP-signed payload starts with a fixed `CONET-ADMISSION-` prefix that no other PGP signing
//!    path of the node may sign.
//! 4. The voter re-reads its observation: if the selected pair changed (ICE restart, new pair),
//!    the challenge is void and must be redone. Then it checks the full fingerprint, both
//!    signatures, the challenge hash (one-time) and expiry, and records the endpoint class:
//!    `Direct` (the observed address is the node's) or `Relay` (only the relay is reachable;
//!    the relay's address is NOT the node's public address).
//!
//! The main wallet signs (registry role), not the probe key: admission and recovery are not
//! among the probe key's four message types, so they get their own domain.
//!
//! Aligned with the node line's contract (interface assumptions, 2026-11-08): the application
//! ID (`appId` / `recId`) is the chain's, not computed here, and the application itself is the
//! main wallet's own transaction (no separate off-chain application signature); the full
//! fingerprint is the v4 fingerprint of the first PGP subkey (the route key); every PGP key used
//! is taken from the chain field and checked against the chain's `pgpHash` (`ChainKey`); a
//! Linux endpoint is the chain's `ipHash`, `tcpPort` and `udpPort`.
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use si_crypto::eip712 as e7;
use si_crypto::eth::{self, keccak256, EthKey};
use si_crypto::opgp::{self, EncryptOpts, PublicCert, SecretCert};

pub const DOMAIN_NAME: &str = "CoNET-NodeAdmission";
pub const DOMAIN_VERSION: &str = "1";
/// Challenge lifetime (suggested, pending).
pub const CHALLENGE_TTL_SEC: u64 = 60;
/// Allowed clock difference (suggested, pending).
pub const CLOCK_SKEW_SEC: u64 = 30;

const RESPONSE_TYPE: &str = "AdmissionResponse(bytes32 appId,uint8 kind,uint256 nodeId,address applicantWallet,bytes20 pgpFingerprint,bytes32 pgpHash,bytes32 ipHash,uint16 tcpPort,uint16 udpPort,bytes32 endpointHash,uint64 endpointVersion,uint256 voterNodeId,bytes32 observationHash,bytes32 challengeHash,uint64 expiresAt)";

/// First admission of a new node, or recovery (offline -> online) of a registered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Kind {
    First = 1,
    Recovery = 2,
}

/// The candidate endpoint the main wallet authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Linux node: canonical IP text, TCP port (voters POST straight to it) and UDP port (bound,
    /// not probed). On chain: `ipHash`, `tcpPort`, `udpPort`, `endpointHash = 0`.
    Tcp {
        ip: String,
        tcp_port: u16,
        udp_port: u16,
    },
    /// Browser node: no listening port. Identified by its WebRTC DTLS certificate fingerprint;
    /// `relay` = None authorizes a direct ICE path, Some(id) a path through that relay (TURN
    /// server or anchor node, by identity).
    Browser {
        dtls_fingerprint: String,
        relay: Option<String>,
    },
}

/// What the voter itself sees of its path to the candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    /// The address the voter's own TCP connection went to.
    Tcp { ip: String, port: u16 },
    /// From the voter's own WebRTC stack (getStats selected candidate pair + remote
    /// certificate): never from the candidate's SDP or signaling.
    WebRtc {
        /// Path identifier from the voter's own stats: the ICE local ufrag (changes on ICE
        /// restart), the selected-pair change count and the candidate pair id. The pair id alone
        /// can survive an ICE restart when addresses stay the same.
        pair_id: String,
        remote_ip: String,
        remote_port: u16,
        /// "host", "srflx", "prflx" or "relay".
        candidate_type: String,
        /// The relay the voter's pair goes through (its TURN server or anchor), when relayed.
        relay: Option<String>,
        /// The remote certificate on the voter's session (the node's, if nothing is in between).
        dtls_fingerprint: String,
        /// The voter's own certificate on this session; the node reports what it sees as the
        /// remote certificate, so a splice by the anchor (two sessions, swapped fingerprints in
        /// signaling) shows up.
        local_dtls_fingerprint: String,
    },
}

/// What a passed check proves about the endpoint (recorded per vote).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointClass {
    /// The observed address is the node's own (TCP, or WebRTC host/srflx/prflx).
    Direct { ip: String, port: u16 },
    /// Only the relay is reachable and the reply was signed by the node's keys. The address
    /// is the relay's; it is NOT the node's public IP and port.
    Relay {
        relay: String,
        relay_ip: String,
        relay_port: u16,
    },
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    keccak256(&parts.concat())
}

fn fp_norm(s: &str) -> String {
    s.trim_start_matches("0x")
        .replace(':', "")
        .to_ascii_uppercase()
}

impl Endpoint {
    /// The chain's `ipHash`: keccak256 of the canonical IP text for a Linux node, zero for a
    /// browser.
    pub fn ip_hash(&self) -> Result<[u8; 32], Fail> {
        match self {
            Endpoint::Tcp { ip, .. } => ip_hash_word(ip),
            Endpoint::Browser { .. } => Ok([0; 32]),
        }
    }
    /// The chain's `tcpPort` and `udpPort` (zero for a browser).
    pub fn ports(&self) -> (u16, u16) {
        match self {
            Endpoint::Tcp {
                tcp_port, udp_port, ..
            } => (*tcp_port, *udp_port),
            Endpoint::Browser { .. } => (0, 0),
        }
    }
    /// The chain's `endpointHash`: zero for a Linux node; for a browser our definition (type
    /// byte 2, DTLS fingerprint, direct or relay, relay identity), proposed to the node line.
    pub fn endpoint_hash(&self) -> Result<[u8; 32], Fail> {
        Ok(match self {
            Endpoint::Tcp { .. } => [0; 32],
            Endpoint::Browser {
                dtls_fingerprint,
                relay,
            } => h(&[
                &[2],
                &keccak256(fp_norm(dtls_fingerprint).as_bytes()),
                &[relay.is_some() as u8],
                &keccak256(relay.as_deref().unwrap_or("").as_bytes()),
            ]),
        })
    }
}

impl Observed {
    pub fn hash(&self) -> Result<[u8; 32], Fail> {
        Ok(match self {
            Observed::Tcp { ip, port } => h(&[&[0x11], &ip_hash_word(ip)?, &port.to_be_bytes()]),
            Observed::WebRtc {
                pair_id,
                remote_ip,
                remote_port,
                candidate_type,
                relay,
                dtls_fingerprint,
                local_dtls_fingerprint,
            } => h(&[
                &[0x12],
                &keccak256(pair_id.as_bytes()),
                &keccak256(remote_ip.as_bytes()),
                &remote_port.to_be_bytes(),
                &keccak256(candidate_type.as_bytes()),
                &keccak256(relay.as_deref().unwrap_or("").as_bytes()),
                &keccak256(fp_norm(dtls_fingerprint).as_bytes()),
                &keccak256(fp_norm(local_dtls_fingerprint).as_bytes()),
            ]),
        })
    }
}

/// Payload prefixes of every PGP-signed admission/recovery message. Any other PGP signing
/// path of the node must refuse payloads that start with `RESERVED_PREFIX`, so a node can
/// never be used to PGP-sign something that passes as a challenge or a reply.
pub const RESERVED_PREFIX: &[u8] = b"CONET-ADMISSION-";
pub const CHALLENGE_PREFIX: &[u8] = b"CONET-ADMISSION-CHALLENGE-v1\n";
pub const REPLY_PREFIX: &[u8] = b"CONET-ADMISSION-REPLY-v1\n";

/// For other PGP-signing code: true = refuse to sign this payload.
pub fn is_reserved_pgp_payload(payload: &[u8]) -> bool {
    payload.starts_with(RESERVED_PREFIX)
}

fn with_prefix(prefix: &[u8], json: Vec<u8>) -> Vec<u8> {
    [prefix, &json].concat()
}

fn strip_prefix<'a>(prefix: &[u8], data: &'a [u8]) -> Result<&'a [u8], Fail> {
    data.strip_prefix(prefix).ok_or(Fail::BadField)
}

/// The browser node's own view of the session a challenge arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    /// Its own certificate.
    pub own_dtls: String,
    /// The remote (voter's) certificate it sees.
    pub peer_dtls: String,
}

/// Does what the voter sees match the authorized endpoint? Returns the class it proves.
pub fn classify(endpoint: &Endpoint, seen: &Observed) -> Result<EndpointClass, Fail> {
    match (endpoint, seen) {
        (Endpoint::Tcp { ip, tcp_port, .. }, Observed::Tcp { ip: i, port: p })
            if ip == i && tcp_port == p =>
        {
            Ok(EndpointClass::Direct {
                ip: i.clone(),
                port: *p,
            })
        }
        (
            Endpoint::Browser {
                dtls_fingerprint,
                relay,
            },
            Observed::WebRtc {
                remote_ip,
                remote_port,
                candidate_type,
                relay: seen_relay,
                dtls_fingerprint: seen_fp,
                ..
            },
        ) => {
            // An mDNS (.local) remote address hides the real one: address not confirmed.
            if remote_ip.ends_with(".local") {
                return Err(Fail::AddressUnconfirmed);
            }
            // The DTLS key on the voter's own session must be the authorized one; otherwise
            // something in the middle terminates DTLS (relay or MITM impersonating the node).
            if fp_norm(seen_fp) != fp_norm(dtls_fingerprint) {
                return Err(Fail::DtlsFingerprint);
            }
            match (candidate_type.as_str(), relay, seen_relay) {
                ("relay", Some(r), Some(sr)) if r == sr => Ok(EndpointClass::Relay {
                    relay: sr.clone(),
                    relay_ip: remote_ip.clone(),
                    relay_port: *remote_port,
                }),
                ("host" | "srflx" | "prflx", None, None) => Ok(EndpointClass::Direct {
                    ip: remote_ip.clone(),
                    port: *remote_port,
                }),
                _ => Err(Fail::WrongEndpoint),
            }
        }
        _ => Err(Fail::WrongEndpoint),
    }
}

/// A PGP public key as the chain holds it: built only from the chain's PGP field (canonical
/// base64 of the armored key) whose keccak256 equals the chain's `pgpHash`. Every key the
/// protocol uses (applicant's, voter's) goes through this check.
pub struct ChainKey {
    key: PublicCert,
    pub pgp_hash: [u8; 32],
    /// v4 fingerprint of the first subkey (the route key), normalized.
    pub fingerprint: String,
}

impl ChainKey {
    pub fn from_chain(field: &str, pgp_hash: &[u8; 32]) -> Result<Self, Fail> {
        use base64::Engine;
        if keccak256(field.as_bytes()) != *pgp_hash {
            return Err(Fail::PgpHash);
        }
        let armor = base64::engine::general_purpose::STANDARD
            .decode(field)
            .map_err(|_| Fail::BadField)?;
        let key = PublicCert::from_armor(std::str::from_utf8(&armor).map_err(|_| Fail::BadField)?)
            .map_err(|_| Fail::BadField)?;
        let fingerprint = key
            .enc_fingerprint()
            .map(|f| fp_norm(&f))
            .ok_or(Fail::Fingerprint)?;
        Ok(Self {
            key,
            pgp_hash: *pgp_hash,
            fingerprint,
        })
    }
    pub fn key(&self) -> &PublicCert {
        &self.key
    }
}

/// Route-key fingerprint of one of our own secret keys.
fn own_fp(k: &SecretCert) -> Result<String, Fail> {
    k.public()
        .enc_fingerprint()
        .map(|f| fp_norm(&f))
        .ok_or(Fail::Fingerprint)
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

/// The application as the chain records it (`getAdmission` / `getRecovery`). `app_id` is the
/// chain's `appId` / `recId`; `node_id` is 0 for a first admission; `pgp_fingerprint` is the
/// route subkey's full v4 fingerprint (40 hex); `pgp_hash` the chain's `pgpHash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    pub app_id: [u8; 32],
    pub kind: Kind,
    pub node_id: u64,
    pub applicant_wallet: String,
    pub pgp_fingerprint: String,
    pub pgp_hash: [u8; 32],
    pub endpoint: Endpoint,
    pub endpoint_version: u64,
    pub proposer_node_id: u64,
    pub expires_at: u64,
}

/// What a voter sends (inside PGP sign + encrypt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub v: u8,
    pub app_id: String,
    pub kind: Kind,
    pub node_id: u64,
    pub endpoint_version: u64,
    pub ip_hash: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub endpoint_hash: String,
    pub observation_hash: String,
    /// For a browser candidate: the DTLS fingerprint the voter's session sees (the applicant
    /// checks it is its own).
    pub seen_dtls: Option<String>,
    /// For a browser candidate: the voter's own certificate on that session.
    pub voter_dtls: Option<String>,
    pub voter_node_id: u64,
    pub voter_fingerprint: String,
    pub applicant_wallet: String,
    pub applicant_fingerprint: String,
    pub chain_id: u64,
    pub registry: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Challenge {
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&serde_json::to_vec(self).expect("serializable"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub challenge_hash: String,
    /// First admission: the main wallet's AdmissionResponse signature. Recovery: none (the main
    /// wallet authorized the candidate endpoint once; each reply is PGP-signed only).
    pub wallet_sig: Option<String>,
    /// Browser: the node's own certificate and the voter's certificate as the node sees them.
    pub node_dtls: Option<String>,
    pub voter_dtls: Option<String>,
}

/// The voter's memory of a challenge it sent, with the observation it was made on.
#[derive(Debug, Clone)]
pub struct Outstanding {
    pub challenge: Challenge,
    pub hash: [u8; 32],
    pub observed: Observed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    Decrypt,
    BadField,
    VoterSig,
    WrongApplication,
    /// The observation does not fit the authorized endpoint (address, port, path type, relay).
    WrongEndpoint,
    /// The DTLS fingerprint on the voter's session is not the authorized one, or the two
    /// sides do not see the same pair of certificates.
    DtlsFingerprint,
    /// The remote address is only an mDNS (.local) name: cannot confirm where the node is.
    AddressUnconfirmed,
    /// The selected candidate pair (or TCP peer) changed since the challenge: redo it.
    PathChanged,
    WrongContext,
    Expired,
    Replay,
    Fingerprint,
    ApplicantPgpSig,
    WalletSig,
    ChallengeMismatch,
    /// Recovery: the signer is not the node's current main wallet, the key is not the one the
    /// registry binds, or the node is not offline.
    NotRegistryBound,
    /// The PGP field does not hash to the chain's `pgpHash`.
    PgpHash,
}

fn word_fp(fp: &str) -> Result<e7::Word, Fail> {
    e7::fixed_bytes_word(&format!("0x{}", fp_norm(fp)), 20).map_err(|_| Fail::BadField)
}

fn ip_hash_word(ip: &str) -> Result<e7::Word, Fail> {
    si_core::statement::ip_hash(ip).map_err(|_| Fail::BadField)
}

pub fn response_digest(
    ctx: &Ctx,
    a: &Application,
    c: &Challenge,
    challenge_hash: &[u8; 32],
) -> Result<[u8; 32], Fail> {
    let obs = e7::bytes32(&format!("0x{}", c.observation_hash)).map_err(|_| Fail::BadField)?;
    let s = e7::hash_words(
        RESPONSE_TYPE,
        &[
            a.app_id,
            e7::u64_word(a.kind as u64),
            e7::u64_word(a.node_id),
            e7::address_word(&a.applicant_wallet).map_err(|_| Fail::BadField)?,
            word_fp(&a.pgp_fingerprint)?,
            a.pgp_hash,
            a.endpoint.ip_hash()?,
            e7::u64_word(a.endpoint.ports().0 as u64),
            e7::u64_word(a.endpoint.ports().1 as u64),
            a.endpoint.endpoint_hash()?,
            e7::u64_word(a.endpoint_version),
            e7::u64_word(c.voter_node_id),
            obs,
            *challenge_hash,
            e7::u64_word(c.expires_at),
        ],
    );
    Ok(e7::digest(&ctx.domain()?, &s))
}

/// What the registry says about a registered node (recovery checks it against this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryView {
    pub node_id: u64,
    pub node_wallet: String,
    pub pgp_fingerprint: String,
    pub pgp_hash: [u8; 32],
    /// The node is offline now (only an offline node can recover).
    pub offline: bool,
}

/// Recovery: the application (`requestRecovery`, sent by the main wallet itself) belongs to
/// the node's current main wallet and registry-bound PGP key, and the node is offline.
pub fn check_recovery(a: &Application, reg: &RegistryView, now: u64) -> Result<(), Fail> {
    if a.kind != Kind::Recovery
        || a.node_id != reg.node_id
        || !a.applicant_wallet.eq_ignore_ascii_case(&reg.node_wallet)
        || fp_norm(&a.pgp_fingerprint) != fp_norm(&reg.pgp_fingerprint)
        || a.pgp_hash != reg.pgp_hash
        || !reg.offline
    {
        return Err(Fail::NotRegistryBound);
    }
    if now > a.expires_at {
        return Err(Fail::Expired);
    }
    Ok(())
}

/// The applicant key must be the application's: same `pgpHash` and route-key fingerprint.
fn applicant_matches(a: &Application, k: &ChainKey) -> Result<(), Fail> {
    if k.pgp_hash != a.pgp_hash {
        return Err(Fail::PgpHash);
    }
    if k.fingerprint != fp_norm(&a.pgp_fingerprint) {
        return Err(Fail::Fingerprint);
    }
    Ok(())
}

/// Voter: a fresh one-time challenge made on what it observes now.
#[allow(clippy::too_many_arguments)]
pub fn make_challenge<R: RngCore + CryptoRng>(
    mut rng: R,
    ctx: &Ctx,
    a: &Application,
    observed: &Observed,
    voter_node_id: u64,
    voter_key: &SecretCert,
    applicant: &ChainKey,
    now: u64,
) -> Result<(Outstanding, String), Fail> {
    applicant_matches(a, applicant)?;
    classify(&a.endpoint, observed)?;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let (seen_dtls, voter_dtls) = match observed {
        Observed::WebRtc {
            dtls_fingerprint,
            local_dtls_fingerprint,
            ..
        } => (
            Some(fp_norm(dtls_fingerprint)),
            Some(fp_norm(local_dtls_fingerprint)),
        ),
        Observed::Tcp { .. } => (None, None),
    };
    let c = Challenge {
        v: 1,
        app_id: hex::encode(a.app_id),
        kind: a.kind,
        node_id: a.node_id,
        endpoint_version: a.endpoint_version,
        ip_hash: hex::encode(a.endpoint.ip_hash()?),
        tcp_port: a.endpoint.ports().0,
        udp_port: a.endpoint.ports().1,
        endpoint_hash: hex::encode(a.endpoint.endpoint_hash()?),
        observation_hash: hex::encode(observed.hash()?),
        seen_dtls,
        voter_dtls,
        voter_node_id,
        voter_fingerprint: own_fp(voter_key)?,
        applicant_wallet: a.applicant_wallet.to_lowercase(),
        applicant_fingerprint: fp_norm(&a.pgp_fingerprint),
        chain_id: ctx.chain_id,
        registry: ctx.registry.to_lowercase(),
        nonce: hex::encode(nonce),
        issued_at: now,
        expires_at: now + CHALLENGE_TTL_SEC,
    };
    let body = with_prefix(
        CHALLENGE_PREFIX,
        serde_json::to_vec(&c).map_err(|_| Fail::BadField)?,
    );
    let armored = opgp::encrypt(
        &mut rng,
        &body,
        applicant.key(),
        EncryptOpts {
            text: false,
            zlib: false,
            sign_with: Some(voter_key),
        },
    )
    .map_err(|_| Fail::BadField)?;
    let hash = c.hash();
    Ok((
        Outstanding {
            challenge: c,
            hash,
            observed: observed.clone(),
        },
        armored,
    ))
}

/// Applicant: answer one challenge. `my_wallet`: the main wallet, needed for a first admission
/// only (a recovery reply is PGP-signed only). `session`: for a browser node, its own view of
/// the WebRTC session the challenge came on. `voter_key_of`: a voter's registered PGP key by
/// node id (None = not registered/active). `seen`: nonces already answered.
#[allow(clippy::too_many_arguments)]
pub fn answer<R: RngCore + CryptoRng>(
    mut rng: R,
    ctx: &Ctx,
    me: &Application,
    my_key: &SecretCert,
    my_wallet: Option<&EthKey>,
    armored: &str,
    session: Option<&SessionView>,
    voter_key_of: impl Fn(u64) -> Option<ChainKey>,
    seen: &mut std::collections::HashSet<String>,
    now: u64,
) -> Result<String, Fail> {
    let plain = opgp::decrypt(armored, my_key, None).map_err(|_| Fail::Decrypt)?;
    let c: Challenge = serde_json::from_slice(strip_prefix(CHALLENGE_PREFIX, &plain.data)?)
        .map_err(|_| Fail::BadField)?;
    let voter_ck = voter_key_of(c.voter_node_id).ok_or(Fail::VoterSig)?;
    if voter_ck.fingerprint != c.voter_fingerprint {
        return Err(Fail::VoterSig);
    }
    let voter = voter_ck.key();
    let checked = opgp::decrypt(armored, my_key, Some(voter)).map_err(|_| Fail::Decrypt)?;
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
        || own_fp(my_key)? != fp_norm(&me.pgp_fingerprint)
    {
        return Err(Fail::WrongApplication);
    }
    if c.ip_hash != hex::encode(me.endpoint.ip_hash()?)
        || (c.tcp_port, c.udp_port) != me.endpoint.ports()
        || c.endpoint_hash != hex::encode(me.endpoint.endpoint_hash()?)
    {
        return Err(Fail::WrongEndpoint);
    }
    // A browser only answers on a session where both sides see the same two certificates:
    // the voter sees ITS authorized certificate, and it sees the voter's certificate.
    let mut dtls_pair = (None, None);
    if let Endpoint::Browser {
        dtls_fingerprint, ..
    } = &me.endpoint
    {
        let s = session.ok_or(Fail::DtlsFingerprint)?;
        let own = fp_norm(&s.own_dtls);
        let peer = fp_norm(&s.peer_dtls);
        if own != fp_norm(dtls_fingerprint)
            || c.seen_dtls.as_deref() != Some(own.as_str())
            || c.voter_dtls.as_deref() != Some(peer.as_str())
        {
            return Err(Fail::DtlsFingerprint);
        }
        dtls_pair = (Some(own), Some(peer));
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
    let hc = c.hash();
    let wallet_sig = match me.kind {
        Kind::First => Some(
            my_wallet
                .ok_or(Fail::WalletSig)?
                .sign_digest(&response_digest(ctx, me, &c, &hc)?)
                .map_err(|_| Fail::WalletSig)?,
        ),
        Kind::Recovery => None,
    };
    let reply = Reply {
        challenge_hash: hex::encode(hc),
        wallet_sig,
        node_dtls: dtls_pair.0,
        voter_dtls: dtls_pair.1,
    };
    let body = with_prefix(
        REPLY_PREFIX,
        serde_json::to_vec(&reply).map_err(|_| Fail::BadField)?,
    );
    opgp::encrypt(
        &mut rng,
        &body,
        voter,
        EncryptOpts {
            text: false,
            zlib: false,
            sign_with: Some(my_key),
        },
    )
    .map_err(|_| Fail::BadField)
}

/// Voter: verify a reply to `outstanding`, with its observation read again NOW. Returns the
/// endpoint class this vote proves. On success the challenge is used up.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    ctx: &Ctx,
    a: &Application,
    outstanding: &Outstanding,
    voter_key: &SecretCert,
    applicant: &ChainKey,
    armored_reply: &str,
    observed_now: &Observed,
    now: u64,
) -> Result<EndpointClass, Fail> {
    applicant_matches(a, applicant)?;
    // ICE restart or a new selected pair (or another TCP peer) voids the challenge.
    if *observed_now != outstanding.observed {
        return Err(Fail::PathChanged);
    }
    let class = classify(&a.endpoint, observed_now)?;
    if now > outstanding.challenge.expires_at + CLOCK_SKEW_SEC {
        return Err(Fail::Expired);
    }
    let d = opgp::decrypt(armored_reply, voter_key, Some(applicant.key()))
        .map_err(|_| Fail::Decrypt)?;
    if d.verified != Some(true) {
        return Err(Fail::ApplicantPgpSig);
    }
    let r: Reply =
        serde_json::from_slice(strip_prefix(REPLY_PREFIX, &d.data)?).map_err(|_| Fail::BadField)?;
    if r.challenge_hash != hex::encode(outstanding.hash) {
        return Err(Fail::ChallengeMismatch);
    }
    let c = &outstanding.challenge;
    if c.app_id != hex::encode(a.app_id)
        || c.kind != a.kind
        || c.node_id != a.node_id
        || c.endpoint_version != a.endpoint_version
        || !c.applicant_wallet.eq_ignore_ascii_case(&a.applicant_wallet)
        || c.applicant_fingerprint != fp_norm(&a.pgp_fingerprint)
        || c.ip_hash != hex::encode(a.endpoint.ip_hash()?)
        || (c.tcp_port, c.udp_port) != a.endpoint.ports()
        || c.endpoint_hash != hex::encode(a.endpoint.endpoint_hash()?)
        || c.observation_hash != hex::encode(observed_now.hash()?)
    {
        return Err(Fail::WrongApplication);
    }
    // Browser: the node's report of the session must match the voter's own view.
    if let Observed::WebRtc {
        dtls_fingerprint,
        local_dtls_fingerprint,
        ..
    } = observed_now
    {
        if r.node_dtls.as_deref() != Some(fp_norm(dtls_fingerprint).as_str())
            || r.voter_dtls.as_deref() != Some(fp_norm(local_dtls_fingerprint).as_str())
        {
            return Err(Fail::DtlsFingerprint);
        }
    }
    match (a.kind, &r.wallet_sig) {
        // Recovery replies are PGP-only (the PGP signature was checked above).
        (Kind::Recovery, None) => Ok(class),
        (Kind::Recovery, Some(_)) => Err(Fail::BadField),
        (Kind::First, Some(sig)) => {
            let digest = response_digest(ctx, a, c, &outstanding.hash)?;
            match eth::recover_digest(&digest, sig) {
                Ok(w) if w.eq_ignore_ascii_case(&a.applicant_wallet) => Ok(class),
                _ => Err(Fail::WalletSig),
            }
        }
        (Kind::First, None) => Err(Fail::WalletSig),
    }
}

/// The fixed set of nodes the project initialised (472), exempt from FIRST admission only.
pub trait TrustedInitialSet {
    fn contains(&self, node_id: u64, main_wallet: &str) -> Option<bool>;
}

pub fn needs_vote(kind: Kind, node_id: u64, wallet: &str, set: &dyn TrustedInitialSet) -> bool {
    match kind {
        Kind::Recovery => true,
        Kind::First => set.contains(node_id, wallet) != Some(true),
    }
}

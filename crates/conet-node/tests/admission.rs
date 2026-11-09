//! Vote admission challenge, local simulation (ADMIT-RUST). Golden TEST keys only:
//! applicant = nodeB (PGP + wallet), voter = nodeA, attacker = "user" PGP key + "temp" wallet.
use conet_node::admission::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use si_crypto::eth::EthKey;
use si_crypto::opgp::SecretCert;
use std::collections::HashSet;

const NOW: u64 = 1_800_000_000;
const REGISTRY: &str = "0x00000000000000000000000000000000c0de0001";

fn g() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

struct Party {
    key: SecretCert,
    public: ChainKey,
    field: String,
    hash: [u8; 32],
    wallet: EthKey,
}

fn party(g: &Value, key: &str, wallet: &str) -> Party {
    let k = &g["keys"][key];
    let key = SecretCert::from_armor(
        k["armoredPrivate"].as_str().unwrap(),
        k["passphrase"].as_str().unwrap(),
    )
    .unwrap()
    .unlock()
    .unwrap();
    let armor = k["armoredPublic"].as_str().unwrap().to_string();
    let field = si_core::statement::pgp_field(&armor);
    let hash = si_core::statement::pgp_hash(&armor);
    let public = ChainKey::from_chain(&field, &hash).unwrap();
    let wallet = EthKey::from_hex(g["wallets"][wallet]["privateKey"].as_str().unwrap()).unwrap();
    Party {
        key,
        public,
        field,
        hash,
        wallet,
    }
}

struct World {
    ctx: Ctx,
    app: Application,
    applicant: Party,
    voter: Party,
    attacker: Party,
    rng: ChaCha20Rng,
}

const VOTER_ID: u64 = 7;

fn here() -> Observed {
    Observed::Tcp {
        ip: "203.0.113.9".into(),
        port: 80,
    }
}

fn at(ip: &str) -> Observed {
    Observed::Tcp {
        ip: ip.into(),
        port: 80,
    }
}

fn world(kind: Kind) -> World {
    let g = g();
    let applicant = party(&g, "nodeB", "nodeB");
    let voter = party(&g, "nodeA", "nodeA");
    let attacker = party(&g, "user", "temp");
    let app = Application {
        app_id: [0x11; 32],
        kind,
        node_id: if kind == Kind::Recovery { 573 } else { 0 },
        applicant_wallet: applicant.wallet.address(),
        pgp_fingerprint: applicant.public.fingerprint.clone(),
        pgp_hash: applicant.hash,
        endpoint: Endpoint::Tcp {
            ip: "203.0.113.9".into(),
            tcp_port: 80,
            udp_port: 0,
        },
        endpoint_version: 1,
        proposer_node_id: VOTER_ID,
        expires_at: NOW + 3_600,
    };
    World {
        ctx: Ctx {
            chain_id: 224_422,
            registry: REGISTRY.into(),
        },
        app,
        applicant,
        voter,
        attacker,
        rng: ChaCha20Rng::seed_from_u64(9),
    }
}

impl World {
    fn challenge(&mut self) -> (Outstanding, String) {
        make_challenge(
            &mut self.rng,
            &self.ctx,
            &self.app,
            &here(),
            VOTER_ID,
            &self.voter.key,
            &self.applicant.public,
            NOW,
        )
        .unwrap()
    }
    fn answer(
        &mut self,
        armored: &str,
        seen: &mut HashSet<String>,
        now: u64,
    ) -> Result<String, Fail> {
        let (vf, vh) = (self.voter.field.clone(), self.voter.hash);
        answer(
            &mut self.rng,
            &self.ctx,
            &self.app,
            &self.applicant.key,
            Some(&self.applicant.wallet),
            armored,
            None,
            move |id| (id == VOTER_ID).then(|| ChainKey::from_chain(&vf, &vh).unwrap()),
            seen,
            now,
        )
    }
    fn verify(&self, o: &Outstanding, reply: &str, now: u64) -> Result<(), Fail> {
        verify(
            &self.ctx,
            &self.app,
            o,
            &self.voter.key,
            &self.applicant.public,
            reply,
            &here(),
            now,
        )
        .map(|_| ())
    }
}

#[test]
fn admission_round_trip_ok() {
    let mut w = world(Kind::First);
    // The application is the main wallet's own chain transaction (applyAdmission), so there is
    // no separate off-chain application signature; the key comes from the chain field.
    let (o, armored) = w.challenge();
    let mut seen = HashSet::new();
    let reply = w.answer(&armored, &mut seen, NOW + 1).unwrap();
    assert_eq!(w.verify(&o, &reply, NOW + 2), Ok(()));
}

#[test]
fn replay_refused_both_sides() {
    let mut w = world(Kind::First);
    let (o, armored) = w.challenge();
    let mut seen = HashSet::new();
    let reply = w.answer(&armored, &mut seen, NOW + 1).unwrap();
    // The applicant answers a challenge once.
    assert_eq!(w.answer(&armored, &mut seen, NOW + 2), Err(Fail::Replay));
    // The voter takes one reply per challenge: a fresh challenge does not accept the old reply.
    assert_eq!(w.verify(&o, &reply, NOW + 2), Ok(()));
    let (o2, _) = w.challenge();
    assert_eq!(w.verify(&o2, &reply, NOW + 3), Err(Fail::ChallengeMismatch));
}

#[test]
fn impersonation_refused() {
    let mut w = world(Kind::First);
    let (o, armored) = w.challenge();
    // A third party cannot even read the challenge (encrypted to the applicant).
    let mut seen = HashSet::new();
    let attacker_try = answer(
        &mut w.rng,
        &w.ctx,
        &w.app,
        &w.attacker.key,
        Some(&w.attacker.wallet),
        &armored,
        None,
        |_| None,
        &mut seen,
        NOW,
    );
    assert_eq!(attacker_try, Err(Fail::Decrypt));
    // A reply signed with another PGP key (even sent to the voter correctly) is refused.
    let reply = w.answer(&armored, &mut seen, NOW + 1).unwrap();
    let wrong_key = verify(
        &w.ctx,
        &w.app,
        &o,
        &w.voter.key,
        &w.attacker.public,
        &reply,
        &here(),
        NOW + 2,
    );
    // Another key's chain field fails the application's pgpHash first.
    assert_eq!(wrong_key, Err(Fail::PgpHash));
    // The applicant's PGP key but another wallet: the wallet signature does not recover.
    let mut stolen = w.app.clone();
    stolen.applicant_wallet = w.attacker.wallet.address();
    let (o2, armored2) = make_challenge(
        &mut w.rng,
        &w.ctx,
        &stolen,
        &here(),
        VOTER_ID,
        &w.voter.key,
        &w.applicant.public,
        NOW,
    )
    .unwrap();
    let (vf, vh) = (w.voter.field.clone(), w.voter.hash);
    let r2 = answer(
        &mut w.rng,
        &w.ctx,
        &stolen,
        &w.applicant.key,
        Some(&w.attacker.wallet),
        &armored2,
        None,
        move |id| (id == VOTER_ID).then(|| ChainKey::from_chain(&vf, &vh).unwrap()),
        &mut HashSet::new(),
        NOW,
    )
    .unwrap();
    // The chain's application names the real applicant wallet.
    assert_eq!(
        verify(
            &w.ctx,
            &w.app,
            &o2,
            &w.voter.key,
            &w.applicant.public,
            &r2,
            &here(),
            NOW
        ),
        Err(Fail::WrongApplication)
    );
}

#[test]
fn reply_for_another_voter_or_relay_refused() {
    let mut w = world(Kind::First);
    let (_, armored) = w.challenge();
    let reply = w.answer(&armored, &mut HashSet::new(), NOW + 1).unwrap();
    // A different voter (attacker key as voter) cannot decrypt a reply made for voter 7.
    let other = Outstanding {
        challenge: serde_json::from_str::<Challenge>(
            &serde_json::to_string(&w.challenge().0.challenge).unwrap(),
        )
        .unwrap(),
        hash: [0; 32],
        observed: here(),
    };
    assert_eq!(
        verify(
            &w.ctx,
            &w.app,
            &other,
            &w.attacker.key,
            &w.applicant.public,
            &reply,
            &here(),
            NOW + 2
        ),
        Err(Fail::Decrypt)
    );
    // A challenge signed by a key that is not the registered voter key: no answer.
    let (_, forged) = make_challenge(
        &mut w.rng,
        &w.ctx,
        &w.app,
        &here(),
        VOTER_ID,
        &w.attacker.key,
        &w.applicant.public,
        NOW,
    )
    .unwrap();
    assert_eq!(
        w.answer(&forged, &mut HashSet::new(), NOW + 1),
        Err(Fail::VoterSig)
    );
}

#[test]
fn wrong_endpoint_refused() {
    let mut w = world(Kind::First);
    let (o, armored) = w.challenge();
    let reply = w.answer(&armored, &mut HashSet::new(), NOW + 1).unwrap();
    // The voter got the reply over another connection than the one it challenged on (a
    // different peer): the challenge is void.
    assert_eq!(
        verify(
            &w.ctx,
            &w.app,
            &o,
            &w.voter.key,
            &w.applicant.public,
            &reply,
            &at("198.51.100.4"),
            NOW + 2
        ),
        Err(Fail::PathChanged)
    );
    // The applicant refuses a challenge for another endpoint (address reuse, stale data).
    let mut moved = w.app.clone();
    moved.endpoint = Endpoint::Tcp {
        ip: "198.51.100.4".into(),
        tcp_port: 80,
        udp_port: 0,
    };
    let (_, armored2) = make_challenge(
        &mut w.rng,
        &w.ctx,
        &moved,
        &at("198.51.100.4"),
        VOTER_ID,
        &w.voter.key,
        &w.applicant.public,
        NOW,
    )
    .unwrap();
    assert_eq!(
        w.answer(&armored2, &mut HashSet::new(), NOW + 1),
        Err(Fail::WrongEndpoint)
    );
}

#[test]
fn expired_or_version_changed_refused() {
    let mut w = world(Kind::Recovery);
    let (o, armored) = w.challenge();
    // Too late for the applicant (60 s + 30 s skew).
    assert_eq!(
        w.answer(&armored, &mut HashSet::new(), NOW + 91),
        Err(Fail::Expired)
    );
    let reply = w.answer(&armored, &mut HashSet::new(), NOW + 1).unwrap();
    assert_eq!(w.verify(&o, &reply, NOW + 91), Err(Fail::Expired));
    // The endpoint changed during the vote: the old reply does not count for the new version.
    let mut newer = w.app.clone();
    newer.endpoint_version = 2;
    assert_eq!(
        verify(
            &w.ctx,
            &newer,
            &o,
            &w.voter.key,
            &w.applicant.public,
            &reply,
            &here(),
            NOW + 2
        ),
        Err(Fail::WrongApplication)
    );
}

#[test]
fn chain_pgp_hash_and_route_fingerprint() {
    let g = g();
    let k = &g["keys"]["nodeB"];
    let armor = k["armoredPublic"].as_str().unwrap();
    let field = si_core::statement::pgp_field(armor);
    let hash = si_core::statement::pgp_hash(armor);
    // The key is built only from the chain field whose hash is the chain's pgpHash.
    let ck = ChainKey::from_chain(&field, &hash).unwrap();
    let mut wrong = hash;
    wrong[0] ^= 1;
    assert!(matches!(
        ChainKey::from_chain(&field, &wrong),
        Err(Fail::PgpHash)
    ));
    // The fingerprint is the ROUTE SUBKEY's (as the contract computes it); its low 64 bits are
    // the key ID; it is not the primary key's fingerprint.
    let key_id = k["encKeyId"].as_str().unwrap().to_uppercase();
    assert!(
        ck.fingerprint.ends_with(&key_id),
        "{} / {}",
        ck.fingerprint,
        key_id
    );
    assert_ne!(
        ck.fingerprint,
        k["fingerprint"].as_str().unwrap().to_uppercase()
    );
    // An application naming another fingerprint, or another pgpHash, is refused.
    let mut w = world(Kind::First);
    w.app.pgp_fingerprint = "00".repeat(20);
    let r = make_challenge(
        &mut w.rng,
        &w.ctx,
        &w.app,
        &here(),
        VOTER_ID,
        &w.voter.key,
        &w.applicant.public,
        NOW,
    );
    assert!(matches!(r, Err(Fail::Fingerprint)));
    let mut w = world(Kind::First);
    w.app.pgp_hash = wrong;
    let r = make_challenge(
        &mut w.rng,
        &w.ctx,
        &w.app,
        &here(),
        VOTER_ID,
        &w.voter.key,
        &w.applicant.public,
        NOW,
    );
    assert!(matches!(r, Err(Fail::PgpHash)));
}

#[test]
fn first_and_recovery_do_not_mix() {
    let mut first = world(Kind::First);
    let (o, armored) = first.challenge();
    let reply = first
        .answer(&armored, &mut HashSet::new(), NOW + 1)
        .unwrap();
    // The same reply presented for a recovery application of the same node: refused.
    let mut rec = first.app.clone();
    rec.kind = Kind::Recovery;
    rec.node_id = 573;
    assert_eq!(
        verify(
            &first.ctx,
            &rec,
            &o,
            &first.voter.key,
            &first.applicant.public,
            &reply,
            &here(),
            NOW + 2
        ),
        Err(Fail::WrongApplication)
    );
}

#[test]
fn other_chain_or_registry_refused() {
    let mut w = world(Kind::First);
    let (_, armored) = w.challenge();
    w.ctx.chain_id = 1;
    assert_eq!(
        w.answer(&armored, &mut HashSet::new(), NOW + 1),
        Err(Fail::WrongContext)
    );
    w.ctx.chain_id = 224_422;
    w.ctx.registry = "0x00000000000000000000000000000000c0de0002".into();
    assert_eq!(
        w.answer(&armored, &mut HashSet::new(), NOW + 1),
        Err(Fail::WrongContext)
    );
}

struct Set(Vec<(u64, String)>);
impl TrustedInitialSet for Set {
    fn contains(&self, id: u64, wallet: &str) -> Option<bool> {
        Some(
            self.0
                .iter()
                .any(|(i, w)| *i == id && w.eq_ignore_ascii_case(wallet)),
        )
    }
}
struct Unknown;
impl TrustedInitialSet for Unknown {
    fn contains(&self, _: u64, _: &str) -> Option<bool> {
        None
    }
}

#[test]
fn initial_set_exempts_first_admission_only() {
    let set = Set(vec![(7, "0xabc".into())]);
    // A proven member skips the FIRST admission vote; anyone else, or an undecidable set, votes.
    assert!(!needs_vote(Kind::First, 7, "0xABC", &set));
    assert!(needs_vote(Kind::First, 8, "0xabc", &set));
    assert!(needs_vote(Kind::First, 7, "0xdef", &set));
    assert!(needs_vote(Kind::First, 7, "0xabc", &Unknown));
    // Recovery always needs a vote, members included.
    assert!(needs_vote(Kind::Recovery, 7, "0xabc", &set));
}

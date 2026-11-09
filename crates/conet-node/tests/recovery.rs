//! R-1: offline -> online recovery, pure logic (RECOVER-RUST). Golden TEST keys only:
//! node = nodeB (registered main wallet + bound PGP key), voter = nodeA, relay/attacker = "user"
//! PGP key + "temp" wallet. Observations stand in for the voter's own getStats / TCP peer.
use conet_node::admission::*;
use conet_node::recovery::{Node, Outcome, Refused, State, Threshold, Verdict};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use si_crypto::eth::EthKey;
use si_crypto::opgp::{PublicCert, SecretCert};
use std::collections::HashSet;

const NOW: u64 = 1_800_000_000;
const VOTER: u64 = 7;
const NODE: u64 = 573;
const DTLS: &str = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
const VOTER_DTLS: &str = "99:88:77:66:55:44:33:22:11:00:99:88:77:66:55:44:33:22:11:00:99:88:77:66:55:44:33:22:11:00:99:88";
const OTHER_DTLS: &str = "11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22";

fn g() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

struct P {
    key: SecretCert,
    public: PublicCert,
    armor: String,
    wallet: EthKey,
}

fn p(g: &Value, key: &str, wallet: &str) -> P {
    let k = &g["keys"][key];
    let armor = k["armoredPublic"].as_str().unwrap().to_string();
    P {
        key: SecretCert::from_armor(
            k["armoredPrivate"].as_str().unwrap(),
            k["passphrase"].as_str().unwrap(),
        )
        .unwrap()
        .unlock()
        .unwrap(),
        public: PublicCert::from_armor(&armor).unwrap(),
        armor,
        wallet: EthKey::from_hex(g["wallets"][wallet]["privateKey"].as_str().unwrap()).unwrap(),
    }
}

struct W {
    ctx: Ctx,
    node: P,
    voter: P,
    relay: P,
    rng: ChaCha20Rng,
}

fn w() -> W {
    let g = g();
    W {
        ctx: Ctx {
            chain_id: 224_422,
            registry: "0x00000000000000000000000000000000c0de0001".into(),
        },
        node: p(&g, "nodeB", "nodeB"),
        voter: p(&g, "nodeA", "nodeA"),
        relay: p(&g, "user", "temp"),
        rng: ChaCha20Rng::seed_from_u64(3),
    }
}

impl W {
    fn app(&self, endpoint: Endpoint, version: u64) -> Application {
        Application {
            app_id: [0x22; 32],
            kind: Kind::Recovery,
            node_id: NODE,
            applicant_wallet: self.node.wallet.address(),
            pgp_fingerprint: self.node.public.fingerprint(),
            endpoint,
            endpoint_version: version,
            proposer_node_id: 0,
            expires_at: NOW + 3_600,
        }
    }
    fn reg(&self, offline: bool) -> RegistryView {
        RegistryView {
            node_id: NODE,
            node_wallet: self.node.wallet.address(),
            pgp_fingerprint: self.node.public.fingerprint(),
            offline,
        }
    }
    fn challenge(&mut self, a: &Application, o: &Observed) -> Result<(Outstanding, String), Fail> {
        make_challenge(
            &mut self.rng,
            &self.ctx,
            a,
            o,
            VOTER,
            &self.voter.key,
            &self.node.public,
            NOW,
        )
    }
    fn answer(&mut self, a: &Application, armored: &str) -> Result<String, Fail> {
        let s = SessionView {
            own_dtls: DTLS.into(),
            peer_dtls: VOTER_DTLS.into(),
        };
        self.answer_on(a, armored, Some(&s))
    }
    fn answer_on(
        &mut self,
        a: &Application,
        armored: &str,
        s: Option<&SessionView>,
    ) -> Result<String, Fail> {
        let v = self.voter.armor.clone();
        let session = match a.endpoint {
            Endpoint::Browser { .. } => s,
            Endpoint::Tcp { .. } => None,
        };
        answer(
            &mut self.rng,
            &self.ctx,
            a,
            &self.node.key,
            None, // recovery: PGP-only replies
            armored,
            session,
            move |id| (id == VOTER).then(|| PublicCert::from_armor(&v).unwrap()),
            &mut HashSet::new(),
            NOW + 1,
        )
    }
    fn verify(
        &self,
        a: &Application,
        o: &Outstanding,
        reply: &str,
        now_seen: &Observed,
    ) -> Result<EndpointClass, Fail> {
        verify(
            &self.ctx,
            a,
            o,
            &self.voter.key,
            &self.node.public,
            reply,
            now_seen,
            NOW + 2,
        )
    }
}

fn webrtc(
    pair: &str,
    ip: &str,
    port: u16,
    kind: &str,
    relay: Option<&str>,
    dtls: &str,
) -> Observed {
    Observed::WebRtc {
        pair_id: pair.into(),
        remote_ip: ip.into(),
        remote_port: port,
        candidate_type: kind.into(),
        relay: relay.map(str::to_string),
        dtls_fingerprint: dtls.into(),
        local_dtls_fingerprint: VOTER_DTLS.into(),
    }
}

fn browser(relay: Option<&str>) -> Endpoint {
    Endpoint::Browser {
        dtls_fingerprint: DTLS.into(),
        relay: relay.map(str::to_string),
    }
}

#[test]
fn recovery_needs_registry_bound_identity() {
    let w = w();
    let a = w.app(
        Endpoint::Tcp {
            ip: "203.0.113.9".into(),
            port: 80,
        },
        1,
    );
    let sig = w
        .node
        .wallet
        .sign_digest(&application_digest(&w.ctx, &a).unwrap())
        .unwrap();
    assert_eq!(check_recovery(&w.ctx, &a, &sig, &w.reg(true), NOW), Ok(()));
    // Not offline (already online): no recovery.
    assert_eq!(
        check_recovery(&w.ctx, &a, &sig, &w.reg(false), NOW),
        Err(Fail::NotRegistryBound)
    );
    // The registry's main wallet changed: the old one cannot authorize the endpoint.
    let mut moved = w.reg(true);
    moved.node_wallet = w.relay.wallet.address();
    assert_eq!(
        check_recovery(&w.ctx, &a, &sig, &moved, NOW),
        Err(Fail::NotRegistryBound)
    );
    // A PGP key other than the one the registry binds.
    let mut other_key = w.reg(true);
    other_key.pgp_fingerprint = w.relay.public.fingerprint();
    assert_eq!(
        check_recovery(&w.ctx, &a, &sig, &other_key, NOW),
        Err(Fail::NotRegistryBound)
    );
    // A signature by someone else over the right application.
    let bad = w
        .relay
        .wallet
        .sign_digest(&application_digest(&w.ctx, &a).unwrap())
        .unwrap();
    assert_eq!(
        check_recovery(&w.ctx, &a, &bad, &w.reg(true), NOW),
        Err(Fail::WalletSig)
    );
}

#[test]
fn browser_direct_vote_records_the_observed_address() {
    let mut w = w();
    let a = w.app(browser(None), 1);
    // The voter's own getStats: selected pair, remote srflx 198.51.100.7:51234, remote DTLS.
    let seen = webrtc("pair-1", "198.51.100.7", 51_234, "srflx", None, DTLS);
    let (o, ch) = w.challenge(&a, &seen).unwrap();
    let reply = w.answer(&a, &ch).unwrap();
    assert_eq!(
        w.verify(&a, &o, &reply, &seen),
        Ok(EndpointClass::Direct {
            ip: "198.51.100.7".into(),
            port: 51_234
        })
    );
}

#[test]
fn browser_relay_vote_is_marked_relay_not_public_address() {
    let mut w = w();
    let a = w.app(browser(Some("turn:relay-1")), 1);
    let seen = webrtc(
        "pair-9",
        "192.0.2.50",
        3478,
        "relay",
        Some("turn:relay-1"),
        DTLS,
    );
    let (o, ch) = w.challenge(&a, &seen).unwrap();
    let reply = w.answer(&a, &ch).unwrap();
    // The address is the relay's; the record says so.
    assert_eq!(
        w.verify(&a, &o, &reply, &seen),
        Ok(EndpointClass::Relay {
            relay: "turn:relay-1".into(),
            relay_ip: "192.0.2.50".into(),
            relay_port: 3478
        })
    );
    // A relayed pair cannot pass as direct, a direct pair cannot pass as relayed, and another
    // relay than the authorized one is refused.
    assert_eq!(
        w.challenge(&w.app(browser(None), 1), &seen).unwrap_err(),
        Fail::WrongEndpoint
    );
    let direct = webrtc("pair-2", "198.51.100.7", 51_234, "host", None, DTLS);
    assert_eq!(w.challenge(&a, &direct).unwrap_err(), Fail::WrongEndpoint);
    let other_relay = webrtc(
        "pair-3",
        "192.0.2.60",
        3478,
        "relay",
        Some("turn:relay-2"),
        DTLS,
    );
    assert_eq!(
        w.challenge(&a, &other_relay).unwrap_err(),
        Fail::WrongEndpoint
    );
}

#[test]
fn relay_cannot_answer_for_the_browser() {
    let mut w = w();
    let a = w.app(browser(Some("turn:relay-1")), 1);
    let seen = webrtc(
        "pair-9",
        "192.0.2.50",
        3478,
        "relay",
        Some("turn:relay-1"),
        DTLS,
    );
    let (o, ch) = w.challenge(&a, &seen).unwrap();
    // The relay forwards ciphertext only: it cannot read the challenge ...
    let v = w.voter.armor.clone();
    let try_answer = answer(
        &mut w.rng,
        &w.ctx,
        &a,
        &w.relay.key,
        None,
        &ch,
        None,
        move |id| (id == VOTER).then(|| PublicCert::from_armor(&v).unwrap()),
        &mut HashSet::new(),
        NOW + 1,
    );
    assert_eq!(try_answer, Err(Fail::Decrypt));
    // ... and a relay that terminates DTLS itself shows its own certificate to the voter:
    // refused before any challenge is sent.
    let mitm = webrtc(
        "pair-9",
        "192.0.2.50",
        3478,
        "relay",
        Some("turn:relay-1"),
        OTHER_DTLS,
    );
    assert_eq!(w.challenge(&a, &mitm).unwrap_err(), Fail::DtlsFingerprint);
    // The real reply still verifies.
    let reply = w.answer(&a, &ch).unwrap();
    assert!(w.verify(&a, &o, &reply, &seen).is_ok());
}

#[test]
fn selected_pair_change_voids_the_challenge() {
    let mut w = w();
    let a = w.app(browser(None), 1);
    let before = webrtc("pair-1", "198.51.100.7", 51_234, "srflx", None, DTLS);
    let (o, ch) = w.challenge(&a, &before).unwrap();
    let reply = w.answer(&a, &ch).unwrap();
    // ICE restart: the voter's selected pair is now another one.
    let after = webrtc("pair-4", "198.51.100.7", 51_999, "srflx", None, DTLS);
    assert_eq!(w.verify(&a, &o, &reply, &after), Err(Fail::PathChanged));
    // Redo on the new pair: passes, and records the new address.
    let (o2, ch2) = w.challenge(&a, &after).unwrap();
    let r2 = w.answer(&a, &ch2).unwrap();
    assert_eq!(
        w.verify(&a, &o2, &r2, &after),
        Ok(EndpointClass::Direct {
            ip: "198.51.100.7".into(),
            port: 51_999
        })
    );
    // The old reply cannot be moved onto the new challenge.
    assert_eq!(
        w.verify(&a, &o2, &reply, &after),
        Err(Fail::ChallengeMismatch)
    );
}

#[test]
fn browser_only_answers_for_its_own_certificate() {
    let mut w = w();
    // The voter's session shows another certificate, but the application authorizes DTLS:
    // the voter refuses to challenge. If a forged challenge claims another seen certificate,
    // the browser refuses to answer.
    let a = w.app(browser(None), 1);
    let fake_app = Application {
        endpoint: Endpoint::Browser {
            dtls_fingerprint: OTHER_DTLS.into(),
            relay: None,
        },
        ..a.clone()
    };
    let seen_other = webrtc("pair-5", "198.51.100.7", 1, "host", None, OTHER_DTLS);
    let (_, ch) = w.challenge(&fake_app, &seen_other).unwrap();
    assert_eq!(w.answer(&a, &ch), Err(Fail::WrongEndpoint));
}

#[test]
fn recovery_state_rules() {
    let t = Threshold {
        min_approve: 2,
        veto_on_evidence: true,
        relay_only_allowed: true,
    };
    let app = [0x22; 32];
    let direct = EndpointClass::Direct {
        ip: "203.0.113.9".into(),
        port: 80,
    };
    let mut n = Node::offline();
    // A direct "mark online" is refused.
    assert_eq!(n.mark_online_direct(), Err(Refused::RecoveryVoteRequired));
    let v1 = n.open(app, [1; 32]).unwrap();
    // Pending: not routable, no voting right.
    assert_eq!(n.routable(), None);
    assert!(!n.may_vote());
    n.vote(app, v1, 10, Verdict::Approve(direct.clone()))
        .unwrap();
    assert_eq!(
        n.vote(app, v1, 10, Verdict::Approve(direct.clone())),
        Err(Refused::AlreadyVoted)
    );
    // The endpoint changes during the vote: new version, old votes void, old-version votes refused.
    let v2 = n.endpoint_changed([2; 32]).unwrap();
    assert_eq!(
        n.vote(app, v1, 11, Verdict::Approve(direct.clone())),
        Err(Refused::StaleVersion)
    );
    n.vote(app, v2, 11, Verdict::Approve(direct.clone()))
        .unwrap();
    n.vote(app, v2, 12, Verdict::Unreachable).unwrap();
    // Only one approval for v2 (the v1 one was voided): stays offline.
    assert_eq!(n.resolve(t), Ok(Outcome::StayedOffline));
    assert_eq!(n.state, State::Offline);
    // A new application; an evidenced rejection vetoes.
    let v = n.open(app, [3; 32]).unwrap();
    for voter in [20, 21, 22] {
        n.vote(app, v, voter, Verdict::Approve(direct.clone()))
            .unwrap();
    }
    n.vote(app, v, 23, Verdict::RejectWithEvidence).unwrap();
    assert_eq!(n.resolve(t), Ok(Outcome::StayedOffline));
    // Enough approvals, no evidence: online, endpoint and state together.
    let v = n.open(app, [4; 32]).unwrap();
    n.vote(app, v, 30, Verdict::Approve(direct.clone()))
        .unwrap();
    n.vote(app, v, 31, Verdict::Approve(direct)).unwrap();
    assert_eq!(n.resolve(t), Ok(Outcome::Online));
    assert_eq!(n.routable(), Some([4; 32]));
    assert!(n.may_vote());
    // Online nodes cannot open a recovery; going offline again needs a new vote.
    assert_eq!(n.open(app, [5; 32]), Err(Refused::NotOffline));
    n.go_offline();
    assert_eq!(n.routable(), None);
}

#[test]
fn mdns_remote_address_is_unconfirmed() {
    let mut w = w();
    let a = w.app(browser(None), 1);
    let seen = webrtc(
        "u|1|p",
        "3f0c9a1e-77aa-4f2b-9d1c-1234abcd5678.local",
        51_234,
        "host",
        None,
        DTLS,
    );
    assert_eq!(
        w.challenge(&a, &seen).unwrap_err(),
        Fail::AddressUnconfirmed
    );
}

#[test]
fn anchor_splice_of_two_sessions_is_detected() {
    let mut w = w();
    let a = w.app(browser(None), 1);
    let seen = webrtc("u|1|p", "198.51.100.7", 51_234, "srflx", None, DTLS);
    let (o, ch) = w.challenge(&a, &seen).unwrap();
    // The anchor spliced two sessions: the browser sees another remote certificate than the
    // voter's own one. The browser refuses to answer.
    let spliced = SessionView {
        own_dtls: DTLS.into(),
        peer_dtls: OTHER_DTLS.into(),
    };
    assert_eq!(
        w.answer_on(&a, &ch, Some(&spliced)),
        Err(Fail::DtlsFingerprint)
    );
    // A browser node without a session view does not answer either.
    assert_eq!(w.answer_on(&a, &ch, None), Err(Fail::DtlsFingerprint));
    // The honest session: both sides see the same pair; the reply carries it and verifies.
    let reply = w.answer(&a, &ch).unwrap();
    assert!(w.verify(&a, &o, &reply, &seen).is_ok());
}

#[test]
fn recovery_reply_is_pgp_only_with_fixed_prefix() {
    let mut w = w();
    let a = w.app(
        Endpoint::Tcp {
            ip: "203.0.113.9".into(),
            port: 80,
        },
        1,
    );
    let seen = Observed::Tcp {
        ip: "203.0.113.9".into(),
        port: 80,
    };
    let (o, ch) = w.challenge(&a, &seen).unwrap();
    let reply = w.answer(&a, &ch).unwrap();
    // The decrypted reply starts with the fixed prefix and carries no wallet signature.
    let d = si_crypto::opgp::decrypt(&reply, &w.voter.key, Some(&w.node.public)).unwrap();
    assert_eq!(d.verified, Some(true));
    assert!(d.data.starts_with(REPLY_PREFIX));
    let r: Reply = serde_json::from_slice(&d.data[REPLY_PREFIX.len()..]).unwrap();
    assert_eq!(r.wallet_sig, None);
    assert_eq!(
        w.verify(&a, &o, &reply, &seen),
        Ok(EndpointClass::Direct {
            ip: "203.0.113.9".into(),
            port: 80
        })
    );
    // Other PGP signing paths must refuse the reserved prefix; ordinary payloads are fine.
    assert!(is_reserved_pgp_payload(REPLY_PREFIX));
    assert!(is_reserved_pgp_payload(CHALLENGE_PREFIX));
    assert!(is_reserved_pgp_payload(b"CONET-ADMISSION-anything"));
    assert!(!is_reserved_pgp_payload(b"hello"));
    // A PGP-signed reply body without the prefix is not accepted.
    let bare = serde_json::to_vec(&r).unwrap();
    let forged = si_crypto::opgp::encrypt(
        &mut w.rng,
        &bare,
        &w.voter.public,
        si_crypto::opgp::EncryptOpts {
            text: false,
            zlib: false,
            sign_with: Some(&w.node.key),
        },
    )
    .unwrap();
    assert_eq!(w.verify(&a, &o, &forged, &seen), Err(Fail::BadField));
}

#[test]
fn relay_only_browser_policy_both_ways() {
    let app = [0x22; 32];
    let relay = EndpointClass::Relay {
        relay: "turn:relay-1".into(),
        relay_ip: "192.0.2.50".into(),
        relay_port: 3478,
    };
    let direct = EndpointClass::Direct {
        ip: "198.51.100.7".into(),
        port: 51_234,
    };
    for allowed in [false, true] {
        let t = Threshold {
            min_approve: 2,
            veto_on_evidence: true,
            relay_only_allowed: allowed,
        };
        let mut n = Node::offline();
        let v = n.open(app, [7; 32]).unwrap();
        n.vote(app, v, 1, Verdict::Approve(relay.clone())).unwrap();
        n.vote(app, v, 2, Verdict::Approve(relay.clone())).unwrap();
        let out = n.resolve(t).unwrap();
        if allowed {
            assert_eq!(out, Outcome::Online);
            assert!(matches!(
                n.state,
                State::Online {
                    class: EndpointClass::Relay { .. },
                    ..
                }
            ));
        } else {
            assert_eq!(out, Outcome::StayedOffline);
            // One direct approval is enough to pass when relay-only is not allowed.
            let v = n.open(app, [8; 32]).unwrap();
            n.vote(app, v, 1, Verdict::Approve(relay.clone())).unwrap();
            n.vote(app, v, 2, Verdict::Approve(direct.clone())).unwrap();
            assert_eq!(n.resolve(t).unwrap(), Outcome::Online);
        }
    }
}

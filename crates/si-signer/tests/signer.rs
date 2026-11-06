//! Signer end-to-end over a real Unix socket, golden TEST keys only.
use serde_json::Value;
use si_core::statement::{Domain, NodeStatement};
use si_core::{RouteDecryptor, WalletSigner};
use si_crypto::{eip712 as e7, eth};
use si_signer::client::SignerClient;
use si_signer::proto::Request;
use si_signer::server::{Signer, SignerConfig};
use si_signer::{keystore, state};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

const REGISTRY: &str = "0x00000000000000000000000000000000c0de0001";

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

struct Env {
    dir: tempfile::TempDir,
    kek: [u8; 32],
    g: Value,
}

impl Env {
    fn new() -> Self {
        let g = golden();
        let dir = tempfile::tempdir().unwrap();
        let kek = [7u8; 32];
        let secrets = keystore::Secrets {
            wallet_hex: g["wallets"]["nodeA"]["privateKey"].as_str().unwrap().into(),
            pgp_armored: g["keys"]["nodeA"]["armoredPrivate"]
                .as_str()
                .unwrap()
                .into(),
            pgp_pass: g["keys"]["nodeA"]["passphrase"].as_str().unwrap().into(),
            previous_pgp_armored: String::new(),
            previous_pgp_pass: String::new(),
        };
        std::fs::write(
            dir.path().join("keystore.json"),
            keystore::seal(&kek, &secrets).unwrap(),
        )
        .unwrap();
        Signer::init_state(&dir.path().join("state.json"), &kek).unwrap();
        Self { dir, kek, g }
    }
    fn state(&self) -> PathBuf {
        self.dir.path().join("state.json")
    }
    fn cfg(
        &self,
        reset_floor: Option<u64>,
        allow_bind: bool,
        allow_uid: Option<u32>,
    ) -> SignerConfig {
        SignerConfig {
            keystore_file: std::fs::read_to_string(self.dir.path().join("keystore.json")).unwrap(),
            kek: Zeroizing::new(self.kek),
            state_path: self.state(),
            verifying_contract: REGISTRY.into(),
            reset_floor,
            allow_bind,
            allow_uid,
        }
    }
    /// Start a signer on a fresh socket; returns the client.
    async fn start(&self, cfg: SignerConfig, name: &str) -> SignerClient {
        let sock = self.dir.path().join(format!("{name}.sock"));
        let signer = Arc::new(Signer::start(cfg).unwrap_or_else(|e| panic!("{}", e.0)));
        let l = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(si_signer::server::serve(l, signer));
        let s = sock.clone();
        tokio::task::spawn_blocking(move || SignerClient::connect(s))
            .await
            .unwrap()
            .unwrap()
    }
}

async fn call(c: &Arc<SignerClient>, r: Request) -> Result<String, String> {
    let c = c.clone();
    tokio::task::spawn_blocking(move || c.call(&r).map_err(|e| e.to_string()))
        .await
        .unwrap()
}

fn statement(node: &str, epoch: u64, kind: u8, payload: &str) -> Request {
    Request::SignStatement {
        node_id: node.into(),
        epoch,
        kind,
        payload_hash: payload.into(),
    }
}

const ONLINE: &str = "0xee5c566b8f23405e1627453857d993550f9849487d1f0174d9e422bacb47098c";
const P1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const P2: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

#[tokio::test(flavor = "multi_thread")]
async fn identity_decrypt_and_hop() {
    let e = Env::new();
    let c = Arc::new(e.start(e.cfg(None, false, None), "a").await);
    assert_eq!(
        c.address(),
        e.g["wallets"]["nodeA"]["address"].as_str().unwrap()
    );
    assert_eq!(
        c.route_key_id(),
        e.g["keys"]["nodeA"]["encKeyId"].as_str().unwrap()
    );

    // decrypt a golden route command
    let v = e.g["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "post-cmd-mailbox-listen")
        .unwrap();
    let armor = v["input"]["armor"].as_str().unwrap().to_string();
    let c2 = c.clone();
    let plain = tokio::task::spawn_blocking(move || c2.decrypt(&armor))
        .await
        .unwrap()
        .unwrap();
    assert!(!plain.is_empty());

    // hop signature equals an in-process signature of the same payload
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let local =
        eth::EthKey::from_hex(e.g["wallets"]["nodeA"]["privateKey"].as_str().unwrap()).unwrap();
    let hop = si_core::sign_hop(&local, "armor", "B71B2F36BC7A9B84", now).unwrap();
    let c3 = c.clone();
    let remote = tokio::task::spawn_blocking(move || {
        si_core::sign_hop(&*c3, "armor", "B71B2F36BC7A9B84", now)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(hop, remote);

    // no arbitrary messages, no stale hop timestamps
    let c4 = c.clone();
    assert!(
        tokio::task::spawn_blocking(move || c4.sign_message("transfer everything"))
            .await
            .unwrap()
            .is_err()
    );
    let r = call(
        &c,
        Request::SignHop {
            t: now - 10_000,
            n: 1,
            h: format!("0x{}", "ab".repeat(32)),
            k: "B71B2F36BC7A9B84".into(),
        },
    )
    .await;
    assert!(r.unwrap_err().contains("hop_fields"));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_statement_per_epoch_and_kind_survives_restart() {
    let e = Env::new();
    let c = Arc::new(e.start(e.cfg(None, false, None), "a").await);
    let s1 = call(&c, statement("7", 10, 1, ONLINE)).await.unwrap();
    assert_eq!(
        call(&c, statement("7", 10, 1, ONLINE)).await.unwrap(),
        s1,
        "same statement, same bytes"
    );
    assert!(call(&c, statement("7", 10, 1, P1))
        .await
        .unwrap_err()
        .contains("online_payload"));
    call(&c, statement("7", 10, 2, P1)).await.unwrap();
    assert!(call(&c, statement("7", 10, 2, P2))
        .await
        .unwrap_err()
        .contains("double_sign"));
    assert!(call(&c, statement("7", 9, 2, P2))
        .await
        .unwrap_err()
        .contains("epoch_rewind"));
    assert!(call(&c, statement("7", 11, 9, P2))
        .await
        .unwrap_err()
        .contains("unknown_kind"));

    // signature recovers to the node wallet over the spec digest
    let st = NodeStatement::online(e7::u256_dec("7").unwrap(), 10);
    let digest = st.digest(&Domain::new(REGISTRY).unwrap());
    assert_eq!(
        eth::recover_digest(&digest, &s1).unwrap(),
        e.g["wallets"]["nodeA"]["address"].as_str().unwrap()
    );

    // restart: the record is on disk, a different payload is still refused
    let c2 = Arc::new(e.start(e.cfg(None, false, None), "b").await);
    assert!(call(&c2, statement("7", 10, 2, P2))
        .await
        .unwrap_err()
        .contains("double_sign"));
    assert!(call(&c2, statement("7", 11, 2, P2)).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_or_damaged_state_disables_statements_until_floor() {
    let e = Env::new();
    std::fs::remove_file(e.state()).unwrap();
    let c = Arc::new(e.start(e.cfg(None, false, None), "a").await);
    assert!(call(&c, statement("7", 10, 1, ONLINE))
        .await
        .unwrap_err()
        .contains("statement_state_unavailable"));
    // hop and decrypt still work without statement state
    assert!(call(&c, Request::Address).await.is_ok());

    let c2 = Arc::new(e.start(e.cfg(Some(100), false, None), "b").await);
    assert!(call(&c2, statement("7", 100, 1, ONLINE))
        .await
        .unwrap_err()
        .contains("epoch_below_floor"));
    assert!(call(&c2, statement("7", 101, 1, ONLINE)).await.is_ok());

    // edited state file is detected
    let text = std::fs::read_to_string(e.state())
        .unwrap()
        .replace("101", "1");
    std::fs::write(e.state(), text).unwrap();
    assert_eq!(
        state::load(&e.state(), &e.kek).unwrap_err(),
        state::LoadError::Damaged
    );
    let c3 = Arc::new(e.start(e.cfg(None, false, None), "c").await);
    assert!(call(&c3, statement("7", 200, 1, ONLINE))
        .await
        .unwrap_err()
        .contains("statement_state_unavailable"));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_kek_does_not_open() {
    let e = Env::new();
    let mut cfg = e.cfg(None, false, None);
    cfg.kek = Zeroizing::new([8u8; 32]);
    assert!(Signer::start(cfg).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_consent_only_when_enabled_and_for_own_key() {
    let e = Env::new();
    let own = format!(
        "0x{}",
        e.g["keys"]["nodeA"]["encKeyId"]
            .as_str()
            .unwrap()
            .to_lowercase()
    );
    let bind = |key: &str| Request::SignBind {
        operator: "0x1111111111111111111111111111111111111111".into(),
        node_id: "0".into(),
        ip_hash: P1.into(),
        key_id: key.into(),
        pgp_hash: P2.into(),
        nonce: "0".into(),
        deadline: "9999999999".into(),
    };
    let c = Arc::new(e.start(e.cfg(None, false, None), "a").await);
    assert!(call(&c, bind(&own))
        .await
        .unwrap_err()
        .contains("bind_disabled"));
    let c2 = Arc::new(e.start(e.cfg(None, true, None), "b").await);
    assert!(call(&c2, bind("0x0102030405060708"))
        .await
        .unwrap_err()
        .contains("bind_key_mismatch"));
    assert!(call(&c2, bind(&own)).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_uid_check() {
    let e = Env::new();
    let me = std::fs::metadata(Path::new(e.dir.path()))
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    let ok = e.start(e.cfg(None, false, Some(me)), "a").await;
    assert!(ok.call(&Request::Address).is_ok());
    let sock = e.dir.path().join("b.sock");
    let signer = Arc::new(Signer::start(e.cfg(None, false, Some(me + 1))).unwrap());
    let l = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(si_signer::server::serve(l, signer));
    assert!(
        tokio::task::spawn_blocking(move || SignerClient::connect(sock))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn notices_use_fixed_texts() {
    use si_core::NodeNotices;
    let e = Env::new();
    let c = Arc::new(e.start(e.cfg(None, false, None), "a").await);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let eoa = e.g["wallets"]["client"]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let addr = e.g["wallets"]["nodeA"]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let (c1, eo) = (c.clone(), eoa.clone());
    let sig =
        tokio::task::spawn_blocking(move || c1.sign_offline_chat("B71B2F36BC7A9B84", &eo, ts))
            .await
            .unwrap()
            .unwrap();
    let text = si_proto::api_texts::notify_offline_chat("B71B2F36BC7A9B84", &eoa, ts);
    assert_eq!(eth::recover_message(&text, &sig).unwrap(), addr);
    let c2 = c.clone();
    let sig = tokio::task::spawn_blocking(move || c2.sign_epoch(2036549))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(eth::recover_message("2036549", &sig).unwrap(), addr);
    // voice call push: fixed text including the node wallet; window checks
    let (c5, eo) = (c.clone(), eoa.clone());
    let exp = ts as i64 * 1000 + 60_000;
    let sig = tokio::task::spawn_blocking(move || {
        c5.sign_voice_call_push(
            "call-0123456789",
            "0123456789abcdef0123",
            &eo,
            exp,
            ts as i64,
        )
    })
    .await
    .unwrap()
    .unwrap();
    let text = si_proto::voice::call_push_text(
        "call-0123456789",
        "0123456789abcdef0123",
        &eoa,
        exp,
        ts as i64,
        &addr,
    );
    assert_eq!(eth::recover_message(&text, &sig).unwrap(), addr);
    let (c6, eo) = (c.clone(), eoa.clone());
    assert!(
        tokio::task::spawn_blocking(move || c6.sign_voice_call_push(
            "call-0123456789",
            "0123456789abcdef0123",
            &eo,
            exp + 3_600_000,
            ts as i64
        ))
        .await
        .unwrap()
        .is_err(),
        "expiry over 10 minutes refused"
    );
    // malformed key ID or stale timestamp is refused
    let (c3, eo) = (c.clone(), eoa.clone());
    assert!(
        tokio::task::spawn_blocking(move || c3.sign_offline_chat("not-a-key", &eo, ts))
            .await
            .unwrap()
            .is_err()
    );
    let c4 = c.clone();
    assert!(
        tokio::task::spawn_blocking(move || c4.sign_native_wakeable(&eoa, ts - 3600))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn generated_keys_serve_and_match_registration_values() {
    let (secrets, public) = keystore::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let kek = [3u8; 32];
    std::fs::write(
        dir.path().join("keystore.json"),
        keystore::seal(&kek, &secrets).unwrap(),
    )
    .unwrap();
    Signer::init_state(&dir.path().join("state.json"), &kek).unwrap();
    let signer = Arc::new(
        Signer::start(SignerConfig {
            keystore_file: std::fs::read_to_string(dir.path().join("keystore.json")).unwrap(),
            kek: Zeroizing::new(kek),
            state_path: dir.path().join("state.json"),
            verifying_contract: REGISTRY.into(),
            reset_floor: None,
            allow_bind: false,
            allow_uid: None,
        })
        .unwrap_or_else(|e| panic!("{}", e.0)),
    );
    let sock = dir.path().join("s.sock");
    tokio::spawn(si_signer::server::serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        signer,
    ));
    let c = tokio::task::spawn_blocking(move || SignerClient::connect(sock))
        .await
        .unwrap()
        .unwrap();
    let cert = si_crypto::opgp::PublicCert::from_armor(&public).unwrap();
    assert_eq!(c.route_key_id(), cert.enc_key_id().unwrap());
    assert!(
        public.contains(&c.address())
            || cert
                .cert
                .details
                .users
                .iter()
                .any(|u| format!("{:?}", u.id).contains(&c.address()))
    );
    assert!(secrets.pgp_pass.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn route_key_rotation_keeps_the_old_key_until_retired() {
    use rand_core_test::seeded;
    let (mut secrets, old_public) = keystore::generate().unwrap();
    let old_cert = si_crypto::opgp::PublicCert::from_armor(&old_public).unwrap();
    let new_public = keystore::rotate_route(&mut secrets).unwrap();
    let new_cert = si_crypto::opgp::PublicCert::from_armor(&new_public).unwrap();
    assert!(
        keystore::rotate_route(&mut secrets).is_err(),
        "one transition at a time"
    );
    let dir = tempfile::tempdir().unwrap();
    let kek = [4u8; 32];
    let start = |secrets: &keystore::Secrets, name: &str| {
        let ks = keystore::seal(&kek, secrets).unwrap();
        let state = dir.path().join(format!("{name}.json"));
        Signer::init_state(&state, &kek).unwrap();
        let signer = Arc::new(
            Signer::start(SignerConfig {
                keystore_file: ks,
                kek: Zeroizing::new(kek),
                state_path: state,
                verifying_contract: REGISTRY.into(),
                reset_floor: None,
                allow_bind: false,
                allow_uid: None,
            })
            .unwrap_or_else(|e| panic!("{}", e.0)),
        );
        let sock = dir.path().join(format!("{name}.sock"));
        tokio::spawn(si_signer::server::serve(
            tokio::net::UnixListener::bind(&sock).unwrap(),
            signer,
        ));
        sock
    };
    let enc = |cert: &si_crypto::opgp::PublicCert, seed: u8| {
        si_crypto::opgp::encrypt(
            seeded(seed),
            b"m",
            cert,
            si_crypto::opgp::EncryptOpts {
                text: false,
                zlib: true,
                sign_with: None,
            },
        )
        .unwrap()
    };
    let (to_old, to_new) = (enc(&old_cert, 1), enc(&new_cert, 2));

    let sock = start(&secrets, "transition");
    let (a, b) = (to_old.clone(), to_new.clone());
    let (cur, old, d_old, d_new) = tokio::task::spawn_blocking(move || {
        let c = SignerClient::connect(sock).unwrap();
        (
            c.route_key_id().to_string(),
            c.old_route_key_ids().to_vec(),
            c.decrypt(&a).is_ok(),
            c.decrypt(&b).is_ok(),
        )
    })
    .await
    .unwrap();
    assert_eq!(cur, new_cert.enc_key_id().unwrap());
    assert_eq!(old, [old_cert.enc_key_id().unwrap()]);
    assert!(d_old && d_new, "both keys decrypt during the transition");

    keystore::retire_previous(&mut secrets);
    let sock = start(&secrets, "retired");
    let (a, b) = (to_old, to_new);
    let (old, d_old, d_new) = tokio::task::spawn_blocking(move || {
        let c = SignerClient::connect(sock).unwrap();
        (
            c.old_route_key_ids().to_vec(),
            c.decrypt(&a).is_ok(),
            c.decrypt(&b).is_ok(),
        )
    })
    .await
    .unwrap();
    assert!(
        old.is_empty() && !d_old && d_new,
        "old key gone after retire"
    );
}

mod rand_core_test {
    pub fn seeded(seed: u8) -> rand_chacha::ChaCha20Rng {
        <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed([seed; 32])
    }
}

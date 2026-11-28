//! The post acknowledgement: a mailbox says stored / duplicate / store_failed and binds the digest of the armor it stored (regression tests; no special environment).
#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::evidence::EvidenceLog;
use conet_node::mailbox::Mailbox;
use conet_node::push::{Push, VoiceCall};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{armor_hash, DiskStore, MailboxStore, MemoryStore, Stored};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn wallet(g: &Value, n: &str) -> EthKey {
    EthKey::from_hex(g["wallets"][n]["privateKey"].as_str().unwrap()).unwrap()
}
fn pubkey(g: &Value, n: &str) -> opgp::PublicCert {
    opgp::PublicCert::from_armor(g["keys"][n]["armoredPublic"].as_str().unwrap()).unwrap()
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Chain double: one user (golden "user" key, wallet "client") whose mailbox is node B.
struct Chain {
    user_key: String,
    user_wallet: String,
    node_b_key: String,
    node_b_wallet: String,
}

impl UserRoutes for Chain {
    fn route_of_user_key<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(k.eq_ignore_ascii_case(&self.user_key)
                .then(|| self.node_b_key.clone()))
        })
    }
    fn user_key_of_wallet<'a>(
        &'a self,
        w: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(w.eq_ignore_ascii_case(&self.user_wallet)
                .then(|| self.user_key.clone()))
        })
    }
    fn wallet_of_user_key<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(k.eq_ignore_ascii_case(&self.user_key)
                .then(|| self.user_wallet.to_lowercase()))
        })
    }
    fn is_my_route<'a>(&'a self, u: &'a str, n: &'a str) -> BoxFut<'a, Result<bool, ChainError>> {
        Box::pin(async move {
            Ok(u.eq_ignore_ascii_case(&self.user_wallet)
                && n.eq_ignore_ascii_case(&self.node_b_wallet))
        })
    }
}

#[derive(Default)]
struct RecordingPush {
    offline: Mutex<Vec<String>>,
    devices: Mutex<Vec<Value>>,
}
impl Push for RecordingPush {
    fn voice_call(&self, _c: VoiceCall) {}
    fn offline_chat(&self, user_key: String) {
        self.offline.lock().unwrap().push(user_key);
    }
    fn native_wakeable<'a>(&'a self, _eoa: &'a str) -> BoxFut<'a, Option<bool>> {
        Box::pin(async { Some(true) })
    }
    fn register_device(&self, p: Value) {
        self.devices.lock().unwrap().push(p);
    }
}

struct Net {
    g: Value,
    a: SocketAddr,
    push: Arc<RecordingPush>,
    store_b: Arc<DiskStore>,
    db_path: std::path::PathBuf,
    user_key: String,
    health: SocketAddr,
    b_key: String,
    b: SocketAddr,
    mailbox: Arc<Mailbox>,
    ev_a: std::path::PathBuf,
    ev_b: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn start() -> Net {
    start_with(None).await
}

async fn start_with(over: Option<Arc<dyn MailboxStore>>) -> Net {
    let g = golden();
    let (ka, ida) = si_core::node::load_route(
        g["keys"]["nodeA"]["armoredPrivate"].as_str().unwrap(),
        g["keys"]["nodeA"]["passphrase"].as_str().unwrap(),
    )
    .unwrap();
    let (kb, idb) = si_core::node::load_route(
        g["keys"]["nodeB"]["armoredPrivate"].as_str().unwrap(),
        g["keys"]["nodeB"]["passphrase"].as_str().unwrap(),
    )
    .unwrap();
    let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
    let user_key = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let chain: Arc<dyn UserRoutes> = Arc::new(Chain {
        user_key: user_key.clone(),
        user_wallet: g["wallets"]["client"]["address"].as_str().unwrap().into(),
        node_b_key: idb.clone(),
        node_b_wallet: g["wallets"]["nodeB"]["address"].as_str().unwrap().into(),
    });
    let routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(600));
        r.replace_nodes([(ida.clone(), aa), (idb.clone(), ab)]);
        Arc::new(r)
    };
    let mut ca = NodeCtx::new(
        ida.clone(),
        Arc::new(ka),
        Arc::new(wallet(&g, "nodeA")),
        Arc::new(wallet(&g, "nodeA")),
        routes(&ida),
        Arc::new(MemoryStore::default()),
    );
    let dir = tempfile::tempdir().unwrap();
    let (ev_a, ev_b) = (dir.path().join("a.jsonl"), dir.path().join("b.jsonl"));
    ca.user_routes = Some(chain.clone());
    ca.evidence = Some(Arc::new(EvidenceLog::open(&ev_a, &ida).unwrap()));
    let db_path = std::env::var("POST_ACK_DB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| dir.path().join("mailbox.redb"));
    let store_b = Arc::new(DiskStore::open(&db_path).unwrap());
    let push = Arc::new(RecordingPush::default());
    let mut cb = NodeCtx::new(
        idb.clone(),
        Arc::new(kb),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        routes(&idb),
        store_b.clone(),
    );
    cb.user_routes = Some(chain);
    cb.evidence = Some(Arc::new(EvidenceLog::open(&ev_b, &idb).unwrap()));
    cb.push = push.clone();
    cb.mailbox = Arc::new(Mailbox::new(
        over.unwrap_or_else(|| store_b.clone()),
        push.clone(),
    ));
    let mailbox = cb.mailbox.clone();
    let cb = Arc::new(cb);
    let lh = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health = lh.local_addr().unwrap();
    tokio::spawn(server::serve_health(lh, cb.clone()));
    tokio::spawn(server::serve(la, Arc::new(ca)));
    tokio::spawn(server::serve(lb, cb));
    Net {
        g,
        a: aa,
        push,
        store_b,
        db_path,
        user_key,
        health,
        b_key: idb.clone(),
        b: ab,
        mailbox,
        ev_a,
        ev_b,
        _dir: dir,
    }
}

fn enc(seed: u8, text: &str, to: &opgp::PublicCert) -> String {
    opgp::encrypt(
        ChaCha20Rng::from_seed([seed; 32]),
        text.as_bytes(),
        to,
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap()
}

/// Signed command `{message, signMessage}` encrypted to node B, as clients build it.
fn command(g: &Value, signer: &str, cmd: Value, seed: u8) -> String {
    let message = cmd.to_string();
    let sig = wallet(g, signer).sign_message(&message).unwrap();
    enc(
        seed,
        &B64.encode(json!({ "message": message, "signMessage": sig }).to_string()),
        &pubkey(g, "nodeB"),
    )
}

async fn open(addr: SocketAddr, armor: &str) -> TcpStream {
    let body = json!({ "data": armor }).to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("POST /post HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    s
}

async fn post_raw(addr: SocketAddr, armor: &str) -> (u16, String) {
    let mut s = open(addr, armor).await;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(12), s.read_to_end(&mut out))
        .await
        .ok();
    let t = String::from_utf8_lossy(&out).into_owned();
    let status = t
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = t
        .split("\r\n\r\n")
        .skip(1)
        .collect::<Vec<_>>()
        .join("\r\n\r\n");
    (status, body)
}

fn stored(armor: &str) -> Stored {
    Stored {
        armor: armor.to_string(),
        no_push: false,
        hop_bytes: 0,
        hops: 0,
    }
}

fn evrows(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// A store that can be switched to failing; everything else behaves like the memory store.
struct SwitchStore {
    fail: std::sync::atomic::AtomicBool,
    inner: MemoryStore,
}
impl MailboxStore for SwitchStore {
    fn save(&self, k: &str, i: Stored) -> bool {
        self.save_result(k, i) == conet_node::store::SaveResult::Stored
    }
    fn save_result(&self, k: &str, i: Stored) -> conet_node::store::SaveResult {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return conet_node::store::SaveResult::Failed;
        }
        if self.inner.save(k, i) {
            conet_node::store::SaveResult::Stored
        } else {
            conet_node::store::SaveResult::Duplicate
        }
    }
    fn pending(&self, k: &str) -> Vec<Stored> {
        self.inner.pending(k)
    }
    fn remove_by_hash(&self, k: &str, h: &str) -> bool {
        self.inner.remove_by_hash(k, h)
    }
}

fn body_json(b: &str) -> Value {
    serde_json::from_str(b).unwrap_or(Value::Null)
}

/// The patched semantics, end to end: stored / duplicate / store_failed on the mailbox and through the entry, the digest bound to the armor,
/// and a retry of the SAME armor after a failure is stored (not a duplicate, not a second copy).
#[tokio::test(flavor = "multi_thread")]
async fn ack_distinguishes_stored_duplicate_and_store_failed() {
    use std::sync::atomic::Ordering;
    let sw = Arc::new(SwitchStore {
        fail: Default::default(),
        inner: MemoryStore::default(),
    });
    let n = start_with(Some(sw.clone())).await;
    let user = pubkey(&n.g, "user");
    let uk = n.user_key.clone();
    let m = enc(60, "ack me", &user);
    let h = armor_hash(&m);
    // first
    let (s, b) = post_raw(n.a, &m).await;
    assert_eq!(
        (s, body_json(&b)),
        (200, json!({ "ok": true, "stored": true, "h": h }))
    );
    assert_eq!(sw.pending(&uk).len(), 1);
    // duplicate (byte-identical) through the entry and directly
    let (_, b) = post_raw(n.a, &m).await;
    assert_eq!(
        body_json(&b),
        json!({ "ok": true, "duplicate": true, "h": h })
    );
    let (_, b) = post_raw(n.b, &m).await;
    assert_eq!(
        body_json(&b),
        json!({ "ok": true, "duplicate": true, "h": h })
    );
    assert_eq!(sw.pending(&uk).len(), 1, "no second copy");
    // store failure: a new armor is refused, with no h, through the entry and directly, and nothing was stored
    sw.fail.store(true, Ordering::SeqCst);
    let m2 = enc(61, "will fail", &user);
    for addr in [n.a, n.b] {
        let (s, b) = post_raw(addr, &m2).await;
        assert_eq!(
            (s, body_json(&b)),
            (200, json!({ "ok": false, "error": "store_failed" })),
            "{b}"
        );
    }
    assert_eq!(sw.pending(&uk).len(), 1);
    // the failure is also a duplicate-looking armor it is not: the SAME armor retried after recovery is stored once
    sw.fail.store(false, Ordering::SeqCst);
    let (_, b) = post_raw(n.a, &m2).await;
    assert_eq!(
        body_json(&b),
        json!({ "ok": true, "stored": true, "h": armor_hash(&m2) })
    );
    let (_, b) = post_raw(n.a, &m2).await;
    assert_eq!(
        body_json(&b),
        json!({ "ok": true, "duplicate": true, "h": armor_hash(&m2) })
    );
    assert_eq!(sw.pending(&uk).len(), 2);
    // evidence on B: stored/duplicate rows are ok, the failed attempts are fail with reason store_failed, h_in is the same digest the sender got
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rows: Vec<Value> = evrows(&n.ev_b)
        .into_iter()
        .filter(|r| r["ev"] == "store")
        .collect();
    assert!(rows
        .iter()
        .any(|r| r["h_in"] == h && r["stored"] == true && r["outcome"] == "ok"));
    assert!(rows
        .iter()
        .any(|r| r["h_in"] == h && r["stored"] == false && r["outcome"] == "ok"));
    assert!(rows
        .iter()
        .filter(|r| r["outcome"] == "fail")
        .all(|r| r["reason"] == "store_failed" && r["stored"] == false));
    assert_eq!(rows.iter().filter(|r| r["outcome"] == "fail").count(), 2);
}

/// Old senders look only at `ok:false`; the new bodies for success keep ok true, so nothing that treated an empty 200 as success is broken.
#[test]
fn bodies_are_compatible_with_old_senders() {
    use conet_node::mailbox::DeliverReport;
    use conet_node::store::SaveResult;
    let r = |o| DeliverReport {
        outcome: o,
        fresh: o == SaveResult::Stored,
        push_enqueued: false,
        live_sessions: 0,
    };
    for (o, ok) in [
        (SaveResult::Stored, true),
        (SaveResult::Duplicate, true),
        (SaveResult::Failed, false),
    ] {
        let v = body_json(&r(o).ack_body("0xabc"));
        assert_eq!(v["ok"], ok);
        assert_eq!(
            v.get("h").is_some(),
            ok,
            "no digest is promised for a failure"
        );
    }
}

/// The same vectors file the TS node checks (`hashPgpArmor`): keccak256 over the UTF-8 bytes. Equal results on both sides prove that the `h` a TS mailbox
/// and a Rust mailbox put into the same kind of reply is the same value for the same armor string.
#[test]
fn armor_hash_matches_the_ts_vectors() {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/post_ack_hash_vectors.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let list = v["vectors"].as_array().unwrap();
    assert_eq!(list.len(), 8);
    for e in list {
        assert_eq!(
            armor_hash(e["input"].as_str().unwrap()),
            e["h"].as_str().unwrap()
        );
    }
    assert_eq!(
        armor_hash(""),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

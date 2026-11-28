//! FUNCTIONAL CHECK (not part of the regression run): the real chat-sdk `postArmorOneEntryAtATime` against a local Rust node, nothing leaves this machine.
//! Needs: node, POST_ACK_SDK_DIST (the SDK dist directory), and for the full-volume part POST_ACK_VOLUME. Run: cargo test -p conet-node --test post_ack_sdk -- --ignored --nocapture
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

fn line(case: &str, what: &str, v: impl std::fmt::Debug) {
    println!("SDKCHECK|{case}|{what}|{v:?}");
}

/// The Node driver around the real SDK function: one JSON line in, one JSON line out.
struct Driver {
    child: std::process::Child,
    out: std::io::BufReader<std::process::ChildStdout>,
    n: u64,
}

impl Driver {
    fn start() -> Self {
        let dist = std::env::var("POST_ACK_SDK_DIST")
            .expect("POST_ACK_SDK_DIST: the chat-sdk dist directory");
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/sdk_post_driver.mjs"
        );
        let mut child = std::process::Command::new("node")
            .arg(script)
            .env("POST_ACK_SDK_DIST", dist)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("node");
        let out = std::io::BufReader::new(child.stdout.take().unwrap());
        Self { child, out, n: 0 }
    }
    fn post(&mut self, port: u16, armor: &str) -> Value {
        use std::io::{BufRead, Write};
        self.n += 1;
        let cmd = json!({ "id": self.n, "port": port, "armor": armor });
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{cmd}").unwrap();
        stdin.flush().unwrap();
        let mut l = String::new();
        self.out.read_line(&mut l).unwrap();
        serde_json::from_str(&l).expect("driver reply")
    }
}

impl Driver {
    /// The chat send built and posted by the real SDK (entry wrap + mailbox work + the user armor); returns the SDK's own expected digest.
    fn chat(
        &mut self,
        entry_port: u16,
        entry_key: &str,
        mailbox_key: &str,
        user_key: &str,
        text: &str,
    ) -> Value {
        use std::io::{BufRead, Write};
        self.n += 1;
        let cmd = json!({ "id": self.n, "op": "chat", "port": entry_port, "entryKey": entry_key, "mailboxKey": mailbox_key, "userKey": user_key, "text": text });
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{cmd}").unwrap();
        stdin.flush().unwrap();
        let mut l = String::new();
        self.out.read_line(&mut l).unwrap();
        serde_json::from_str(&l).expect("driver reply")
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A node that answers every post with an empty 200, like an older node.
async fn old_node() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    a
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "functional check with the real SDK: needs node, POST_ACK_SDK_DIST (and POST_ACK_VOLUME for the full-volume part)"]
async fn sdk_new_duplicate_ack_retry_failure_old_node_and_digest() {
    use std::sync::atomic::Ordering;
    let sw = Arc::new(SwitchStore {
        fail: Default::default(),
        inner: MemoryStore::default(),
    });
    let n = start_with(Some(sw.clone())).await;
    let user = pubkey(&n.g, "user");
    let uk = n.user_key.clone();
    let mut d = Driver::start();
    let port = n.b.port();

    // 1 new: the SDK returns ok and the body carries h that equals the client's own expectation
    let m1 = enc(70, "sdk first", &user);
    let h1 = armor_hash(&m1);
    let r = tokio::task::block_in_place(|| d.post(port, &m1));
    line("1 new", "sdk result", &r);
    assert_eq!(r["ok"], true);
    assert_eq!(
        body_json(r["body"].as_str().unwrap()),
        json!({ "ok": true, "stored": true, "h": h1 })
    );
    assert_eq!(sw.pending(&uk).len(), 1);
    // 2 duplicate: the same armor again (the SDK reuses what it is given)
    let r = tokio::task::block_in_place(|| d.post(port, &m1));
    line("2 duplicate", "sdk result", &r);
    assert_eq!(
        (r["ok"].clone(), body_json(r["body"].as_str().unwrap())),
        (
            json!(true),
            json!({ "ok": true, "duplicate": true, "h": h1 })
        )
    );
    assert_eq!(sw.pending(&uk).len(), 1, "one copy");
    // 3 read back and ACK (the real command through the entry); the stored armor is byte for byte the posted one
    assert_eq!(sw.pending(&uk)[0].armor, m1);
    let ack = json!({ "command": "gossip_delivery_ack", "walletAddress": n.g["wallets"]["client"]["address"], "armorHash": h1, "timestamp": now() });
    let (_, b) = post_raw(n.a, &command(&n.g, "client", ack, 71)).await;
    line("3 ack", "reply", &b);
    assert_eq!(body_json(&b)["removed"], true);
    assert_eq!(sw.pending(&uk).len(), 0);
    // 4 retry after the ACK: stored again, not duplicate
    let r = tokio::task::block_in_place(|| d.post(port, &m1));
    line("4 retry after ack", "sdk result", &r);
    assert_eq!(
        body_json(r["body"].as_str().unwrap()),
        json!({ "ok": true, "stored": true, "h": h1 })
    );
    // 5 store failure: the SDK sees {"ok":false,"error":"store_failed"} as an explicit failure and reports ok=false after its attempts
    sw.fail.store(true, Ordering::SeqCst);
    let m2 = enc(72, "sdk fail", &user);
    let h2 = armor_hash(&m2);
    let r = tokio::task::block_in_place(|| d.post(port, &m2));
    line("5 store failure", "sdk result", &r);
    assert_eq!(r["ok"], false);
    assert_eq!(sw.pending(&uk).len(), 1, "nothing was stored");
    // 6 recovery: the SAME armor retried is stored exactly once
    sw.fail.store(false, Ordering::SeqCst);
    let r = tokio::task::block_in_place(|| d.post(port, &m2));
    line("6 retry same armor after recovery", "sdk result", &r);
    assert_eq!(
        body_json(r["body"].as_str().unwrap()),
        json!({ "ok": true, "stored": true, "h": h2 })
    );
    assert_eq!(sw.pending(&uk).len(), 2);
    // 7 an old node's empty 200: the SDK reports ok=true with an empty body: no digest, so the post is unconfirmed (the SDK caller drops the body today)
    let old = old_node().await;
    let r = tokio::task::block_in_place(|| d.post(old.port(), &m1));
    line("7 old node empty 200", "sdk result", &r);
    assert_eq!(
        (r["ok"].clone(), r["body"].as_str().unwrap()),
        (json!(true), "")
    );
    // 9 the REAL chat send (SDK-built user armor, mailbox work, entry wrap) through entry A to mailbox B: the digest the client computes from its own
    // armor (SDK keccakUtf8 of the trimmed user armor) equals the h in the reply, and B stored exactly that string. Line ends: see the flags.
    let g = &n.g;
    let key = |name: &str| {
        g["keys"][name]["armoredPublic"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let r = tokio::task::block_in_place(|| {
        d.chat(
            n.a.port(),
            &key("nodeA"),
            &key("nodeB"),
            &key("user"),
            "sdk chat",
        )
    });
    line(
        "9 real chat send",
        "ok/attempts/userArmorHasCR/userArmorEndsWithNewline",
        (
            &r["ok"],
            &r["attempts"],
            &r["userArmorHasCR"],
            &r["userArmorEndsWithNewline"],
        ),
    );
    line("9 real chat send", "body", &r["body"]);
    assert_eq!(r["ok"], true);
    let expected = r["expectedH"].as_str().unwrap().to_string();
    assert_eq!(
        body_json(r["body"].as_str().unwrap()),
        json!({ "ok": true, "stored": true, "h": expected })
    );
    let ua = r["userArmor"].as_str().unwrap();
    assert_eq!(
        armor_hash(ua.trim()),
        expected,
        "Rust armor_hash and SDK keccakUtf8 agree on the SDK's own armor"
    );
    assert!(
        sw.pending(&uk).iter().any(|s| s.armor == ua.trim()),
        "B stored the trimmed user armor"
    );
    // the same chat armor resent through the real SDK: duplicate with the same digest (a re-encryption would be a new armor)
    // (the driver builds a fresh armor per call, so a resend of the identical armor goes through the plain post above; here only the shape is checked)
    // 10 digest rules in the plain forms (a) onion, (b) mailbox work with CRLF inside `data`, (c) bare armor
    let inner = enc(73, "onion inner", &user);
    let onion = enc(74, &inner, &pubkey(&n.g, "nodeA"));
    let (_, b) = post_raw(n.a, &onion).await;
    line("10a onion via entry", "reply", &b);
    assert_eq!(
        body_json(&b),
        json!({ "ok": true, "stored": true, "h": armor_hash(inner.trim()) })
    );
    assert_ne!(
        armor_hash(inner.trim()),
        armor_hash(&inner.trim().replace('\n', "\r\n")),
        "the CRLF form hashes differently"
    );
    let inner2 = enc(75, "work inner", &user);
    let crlf_inner = format!("{}\r\n", inner2.trim().replace('\n', "\r\n"));
    let work = enc(
        76,
        &json!({ "data": crlf_inner }).to_string(),
        &pubkey(&n.g, "nodeB"),
    );
    let (_, b) = post_raw(n.a, &work).await;
    line("10b mailbox work with CRLF in data", "reply", &b);
    assert_eq!(
        body_json(&b),
        json!({ "ok": true, "stored": true, "h": armor_hash(crlf_inner.trim()) })
    );
    assert_ne!(
        h1,
        armor_hash(m1.trim()),
        "the fixture armor ends with a newline, and the bare post keeps it"
    );
}

/// The write failure on a really full volume, seen by the real SDK. Phase 1 runs in a child process (so that its database handle is released at exit):
/// posts succeed until the volume refuses a write, then the SDK reports ok=false; after space is freed the same process still fails (redb: "A previous IO
/// error occurred. The database must be closed and re-opened"). Phase 2 (this process) re-opens the database, starts a node on it and the real SDK retries
/// the SAME armor: it is stored once, with the digest.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "functional check with the real SDK on a filled volume: needs node, POST_ACK_SDK_DIST and POST_ACK_VOLUME (a small mounted volume this test fills)"]
async fn sdk_on_a_full_volume() {
    let Ok(vol) = std::env::var("POST_ACK_VOLUME") else {
        println!("skipped: set POST_ACK_VOLUME to a small mounted volume");
        return;
    };
    let dir = std::path::Path::new(&vol);
    if std::env::var("POST_ACK_FV_CHILD").is_ok() {
        return full_volume_phase1(dir).await;
    }
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(&exe)
        .args([
            "--exact",
            "sdk_on_a_full_volume",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("POST_ACK_FV_CHILD", "1")
        .output()
        .unwrap();
    for l in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("SDKCHECK"))
    {
        println!("{l}");
    }
    assert!(
        out.status.success(),
        "phase 1 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // phase 2: restart on the same database
    let failed = std::fs::read_to_string(dir.join("failed.armor")).unwrap();
    let store = Arc::new(DiskStore::open(&dir.join("sdk.redb")).unwrap());
    let n = start_with(Some(store.clone())).await;
    let uk = n.user_key.clone();
    let rows = store.pending(&uk).len();
    let mut d = Driver::start();
    let r = tokio::task::block_in_place(|| d.post(n.b.port(), &failed));
    line(
        "full volume phase 2",
        "after restart, retry of the same armor",
        &r,
    );
    // After the restart the armor ends as stored (the failed commit did not reach the file) or duplicate (it did): one copy either way.
    let first = body_json(r["body"].as_str().unwrap());
    let h = armor_hash(&failed);
    assert!(
        first == json!({ "ok": true, "stored": true, "h": h })
            || first == json!({ "ok": true, "duplicate": true, "h": h }),
        "{first}"
    );
    assert_eq!(
        store.pending(&uk).len(),
        if first["stored"] == true {
            rows + 1
        } else {
            rows
        }
    );
    let r = tokio::task::block_in_place(|| d.post(n.b.port(), &failed));
    assert_eq!(
        body_json(r["body"].as_str().unwrap()),
        json!({ "ok": true, "duplicate": true, "h": h })
    );
    line(
        "full volume phase 2",
        "second retry is a duplicate, rows",
        store.pending(&uk).len(),
    );
}

async fn full_volume_phase1(dir: &std::path::Path) {
    let store = Arc::new(DiskStore::open(&dir.join("sdk.redb")).unwrap());
    let n = start_with(Some(store.clone())).await;
    let user = pubkey(&n.g, "user");
    let uk = n.user_key.clone();
    let mut d = Driver::start();
    let port = n.b.port();
    let r = tokio::task::block_in_place(|| d.post(port, &enc(80, "seed", &user)));
    assert_eq!(r["ok"], true);
    {
        use std::io::Write;
        let mut f = std::fs::File::create(dir.join("filler.bin")).unwrap();
        let chunk = [7u8; 512];
        let mut written = 0u64;
        while f.write_all(&chunk).is_ok() {
            written += 512;
        }
        line("full volume", "filler bytes", written);
    }
    let mut ok_posts = 0u32;
    let mut failed: Option<(String, Value)> = None;
    for i in 0..3000u32 {
        let m = enc(100 + (i % 100) as u8, &format!("sdk filler {i}"), &user);
        let r = tokio::task::block_in_place(|| d.post(port, &m));
        if r["ok"] == true {
            ok_posts += 1;
        } else {
            failed = Some((m, r));
            break;
        }
    }
    line(
        "full volume",
        "posts accepted before the first failure",
        ok_posts,
    );
    let (m, r) = failed.expect("the volume never refused a write");
    line("full volume", "sdk result at the first failure", &r);
    assert_eq!(r["ok"], false);
    let rows = store.pending(&uk).len();
    line("full volume", "rows", rows);
    // free space; the same process keeps failing (the database must be re-opened)
    std::fs::remove_file(dir.join("filler.bin")).unwrap();
    let r = tokio::task::block_in_place(|| d.post(port, &m));
    line("full volume", "same process, same armor, space freed", &r);
    assert_eq!(r["ok"], false);
    assert_eq!(store.pending(&uk).len(), rows);
    std::fs::write(dir.join("failed.armor"), &m).unwrap();
}

//! MEASUREMENT (not part of the regression run): what a mailbox answers for a first, a duplicate and a failed store.
//! The real write failure needs a small volume that the test fills: set POST_ACK_VOLUME to its mount point; without it that test skips.
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

fn line(case: &str, what: &str, v: impl std::fmt::Debug) {
    println!("MEASURE|{case}|{what}|{v:?}");
}

/// Cases 1 and 2 at the store/mailbox level (what save and deliver_report return) and at the HTTP level (mailbox direct and through the entry).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement, not regression: run with -- --ignored --nocapture"]
async fn measure_post_ack_semantics() {
    let n = start().await;
    let user = pubkey(&n.g, "user");
    let uk = n.user_key.clone();
    let count = |s: &DiskStore| s.pending(&uk).len();

    // ---- mailbox level, own DiskStore (case 1 first, case 2 duplicate, case 3 failure)
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("unit.redb");
    let store = Arc::new(DiskStore::open(&p).unwrap());
    let mb = Mailbox::new(store.clone(), Arc::new(RecordingPush::default()));
    let m = enc(30, "unit first", &user);
    let h = armor_hash(&m);
    let r1 = mb.deliver_report(&uk, stored(&m));
    line("1 first", "deliver_report", &r1);
    line("1 first", "rows", count(&store));
    let r2 = mb.deliver_report(&uk, stored(&m));
    line("2 duplicate", "deliver_report", &r2);
    line("2 duplicate", "rows", count(&store));
    // a failed store cannot be injected reliably at this level (truncating the file under an open redb handle does not fail the write):
    // see measure_real_write_failure, which fills a small volume
    line("1-3", "armor_hash(m)", &h);

    // ---- HTTP level on the node pair: first / duplicate through entry A and direct on B
    let a1 = enc(40, "http first", &user);
    let (s, b) = post_raw(n.b, &a1).await;
    line("1 first", "B direct status/body", (s, &b));
    line(
        "1 first",
        "classify(B reply)",
        conet_node::deliver::classify(s, b.as_bytes()),
    );
    line("1 first", "rows", n.store_b.pending(&uk).len());
    let (s, b) = post_raw(n.b, &a1).await;
    line("2 duplicate", "B direct status/body", (s, &b));
    line(
        "2 duplicate",
        "classify(B reply)",
        conet_node::deliver::classify(s, b.as_bytes()),
    );
    line("2 duplicate", "rows", n.store_b.pending(&uk).len());
    let a2 = enc(41, "http via entry", &user);
    let (s, b) = post_raw(n.a, &a2).await;
    line("1 first", "via entry A status/body", (s, &b));
    let (s, b) = post_raw(n.a, &a2).await;
    line("2 duplicate", "via entry A status/body", (s, &b));
    line("2 duplicate", "rows", n.store_b.pending(&uk).len());
    tokio::time::sleep(Duration::from_millis(300)).await;
    for r in evrows(&n.ev_b).iter().filter(|r| r["ev"] == "store") {
        line(
            "evidence B store row",
            "h_in/stored/outcome",
            (&r["h_in"], &r["stored"], &r["outcome"]),
        );
    }
    for r in evrows(&n.ev_a).iter().filter(|r| r["ev"] == "post") {
        line(
            "evidence A post row",
            "outcome/forward/h_in",
            (&r["outcome"], &r["forward"], &r["h_in"]),
        );
    }
}

/// Case 3 with a real write failure: the database lives on a small volume that is filled up (ENOSPC), then new distinct armors are posted until the first save
/// fails. The test re-runs itself in a child process so that the node under test starts on the full volume.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement, not regression: needs POST_ACK_VOLUME (a small mounted volume it fills); run with -- --ignored --nocapture"]
async fn measure_real_write_failure() {
    if std::env::var("POST_ACK_CHILD").is_ok() {
        return child_case3().await;
    }
    let g = golden();
    let user = pubkey(&g, "user");
    let uk = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let Ok(vol) = std::env::var("POST_ACK_VOLUME") else {
        println!("skipped: set POST_ACK_VOLUME to a small mounted volume (the test fills it) to measure a real write failure");
        return;
    };
    let p = std::path::Path::new(&vol).join("full.redb");
    {
        let s = Arc::new(DiskStore::open(&p).unwrap());
        let mb = Mailbox::new(s.clone(), Arc::new(RecordingPush::default()));
        let r = mb.deliver_report(&uk, stored(&enc(50, "seed", &user)));
        line("3 failure (setup)", "seed deliver_report", r);
    }
    // fill the volume until the filesystem refuses (ENOSPC)
    {
        use std::io::Write;
        let mut f = std::fs::File::create(std::path::Path::new(&vol).join("filler.bin")).unwrap();
        let chunk = [7u8; 512];
        let mut written = 0u64;
        while f.write_all(&chunk).is_ok() {
            written += 512;
        }
        line(
            "3 failure (setup)",
            "filler bytes written before ENOSPC",
            written,
        );
    }
    let exe = std::env::current_exe().unwrap();
    let cmd = format!(
        "exec '{}' --exact measure_real_write_failure --include-ignored --nocapture --test-threads=1",
        exe.display()
    );
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("POST_ACK_CHILD", "1")
        .env("POST_ACK_DB", &p)
        .output()
        .unwrap();
    for l in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("MEASURE"))
    {
        println!("{l}");
    }
    println!("MEASURE|3 failure (child)|exit|{:?}", out.status.code());
    if !out.status.success() {
        println!(
            "{}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

async fn child_case3() {
    let n = start().await;
    let user = pubkey(&n.g, "user");
    let uk = n.user_key.clone();
    line("3 failure", "rows_before", n.store_b.pending(&uk).len());
    // the volume is full but the database file still has free pages: fill them with distinct messages until a NEW armor is no longer saved
    let mut ok_saves = 0u32;
    let mut first_fail = None;
    for i in 0..3000u32 {
        let m = enc(100 + (i % 100) as u8, &format!("filler {i}"), &user);
        let r = n.mailbox.deliver_report(&uk, stored(&m));
        if r.fresh {
            ok_saves += 1
        } else {
            first_fail = Some((i, r));
            break;
        }
    }
    line(
        "3 failure",
        "distinct new messages saved before the first failure",
        ok_saves,
    );
    line(
        "3 failure",
        "deliver_report at the first failure (a NEW, never seen armor)",
        first_fail,
    );
    line(
        "3 failure",
        "rows_after_mailbox_failure",
        n.store_b.pending(&uk).len(),
    );
    let a3 = enc(52, "http write fails", &user);
    let (s, b) = post_raw(n.b, &a3).await;
    line("3 failure", "B direct status/body", (s, &b));
    line(
        "3 failure",
        "classify(B reply)",
        conet_node::deliver::classify(s, b.as_bytes()),
    );
    let a4 = enc(53, "http write fails via entry", &user);
    let (s, b) = post_raw(n.a, &a4).await;
    line("3 failure", "via entry A status/body", (s, &b));
    line("3 failure", "rows_after_http", n.store_b.pending(&uk).len());
    tokio::time::sleep(Duration::from_millis(300)).await;
    for r in evrows(&n.ev_b).iter().filter(|r| r["ev"] == "store") {
        line(
            "evidence B store row",
            "stored/outcome",
            (&r["stored"], &r["outcome"]),
        );
    }
}

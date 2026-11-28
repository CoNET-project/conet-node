//! A running mailbox node over a database that holds rows it cannot read, or whose reads fail. Expected behaviour: the health line shows it, the readable messages of the
//! same mailbox are still delivered to their owner, an acknowledgement the node cannot carry out is not answered with success, nothing unreadable is removed or
//! overwritten, and a new message that commits locally is accepted. Golden TEST keys, chain replaced by a double, synthetic database.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{armor_hash, DiskStore, MailboxStore, MemoryStore, SaveResult, Stored};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MSGS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("msgs");

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

async fn post(addr: SocketAddr, armor: &str) -> String {
    let mut s = open(addr, armor).await;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .unwrap()
        .ok();
    let t = String::from_utf8_lossy(&out).into_owned();
    t.split("\r\n\r\n")
        .skip(1)
        .collect::<Vec<_>>()
        .join("\r\n\r\n")
}

/// A listen as the client sees it: SSE through the entry, frames opened with the stream key.
struct Listen {
    s: TcpStream,
    key: [u8; 32],
    buf: String,
}

impl Listen {
    async fn connect(n: &Net, seed: u8) -> Self {
        let key = [seed; 32];
        let cmd = json!({ "command": "mailbox_listen", "walletAddress": n.g["wallets"]["client"]["address"], "streamKey": B64.encode(key), "timestamp": now() });
        let s = open(n.a, &command(&n.g, "client", cmd, seed)).await;
        let mut l = Self {
            s,
            key,
            buf: String::new(),
        };
        let hs = l.next().await.expect("handshake");
        assert_eq!(hs["kind"], "mailbox");
        assert_eq!(
            hs["nodeWallet"],
            n.g["wallets"]["nodeB"]["address"]
                .as_str()
                .unwrap()
                .to_lowercase()
        );
        l
    }
    /// Next opened frame, or None after 2 s without one.
    async fn next(&mut self) -> Option<Value> {
        loop {
            let frame = self.buf.find("data: ").and_then(|i| {
                let rest = &self.buf[i + 6..];
                rest.find("\r\n")
                    .map(|end| (rest[..end].to_string(), rest[end..].to_string()))
            });
            if let Some((payload, rest)) = frame {
                self.buf = rest;
                let (json, len) =
                    si_core::open_mailbox(&payload, &self.key).expect("sealed frame opens");
                assert_eq!(len % 256, 0, "padded to 256");
                return Some(serde_json::from_str(&json).unwrap());
            }
            let mut chunk = [0u8; 8192];
            match tokio::time::timeout(Duration::from_secs(2), self.s.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => self.buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
                _ => return None,
            }
        }
    }
}

struct Net {
    g: Value,
    a: SocketAddr,
    health: SocketAddr,
    store: Arc<DiskStore>,
    user_key: String,
}

fn armor(n: usize) -> String {
    format!("-----BEGIN PGP MESSAGE-----\nsynthetic-{n}\n-----END PGP MESSAGE-----")
}

fn item(n: usize) -> Stored {
    Stored {
        armor: armor(n),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Damage {
    None,
    NotJson,
    TextDoesNotMatchHash,
}

fn rows(db: &Path) -> Vec<(u64, Vec<u8>)> {
    let db = Database::open(db).unwrap();
    let t = db.begin_read().unwrap().open_table(MSGS).unwrap();
    t.iter()
        .unwrap()
        .map(|e| {
            let (k, v) = e.unwrap();
            (k.value().1, v.value().to_vec())
        })
        .collect()
}

/// Messages 1, 2 and 3 of the user; the row of message 2 is then damaged. Returns the damaged bytes.
fn prepare(db: &Path, key: &str, how: Damage) -> Vec<u8> {
    let s = DiskStore::open(db).unwrap();
    for n in 1..=3 {
        assert_eq!(s.save_result(key, item(n)), SaveResult::Stored);
    }
    drop(s);
    let (seq, original) = rows(db)[1].clone();
    let bytes = match how {
        Damage::None => return original,
        Damage::NotJson => original[..original.len() / 2].to_vec(),
        Damage::TextDoesNotMatchHash => {
            let mut j: Value = serde_json::from_slice(&original).unwrap();
            j["item"]["armor"] = json!(format!("{}-altered", armor(2)));
            serde_json::to_vec(&j).unwrap()
        }
    };
    let raw = Database::open(db).unwrap();
    let w = raw.begin_write().unwrap();
    w.open_table(MSGS)
        .unwrap()
        .insert((key.to_uppercase().as_str(), seq), bytes.as_slice())
        .unwrap();
    w.commit().unwrap();
    bytes
}

/// Entry A and mailbox B; B keeps its mail in the redb file `db`.
async fn start(db: &Path, how: Damage) -> (Net, Vec<u8>) {
    let g = golden();
    let load = |n: &str| {
        si_core::node::load_route(
            g["keys"][n]["armoredPrivate"].as_str().unwrap(),
            g["keys"][n]["passphrase"].as_str().unwrap(),
        )
        .unwrap()
    };
    let ((ka, ida), (kb, idb)) = (load("nodeA"), load("nodeB"));
    let (la, lb) = (
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    );
    let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
    let user_key = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let damaged = prepare(db, &user_key, how);
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
    ca.user_routes = Some(chain.clone());
    let store = Arc::new(DiskStore::open(db).unwrap());
    let mut cb = NodeCtx::new(
        idb.clone(),
        Arc::new(kb),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        routes(&idb),
        store.clone(),
    );
    cb.user_routes = Some(chain);
    let cb = Arc::new(cb);
    let lh = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health = lh.local_addr().unwrap();
    tokio::spawn(server::serve_health(lh, cb.clone()));
    tokio::spawn(server::serve(la, Arc::new(ca)));
    tokio::spawn(server::serve(lb, cb));
    let n = Net {
        g,
        a: aa,
        health,
        store,
        user_key,
    };
    (n, damaged)
}

async fn healthz(n: &Net) -> String {
    let mut h = TcpStream::connect(n.health).await.unwrap();
    h.write_all(b"GET /healthz HTTP/1.1\r\nHost: l\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    h.read_to_string(&mut out).await.unwrap();
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

async fn ack(n: &Net, hash: &str, seed: u8) -> Value {
    let ack = json!({ "command": "gossip_delivery_ack", "walletAddress": n.g["wallets"]["client"]["address"], "armorHash": hash, "timestamp": now() });
    let r = post(n.a, &command(&n.g, "client", ack, seed)).await;
    serde_json::from_str(&r).unwrap_or(Value::Null)
}

/// What the owner receives from a signed listen.
async fn listen_all(n: &Net, seed: u8) -> Vec<String> {
    let mut l = Listen::connect(n, seed).await;
    let mut out = vec![];
    while let Some(f) = l.next().await {
        out.push(f["data"].as_str().unwrap_or("").to_string());
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn the_health_line_shows_damaged_rows_from_the_start() {
    for how in [Damage::NotJson, Damage::TextDoesNotMatchHash] {
        let d = tempfile::tempdir().unwrap();
        let (n, _) = start(&d.path().join("m.redb"), how).await;
        let h = healthz(&n).await;
        println!("MEASURE healthz={h:?}");
        assert!(
            h.starts_with("ok ") && h.contains("mailbox_damaged=1"),
            "{h}"
        );
    }
    let d = tempfile::tempdir().unwrap();
    let (n, _) = start(&d.path().join("m.redb"), Damage::None).await;
    let h = healthz(&n).await;
    assert!(
        h.contains("mailbox_damaged=0") && h.contains("mailbox_read_errors=0"),
        "{h}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_still_reads_the_other_messages_and_never_an_altered_one() {
    for how in [Damage::NotJson, Damage::TextDoesNotMatchHash] {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("m.redb");
        let (n, damaged) = start(&db, how).await;
        let got = listen_all(&n, 1).await;
        println!("MEASURE owner listen received {got:?}");
        assert_eq!(got, vec![armor(1), armor(3)]);
        drop(n);
        let _ = (damaged, db);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_the_node_cannot_carry_out_is_not_a_success() {
    let d = tempfile::tempdir().unwrap();
    let (n, _) = start(&d.path().join("m.redb"), Damage::NotJson).await;
    let r = ack(&n, &armor_hash(&armor(2)), 20).await;
    println!("MEASURE ack of the message in the damaged row -> {r}");
    assert_eq!(r, json!({ "ok": false, "error": "store_failed" }));
    // a readable message of the same mailbox is acknowledged as usual
    let r = ack(&n, &armor_hash(&armor(1)), 21).await;
    assert_eq!(r, json!({ "ok": true, "removed": true }));
    // and a new message that commits locally is accepted
    assert_eq!(
        n.store.save_result(&n.user_key, item(4)),
        SaveResult::Stored
    );
    assert_eq!(listen_all(&n, 2).await, vec![armor(3), armor(4)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_unreadable_row_is_never_removed_or_overwritten() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("m.redb");
    let damaged;
    let key;
    {
        let rt_db = db.clone();
        key = golden()["keys"]["user"]["encKeyId"]
            .as_str()
            .unwrap()
            .to_string();
        damaged = prepare(&rt_db, &key, Damage::NotJson);
    }
    {
        let s = DiskStore::open(&db).unwrap();
        assert_eq!(s.pending(&key).len(), 2);
        s.remove_by_hash(&key, &armor_hash(&armor(1)));
        s.remove_by_hash(&key, &armor_hash(&armor(2)));
        s.remove_by_hash(&key, &armor_hash(&armor(3)));
        for n in 2..=5 {
            s.save_result(&key, item(n));
        }
    }
    assert!(
        rows(&db).iter().any(|(_, v)| *v == damaged),
        "the unreadable row changed or is gone"
    );
}

#[cfg(feature = "test-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_under_a_read_error_is_not_a_success_and_the_error_is_visible() {
    let d = tempfile::tempdir().unwrap();
    let (n, _) = start(&d.path().join("m.redb"), Damage::None).await;
    n.store.fail_reads_for(&n.user_key, 0, 1);
    let r = ack(&n, &armor_hash(&armor(1)), 30).await;
    let h = healthz(&n).await;
    println!("MEASURE ack under a read error -> {r}; healthz={h:?}");
    assert_eq!(r, json!({ "ok": false, "error": "store_failed" }));
    assert!(h.contains("mailbox_read_errors=1"), "{h}");
    assert_eq!(listen_all(&n, 3).await.len(), 3, "nothing was removed");
}

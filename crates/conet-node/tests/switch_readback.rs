//! Mail accepted before a switch and not yet acknowledged must be readable by its owner afterwards, one by one. Synthetic TS mailbox files, the real binary for the import,
//! the export and the digests, and the owner's signed listen against a mailbox node built from this library over the imported database (chain replaced by a double; a
//! "restart" is a new node and a new runtime over the same file, not a new process). The rollback direction is checked on the TS files; no TS node runs here.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{armor_hash, DiskStore, MemoryStore};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
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
}

/// Runs one life of the node over `db`; everything it started is gone (and the file released) when this returns.
fn node_life<T>(
    db: &Path,
    f: impl for<'a> FnOnce(&'a Net) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>,
) -> T {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = rt.block_on(async {
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
        let chain: Arc<dyn UserRoutes> = Arc::new(Chain {
            user_key: user_key(&g),
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
        let store = Arc::new(DiskStore::open_installed(db).expect("the node opens its database"));
        let mut cb = NodeCtx::new(
            idb.clone(),
            Arc::new(kb),
            Arc::new(wallet(&g, "nodeB")),
            Arc::new(wallet(&g, "nodeB")),
            routes(&idb),
            store,
        );
        cb.user_routes = Some(chain);
        tokio::spawn(server::serve(la, Arc::new(ca)));
        tokio::spawn(server::serve(lb, Arc::new(cb)));
        let net = Net { g, a: aa };
        f(&net).await
    });
    rt.shutdown_timeout(Duration::from_secs(5));
    out
}

fn user_key(g: &Value) -> String {
    g["keys"]["user"]["encKeyId"]
        .as_str()
        .unwrap()
        .to_uppercase()
}

fn armor(tag: &str) -> String {
    format!("-----BEGIN PGP MESSAGE-----\nsynthetic-{tag}\n-----END PGP MESSAGE-----")
}

/// Count and content hashes of what the owner's signed listen delivers, in the order of arrival.
fn owner_reads(db: &Path, seed: u8) -> Vec<String> {
    node_life(db, |n| {
        Box::pin(async move {
            let mut l = Listen::connect(n, seed).await;
            let mut out = vec![];
            while let Some(f) = l.next().await {
                out.push(armor_hash(f["data"].as_str().unwrap()));
            }
            out
        })
    })
}

fn hashes(tags: &[&str]) -> Vec<String> {
    tags.iter().map(|t| armor_hash(&armor(t))).collect()
}

fn same_set_each_once(got: &[String], want: &[String], what: &str) {
    println!(
        "MEASURE {what}: found {} message(s), expected {}",
        got.len(),
        want.len()
    );
    assert_eq!(got.len(), want.len(), "{what}: count");
    let g: BTreeSet<&String> = got.iter().collect();
    assert_eq!(g.len(), got.len(), "{what}: a message was delivered twice");
    assert_eq!(g, want.iter().collect::<BTreeSet<_>>(), "{what}: content");
}

fn cli(args: &[&str]) -> String {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_conet-node"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "{:?}: {}",
        args[0],
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn live_ts(dir: &Path, key: &str) -> Vec<String> {
    let mut out = vec![];
    for name in [format!("{key}.inflight.json"), format!("{key}.json")] {
        if let Ok(b) = std::fs::read(dir.join(name)) {
            let list: Vec<String> = serde_json::from_slice(&b).unwrap();
            out.extend(list.iter().map(|a| armor_hash(a)));
        }
    }
    out
}

fn post_new(db: &Path, tag: &str) -> String {
    node_life(db, |n| {
        let tag = tag.to_string();
        Box::pin(async move {
            // a new message arrives the way a sender posts it: encrypted to the owner, through the other node
            let sent = enc(90, &tag, &pubkey(&n.g, "user"));
            let reply = post(n.a, &sent).await;
            let v: Value = serde_json::from_str(&reply).unwrap_or(Value::Null);
            assert!(v["ok"] == true && v["stored"] == true, "{reply}");
            // the hash the node answered with is the one the owner's copy must have
            v["h"].as_str().unwrap().to_string()
        })
    })
}

fn ack(db: &Path, hash: &str) {
    let hash = hash.to_string();
    node_life(db, |n| {
        Box::pin(async move {
            let c = json!({ "command": "gossip_delivery_ack", "walletAddress": n.g["wallets"]["client"]["address"], "armorHash": hash, "timestamp": now() });
            let r = post(n.a, &command(&n.g, "client", c, 70)).await;
            assert_eq!(
                serde_json::from_str::<Value>(&r).unwrap(),
                json!({ "ok": true, "removed": true })
            );
        })
    })
}

#[test]
fn unacknowledged_mail_is_read_back_by_its_owner_after_the_switch_and_kept_for_the_rollback() {
    let d = tempfile::tempdir().unwrap();
    let (ts, db) = (d.path().join(".data"), d.path().join("mailbox.redb"));
    std::fs::create_dir_all(&ts).unwrap();
    let key = user_key(&golden());
    let write = |name: String, tags: &[&str]| {
        let list: Vec<String> = tags.iter().map(|t| armor(t)).collect();
        std::fs::write(ts.join(name), serde_json::to_string(&list).unwrap()).unwrap();
    };
    // TS has stopped writing: five messages of the owner (one listed in both files) and one of another key
    write(format!("{key}.inflight.json"), &["a1", "a2"]);
    write(format!("{key}.json"), &["a2", "a3", "a4", "a5"]);
    write("FEDCBA9876543210.json".into(), &["b1"]);
    let (t, s) = (ts.to_str().unwrap(), db.to_str().unwrap());
    let ts_digest = cli(&["--ts-mailbox-digest", t]);
    println!("MEASURE {ts_digest}");
    println!(
        "MEASURE {}",
        cli(&["--import-ts-mailbox", t, "--mailbox-db", s])
    );
    let db_digest = cli(&["--mailbox-digest", "--mailbox-db", s]);
    assert_eq!(
        ts_digest.replace("ts-mailbox-digest", ""),
        db_digest.replace("mailbox-digest", "")
    );

    let before = hashes(&["a1", "a2", "a3", "a4", "a5"]);
    same_set_each_once(&owner_reads(&db, 1), &before, "after the switch");
    same_set_each_once(
        &owner_reads(&db, 2),
        &before,
        "after a restart, nothing acknowledged",
    );
    ack(&db, &before[0]);
    let new = post_new(&db, "n1");
    let mut now_pending = before[1..].to_vec();
    now_pending.push(new);
    same_set_each_once(
        &owner_reads(&db, 3),
        &now_pending,
        "after one acknowledgement and one new message",
    );

    // rollback: node stopped, export
    let report = cli(&["--export-ts-mailbox", t, "--mailbox-db", s]);
    println!("MEASURE {report}");
    assert!(report.contains("failed_keys=0 skipped_keys=0"), "{report}");
    same_set_each_once(
        &live_ts(&ts, &key),
        &now_pending,
        "TS files after the rollback export",
    );
    assert_eq!(live_ts(&ts, "FEDCBA9876543210"), hashes(&["b1"]));
}

/// A database written by an earlier build, given by the environment (see the review notes for how it is produced): after the preparation step of this build adopts it,
/// the owner reads every message once. `OLD_MAILBOX_DB` is the file, `OLD_MAILBOX_TAGS` the space separated message tags the writer used.
#[test]
#[ignore = "needs a database written by an earlier build"]
fn mail_in_a_database_of_an_earlier_build_is_read_back_by_its_owner() {
    let source = std::env::var("OLD_MAILBOX_DB").expect("OLD_MAILBOX_DB");
    let tags = std::env::var("OLD_MAILBOX_TAGS").expect("OLD_MAILBOX_TAGS");
    let want = hashes(&tags.split_whitespace().collect::<Vec<_>>());
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("mailbox.redb");
    std::fs::copy(&source, &db).unwrap();
    let out = cli(&[
        "--prepare-mailbox-db",
        "--mailbox-db",
        db.to_str().unwrap(),
        "--mailbox-marker",
        d.path().join("mailbox.installed").to_str().unwrap(),
    ]);
    assert!(out.contains("Adopted"), "{out}");
    println!(
        "MEASURE {}",
        cli(&["--mailbox-digest", "--mailbox-db", db.to_str().unwrap()])
    );
    same_set_each_once(&owner_reads(&db, 4), &want, "database of an earlier build");
    same_set_each_once(&owner_reads(&db, 5), &want, "the same after a restart");
}

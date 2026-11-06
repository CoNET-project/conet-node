//! Stage A2 end-to-end: client → entry A → mailbox B, golden TEST keys, chain replaced by a double.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::mailbox::Mailbox;
use conet_node::push::{Push, VoiceCall};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{armor_hash, MailboxStore, MemoryStore};
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
    store_b: Arc<MemoryStore>,
    user_key: String,
    health: SocketAddr,
}

async fn start() -> Net {
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
    ca.user_routes = Some(chain.clone());
    let store_b = Arc::new(MemoryStore::default());
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
    cb.push = push.clone();
    cb.mailbox = Arc::new(Mailbox::new(store_b.clone(), push.clone()));
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
        user_key,
        health,
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

#[tokio::test(flavor = "multi_thread")]
async fn live_offline_ack_and_queries() {
    let n = start().await;
    let user = pubkey(&n.g, "user");

    // live delivery through entry A to the listen on B
    let mut l = Listen::connect(&n, 1).await;
    let m1 = enc(10, "first", &user);
    assert_eq!(post(n.a, &m1).await, "");
    assert_eq!(l.next().await.unwrap()["data"], m1);
    assert_eq!(
        n.push.offline.lock().unwrap().as_slice(),
        std::slice::from_ref(&n.user_key),
        "push after durable save"
    );

    // presence while listening (asked by another wallet)
    let q = json!({ "command": "wallet_online_query", "walletAddress": n.g["wallets"]["other"]["address"], "targetWallet": n.g["wallets"]["client"]["address"], "timestamp": now() });
    let r: Value = serde_json::from_str(&post(n.a, &command(&n.g, "other", q, 20)).await).unwrap();
    assert_eq!(r["online"], true);
    assert_eq!(
        r["nodeWallet"],
        n.g["wallets"]["nodeB"]["address"]
            .as_str()
            .unwrap()
            .to_lowercase()
    );

    // offline: the listen goes away, a NoPush work item arrives, then the client listens again
    drop(l);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let m2 = enc(11, "second", &user);
    let work = enc(
        12,
        &json!({ "data": m2, "NoPush": true }).to_string(),
        &pubkey(&n.g, "nodeB"),
    );
    assert_eq!(post(n.a, &work).await, "");
    assert_eq!(
        n.push.offline.lock().unwrap().len(),
        1,
        "NoPush skips the push"
    );
    let mut l2 = Listen::connect(&n, 2).await;
    let got: Vec<Value> = vec![
        l2.next().await.unwrap()["data"].clone(),
        l2.next().await.unwrap()["data"].clone(),
    ];
    assert_eq!(
        got,
        [json!(m1), json!(m2.trim_end())],
        "both unacked messages flushed in order"
    );

    // ACK the first one; a new listen only gets the second
    let ack = json!({ "command": "gossip_delivery_ack", "walletAddress": n.g["wallets"]["client"]["address"], "armorHash": armor_hash(&m1), "timestamp": now() });
    let r: Value =
        serde_json::from_str(&post(n.a, &command(&n.g, "client", ack, 21)).await).unwrap();
    assert_eq!(r, json!({ "ok": true, "removed": true }));
    drop(l2);
    let mut l3 = Listen::connect(&n, 3).await;
    assert_eq!(l3.next().await.unwrap()["data"], m2.trim_end());
    assert!(l3.next().await.is_none());
    assert_eq!(n.store_b.pending(&n.user_key).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn wake_query_device_register_and_route_checks() {
    let n = start().await;
    let client = n.g["wallets"]["client"]["address"].as_str().unwrap();
    let other = n.g["wallets"]["other"]["address"].as_str().unwrap();

    let q = json!({ "command": "wallet_native_wake_query", "walletAddress": other, "targetWallet": client, "timestamp": now() });
    let r: Value = serde_json::from_str(&post(n.a, &command(&n.g, "other", q, 30)).await).unwrap();
    assert_eq!(
        r,
        json!({ "ok": true, "wallet": client.to_lowercase(), "nativeWakeable": true })
    );

    // a wallet whose mailbox is elsewhere
    let q = json!({ "command": "wallet_online_query", "walletAddress": client, "targetWallet": other, "timestamp": now() });
    let r: Value = serde_json::from_str(&post(n.a, &command(&n.g, "client", q, 31)).await).unwrap();
    assert_eq!(r["error"], "not_my_route");

    // stale timestamp
    let q = json!({ "command": "wallet_online_query", "walletAddress": other, "targetWallet": client, "timestamp": now() - 3600 });
    let r: Value = serde_json::from_str(&post(n.a, &command(&n.g, "other", q, 32)).await).unwrap();
    assert_eq!(r["error"], "timestamp");

    let reg = json!({ "command": "push_device_register", "walletAddress": client, "deviceToken": "tok", "platform": "ios", "bundleId": "app.test", "registrationSignature": "0xsig", "timestamp": now() });
    let r: Value =
        serde_json::from_str(&post(n.a, &command(&n.g, "client", reg, 33)).await).unwrap();
    assert_eq!(r, json!({ "ok": true }));
    assert_eq!(n.push.devices.lock().unwrap()[0]["platform"], "ios");

    // unknown user key: no route (and A asks the chain double only once per minute)
    let stranger = enc(34, "x", &pubkey(&n.g, "user2"));
    assert!(post(n.a, &stranger).await.contains("no_route"));
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_chat_listen_marks_online_and_health_reports_it() {
    let n = start().await;
    let client = n.g["wallets"]["client"]["address"].as_str().unwrap();
    let other = n.g["wallets"]["other"]["address"].as_str().unwrap();
    let cmd = json!({ "command": "mining", "listenKind": "chat", "walletAddress": client });
    let mut legacy = open(n.a, &command(&n.g, "client", cmd, 40)).await;
    let mut buf = [0u8; 4096];
    let k = tokio::time::timeout(Duration::from_secs(5), legacy.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..k]).to_string();
    assert!(
        head.contains("text/event-stream") && head.contains("\"status\":200"),
        "{head}"
    );

    let q = json!({ "command": "wallet_online_query", "walletAddress": other, "targetWallet": client, "timestamp": now() });
    let r: Value = serde_json::from_str(&post(n.a, &command(&n.g, "other", q, 41)).await).unwrap();
    assert_eq!(r["online"], true, "legacy listen counts as online");

    // plain `mining` (no chat label) is not served
    let cmd = json!({ "command": "mining", "walletAddress": client });
    assert!(post(n.a, &command(&n.g, "client", cmd, 42))
        .await
        .contains("404 Not Found"));

    let mut h = TcpStream::connect(n.health).await.unwrap();
    h.write_all(b"GET /healthz HTTP/1.1\r\nHost: l\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    h.read_to_string(&mut out).await.unwrap();
    assert!(
        out.contains("ok ") && out.contains("nodes=2") && out.contains("listens=1"),
        "{out}"
    );

    drop(legacy);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let q = json!({ "command": "wallet_online_query", "walletAddress": other, "targetWallet": client, "timestamp": now() });
    let r: Value = serde_json::from_str(&post(n.a, &command(&n.g, "other", q, 43)).await).unwrap();
    assert_eq!(r["online"], false);
}

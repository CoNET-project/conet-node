//! Mailbox authorisation: listening and acknowledging need the mailbox owner's signature; a paying wallet may sign the message when the owner has signed
//! the statement for that exact message. Golden TEST wallets, chain replaced by a double.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::evidence::EvidenceLog;
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
    b_key: String,
    ev_a: std::path::PathBuf,
    ev_b: std::path::PathBuf,
    _dir: tempfile::TempDir,
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
    let dir = tempfile::tempdir().unwrap();
    let (ev_a, ev_b) = (dir.path().join("a.jsonl"), dir.path().join("b.jsonl"));
    ca.user_routes = Some(chain.clone());
    ca.evidence = Some(Arc::new(EvidenceLog::open(&ev_a, &ida).unwrap()));
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
    cb.evidence = Some(Arc::new(EvidenceLog::open(&ev_b, &idb).unwrap()));
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
        b_key: idb.clone(),
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

/// Like `command`, with the owner's signature over the statement for this exact message (the delegated-payment form).
fn command_owned(g: &Value, payer: &str, owner: &str, cmd: Value, seed: u8) -> String {
    let message = cmd.to_string();
    let sig = wallet(g, payer).sign_message(&message).unwrap();
    let proof = wallet(g, owner)
        .sign_message(&si_proto::owner_statement(&si_crypto::eth::keccak_hex(
            &message,
        )))
        .unwrap();
    enc(
        seed,
        &B64.encode(
            json!({ "message": message, "signMessage": sig, "ownerSignature": proof }).to_string(),
        ),
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

/// A mailbox_listen for `owner_addr`, signed by `signer`; `owner_proof` adds the owner's signature (delegated payment).
async fn listen_for(
    n: &Net,
    signer: &str,
    owner_addr: &Value,
    delegated: Option<&str>,
    seed: u8,
) -> Option<Listen> {
    let key = [seed; 32];
    let mut cmd = json!({ "command": "mailbox_listen", "walletAddress": owner_addr, "streamKey": B64.encode(key), "timestamp": now() });
    let armor = match delegated {
        Some(owner) => {
            cmd["billingWallet"] = n.g["wallets"][signer]["address"].clone();
            command_owned(&n.g, signer, owner, cmd, seed)
        }
        None => command(&n.g, signer, cmd, seed),
    };
    let s = open(n.a, &armor).await;
    let mut l = Listen {
        s,
        key,
        buf: String::new(),
    };
    let hs = l.next().await?;
    (hs["kind"] == "mailbox").then_some(l)
}

fn ack_cmd(n: &Net, owner_addr: &Value, hash: &str, billing: Option<&str>) -> Value {
    let mut c = json!({ "command": "gossip_delivery_ack", "walletAddress": owner_addr, "armorHash": hash, "timestamp": now() });
    if let Some(b) = billing {
        c["billingWallet"] = n.g["wallets"][b]["address"].clone();
    }
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_and_ack_belong_to_the_mailbox_owner() {
    let n = start().await;
    let user = pubkey(&n.g, "user");
    let owner = n.g["wallets"]["client"]["address"].clone();
    let m1 = enc(10, "for the owner", &user);
    let _ = post(n.a, &m1).await;
    assert_eq!(n.store_b.pending(&n.user_key).len(), 1);
    // listen and acknowledge need the owner's signature: a message signed by another wallet is not accepted (with or without a billing field)
    assert!(listen_for(&n, "other", &owner, None, 1).await.is_none());
    let mut payer_cmd = json!({ "command": "mailbox_listen", "walletAddress": owner, "streamKey": B64.encode([2u8; 32]), "timestamp": now(), "billingWallet": n.g["wallets"]["other"]["address"] });
    let s = open(n.a, &command(&n.g, "other", payer_cmd.take(), 2)).await;
    let mut l = Listen {
        s,
        key: [2u8; 32],
        buf: String::new(),
    };
    assert!(
        l.next().await.is_none(),
        "no handshake without the owner's signature"
    );
    let h = armor_hash(&m1);
    let _ = post(
        n.a,
        &command(&n.g, "other", ack_cmd(&n, &owner, &h, None), 20),
    )
    .await;
    let _ = post(
        n.a,
        &command(&n.g, "other", ack_cmd(&n, &owner, &h, Some("other")), 21),
    )
    .await;
    assert_eq!(
        n.store_b.pending(&n.user_key).len(),
        1,
        "the original message is unchanged"
    );
    // the owner still gets the message and acknowledges it
    let mut lo = listen_for(&n, "client", &owner, None, 3)
        .await
        .expect("the owner listens");
    assert_eq!(lo.next().await.unwrap()["data"], m1);
    let r: Value = serde_json::from_str(
        &post(
            n.a,
            &command(&n.g, "client", ack_cmd(&n, &owner, &h, None), 22),
        )
        .await,
    )
    .unwrap();
    assert_eq!(r["removed"], true);
    assert_eq!(n.store_b.pending(&n.user_key).len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn delegated_payment_works_with_the_owner_signature() {
    let n = start().await;
    let user = pubkey(&n.g, "user");
    let owner = n.g["wallets"]["client"]["address"].clone();
    let m1 = enc(11, "delegated", &user);
    let _ = post(n.a, &m1).await;
    // the payer signs, the owner authorises this exact message
    let mut l = listen_for(&n, "other", &owner, Some("client"), 4)
        .await
        .expect("delegated listen");
    assert_eq!(l.next().await.unwrap()["data"], m1);
    let h = armor_hash(&m1);
    let ack = ack_cmd(&n, &owner, &h, Some("other"));
    let r: Value =
        serde_json::from_str(&post(n.a, &command_owned(&n.g, "other", "client", ack, 23)).await)
            .unwrap();
    assert_eq!(r["removed"], true);
    // a proof by another wallet, or one made for another message, is refused
    let m2 = enc(12, "second", &user);
    let _ = post(n.a, &m2).await;
    let h2 = armor_hash(&m2);
    let r = post(
        n.a,
        &command_owned(
            &n.g,
            "other",
            "nodeA",
            ack_cmd(&n, &owner, &h2, Some("other")),
            24,
        ),
    )
    .await;
    assert!(!r.contains("removed"), "{r}");
    assert_eq!(n.store_b.pending(&n.user_key).len(), 1);
}

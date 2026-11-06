//! M2 line C end-to-end: client → entry E → voice relay R, golden TEST keys.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::mailbox::Mailbox;
use conet_node::push::{Push, VoiceCall};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{MailboxStore, MemoryStore};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
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

struct Chain {
    user_key: String,
    relay_key: String,
    user_wallet: String,
}
impl UserRoutes for Chain {
    fn route_of_user_key<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(k.eq_ignore_ascii_case(&self.user_key)
                .then(|| self.relay_key.clone()))
        })
    }
    fn user_key_of_wallet<'a>(
        &'a self,
        _w: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async { Ok(None) })
    }
    fn wallet_of_user_key<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(k.eq_ignore_ascii_case(&self.user_key)
                .then(|| self.user_wallet.clone()))
        })
    }
    fn is_my_route<'a>(&'a self, _u: &'a str, _n: &'a str) -> BoxFut<'a, Result<bool, ChainError>> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Default)]
struct Calls(Mutex<Vec<VoiceCall>>);
impl Push for Calls {
    fn voice_call(&self, c: VoiceCall) {
        self.0.lock().unwrap().push(c);
    }
    fn offline_chat(&self, _k: String) {}
    fn native_wakeable<'a>(&'a self, _e: &'a str) -> BoxFut<'a, Option<bool>> {
        Box::pin(async { None })
    }
    fn register_device(&self, _p: Value) {}
}

struct Net {
    g: Value,
    entry: SocketAddr,
    relay_store: Arc<MemoryStore>,
    calls: Arc<Calls>,
}

async fn start() -> Net {
    let g = golden();
    let load = |n: &str| {
        si_core::node::load_route(
            g["keys"][n]["armoredPrivate"].as_str().unwrap(),
            g["keys"][n]["passphrase"].as_str().unwrap(),
        )
        .unwrap()
    };
    let ((kr, idr), (ke, ide)) = (load("nodeA"), load("nodeB"));
    let (lr, le) = (
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    );
    let (ar, ae) = (lr.local_addr().unwrap(), le.local_addr().unwrap());
    let user_key = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(600));
        r.replace_nodes([(idr.clone(), ar), (ide.clone(), ae)]);
        Arc::new(r)
    };
    let relay_store = Arc::new(MemoryStore::default());
    let calls = Arc::new(Calls::default());
    let mut cr = NodeCtx::new(
        idr.clone(),
        Arc::new(kr),
        Arc::new(wallet(&g, "nodeA")),
        Arc::new(wallet(&g, "nodeA")),
        routes(&idr),
        relay_store.clone(),
    );
    cr.user_routes = Some(Arc::new(Chain {
        user_key,
        relay_key: idr.clone(),
        user_wallet: g["wallets"]["client"]["address"]
            .as_str()
            .unwrap()
            .to_lowercase(),
    }));
    cr.push = calls.clone();
    cr.mailbox = Arc::new(Mailbox::new(relay_store.clone(), calls.clone()));
    let ce = NodeCtx::new(
        ide.clone(),
        Arc::new(ke),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        routes(&ide),
        Arc::new(MemoryStore::default()),
    );
    tokio::spawn(server::serve(lr, Arc::new(cr)));
    tokio::spawn(server::serve(le, Arc::new(ce)));
    Net {
        g,
        entry: ae,
        relay_store,
        calls,
    }
}

fn rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    ChaCha20Rng::from_seed(seed)
}

/// Unsigned voice command → base64 JSON encrypted to the relay (nodeA), as the SDKs send it.
fn voice_cmd(g: &Value, cmd: &Value) -> String {
    opgp::encrypt(
        rng(),
        B64.encode(cmd.to_string()).as_bytes(),
        &pubkey(g, "nodeA"),
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap()
}

fn listen_cmd(g: &Value, session: &str, wk: &[u8; 32], temp: &str) -> Value {
    let wk = B64.encode(wk);
    let ts = now();
    let relay = g["keys"]["nodeA"]["encKeyId"].as_str().unwrap();
    let temp_w = wallet(g, temp);
    let temp_sig = temp_w
        .sign_message(&si_proto::voice_listen_text(session, &wk, relay, ts as u64))
        .unwrap();
    let not_after = ts + 3600;
    let pay_sig = wallet(g, "payer")
        .sign_message(&si_proto::voice_pay_text(
            &temp_w.address(),
            not_after as u64,
            0,
            0,
        ))
        .unwrap();
    json!({ "command": "voice_listen", "v": 3, "sessionId": session, "wk": wk, "timestamp": ts, "temp": temp_w.address(), "tempSig": temp_sig,
            "pay": { "payer": wallet(g, "payer").address(), "notAfter": not_after, "maxBytes": 0, "maxSeconds": 0, "sig": pay_sig } })
}

fn chunk(g: &Value, session: &str, wk: &[u8; 32], blob: &[u8]) -> String {
    let loc = hex::decode(session).unwrap();
    let mut c = si_proto::VOICE_CHUNK_MAGIC.to_vec();
    c.extend_from_slice(&loc);
    c.extend_from_slice(&si_crypto::sym::chunk_mac(wk, &loc, blob));
    c.extend_from_slice(blob);
    opgp::encrypt(
        rng(),
        &c,
        &pubkey(g, "nodeA"),
        opgp::EncryptOpts {
            text: false,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap()
}

async fn open(addr: SocketAddr, armor: &str) -> TcpStream {
    let body = json!({ "data": armor }).to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!(
            "POST /post HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    s
}

async fn post(addr: SocketAddr, armor: &str) -> Value {
    let mut s = open(addr, armor).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    let t = String::from_utf8_lossy(&out).into_owned();
    serde_json::from_str(t.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap_or(Value::Null)
}

async fn read_some(s: &mut TcpStream, buf: &mut String, want: &str) -> bool {
    let mut chunk = [0u8; 16384];
    while !buf.contains(want) {
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
            _ => return false,
        }
    }
    true
}

fn session() -> (String, [u8; 32]) {
    let mut wk = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut wk);
    (conet_node::voice::random_session_id(), wk)
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_relays_chunks_in_order_and_refuses_bad_ones() {
    let n = start().await;
    let (sid, wk) = session();
    let mut l = open(
        n.entry,
        &voice_cmd(&n.g, &listen_cmd(&n.g, &sid, &wk, "temp")),
    )
    .await;
    let mut buf = String::new();
    let ready =
        si_proto::voice::ready_frame(&sid, n.g["wallets"]["nodeA"]["address"].as_str().unwrap());
    assert!(read_some(&mut l, &mut buf, &ready).await, "{buf}");
    assert!(
        buf.starts_with(si_proto::voice::SSE_HEADERS),
        "SI headers byte for byte: {buf}"
    );

    for i in 0..3u8 {
        assert_eq!(
            post(n.entry, &chunk(&n.g, &sid, &wk, &[i; 50])).await,
            json!({ "ok": true })
        );
    }
    for i in 0..3u8 {
        assert!(
            read_some(
                &mut l,
                &mut buf,
                &si_proto::voice::chunk_frame(&B64.encode([i; 50]))
            )
            .await,
            "chunk {i}"
        );
    }
    let order: Vec<usize> = (0..3u8)
        .map(|i| {
            buf.find(&si_proto::voice::chunk_frame(&B64.encode([i; 50])))
                .unwrap()
        })
        .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "in order");

    let wrong = [9u8; 32];
    assert_eq!(
        post(n.entry, &chunk(&n.g, &sid, &wrong, b"x")).await["error"],
        "voice_chunk_auth"
    );
    let (other, _) = session();
    assert_eq!(
        post(n.entry, &chunk(&n.g, &other, &wk, b"x")).await["error"],
        "target_voice_session_not_found"
    );
    assert_eq!(
        post(n.entry, &chunk(&n.g, &sid, &wk, &vec![1u8; 9001])).await["error"],
        "invalid_voice_chunk"
    );

    // same temp wallet for another session while valid; same session again
    let (sid2, wk2) = session();
    assert_eq!(
        post(
            n.entry,
            &voice_cmd(&n.g, &listen_cmd(&n.g, &sid2, &wk2, "temp"))
        )
        .await["error"],
        "voice_temp_reused"
    );
    assert_eq!(
        post(
            n.entry,
            &voice_cmd(&n.g, &listen_cmd(&n.g, &sid, &wk, "other"))
        )
        .await["error"],
        "session_conflict"
    );

    // unlisten ends the stream
    assert_eq!(
        post(
            n.entry,
            &voice_cmd(
                &n.g,
                &json!({ "command": "voice_unlisten", "sessionId": sid })
            )
        )
        .await,
        json!({ "ok": true, "sessionId": sid })
    );
    let mut rest = Vec::new();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), l.read_to_end(&mut rest))
            .await
            .is_ok(),
        "stream closed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn chunk_rate_limit() {
    let n = start().await;
    let (sid, wk) = session();
    let mut l = open(
        n.entry,
        &voice_cmd(&n.g, &listen_cmd(&n.g, &sid, &wk, "billing")),
    )
    .await;
    let mut buf = String::new();
    assert!(read_some(&mut l, &mut buf, "voice_ready").await);
    // 7,000-byte chunks: the 86th exceeds 600,000 bytes within one second
    let armors: Vec<String> = (0..90)
        .map(|_| chunk(&n.g, &sid, &wk, &vec![7u8; 7000]))
        .collect();
    let mut limited = 0;
    for a in &armors {
        if post(n.entry, a).await["error"] == "voice_chunk_rate" {
            limited += 1;
        }
    }
    assert!(limited >= 1, "rate limit hit");
}

#[tokio::test(flavor = "multi_thread")]
async fn offers_store_deliver_push_and_fetch() {
    let n = start().await;
    let offer = opgp::encrypt(
        rng(),
        b"offer for the callee",
        &pubkey(&n.g, "user"),
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap();
    let exp = now() * 1000 + 120_000;
    let store = json!({ "command": "voice_offer_store", "callId": "call-abcdef01", "sessionId": "0123456789abcdef0123", "offerArmor": offer, "expiresAt": exp, "push": 1, "pushTimestamp": now() });
    let r = post(n.entry, &voice_cmd(&n.g, &store)).await;
    assert_eq!(
        r,
        json!({ "ok": true, "callId": "call-abcdef01", "sessionId": "0123456789abcdef0123", "delivered": true, "pushed": true })
    );
    let user = n.g["keys"]["user"]["encKeyId"].as_str().unwrap();
    let saved = n.relay_store.pending(user);
    assert_eq!(saved.len(), 1);
    assert!(saved[0].no_push, "offer stored without a chat push");
    let calls = n.calls.0.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].callee_eoa,
        n.g["wallets"]["client"]["address"]
            .as_str()
            .unwrap()
            .to_lowercase()
    );

    let fetch = json!({ "command": "voice_offer_fetch", "callId": "CALL-ABCDEF01", "sessionId": "0123456789ABCDEF0123" });
    let r = post(n.entry, &voice_cmd(&n.g, &fetch)).await;
    assert_eq!(r["ok"], true);
    assert_eq!(r["offerArmor"], offer.trim());
    assert_eq!(r["expiresAt"], exp);

    let missing = json!({ "command": "voice_offer_fetch", "callId": "call-nothere", "sessionId": "0123456789abcdef0123" });
    assert_eq!(
        post(n.entry, &voice_cmd(&n.g, &missing)).await,
        json!({ "ok": false, "error": "not_found", "callId": "call-nothere", "sessionId": "0123456789abcdef0123" })
    );

    let bad = json!({ "command": "voice_offer_store", "callId": "short", "sessionId": "0123456789abcdef0123", "offerArmor": offer });
    assert_eq!(
        post(n.entry, &voice_cmd(&n.g, &bad)).await,
        json!({ "ok": false, "error": "invalid_voice_offer_store", "callId": "short", "sessionId": "0123456789abcdef0123" })
    );
}

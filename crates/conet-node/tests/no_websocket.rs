//! AGENTS.md "禁止使用 WebSocket": negative run-time checks on 127.0.0.1 only (no outside
//! connection; golden TEST keys). The node must never accept a WebSocket upgrade:
//! - `GET` / `OPTIONS` / `POST /post` / `GET /webrtc` / the health port, each carrying
//!   `Upgrade: websocket` + `Sec-WebSocket-Key`: never `101`, never `Sec-WebSocket-Accept`;
//! - the upgrade attempts are refused before any upstream connection (a local fake upstream
//!   counts its connections);
//! - a normal forwarded `POST /post` with only WebSocket metadata (no `Upgrade` or
//!   `Connection: upgrade`) reaches the next hop as a fresh request the node builds itself, with
//!   no `Upgrade` or `Sec-WebSocket-*` headers.
//!
//! The TLS listener runs the same `server::handle` on the decrypted stream, so the plain-port
//! checks cover its request handling.
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{MailboxStore, MemoryStore};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const WS: [&str; 4] = [
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Version: 13",
];

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// A local stand-in for the next hop: records every request and answers 200.
struct FakeHop {
    addr: SocketAddr,
    conns: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

async fn fake_hop() -> FakeHop {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(vec![]));
    let (c, s) = (conns.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = l.accept().await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            let s = s.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let mut got = Vec::new();
                while let Ok(Ok(k)) =
                    tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf)).await
                {
                    if k == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..k]);
                    if got.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                s.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&got).into_owned());
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    FakeHop { addr, conns, seen }
}

/// One entry node A whose mailbox node for the test user is the fake hop.
async fn start(hop: SocketAddr) -> (SocketAddr, SocketAddr, Value) {
    let g = golden();
    let (k, id) = si_core::node::load_route(
        g["keys"]["nodeA"]["armoredPrivate"].as_str().unwrap(),
        g["keys"]["nodeA"]["passphrase"].as_str().unwrap(),
    )
    .unwrap();
    let hop_id = si_core::node::load_route(
        g["keys"]["nodeB"]["armoredPrivate"].as_str().unwrap(),
        g["keys"]["nodeB"]["passphrase"].as_str().unwrap(),
    )
    .unwrap()
    .1;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let routes = RouteTable::new(&id, Duration::from_secs(3600));
    routes.replace_nodes([(id.clone(), a), (hop_id.clone(), hop)]);
    routes.set_user_route(g["keys"]["user"]["encKeyId"].as_str().unwrap(), &hop_id);
    let w = || {
        Arc::new(EthKey::from_hex(g["wallets"]["nodeA"]["privateKey"].as_str().unwrap()).unwrap())
    };
    let store: Arc<dyn MailboxStore> = Arc::new(MemoryStore::default());
    let mut c = NodeCtx::new(id, Arc::new(k), w(), w(), Arc::new(routes), store);
    c.connect_timeout = Duration::from_secs(2);
    let ctx = Arc::new(c);
    tokio::spawn(server::serve(l, ctx.clone()));
    let hl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health = hl.local_addr().unwrap();
    tokio::spawn(server::serve_health(hl, ctx));
    (a, health, g)
}

async fn send(addr: SocketAddr, head: &str, body: &str) -> String {
    send_with_headers(addr, head, body, &WS).await
}

async fn send_with_websocket_metadata(addr: SocketAddr, head: &str, body: &str) -> String {
    const METADATA: [&str; 2] = [
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
    ];
    send_with_headers(addr, head, body, &METADATA).await
}

async fn send_with_headers(
    addr: SocketAddr,
    head: &str,
    body: &str,
    headers: &[&str],
) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    let req = format!(
        "{head}\r\nHost: test\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn assert_not_upgraded(what: &str, resp: &str) {
    let first = resp.lines().next().unwrap_or("");
    assert!(!first.contains(" 101"), "{what}: {first}");
    assert!(
        !resp.to_ascii_lowercase().contains("sec-websocket-accept"),
        "{what}: {resp}"
    );
    assert!(
        !resp.to_ascii_lowercase().contains("upgrade: websocket"),
        "{what}: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_attempts_are_refused_before_any_upstream_connection() {
    let hop = fake_hop().await;
    let (a, health, _) = start(hop.addr).await;
    for (head, body) in [
        ("GET / HTTP/1.1", ""),
        ("GET /ws HTTP/1.1", ""),
        ("GET /webrtc HTTP/1.1", ""),
        ("OPTIONS / HTTP/1.1", ""),
        ("POST /post HTTP/1.1", "{}"),
    ] {
        let resp = send(a, head, body).await;
        assert_not_upgraded(head, &resp);
    }
    let resp = send(health, "GET /healthz HTTP/1.1", "").await;
    assert_not_upgraded("health", &resp);
    let resp = send(health, "GET /ws HTTP/1.1", "").await;
    assert_not_upgraded("health /ws", &resp);
    assert_eq!(
        hop.conns.load(Ordering::SeqCst),
        0,
        "no upstream connection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_request_never_carries_upgrade_headers() {
    let hop = fake_hop().await;
    let (a, _, g) = start(hop.addr).await;
    let to =
        opgp::PublicCert::from_armor(g["keys"]["user"]["armoredPublic"].as_str().unwrap()).unwrap();
    let armor = opgp::encrypt(
        ChaCha20Rng::from_seed([9; 32]),
        b"hello user",
        &to,
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap();
    let body = json!({ "data": armor }).to_string();
    let resp = send_with_websocket_metadata(a, "POST /post HTTP/1.1", &body).await;
    assert_not_upgraded("forwarded POST", &resp);
    assert_eq!(hop.conns.load(Ordering::SeqCst), 1, "forwarded once");
    let seen = hop.seen.lock().unwrap().clone();
    let req = seen[0].to_ascii_lowercase();
    assert!(req.starts_with("post /post http/1.1"), "{req}");
    for bad in ["upgrade:", "connection: upgrade", "sec-websocket"] {
        assert!(!req.contains(bad), "next hop got {bad:?}: {req}");
    }
}

/// Probe self-check: the assertion really catches an accepted upgrade.
#[test]
#[should_panic]
fn probe_catches_a_101() {
    assert_not_upgraded(
        "synthetic",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    );
}

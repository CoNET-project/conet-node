//! M2 line E end-to-end: SilentPass exit through an entry node, golden TEST keys.
//! A loopback echo server stands in for the internet (the test policy allows loopback only).
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::BoxFut;
use conet_node::exit::{EgressPolicy, Exit, Passport, Resolver};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::MemoryStore;
use rand_core::RngCore;
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
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

struct Paid(String);
impl Passport for Paid {
    fn is_paid<'a>(&'a self, w: &'a str) -> BoxFut<'a, bool> {
        let ok = w.eq_ignore_ascii_case(&self.0);
        Box::pin(async move { ok })
    }
}
struct Loopback;
impl Resolver for Loopback {
    fn resolve_v4<'a>(&'a self, _h: &'a str) -> BoxFut<'a, Vec<Ipv4Addr>> {
        Box::pin(async { vec![Ipv4Addr::LOCALHOST] })
    }
}

/// Echo server: returns whatever it receives.
async fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

struct Net {
    g: Value,
    /// Entry E in front of both exits (the command's encryption key picks the exit).
    entry: SocketAddr,
}

/// Exit node X (nodeA key) with a test policy allowing loopback, a strict exit Y (nodeC key,
/// real policy), and entry E (nodeB) in front of both.
async fn start() -> Net {
    let g = golden();
    let load = |n: &str| {
        si_core::node::load_route(
            g["keys"][n]["armoredPrivate"].as_str().unwrap(),
            g["keys"][n]["passphrase"].as_str().unwrap(),
        )
        .unwrap()
    };
    let ((kx, idx), (ke, ide), (ky, idy)) = (load("nodeA"), load("nodeB"), load("user2"));
    let (lx, le, ly) = (
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    );
    let (ax, ae, ay) = (
        lx.local_addr().unwrap(),
        le.local_addr().unwrap(),
        ly.local_addr().unwrap(),
    );
    let routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(600));
        r.replace_nodes([(idx.clone(), ax), (ide.clone(), ae), (idy.clone(), ay)]);
        Arc::new(r)
    };
    let paid: Arc<dyn Passport> = Arc::new(Paid(
        g["wallets"]["client"]["address"].as_str().unwrap().into(),
    ));
    let mut cx = NodeCtx::new(
        idx.clone(),
        Arc::new(kx),
        Arc::new(wallet(&g, "nodeA")),
        Arc::new(wallet(&g, "nodeA")),
        routes(&idx),
        Arc::new(MemoryStore::default()),
    );
    cx.exit = Some(Arc::new(Exit::new(
        EgressPolicy {
            local: Default::default(),
            allow_loopback_for_tests: true,
        },
        Arc::new(Loopback),
        paid.clone(),
    )));
    let mut cy = NodeCtx::new(
        idy.clone(),
        Arc::new(ky),
        Arc::new(wallet(&g, "nodeC")),
        Arc::new(wallet(&g, "nodeC")),
        routes(&idy),
        Arc::new(MemoryStore::default()),
    );
    cy.exit = Some(Arc::new(Exit::new(
        EgressPolicy {
            local: Default::default(),
            allow_loopback_for_tests: false,
        },
        Arc::new(Loopback),
        paid,
    )));
    let ce = NodeCtx::new(
        ide.clone(),
        Arc::new(ke),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        routes(&ide),
        Arc::new(MemoryStore::default()),
    );
    tokio::spawn(server::serve(lx, Arc::new(cx)));
    tokio::spawn(server::serve(ly, Arc::new(cy)));
    tokio::spawn(server::serve(le, Arc::new(ce)));
    Net { g, entry: ae }
}

/// Signed `SaaS_Sock5*` command encrypted to `to` (an exit's route key).
#[allow(clippy::too_many_arguments)]
fn sock5(
    g: &Value,
    signer: &str,
    to: &str,
    command: &str,
    host: &str,
    port: u16,
    first: &[u8],
    extra: Value,
) -> String {
    let mut c = json!({ "command": command, "walletAddress": wallet(g, signer).address(), "requestData": [{ "host": host, "port": port, "buffer": B64.encode(first) }] });
    if let (Some(o), Some(e)) = (c.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    let message = c.to_string();
    let sig = wallet(g, signer).sign_message(&message).unwrap();
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let cert =
        opgp::PublicCert::from_armor(g["keys"][to]["armoredPublic"].as_str().unwrap()).unwrap();
    opgp::encrypt(
        <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed(seed),
        B64.encode(json!({ "message": message, "signMessage": sig }).to_string())
            .as_bytes(),
        &cert,
        opgp::EncryptOpts {
            text: true,
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

async fn read_exact_timeout(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("timeout")
        .expect("read");
    buf
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_pipes_both_ways_and_ignores_type() {
    let n = start().await;
    let port = echo().await;
    for with_type in [false, true] {
        let mut cmd = sock5(
            &n.g,
            "client",
            "nodeA",
            "SaaS_Sock5",
            "echo.example",
            port,
            b"hello",
            json!({}),
        );
        if with_type {
            // a `type` inside requestData must not change anything (no V3 in Rust)
            let mut c: Value = json!({ "command": "SaaS_Sock5", "walletAddress": wallet(&n.g, "client").address(), "requestData": [{ "host": "echo.example", "port": port, "buffer": B64.encode(b"hello"), "type": "http" }] });
            let message = c.take().to_string();
            let sig = wallet(&n.g, "client").sign_message(&message).unwrap();
            let cert = opgp::PublicCert::from_armor(
                n.g["keys"]["nodeA"]["armoredPublic"].as_str().unwrap(),
            )
            .unwrap();
            let mut seed = [3u8; 32];
            rand_core::OsRng.fill_bytes(&mut seed);
            cmd = opgp::encrypt(
                <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed(seed),
                B64.encode(json!({ "message": message, "signMessage": sig }).to_string())
                    .as_bytes(),
                &cert,
                opgp::EncryptOpts {
                    text: true,
                    zlib: true,
                    sign_with: None,
                },
            )
            .unwrap();
        }
        let mut s = open(n.entry, &cmd).await;
        assert_eq!(
            read_exact_timeout(&mut s, 5).await,
            b"hello",
            "first bytes reached the target and came back"
        );
        s.write_all(b" world").await.unwrap();
        assert_eq!(read_exact_timeout(&mut s, 6).await, b" world");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unpaid_gets_the_si_402_page() {
    let n = start().await;
    let port = echo().await;
    let mut s = open(
        n.entry,
        &sock5(
            &n.g,
            "other",
            "nodeA",
            "SaaS_Sock5",
            "echo.example",
            port,
            b"x",
            json!({}),
        ),
    )
    .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    let text = String::from_utf8(out).unwrap();
    let want = n.g["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "exit-402-page")
        .unwrap()["expect"]
        .clone();
    assert!(
        text.starts_with(want["statusLine"].as_str().unwrap()),
        "{text}"
    );
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert_eq!(body, want["html"].as_str().unwrap(), "SI page body");
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "real byte length"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_targets_close_without_a_reply() {
    let n = start().await;
    let port = echo().await;
    // strict exit (user2 key): loopback is not global unicast
    let mut s = open(
        n.entry,
        &sock5(
            &n.g,
            "client",
            "user2",
            "SaaS_Sock5",
            "127.0.0.1",
            port,
            b"x",
            json!({}),
        ),
    )
    .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    assert!(
        out.is_empty(),
        "closed silently: {}",
        String::from_utf8_lossy(&out)
    );
    // port 25 refused even where loopback is allowed
    let mut s = open(
        n.entry,
        &sock5(
            &n.g,
            "client",
            "nodeA",
            "SaaS_Sock5",
            "127.0.0.1",
            25,
            b"x",
            json!({}),
        ),
    )
    .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    assert!(out.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_pairs_upload_and_download_legs() {
    let n = start().await;
    let port = echo().await;
    let key = json!({ "Securitykey": "pair-key-0123456789" });
    // first leg: opens the target and uploads
    let mut up = open(
        n.entry,
        &sock5(
            &n.g,
            "client",
            "nodeA",
            "SaaS_Sock5_v2",
            "echo.example",
            port,
            b"ping",
            key.clone(),
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // second leg: receives the target's replies
    let mut down = open(
        n.entry,
        &sock5(
            &n.g,
            "client",
            "nodeA",
            "SaaS_Sock5_v2",
            "echo.example",
            port,
            b"",
            key,
        ),
    )
    .await;
    assert_eq!(read_exact_timeout(&mut down, 4).await, b"ping");
    up.write_all(b"more").await.unwrap();
    assert_eq!(
        read_exact_timeout(&mut down, 4).await,
        b"more",
        "upload on leg 1, download on leg 2"
    );
}

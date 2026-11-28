//! The public liveness probe of a node: `GET /` on port 80 (plain) and 443 (TLS). The PWA and worker (chat SDK `probeGossipNode`) probe
//! `https://<domain>.conet.network/` with a bare GET and mark a node healthy only on a status from 200 to 399; the entry C and the send entries are chosen from the
//! healthy ones. A node that answers 404 is never chosen as an entry in a normal network. TS answers with the home page it proxies (200). Synthetic; local only.
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::MemoryStore;
use serde_json::Value;
use si_crypto::eth::EthKey;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// The SDK rule (vendor/conet-chat-sdk/src/nodes.ts probeGossipNode): healthy only for 200 <= status < 400.
fn sdk_probe_healthy(status: u16) -> bool {
    (200..400).contains(&status)
}

struct Node {
    plain: SocketAddr,
    tls: SocketAddr,
    domain: String,
    cert_pem: String,
}

async fn start() -> Node {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let g = golden();
    let (k, id) = si_core::node::load_route(
        g["keys"]["nodeA"]["armoredPrivate"].as_str().unwrap(),
        g["keys"]["nodeA"]["passphrase"].as_str().unwrap(),
    )
    .unwrap();
    let wallet = || {
        Arc::new(EthKey::from_hex(g["wallets"]["nodeA"]["privateKey"].as_str().unwrap()).unwrap())
    };
    let lp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lt = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (plain, tls) = (lp.local_addr().unwrap(), lt.local_addr().unwrap());
    let routes = Arc::new(RouteTable::new(&id, Duration::from_secs(600)));
    routes.replace_nodes([(id.clone(), plain)]);
    let ctx = Arc::new(NodeCtx::new(
        id.clone(),
        Arc::new(k),
        wallet(),
        wallet(),
        routes,
        Arc::new(MemoryStore::default()),
    ));
    let domain = conet_node::tls::node_domain(&id);
    let ck = rcgen::generate_simple_self_signed(vec![domain.clone()]).unwrap();
    let (cert_pem, key_pem) = (ck.cert.pem(), ck.signing_key.serialize_pem());
    tokio::spawn(conet_node::tls::serve_tls(
        lt,
        ctx.clone(),
        conet_node::tls::TlsSource::Static {
            cert_pem: cert_pem.clone().into_bytes(),
            key_pem: key_pem.into_bytes(),
        },
    ));
    tokio::spawn(server::serve(lp, ctx));
    Node {
        plain,
        tls,
        domain,
        cert_pem,
    }
}

/// Sends a bare GET (the SDK probe: Accept text/html, no body) and returns (status, header block, body).
async fn get<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, path: &str) -> (u16, String, String) {
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: t\r\nAccept: text/html\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    let t = String::from_utf8_lossy(&out).into_owned();
    let status = t
        .split(' ')
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let (head, body) = t
        .split_once("\r\n\r\n")
        .map(|(h, b)| (h.to_string(), b.to_string()))
        .unwrap_or((t.clone(), String::new()));
    (status, head, body)
}

async fn tls_stream(n: &Node) -> tokio_rustls::client::TlsStream<TcpStream> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(n.cert_pem.as_bytes()).unwrap())
        .unwrap();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(n.tls).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(n.domain.clone()).unwrap(), tcp)
        .await
        .unwrap()
}

/// (a) Plain HTTP (port 80 path): GET / answers 200.
#[tokio::test(flavor = "multi_thread")]
async fn plain_get_root_is_200() {
    let n = start().await;
    let mut s = TcpStream::connect(n.plain).await.unwrap();
    let (status, head, body) = get(&mut s, "/").await;
    println!(
        "MEASURE plain GET /: status={status} body_len={} head={:?}",
        body.len(),
        head.lines().next()
    );
    assert_eq!(status, 200, "GET / on the plain port");
}

/// (b) TLS (port 443 path): GET / answers 200.
#[tokio::test(flavor = "multi_thread")]
async fn tls_get_root_is_200() {
    let n = start().await;
    let mut s = tls_stream(&n).await;
    let (status, head, body) = get(&mut s, "/").await;
    println!(
        "MEASURE tls GET /: status={status} body_len={} head={:?}",
        body.len(),
        head.lines().next()
    );
    assert_eq!(status, 200, "GET / on the TLS port");
}

/// (c) Everything else stays closed: other GET paths are 404 (no wider exposure), also GET /post and GET /webrtc without state.
#[tokio::test(flavor = "multi_thread")]
async fn other_get_paths_stay_404() {
    let n = start().await;
    for path in [
        "/post",
        "/webrtc",
        "/index.html",
        "/solana-rpc",
        "/nodeWallet",
        "/?x=1",
    ] {
        let mut s = TcpStream::connect(n.plain).await.unwrap();
        let (status, _, _) = get(&mut s, path).await;
        println!("MEASURE plain GET {path}: status={status}");
        assert_eq!(status, 404, "{path}");
    }
    let mut s = tls_stream(&n).await;
    let (status, _, _) = get(&mut s, "/other").await;
    assert_eq!(status, 404, "TLS GET /other");
}

/// (d) The SDK rule applied to the real answers: both ports are healthy for the chat SDK probe (200 to 399), the reply is a well formed HTTP/1.1 response
/// whose Content-Length equals its body, and it carries no node identity (no wallet, no key ID).
#[tokio::test(flavor = "multi_thread")]
async fn the_sdk_probe_rule_marks_both_ports_healthy() {
    let n = start().await;
    let mut p = TcpStream::connect(n.plain).await.unwrap();
    let mut t = tls_stream(&n).await;
    for (label, (status, head, body)) in [
        ("plain", get(&mut p, "/").await),
        ("tls", get(&mut t, "/").await),
    ] {
        println!(
            "MEASURE {label}: status={status} healthy={}",
            sdk_probe_healthy(status)
        );
        assert!(
            sdk_probe_healthy(status),
            "{label}: status {status} is not healthy for the SDK probe"
        );
        assert!(head.starts_with("HTTP/1.1 "), "{label}: {head}");
        let cl: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap())
            })
            .expect("content-length");
        assert_eq!(cl, body.len(), "{label}: content-length");
        let lower = format!("{head}{body}").to_ascii_lowercase();
        assert!(
            !lower.contains("0x")
                && !lower.contains(&n.domain.split('.').next().unwrap().to_ascii_lowercase()),
            "{label}: no identity in the probe answer"
        );
    }
}

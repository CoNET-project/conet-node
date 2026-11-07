//! Stage A1 end-to-end: three nodes on 127.0.0.1 with golden TEST keys.
//! A = entry, B = mailbox of the test user, C = node without user routes.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{MailboxStore, MemoryStore};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Net {
    golden: Value,
    a: SocketAddr,
    c: SocketAddr,
    store_b: Arc<MemoryStore>,
    ids: [String; 3],
}

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn key(g: &Value, name: &str) -> (opgp::SecretCert, String) {
    si_core::node::load_route(
        g["keys"][name]["armoredPrivate"].as_str().unwrap(),
        g["keys"][name]["passphrase"].as_str().unwrap(),
    )
    .unwrap()
}

fn wallet(g: &Value, name: &str) -> EthKey {
    EthKey::from_hex(g["wallets"][name]["privateKey"].as_str().unwrap()).unwrap()
}

fn pubkey(g: &Value, name: &str) -> opgp::PublicCert {
    opgp::PublicCert::from_armor(g["keys"][name]["armoredPublic"].as_str().unwrap()).unwrap()
}

async fn start() -> Net {
    let g = golden();
    let names = [("nodeA", "nodeA"), ("nodeB", "nodeB"), ("user2", "nodeC")];
    let mut listeners = vec![];
    let mut addrs = vec![];
    for _ in 0..3 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addrs.push(l.local_addr().unwrap());
        listeners.push(l);
    }
    let keys: Vec<_> = names.iter().map(|(k, _)| key(&g, k)).collect();
    let ids = [keys[0].1.clone(), keys[1].1.clone(), keys[2].1.clone()];
    let user_key = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let store_b = Arc::new(MemoryStore::default());
    for (i, ((k, id), l)) in keys.into_iter().zip(listeners).enumerate() {
        let routes = RouteTable::new(&id, Duration::from_secs(3600));
        routes.replace_nodes(ids.iter().cloned().zip(addrs.iter().cloned()));
        if i != 2 {
            routes.set_user_route(&user_key, &ids[1]);
        }
        let store: Arc<dyn MailboxStore> = if i == 1 {
            store_b.clone()
        } else {
            Arc::new(MemoryStore::default())
        };
        let mut c = NodeCtx::new(
            id,
            Arc::new(k),
            Arc::new(wallet(&g, names[i].1)),
            Arc::new(wallet(&g, names[i].1)),
            Arc::new(routes),
            store,
        );
        c.connect_timeout = Duration::from_secs(2);
        let ctx = Arc::new(c);
        tokio::spawn(server::serve(l, ctx));
    }
    Net {
        golden: g,
        a: addrs[0],
        c: addrs[2],
        store_b,
        ids,
    }
}

/// POST /post and read until the server closes. Returns (bytes, closed_without_response).
async fn post(addr: SocketAddr, armor: &str, extra_headers: &[String]) -> String {
    let body = json!({ "data": armor }).to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let extra: String = extra_headers.iter().map(|h| format!("{h}\r\n")).collect();
    let req = format!("POST /post HTTP/1.1\r\nHost: test\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .expect("response timeout")
        .ok();
    String::from_utf8_lossy(&out).into_owned()
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn enc(seed: u8, text: &str, to: &opgp::PublicCert) -> String {
    opgp::encrypt(
        rng(seed),
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

#[tokio::test(flavor = "multi_thread")]
async fn entry_forwards_user_mail_to_mailbox_with_hop_sig() {
    let n = start().await;
    let armor = enc(1, "hello user", &pubkey(&n.golden, "user"));
    let resp = post(n.a, &armor, &[]).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let user = n.golden["keys"]["user"]["encKeyId"].as_str().unwrap();
    let got = n.store_b.pending(user);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].armor, armor);
    assert_eq!(got[0].hops, 1);
    assert_eq!(got[0].hop_bytes, armor.len() as u64);
}

#[tokio::test(flavor = "multi_thread")]
async fn mailbox_work_for_b_through_entry_a() {
    let n = start().await;
    let inner = enc(2, "for user", &pubkey(&n.golden, "user"));
    let work = enc(
        3,
        &json!({ "data": inner, "NoPush": true }).to_string(),
        &pubkey(&n.golden, "nodeB"),
    );
    let resp = post(n.a, &work, &[]).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let got = n
        .store_b
        .pending(n.golden["keys"]["user"]["encKeyId"].as_str().unwrap());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].armor, inner.trim_end()); // SI asPgpMessageArmor cuts after END
    assert!(got[0].no_push);
}

#[tokio::test(flavor = "multi_thread")]
async fn onion_peeled_at_a_then_delivered_at_b() {
    let n = start().await;
    let inner = enc(4, "onion inner", &pubkey(&n.golden, "user"));
    let outer = enc(5, &inner, &pubkey(&n.golden, "nodeA"));
    let resp = post(n.a, &outer, &[]).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let got = n
        .store_b
        .pending(n.golden["keys"]["user"]["encKeyId"].as_str().unwrap());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].armor, inner.trim_end()); // SI asPgpMessageArmor cuts after END
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_user_gets_no_route() {
    let n = start().await;
    let armor = enc(6, "x", &pubkey(&n.golden, "user"));
    let resp = post(n.c, &armor, &[]).await;
    assert!(
        resp.ends_with(r#"{"ok":false,"error":"no_route"}"#),
        "{resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn three_hops_already_means_no_forward() {
    let n = start().await;
    let armor = enc(7, "x", &pubkey(&n.golden, "user"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let hops: Vec<_> = ["other", "billing", "payer"]
        .iter()
        .map(|w| si_core::sign_hop(&wallet(&n.golden, w), &armor, &n.ids[1], now).unwrap())
        .collect();
    let header = format!(
        "X-CoNET-Hop-Sigs: {}",
        B64.encode(serde_json::to_string(&hops).unwrap())
    );
    let resp = post(n.a, &armor, &[header]).await;
    assert!(resp.is_empty(), "expected plain end, got {resp}");
    assert!(n
        .store_b
        .pending(n.golden["keys"]["user"]["encKeyId"].as_str().unwrap())
        .is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn same_node_onion_is_ended() {
    let n = start().await;
    let inner = enc(8, "x", &pubkey(&n.golden, "nodeA"));
    let outer = enc(9, &inner, &pubkey(&n.golden, "nodeA"));
    assert!(post(n.a, &outer, &[]).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn public_node_wallet_path_is_gone_and_body_is_capped() {
    let n = start().await;
    let mut s = TcpStream::connect(n.a).await.unwrap();
    s.write_all(b"GET /nodeWallet HTTP/1.1\r\nHost: t\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 404"), "{out}");
    // over 256 KB: refused before the body is read
    let mut s = TcpStream::connect(n.a).await.unwrap();
    s.write_all(b"POST /post HTTP/1.1\r\nHost: t\r\nContent-Length: 300000\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 404"), "{out}");
}

/// Entry A runs with its keys in the signer process; B is in-process.
#[tokio::test(flavor = "multi_thread")]
async fn entry_with_signer_process() {
    let g = golden();
    let dir = tempfile::tempdir().unwrap();
    let kek = [9u8; 32];
    let secrets = si_signer::keystore::Secrets {
        wallet_hex: g["wallets"]["nodeA"]["privateKey"].as_str().unwrap().into(),
        pgp_armored: g["keys"]["nodeA"]["armoredPrivate"]
            .as_str()
            .unwrap()
            .into(),
        pgp_pass: g["keys"]["nodeA"]["passphrase"].as_str().unwrap().into(),
        previous_pgp_armored: String::new(),
        previous_pgp_pass: String::new(),
    };
    let signer = Arc::new(
        si_signer::server::Signer::start(si_signer::server::SignerConfig {
            keystore_file: si_signer::keystore::seal(&kek, &secrets).unwrap(),
            kek: zeroize::Zeroizing::new(kek),
            verifying_contract: "0x00000000000000000000000000000000c0de0001".into(),
            allow_bind: false,
            allow_uid: None,
        })
        .unwrap_or_else(|e| panic!("{}", e.0)),
    );
    let sock = dir.path().join("signer.sock");
    tokio::spawn(si_signer::server::serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        signer,
    ));
    let client = Arc::new(
        tokio::task::spawn_blocking(move || si_signer::client::SignerClient::connect(sock))
            .await
            .unwrap()
            .unwrap(),
    );

    let (kb, idb) = key(&g, "nodeB");
    let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
    let ida = client.route_key_id().to_string();
    let user = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let mk_routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(3600));
        r.replace_nodes([(ida.clone(), aa), (idb.clone(), ab)]);
        r.set_user_route(&user, &idb);
        Arc::new(r)
    };
    let store_b = Arc::new(MemoryStore::default());
    let ctx_a = Arc::new(NodeCtx::new(
        ida.clone(),
        client.clone(),
        client.clone(),
        client.clone(),
        mk_routes(&ida),
        Arc::new(MemoryStore::default()),
    ));
    let ctx_b = Arc::new(NodeCtx::new(
        idb.clone(),
        Arc::new(kb),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        mk_routes(&idb),
        store_b.clone(),
    ));
    tokio::spawn(server::serve(la, ctx_a));
    tokio::spawn(server::serve(lb, ctx_b));

    // onion: A must decrypt (via signer) and sign the hop (via signer)
    let inner = enc(10, "via signer", &pubkey(&g, "user"));
    let outer = enc(11, &inner, &pubkey(&g, "nodeA"));
    let resp = post(aa, &outer, &[]).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let got = store_b.pending(&user);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].hops, 1);
    assert_eq!(
        got[0].hop_bytes,
        inner.trim_end().len() as u64,
        "hop row signed by the signer verifies at B"
    );
}

/// Client → entry A over HTTPS (:443 path) → mailbox B over plain SI-to-SI forwarding.
#[tokio::test(flavor = "multi_thread")]
async fn https_entry_forwards_like_plain() {
    use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let g = golden();
    let (ka, ida) = key(&g, "nodeA");
    let (kb, idb) = key(&g, "nodeB");
    let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
    let user = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(3600));
        r.replace_nodes([(ida.clone(), aa), (idb.clone(), ab)]);
        r.set_user_route(&user, &idb);
        Arc::new(r)
    };
    let domain = conet_node::tls::node_domain(&ida);
    let ck = rcgen::generate_simple_self_signed(vec![domain.clone()]).unwrap();
    let (cert_pem, key_pem) = (ck.cert.pem(), ck.signing_key.serialize_pem());
    let ctx_a = Arc::new(NodeCtx::new(
        ida.clone(),
        Arc::new(ka),
        Arc::new(wallet(&g, "nodeA")),
        Arc::new(wallet(&g, "nodeA")),
        routes(&ida),
        Arc::new(MemoryStore::default()),
    ));
    let store_b = Arc::new(MemoryStore::default());
    let ctx_b = Arc::new(NodeCtx::new(
        idb.clone(),
        Arc::new(kb),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        routes(&idb),
        store_b.clone(),
    ));
    let lt = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = lt.local_addr().unwrap();
    tokio::spawn(conet_node::tls::serve_tls(
        lt,
        ctx_a.clone(),
        conet_node::tls::TlsSource::Static {
            cert_pem: cert_pem.clone().into_bytes(),
            key_pem: key_pem.into_bytes(),
        },
    ));
    tokio::spawn(server::serve(la, ctx_a));
    tokio::spawn(server::serve(lb, ctx_b));

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap())
        .unwrap();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(at).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from(domain).unwrap(), tcp)
        .await
        .unwrap();

    let armor = enc(20, "over https", &pubkey(&g, "user"));
    let body = json!({ "data": armor }).to_string();
    tls.write_all(format!("POST /post HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut out)).await;
    let resp = String::from_utf8_lossy(&out);
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let got = store_b.pending(&user);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].armor, armor);
    assert_eq!(got[0].hops, 1);
}

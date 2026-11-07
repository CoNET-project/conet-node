//! DNS-01 issuance against Pebble (Let's Encrypt's test CA) and pebble-challtestsrv (its mock
//! DNS), with a mock DNS daemon that checks the node's signed requests. No real DNS and no real
//! CA are touched. Needs `PEBBLE_BIN` and `PEBBLE_CHALLTESTSRV_BIN`; skipped without them
//! (CI installs both).
use conet_node::acme_dns::{
    self, issue, load_cached, verify_dns01_request, CertSlot, Dns01Opts, DnsDaemon,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use serde_json::Value;
use si_crypto::eth::EthKey;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY_ID: &str = "C0FFEE0123456789";

fn bins() -> Option<(PathBuf, PathBuf)> {
    Some((
        std::env::var_os("PEBBLE_BIN")?.into(),
        std::env::var_os("PEBBLE_CHALLTESTSRV_BIN")?.into(),
    ))
}

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn wallet(n: &str) -> EthKey {
    EthKey::from_hex(golden()["wallets"][n]["privateKey"].as_str().unwrap()).unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Kids(Vec<Child>);
impl Drop for Kids {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct Pebble {
    _kids: Kids,
    directory: String,
    ca_pem: PathBuf,
    management: String,
    chall_mgmt: String,
}

/// Test PKI for Pebble's own HTTPS, then Pebble and the mock DNS.
async fn start(dir: &Path, pebble: &Path, chall: &Path) -> Pebble {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "pebble test root");
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let ca_pem = dir.join("ca.pem");
    std::fs::write(&ca_pem, ca_cert.pem()).unwrap();
    std::fs::write(dir.join("leaf.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.join("leaf.key"), leaf_key.serialize_pem()).unwrap();

    let (acme, mgmt, dns, chall_mgmt) = (free_port(), free_port(), free_port(), free_port());
    let cfg = serde_json::json!({"pebble": {
        "listenAddress": format!("127.0.0.1:{acme}"),
        "managementListenAddress": format!("127.0.0.1:{mgmt}"),
        "certificate": dir.join("leaf.pem"),
        "privateKey": dir.join("leaf.key"),
        "httpPort": free_port(),
        "tlsPort": free_port(),
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false
    }});
    std::fs::write(dir.join("pebble.json"), cfg.to_string()).unwrap();
    let quiet = || Stdio::null();
    let c = Command::new(chall)
        .args([
            "-dnsserver",
            &format!("127.0.0.1:{dns}"),
            "-management",
            &format!("127.0.0.1:{chall_mgmt}"),
            "-http01",
            "",
            "-https01",
            "",
            "-tlsalpn01",
            "",
            "-doh",
            "",
        ])
        .stdout(quiet())
        .stderr(quiet())
        .spawn()
        .unwrap();
    let p = Command::new(pebble)
        .args(["-config"])
        .arg(dir.join("pebble.json"))
        .args(["-dnsserver", &format!("127.0.0.1:{dns}")])
        .env("PEBBLE_VA_NOSLEEP", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        .stdout(quiet())
        .stderr(quiet())
        .spawn()
        .unwrap();
    let kids = Kids(vec![c, p]);
    let http = client(&ca_pem);
    let directory = format!("https://127.0.0.1:{acme}/dir");
    for _ in 0..100 {
        if http.get(&directory).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Pebble {
        _kids: kids,
        directory,
        ca_pem,
        management: format!("https://127.0.0.1:{mgmt}"),
        chall_mgmt: format!("http://127.0.0.1:{chall_mgmt}"),
    }
}

fn client(ca_pem: &Path) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(ca_pem).unwrap()).unwrap();
    reqwest::Client::builder()
        .tls_certs_only([ca])
        .build()
        .unwrap()
}

/// Mock DNS daemon: checks each signed request, requires `expect_wallet` for `KEY_ID`, then
/// sets or clears the TXT record in challtestsrv. Counts accepted requests.
async fn mock_daemon(
    chall_mgmt: String,
    expect_wallet: String,
    accepted: Arc<AtomicUsize>,
) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let http = reqwest::Client::new();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (http, chall, expect, accepted) = (
                http.clone(),
                chall_mgmt.clone(),
                expect_wallet.clone(),
                accepted.clone(),
            );
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let body = loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string();
                    }
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let ok = match verify_dns01_request(&body, now) {
                    Ok(r) if r.wallet.eq_ignore_ascii_case(&expect) && r.key_id == KEY_ID => {
                        let host = format!("{}.", r.name);
                        let rsp = if r.op == "set" {
                            http.post(format!("{chall}/set-txt"))
                                .json(&serde_json::json!({"host": host, "value": r.value}))
                                .send()
                                .await
                        } else {
                            http.post(format!("{chall}/clear-txt"))
                                .json(&serde_json::json!({"host": host}))
                                .send()
                                .await
                        };
                        rsp.map(|r| r.status().is_success()).unwrap_or(false)
                    }
                    _ => false,
                };
                if ok {
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
                let status = if ok { "200 OK" } else { "403 Forbidden" };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    url
}

fn opts(p: &Pebble, cache: PathBuf, daemon: &str) -> Dns01Opts {
    let mut o = Dns01Opts::new(
        conet_node::tls::node_domain(KEY_ID),
        cache,
        daemon.to_string(),
    );
    o.directory = p.directory.clone();
    o.directory_root = Some(p.ca_pem.clone());
    o.settle = Duration::from_millis(100);
    o
}

/// Handshake against the served certificate, trusting Pebble's issuing root, by node name.
async fn handshake(slot: Arc<CertSlot>, root_pem: &[u8]) {
    use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(root_pem) {
        roots.add(c.unwrap()).unwrap();
    }
    let ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (a, b) = tokio::io::duplex(64 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(conet_node::tls::dns01_config(slot));
    let server = tokio::spawn(async move { acceptor.accept(b).await.map(|_| ()) });
    let name = ServerName::try_from(conet_node::tls::node_domain(KEY_ID)).unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(ccfg))
        .connect(name, a)
        .await
        .expect("client trusts the DNS-01 certificate for the node name");
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn dns01_issues_through_the_daemon_and_renews_from_cache() {
    let Some((pebble, chall)) = bins() else {
        eprintln!("skipped: PEBBLE_BIN / PEBBLE_CHALLTESTSRV_BIN not set");
        return;
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), &pebble, &chall).await;
    let node = Arc::new(wallet("nodeA"));
    let accepted = Arc::new(AtomicUsize::new(0));
    let url = mock_daemon(p.chall_mgmt.clone(), node.address(), accepted.clone()).await;
    let cache = dir.path().join("cache");
    let o = opts(&p, cache.clone(), &url);

    // run(): no cache, so it issues and fills the slot.
    let slot = Arc::new(CertSlot::default());
    let task = tokio::spawn(acme_dns::run(
        o.clone(),
        DnsDaemon::new(&url, KEY_ID, &node.address(), node.clone()),
        slot.clone(),
    ));
    for _ in 0..600 {
        if slot.get().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    task.abort();
    assert!(slot.get().is_some(), "certificate issued within 60 s");
    // one set and one delete, each signed and accepted
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["dns01-key.pem", "dns01-account.json"] {
            let mode = std::fs::metadata(cache.join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
    }
    let root = client(&p.ca_pem)
        .get(format!("{}/roots/0", p.management))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    handshake(slot, &root).await;

    // Restart: the cached certificate is served at once, nothing is asked of the daemon.
    let cached = load_cached(&o).expect("cached certificate for the node name");
    assert!(cached.not_after > 0);
    let slot2 = Arc::new(CertSlot::default());
    let task = tokio::spawn(acme_dns::run(
        o.clone(),
        DnsDaemon::new(&url, KEY_ID, &node.address(), node.clone()),
        slot2.clone(),
    ));
    for _ in 0..50 {
        if slot2.get().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    task.abort();
    assert!(slot2.get().is_some());
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_refuses_another_wallet_and_issuance_fails() {
    let Some((pebble, chall)) = bins() else {
        eprintln!("skipped: PEBBLE_BIN / PEBBLE_CHALLTESTSRV_BIN not set");
        return;
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), &pebble, &chall).await;
    let registered = wallet("nodeA");
    let impostor = Arc::new(wallet("nodeB"));
    let accepted = Arc::new(AtomicUsize::new(0));
    let url = mock_daemon(p.chall_mgmt.clone(), registered.address(), accepted.clone()).await;
    let o = opts(&p, dir.path().join("cache"), &url);
    let err = issue(
        &o,
        &DnsDaemon::new(&url, KEY_ID, &impostor.address(), impostor.clone()),
    )
    .await
    .err()
    .expect("a wallet the daemon does not know for this key ID gets no TXT record");
    assert!(err.contains("dns daemon"), "{err}");
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(load_cached(&o).is_none());
}

/// Request format checks; no Pebble needed.
#[tokio::test]
async fn signed_requests_verify_and_tampering_fails() {
    let node = Arc::new(wallet("nodeA"));
    let d = DnsDaemon::new("http://127.0.0.1:1", KEY_ID, &node.address(), node.clone());
    let v = "y".repeat(43);
    let body = d.request_body(&v, "set").await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let r = verify_dns01_request(&body, now).unwrap();
    assert_eq!(r.key_id, KEY_ID);
    assert_eq!(r.name, "_acme-challenge.c0ffee0123456789.conet.network");
    assert!(r.wallet.eq_ignore_ascii_case(&node.address()));
    // another value, another op, another key ID: signature no longer matches
    for (from, to) in [
        (v.as_str(), "z".repeat(43)),
        ("\"op\":\"set\"", "\"op\":\"delete\"".to_string()),
        (KEY_ID, "C0FFEE0123456780".to_string()),
    ] {
        let t = body.replacen(from, &to, 1);
        assert_ne!(t, body);
        assert!(verify_dns01_request(&t, now).is_err(), "{to}");
    }
    // stale request
    assert!(verify_dns01_request(&body, now + 400).is_err());
}

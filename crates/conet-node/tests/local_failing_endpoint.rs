//! LOCAL TEST ENDPOINT (an ignored helper, not a regression test): an isolated Rust entry node A and mailbox node B on loopback whose mailbox store can be switched, by a control
//! URL, between normal and "refuse every new message": the POST reply is then `{"ok":false,"error":"store_failed"}` (the real reply of the node for a refused message, also
//! through the entry A). It lets a sender-side test (a browser build) check that the pending message is kept on a refusal and stored exactly once after the recovery.
//! Any user key is routed to B (a permissive chain double), so a test account of any identity works. Loopback only; no network; synthetic keys of the repository's golden file.
//! Run: `ENDPOINT_DIR=/some/dir cargo test -p conet-node --test local_failing_endpoint -- --ignored --exact serve_failing_mailbox_endpoint --nocapture`
//! (`ENDPOINT_PORT_BASE` default 18180 gives A http, B http, A tls, B tls, control = base .. base+4; `ENDPOINT_SECS` how long it serves, default 3600).
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use serde_json::{json, Value};
use si_crypto::eth::EthKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Every user key has its mailbox on B; no wallet lookups.
struct AnyUserToB {
    b_key: String,
}

impl UserRoutes for AnyUserToB {
    fn route_of_user_key<'a>(
        &'a self,
        _k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move { Ok(Some(self.b_key.clone())) })
    }
    fn user_key_of_wallet<'a>(
        &'a self,
        _w: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async { Ok(None) })
    }
    fn wallet_of_user_key<'a>(
        &'a self,
        _k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async { Ok(None) })
    }
    fn is_my_route<'a>(&'a self, _u: &'a str, _n: &'a str) -> BoxFut<'a, Result<bool, ChainError>> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Default)]
struct Counters {
    stored: usize,
    duplicate: usize,
    failed: usize,
    /// (n, outcome, armor hash): hashes only, never content.
    events: Vec<(usize, &'static str, String)>,
}

struct SwitchStore {
    inner: DiskStore,
    fail: AtomicBool,
    seen: Mutex<Counters>,
}

impl MailboxStore for SwitchStore {
    fn save(&self, k: &str, i: Stored) -> bool {
        self.save_result(k, i) == SaveResult::Stored
    }
    fn save_result(&self, k: &str, i: Stored) -> SaveResult {
        let h = armor_hash(&i.armor);
        let r = if self.fail.load(Ordering::SeqCst) {
            SaveResult::Failed
        } else {
            self.inner.save_result(k, i)
        };
        let mut c = self.seen.lock().unwrap();
        let name = match r {
            SaveResult::Stored => {
                c.stored += 1;
                "stored"
            }
            SaveResult::Duplicate => {
                c.duplicate += 1;
                "duplicate"
            }
            SaveResult::Failed => {
                c.failed += 1;
                "store_failed"
            }
        };
        let n = c.events.len() + 1;
        c.events.push((n, name, h));
        r
    }
    fn pending(&self, k: &str) -> Vec<Stored> {
        self.inner.pending(k)
    }
    fn remove_by_hash(&self, k: &str, h: &str) -> bool {
        self.inner.remove_by_hash(k, h)
    }
}

async fn control(listener: TcpListener, store: Arc<SwitchStore>) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
            let body = match path.as_str() {
                "/fail" => {
                    store.fail.store(true, Ordering::SeqCst);
                    json!({ "mode": "store_failed" })
                }
                "/ok" => {
                    store.fail.store(false, Ordering::SeqCst);
                    json!({ "mode": "ok" })
                }
                "/status" | "/count" => {
                    let c = store.seen.lock().unwrap();
                    let rows: usize = store
                        .inner
                        .mailbox_keys()
                        .unwrap()
                        .iter()
                        .map(|k| store.inner.pending(k).len())
                        .sum();
                    json!({
                        "mode": if store.fail.load(Ordering::SeqCst) { "store_failed" } else { "ok" },
                        "rows_stored_now": rows,
                        "events": { "stored": c.stored, "duplicate": c.duplicate, "store_failed": c.failed },
                    })
                }
                "/events" => {
                    let c = store.seen.lock().unwrap();
                    let last: Vec<Value> = c
                        .events
                        .iter()
                        .rev()
                        .take(50)
                        .rev()
                        .map(|(n, o, h)| json!({ "n": n, "outcome": o, "armor_hash": h }))
                        .collect();
                    json!({ "events": last })
                }
                _ => json!({ "paths": ["/fail", "/ok", "/status", "/events"] }),
            };
            let body = body.to_string();
            let _ = s
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                .await;
        });
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "local helper for a sender-side browser test; needs ENDPOINT_DIR"]
async fn serve_failing_mailbox_endpoint() {
    let Ok(dir) = std::env::var("ENDPOINT_DIR") else {
        println!("skipped: set ENDPOINT_DIR");
        return;
    };
    let base: u16 = std::env::var("ENDPOINT_PORT_BASE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(18180);
    let secs: u64 = std::env::var("ENDPOINT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let g = golden();
    let load = |n: &str| {
        si_core::node::load_route(
            g["keys"][n]["armoredPrivate"].as_str().unwrap(),
            g["keys"][n]["passphrase"].as_str().unwrap(),
        )
        .unwrap()
    };
    let wallet = |n: &str| {
        Arc::new(EthKey::from_hex(g["wallets"][n]["privateKey"].as_str().unwrap()).unwrap())
    };
    let (ka, ida) = load("nodeA");
    let (kb, idb) = load("nodeB");
    let bind = |p: u16| async move {
        TcpListener::bind(("127.0.0.1", p))
            .await
            .expect("port is free")
    };
    let (la, lb, lat, lbt, lc) = (
        bind(base).await,
        bind(base + 1).await,
        bind(base + 2).await,
        bind(base + 3).await,
        bind(base + 4).await,
    );
    let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
    let routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(600));
        r.replace_nodes([(ida.clone(), aa), (idb.clone(), ab)]);
        Arc::new(r)
    };
    let chain: Arc<dyn UserRoutes> = Arc::new(AnyUserToB { b_key: idb.clone() });
    let store = Arc::new(SwitchStore {
        inner: DiskStore::open(&std::path::Path::new(&dir).join("mailbox.redb")).unwrap(),
        fail: AtomicBool::new(false),
        seen: Mutex::new(Counters::default()),
    });
    let mut ca = NodeCtx::new(
        ida.clone(),
        Arc::new(ka),
        wallet("nodeA"),
        wallet("nodeA"),
        routes(&ida),
        Arc::new(conet_node::store::MemoryStore::default()),
    );
    ca.user_routes = Some(chain.clone());
    let mut cb = NodeCtx::new(
        idb.clone(),
        Arc::new(kb),
        wallet("nodeB"),
        wallet("nodeB"),
        routes(&idb),
        Arc::new(conet_node::store::MemoryStore::default()),
    );
    cb.user_routes = Some(chain);
    cb.mailbox = Arc::new(conet_node::mailbox::Mailbox::new(
        store.clone(),
        Arc::new(conet_node::push::NoPush),
    ));
    let (ca, cb) = (Arc::new(ca), Arc::new(cb));
    let ck =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let tls = |ctx: Arc<NodeCtx>, l: TcpListener| {
        tokio::spawn(conet_node::tls::serve_tls(
            l,
            ctx,
            conet_node::tls::TlsSource::Static {
                cert_pem: ck.cert.pem().into_bytes(),
                key_pem: ck.signing_key.serialize_pem().into_bytes(),
            },
        ))
    };
    tls(ca.clone(), lat);
    tls(cb.clone(), lbt);
    tokio::spawn(server::serve(la, ca));
    tokio::spawn(server::serve(lb, cb));
    tokio::spawn(control(lc, store));
    std::fs::write(std::path::Path::new(&dir).join("cert.pem"), ck.cert.pem()).unwrap();
    let info = json!({
        "note": "loopback only; entry A forwards to mailbox B; every user key is routed to B; GET http://127.0.0.1:<control>/fail then /ok switches the mailbox store",
        "entryA": { "http": format!("127.0.0.1:{base}"), "tls": format!("127.0.0.1:{}", base + 2), "routeKeyId": ida, "armoredPublic": g["keys"]["nodeA"]["armoredPublic"] },
        "mailboxB": { "http": format!("127.0.0.1:{}", base + 1), "tls": format!("127.0.0.1:{}", base + 3), "routeKeyId": idb, "armoredPublic": g["keys"]["nodeB"]["armoredPublic"] },
        "control": format!("127.0.0.1:{}", base + 4),
        "tlsCert": "cert.pem (self-signed, localhost and 127.0.0.1)",
    });
    std::fs::write(
        std::path::Path::new(&dir).join("endpoint.json"),
        serde_json::to_string_pretty(&info).unwrap(),
    )
    .unwrap();
    println!("ENDPOINT READY {}", info["control"]);
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// Drives a RUNNING endpoint (started by `serve_failing_mailbox_endpoint`) the way a sender does and checks the three states with the real reply bodies:
/// ok → stored; /fail → `{"ok":false,"error":"store_failed"}` through the entry A; /ok → the SAME armor stored once, a second post a duplicate; counts from /status.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "drives a running endpoint; needs ENDPOINT_DIR"]
async fn drive_failing_mailbox_endpoint() {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    let dir = std::env::var("ENDPOINT_DIR").expect("ENDPOINT_DIR");
    let info: Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(&dir).join("endpoint.json")).unwrap(),
    )
    .unwrap();
    let g = golden();
    let user = si_crypto::opgp::PublicCert::from_armor(
        g["keys"]["user"]["armoredPublic"].as_str().unwrap(),
    )
    .unwrap();
    let enc = |seed: u8, text: &str| {
        si_crypto::opgp::encrypt(
            ChaCha20Rng::from_seed([seed; 32]),
            text.as_bytes(),
            &user,
            si_crypto::opgp::EncryptOpts {
                text: true,
                zlib: true,
                sign_with: None,
            },
        )
        .unwrap()
    };
    let http = |addr: String, req: String| async move {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        let t = String::from_utf8_lossy(&out).into_owned();
        t.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    };
    let a = info["entryA"]["http"].as_str().unwrap().to_string();
    let ctl = info["control"].as_str().unwrap().to_string();
    let post = |armor: String| {
        let a = a.clone();
        async move {
            let body = json!({ "data": armor }).to_string();
            let b = http(a, format!("POST /post HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await;
            serde_json::from_str::<Value>(&b).unwrap_or(Value::Null)
        }
    };
    let get = |p: &str| {
        let ctl = ctl.clone();
        let p = p.to_string();
        async move {
            serde_json::from_str::<Value>(
                &http(
                    ctl,
                    format!("GET {p} HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n"),
                )
                .await,
            )
            .unwrap()
        }
    };
    println!("MEASURE start: {}", get("/ok").await);
    let m1 = enc(1, "first");
    let r = post(m1.clone()).await;
    println!("MEASURE ok mode, first post: {r}");
    assert_eq!(r["ok"], true);
    assert_eq!(r["stored"], true);
    println!("MEASURE switch: {}", get("/fail").await);
    let m2 = enc(2, "refused then retried");
    let r = post(m2.clone()).await;
    println!("MEASURE store_failed mode, post through the entry: {r}");
    assert_eq!(r, json!({ "ok": false, "error": "store_failed" }));
    let s = get("/status").await;
    println!("MEASURE status while failing: {s}");
    assert_eq!(
        (
            s["events"]["stored"].as_u64(),
            s["events"]["store_failed"].as_u64(),
            s["rows_stored_now"].as_u64()
        ),
        (Some(1), Some(1), Some(1))
    );
    println!("MEASURE switch back: {}", get("/ok").await);
    let r = post(m2.clone()).await;
    println!("MEASURE after recovery, the SAME armor again: {r}");
    assert_eq!(r["stored"], true);
    let r = post(m2.clone()).await;
    assert_eq!(r["duplicate"], true);
    let s = get("/status").await;
    println!("MEASURE status after recovery: {s}");
    assert_eq!(
        (
            s["events"]["stored"].as_u64(),
            s["events"]["duplicate"].as_u64(),
            s["events"]["store_failed"].as_u64(),
            s["rows_stored_now"].as_u64()
        ),
        (Some(2), Some(1), Some(1), Some(2))
    );
    println!(
        "MEASURE last events (hashes only): {}",
        get("/events").await
    );
}

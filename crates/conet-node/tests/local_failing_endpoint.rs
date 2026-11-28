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
    /// Replies withheld in drop-response mode: in all and per hash prefix.
    dropped: usize,
    dropped_by_hash: std::collections::BTreeMap<String, usize>,
}

/// How long a reply is withheld in drop-response mode (the sender's attempt timeout is 8 seconds).
const DROP_DELAY: Duration = Duration::from_secs(12);

struct SwitchStore {
    inner: DiskStore,
    fail: AtomicBool,
    /// The message is stored as usual but the reply is withheld (see DROP_DELAY).
    drop_response: AtomicBool,
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
        c.events.push((n, name, h.clone()));
        let withhold = r != SaveResult::Failed && self.drop_response.load(Ordering::SeqCst);
        if withhold {
            c.dropped += 1;
            *c.dropped_by_hash
                .entry(h[..14.min(h.len())].to_string())
                .or_default() += 1;
        }
        drop(c);
        if withhold {
            // "Response lost": the message is already stored; the reply is held back for DROP_DELAY, longer than the sender's 8 second attempt timeout, so the sender sees no answer
            // and retries; the reply is then written to a connection the sender has closed. The thread is handed back to the runtime meanwhile.
            tokio::task::block_in_place(|| std::thread::sleep(DROP_DELAY));
        }
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
                    store.drop_response.store(false, Ordering::SeqCst);
                    json!({ "mode": "store_failed" })
                }
                "/drop-response" => {
                    store.fail.store(false, Ordering::SeqCst);
                    store.drop_response.store(true, Ordering::SeqCst);
                    json!({ "mode": "drop_response" })
                }
                "/ok" => {
                    store.drop_response.store(false, Ordering::SeqCst);
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
                        "mode": if store.fail.load(Ordering::SeqCst) { "store_failed" } else if store.drop_response.load(Ordering::SeqCst) { "drop_response" } else { "ok" },
                        "responses_dropped": c.dropped,
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
                        .map(|(n, o, h)| json!({ "n": n, "outcome": o, "armor_hash_prefix": &h[..14.min(h.len())] }))
                        .collect();
                    json!({ "events": last })
                }
                // counts per inner armor (keccak256 of what the mailbox stores), by hash prefix only: stored, duplicate and store_failed for each distinct message
                "/byhash" => {
                    let c = store.seen.lock().unwrap();
                    let mut m: std::collections::BTreeMap<String, [usize; 3]> = Default::default();
                    for (_, o, h) in &c.events {
                        let e = m.entry(h[..14.min(h.len())].to_string()).or_default();
                        match *o {
                            "stored" => e[0] += 1,
                            "duplicate" => e[1] += 1,
                            _ => e[2] += 1,
                        }
                    }
                    let per: Vec<Value> = m.iter().map(|(h, e)| json!({ "armor_hash_prefix": h, "stored": e[0], "duplicate": e[1], "store_failed": e[2], "responses_dropped": c.dropped_by_hash.get(h).copied().unwrap_or(0) })).collect();
                    json!({ "distinct_messages": per.len(), "responses_dropped": c.dropped, "per_message": per })
                }
                _ => {
                    json!({ "paths": ["/fail", "/ok", "/drop-response", "/status", "/events", "/byhash"] })
                }
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
        drop_response: AtomicBool::new(false),
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
        "MEASURE last events (hash prefixes only): {}",
        get("/events").await
    );
    let by = get("/byhash").await;
    println!("MEASURE counts per inner armor (prefixes only): {by}");
    assert_eq!(by["distinct_messages"], 2);
    let per = by["per_message"].as_array().unwrap();
    let total: u64 = per.iter().map(|p| p["stored"].as_u64().unwrap()).sum();
    assert_eq!(total, 2, "each of the two messages was stored once");
    assert!(
        per.iter().any(|p| p["store_failed"].as_u64() == Some(1)
            && p["stored"].as_u64() == Some(1)
            && p["duplicate"].as_u64() == Some(1)),
        "the refused message: one refusal, one store after the recovery, one duplicate"
    );
}

/// Drives a RUNNING endpoint through "stored but the reply is lost": /drop-response → the message is stored (the counters show it, `responses_dropped` goes up) but the sender gets
/// NO answer within its timeout; /ok → the SAME armor again is answered `duplicate` with its hash (no second row); the counters agree.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "drives a running endpoint; needs ENDPOINT_DIR"]
async fn drive_drop_response_mode() {
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
    let armor = si_crypto::opgp::encrypt(
        ChaCha20Rng::from_seed([9; 32]),
        b"response lost then retried",
        &user,
        si_crypto::opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap();
    let a = info["entryA"]["http"].as_str().unwrap().to_string();
    let ctl = info["control"].as_str().unwrap().to_string();
    let call = |addr: String, req: String, wait: u64| async move {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let done = tokio::time::timeout(Duration::from_secs(wait), s.read_to_end(&mut out))
            .await
            .is_ok();
        (
            done,
            String::from_utf8_lossy(&out)
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .to_string(),
        )
    };
    let get = |p: &str| {
        let (ctl, p) = (ctl.clone(), p.to_string());
        async move {
            serde_json::from_str::<Value>(
                &call(
                    ctl,
                    format!("GET {p} HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n"),
                    5,
                )
                .await
                .1,
            )
            .unwrap()
        }
    };
    let body = json!({ "data": armor }).to_string();
    let post = format!("POST /post HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let before = get("/status").await;
    println!("MEASURE switch: {}", get("/drop-response").await);
    let (answered, text) = call(a.clone(), post.clone(), 3).await;
    println!("MEASURE post while the reply is dropped: answered within 3 s = {answered}, body = {text:?}");
    assert!(!answered || text.is_empty(), "the sender got no answer");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = get("/status").await;
    println!("MEASURE status after the dropped reply: {s}");
    assert_eq!(
        s["events"]["stored"].as_u64().unwrap(),
        before["events"]["stored"].as_u64().unwrap() + 1,
        "the message WAS stored"
    );
    assert_eq!(
        s["responses_dropped"].as_u64().unwrap(),
        before["responses_dropped"].as_u64().unwrap_or(0) + 1
    );
    assert_eq!(
        s["rows_stored_now"].as_u64().unwrap(),
        before["rows_stored_now"].as_u64().unwrap() + 1
    );
    println!("MEASURE switch back: {}", get("/ok").await);
    let (answered, text) = call(a.clone(), post, 8).await;
    let r: Value = serde_json::from_str(&text).unwrap();
    println!("MEASURE the SAME armor again after /ok: answered = {answered}, reply = {r}");
    assert!(
        answered && r["ok"] == true && r["duplicate"] == true,
        "the retry is answered duplicate with its hash"
    );
    let s2 = get("/status").await;
    println!("MEASURE status after the retry: {s2}");
    assert_eq!(s2["rows_stored_now"], s["rows_stored_now"], "no second row");
    assert_eq!(
        s2["events"]["duplicate"].as_u64().unwrap(),
        s["events"]["duplicate"].as_u64().unwrap() + 1
    );
    let by = get("/byhash").await;
    println!("MEASURE counts per message: {by}");
}

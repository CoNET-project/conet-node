//! Dual mailbox delivery (design §23, user decisions H-4 and W56) on 127.0.0.1 with TEST keys.
//! A = entry; the user names B and C as primary mailboxes and D as the secondary.
use conet_node::deliver::DeliveryOpts;
use conet_node::route::{RouteTable, UserRoute};
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

fn golden() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn wallet(g: &Value, name: &str) -> EthKey {
    EthKey::from_hex(g["wallets"][name]["privateKey"].as_str().unwrap()).unwrap()
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn quick() -> DeliveryOpts {
    DeliveryOpts {
        connect: Duration::from_millis(500),
        connect_retries: 1,
        reply: Duration::from_secs(2),
        primary_deadline: Duration::from_secs(3),
        secondary_deadline: Duration::from_secs(3),
        spread: Duration::from_millis(100),
        fail_after: 3,
        fail_ttl: Duration::from_secs(60),
    }
}

/// How each mailbox behaves in a scenario.
#[derive(Clone, Copy, PartialEq)]
enum Mb {
    /// A real node that stores.
    Up,
    /// Nothing listens there.
    Down,
    /// A real node whose own chain view says it may not hold mailboxes (replies `no_route`).
    NotMailbox,
    /// Listed in the entry's table without the mailbox bit (chain-invalid at the entry).
    ChainInvalid,
    /// A fake node that answers "recipient unpaid".
    Unpaid,
}

struct Net {
    golden: Value,
    a: SocketAddr,
    /// Stores of B, C, D.
    stores: [Arc<MemoryStore>; 3],
}

async fn fake_unpaid() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let _ = s.read(&mut buf).await;
                let body = r#"{"ok":false,"error":"recipient_unpaid"}"#;
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    a
}

async fn start(b: Mb, c: Mb, d: Option<Mb>) -> Net {
    let g = golden();
    // Route keys: A, B, C from the golden set; D generated (no fourth golden node key).
    let mut keys = vec![];
    for name in ["nodeA", "nodeB", "user2"] {
        keys.push(
            si_core::node::load_route(
                g["keys"][name]["armoredPrivate"].as_str().unwrap(),
                g["keys"][name]["passphrase"].as_str().unwrap(),
            )
            .unwrap(),
        );
    }
    let (d_sec, _, _) = opgp::generate_route_key(rng(9), "0xd").unwrap();
    keys.push(si_core::node::load_route(&d_sec, "").unwrap());
    let ids: Vec<String> = keys.iter().map(|k| k.1.clone()).collect();
    let wallets = ["nodeA", "nodeB", "nodeC", "other"];
    let behaviour = [Mb::Up, b, c, d.unwrap_or(Mb::Down)];

    let mut listeners = vec![];
    let mut addrs = vec![];
    for (i, m) in behaviour.iter().enumerate() {
        match m {
            Mb::Unpaid => {
                addrs.push(fake_unpaid().await);
                listeners.push(None);
            }
            Mb::Down => {
                // Bind and drop: the port is closed.
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addrs.push(l.local_addr().unwrap());
                drop(l);
                listeners.push(None);
            }
            _ => {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addrs.push(l.local_addr().unwrap());
                listeners.push(Some(l));
            }
        }
        let _ = i;
    }
    let user_key = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let stores = [
        Arc::new(MemoryStore::default()),
        Arc::new(MemoryStore::default()),
        Arc::new(MemoryStore::default()),
    ];
    for (i, ((k, id), l)) in keys.into_iter().zip(listeners).enumerate() {
        let Some(l) = l else { continue };
        let routes = RouteTable::new(&id, Duration::from_secs(3600));
        let entries = ids.iter().zip(&addrs).enumerate().map(|(j, (k, a))| {
            // The entry sees ChainInvalid nodes without the mailbox bit; a NotMailbox node
            // is missing from its own (V2-style) table.
            let mailbox = behaviour[j] != Mb::ChainInvalid;
            (k.clone(), *a, mailbox)
        });
        let entries: Vec<_> = if behaviour[i] == Mb::NotMailbox {
            entries.filter(|(k, _, _)| *k != id).collect()
        } else {
            entries.collect()
        };
        routes.replace_node_entries(entries, true);
        if i == 0 {
            let secondary = d.map(|_| ids[3].clone());
            routes.set_user_routes(
                &user_key,
                UserRoute::new(vec![ids[1].clone(), ids[2].clone()], secondary).unwrap(),
            );
        } else {
            routes.set_user_route(&user_key, &id);
        }
        let store: Arc<dyn MailboxStore> = if i == 0 {
            Arc::new(MemoryStore::default())
        } else {
            stores[i - 1].clone()
        };
        let mut ctx = NodeCtx::new(
            id,
            Arc::new(k),
            Arc::new(wallet(&g, wallets[i])),
            Arc::new(wallet(&g, wallets[i])),
            Arc::new(routes),
            store,
        );
        ctx.delivery = quick();
        tokio::spawn(server::serve(l, Arc::new(ctx)));
    }
    Net {
        golden: g,
        a: addrs[0],
        stores,
    }
}

async fn post(addr: SocketAddr, armor: &str) -> String {
    let body = json!({ "data": armor }).to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /post HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(15), s.read(&mut out))
        .await
        .expect("reply timeout")
        .unwrap_or(0);
    String::from_utf8_lossy(&out[..n]).into_owned()
}

fn mail(g: &Value, seed: u8) -> String {
    let to =
        opgp::PublicCert::from_armor(g["keys"]["user"]["armoredPublic"].as_str().unwrap()).unwrap();
    opgp::encrypt(
        rng(seed),
        b"dual mailbox test",
        &to,
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap()
}

impl Net {
    fn count(&self, i: usize) -> usize {
        let user = self.golden["keys"]["user"]["encKeyId"].as_str().unwrap();
        self.stores[i].pending(user).len()
    }
    /// Wait until the stores hold `want` (B, C, D) or time out.
    async fn expect(&self, want: [usize; 3]) {
        for _ in 0..50 {
            if [self.count(0), self.count(1), self.count(2)] == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "stores {:?}, want {want:?}",
            [self.count(0), self.count(1), self.count(2)]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn both_primaries_store_and_secondary_stays_empty() {
    let n = start(Mb::Up, Mb::Up, Some(Mb::Up)).await;
    let resp = post(n.a, &mail(&n.golden, 1)).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    n.expect([1, 1, 0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_primary_down_is_enough() {
    let n = start(Mb::Up, Mb::Down, Some(Mb::Up)).await;
    let resp = post(n.a, &mail(&n.golden, 2)).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    n.expect([1, 0, 0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn chain_invalid_and_down_primaries_fall_back_to_secondary() {
    let n = start(Mb::ChainInvalid, Mb::Down, Some(Mb::Up)).await;
    let resp = post(n.a, &mail(&n.golden, 3)).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    n.expect([0, 0, 1]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refusing_primaries_fall_back_to_secondary() {
    let n = start(Mb::NotMailbox, Mb::NotMailbox, Some(Mb::Up)).await;
    let resp = post(n.a, &mail(&n.golden, 4)).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    n.expect([0, 0, 1]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unpaid_everywhere_tells_the_sender() {
    let n = start(Mb::Unpaid, Mb::Unpaid, None).await;
    let resp = post(n.a, &mail(&n.golden, 5)).await;
    assert!(
        resp.ends_with(r#"{"ok":false,"error":"recipient_unpaid"}"#),
        "{resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unpaid_primaries_still_try_the_secondary() {
    let n = start(Mb::Unpaid, Mb::Down, Some(Mb::Up)).await;
    let resp = post(n.a, &mail(&n.golden, 6)).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    n.expect([0, 0, 1]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_reachable_is_a_plain_failure() {
    let n = start(Mb::Down, Mb::Down, Some(Mb::Down)).await;
    let resp = post(n.a, &mail(&n.golden, 7)).await;
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    n.expect([0, 0, 0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn all_chain_invalid_is_no_route() {
    let n = start(Mb::ChainInvalid, Mb::ChainInvalid, Some(Mb::ChainInvalid)).await;
    let resp = post(n.a, &mail(&n.golden, 8)).await;
    assert!(
        resp.ends_with(r#"{"ok":false,"error":"no_route"}"#),
        "{resp}"
    );
}

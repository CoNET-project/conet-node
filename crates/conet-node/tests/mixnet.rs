//! M3 mixed-network regression: live CoNET-SI nodes and conet-node nodes in one network.
//! Runs only with `MIXNET_CONFIG=<work>/mixnet.json` (written by `tools/mixnet/setup.mjs`);
//! `tools/mixnet/run.sh` builds and starts the network in an isolated network namespace.
//! TEST keys only. Every scenario crosses implementations in both directions.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::store::armor_hash;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Mix {
    g: Value,
    c: Value,
}

fn load() -> Option<Mix> {
    let path = std::env::var("MIXNET_CONFIG").ok()?;
    let g = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    Some(Mix {
        g: serde_json::from_str(&std::fs::read_to_string(g).unwrap()).unwrap(),
        c: serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(),
    })
}

macro_rules! mix {
    () => {
        match load() {
            Some(m) => m,
            None => {
                eprintln!("skipped: MIXNET_CONFIG not set");
                return;
            }
        }
    };
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    ChaCha20Rng::from_seed(seed)
}

impl Mix {
    fn node(&self, name: &str) -> &Value {
        self.c["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == name)
            .unwrap_or_else(|| panic!("node {name}"))
    }
    fn addr(&self, name: &str) -> SocketAddr {
        self.node(name)["addr"].as_str().unwrap().parse().unwrap()
    }
    fn node_cert(&self, name: &str) -> opgp::PublicCert {
        opgp::PublicCert::from_armor(self.node(name)["armoredPublic"].as_str().unwrap()).unwrap()
    }
    fn node_wallet(&self, name: &str) -> String {
        self.node(name)["wallet"].as_str().unwrap().to_string()
    }
    fn user(&self, name: &str) -> &Value {
        self.c["users"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == name)
            .unwrap()
    }
    fn user_cert(&self, name: &str) -> opgp::PublicCert {
        let k = self.user(name)["goldenKey"].as_str().unwrap();
        opgp::PublicCert::from_armor(self.g["keys"][k]["armoredPublic"].as_str().unwrap()).unwrap()
    }
    fn wallet(&self, golden_name: &str) -> EthKey {
        EthKey::from_hex(
            self.g["wallets"][golden_name]["privateKey"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }
    fn user_wallet(&self, user: &str) -> EthKey {
        self.wallet(self.user(user)["goldenWallet"].as_str().unwrap())
    }
    fn mailbox_of(&self, user: &str) -> String {
        self.user(user)["mailbox"].as_str().unwrap().to_string()
    }

    /// Signed command `{message, signMessage}`, base64, encrypted to node `to` (client form).
    fn command(&self, signer: &EthKey, cmd: Value, to: &str) -> String {
        let message = cmd.to_string();
        let sig = signer.sign_message(&message).unwrap();
        enc(
            B64.encode(json!({ "message": message, "signMessage": sig }).to_string())
                .as_bytes(),
            &self.node_cert(to),
            true,
        )
    }
}

fn enc(data: &[u8], to: &opgp::PublicCert, text: bool) -> String {
    opgp::encrypt(
        rng(),
        data,
        to,
        opgp::EncryptOpts {
            text,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap()
}

async fn open(addr: SocketAddr, armor: &str) -> TcpStream {
    let body = json!({ "data": armor }).to_string();
    let mut s = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .expect("connect timeout")
        .expect("connect");
    s.write_all(
        format!(
            "POST /post HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    s
}

/// Whole reply (status line kept), until close or 15 s.
async fn post_raw(addr: SocketAddr, armor: &str) -> String {
    let mut s = open(addr, armor).await;
    let mut out = Vec::new();
    let mut chunk = [0u8; 16384];
    let end = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        match tokio::time::timeout_at(end, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                out.extend_from_slice(&chunk[..n]);
                // Bodies with a length are complete once that many bytes are in.
                let t = String::from_utf8_lossy(&out);
                if let Some(i) = t.find("\r\n\r\n") {
                    let head = t[..i].to_ascii_lowercase();
                    if let Some(l) = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                    {
                        if out.len() >= i + 4 + l {
                            break;
                        }
                    }
                }
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn body(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

/// A mailbox listen through an entry, as the client sees it.
struct Listen {
    s: TcpStream,
    key: [u8; 32],
    buf: String,
}

impl Listen {
    async fn connect(m: &Mix, user: &str, entry: &str) -> Self {
        let mut key = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut key);
        let w = m.user_wallet(user);
        let cmd = json!({ "command": "mailbox_listen", "walletAddress": w.address(), "streamKey": B64.encode(key), "timestamp": now() });
        let mailbox = m.mailbox_of(user);
        let s = open(m.addr(entry), &m.command(&w, cmd, &mailbox)).await;
        let mut l = Self {
            s,
            key,
            buf: String::new(),
        };
        let hs = l
            .next(10)
            .await
            .unwrap_or_else(|| panic!("listen handshake via {entry} at {mailbox}"));
        assert_eq!(hs["kind"], "mailbox", "{hs}");
        assert_eq!(
            hs["nodeWallet"].as_str().unwrap_or("").to_lowercase(),
            m.node_wallet(&mailbox)
        );
        l
    }
    async fn next(&mut self, secs: u64) -> Option<Value> {
        loop {
            let frame = self.buf.find("data: ").and_then(|i| {
                let rest = &self.buf[i + 6..];
                rest.find("\r\n")
                    .map(|end| (rest[..end].to_string(), rest[end..].to_string()))
            });
            if let Some((payload, rest)) = frame {
                self.buf = rest;
                let (json, _) = si_core::open_mailbox(&payload, &self.key).expect("sealed frame");
                return Some(serde_json::from_str(&json).unwrap());
            }
            let mut chunk = [0u8; 16384];
            match tokio::time::timeout(Duration::from_secs(secs), self.s.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => self.buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
                _ => return None,
            }
        }
    }
    /// Next frame carrying `armor` (skips others), within `secs`; returns the armor as received.
    async fn take(&mut self, armor: &str, secs: u64) -> Option<String> {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        while tokio::time::Instant::now() < end {
            match self.next(secs).await {
                Some(f) => {
                    let got = f["data"].as_str().unwrap_or("");
                    if got.trim_end() == armor.trim_end() {
                        return Some(got.to_string());
                    }
                }
                None => return None,
            }
        }
        None
    }
    async fn expect(&mut self, armor: &str, secs: u64) -> bool {
        self.take(armor, secs).await.is_some()
    }
}

/// Live delivery: listen through one entry, send through another.
async fn live(m: &Mix, user: &str, listen_via: &str, send_via: &str) {
    let mut l = Listen::connect(m, user, listen_via).await;
    let msg = enc(
        format!("live {user} {listen_via}->{send_via} {}", now()).as_bytes(),
        &m.user_cert(user),
        true,
    );
    let r = post_raw(m.addr(send_via), &msg).await;
    assert!(r.starts_with("HTTP/1.1 200"), "post via {send_via}: {r}");
    assert!(
        l.expect(&msg, 10).await,
        "{user}: listen via {listen_via} at {} did not get mail sent via {send_via}",
        m.mailbox_of(user)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mailbox_live_delivery_across_implementations() {
    let m = mix!();
    // user1's mailbox is R1 (Rust), user2's is S2 (SI).
    live(&m, "user1", "S1", "S2").await; // SI entries -> Rust mailbox
    live(&m, "user1", "R2", "S1").await;
    live(&m, "user2", "R1", "R2").await; // Rust entries -> SI mailbox
    live(&m, "user2", "S1", "R1").await;
}

async fn offline_then_ack(m: &Mix, user: &str, send_via: &str, ack_via: &str) {
    let msg = enc(
        format!("offline {user} {}", now()).as_bytes(),
        &m.user_cert(user),
        true,
    );
    let r = post_raw(m.addr(send_via), &msg).await;
    assert!(r.starts_with("HTTP/1.1 200"), "post via {send_via}: {r}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut l = Listen::connect(m, user, ack_via).await;
    let got = l
        .take(&msg, 10)
        .await
        .unwrap_or_else(|| panic!("{user}: stored mail flushed on listen"));
    drop(l);
    // Clients ACK the hash of the armor as they received it.
    let w = m.user_wallet(user);
    let ack = json!({ "command": "gossip_delivery_ack", "walletAddress": w.address(), "armorHash": armor_hash(&got), "timestamp": now() });
    let r = post_raw(m.addr(ack_via), &m.command(&w, ack, &m.mailbox_of(user))).await;
    let v: Value = serde_json::from_str(body(&r)).unwrap_or(Value::Null);
    assert_eq!(v["ok"], true, "ack via {ack_via}: {r}");
    assert_eq!(
        v["removed"],
        true,
        "ack removed the stored mail at {}: {r}",
        m.mailbox_of(user)
    );
    let mut l = Listen::connect(m, user, ack_via).await;
    assert!(!l.expect(&msg, 3).await, "acked mail is not flushed again");
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_store_flush_and_ack_across_implementations() {
    let m = mix!();
    offline_then_ack(&m, "user1", "S2", "S1").await; // Rust mailbox, SI entries
    offline_then_ack(&m, "user2", "R1", "R2").await; // SI mailbox, Rust entries
}

#[tokio::test(flavor = "multi_thread")]
async fn onion_layers_peel_across_implementations() {
    let m = mix!();
    for (user, outer_node, entry) in [("user2", "R2", "R2"), ("user1", "S1", "S1")] {
        let mut l = Listen::connect(&m, user, entry).await;
        let inner = enc(
            format!("onion {user} {}", now()).as_bytes(),
            &m.user_cert(user),
            true,
        );
        let outer = enc(inner.as_bytes(), &m.node_cert(outer_node), true);
        let r = post_raw(m.addr(entry), &outer).await;
        assert!(r.starts_with("HTTP/1.1 200"), "onion via {entry}: {r}");
        assert!(l.expect(&inner, 10).await, "{user}: onion inner delivered");
    }
}

// ---------------------------------------------------------------- voice v3

fn voice_listen(m: &Mix, relay: &str, session: &str, wk: &[u8; 32]) -> String {
    let wk = B64.encode(wk);
    let ts = now();
    let relay_key = m.node(relay)["keyId"].as_str().unwrap();
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let temp = EthKey::from_hex(&hex::encode(seed)).unwrap();
    let temp_sig = temp
        .sign_message(&si_proto::voice_listen_text(
            session, &wk, relay_key, ts as u64,
        ))
        .unwrap();
    let payer = m.wallet("payer");
    let not_after = ts + 3600;
    let pay_sig = payer
        .sign_message(&si_proto::voice_pay_text(
            &temp.address(),
            not_after as u64,
            0,
            0,
        ))
        .unwrap();
    let cmd = json!({ "command": "voice_listen", "v": 3, "sessionId": session, "wk": wk, "timestamp": ts, "temp": temp.address(), "tempSig": temp_sig,
        "pay": { "payer": payer.address(), "notAfter": not_after, "maxBytes": 0, "maxSeconds": 0, "sig": pay_sig } });
    enc(
        B64.encode(cmd.to_string()).as_bytes(),
        &m.node_cert(relay),
        true,
    )
}

fn voice_chunk(m: &Mix, relay: &str, session: &str, wk: &[u8; 32], blob: &[u8]) -> String {
    let loc = hex::decode(session).unwrap();
    let mut c = si_proto::VOICE_CHUNK_MAGIC.to_vec();
    c.extend_from_slice(&loc);
    c.extend_from_slice(&si_crypto::sym::chunk_mac(wk, &loc, blob));
    c.extend_from_slice(blob);
    enc(&c, &m.node_cert(relay), false)
}

async fn read_until(s: &mut TcpStream, buf: &mut String, want: &str, secs: u64) -> bool {
    let mut chunk = [0u8; 16384];
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !buf.contains(want) {
        match tokio::time::timeout_at(end, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
            _ => return false,
        }
    }
    true
}

async fn voice(m: &Mix, relay: &str, listen_via: &str, send_via: &str) {
    let mut wk = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut wk);
    let sid = conet_node::voice::random_session_id();
    let mut l = open(m.addr(listen_via), &voice_listen(m, relay, &sid, &wk)).await;
    let mut buf = String::new();
    let ready = si_proto::voice::ready_frame(&sid, &m.node_wallet(relay));
    assert!(
        read_until(&mut l, &mut buf, &ready, 10).await,
        "voice ready from {relay} via {listen_via}: {buf}"
    );
    for i in 0..3u8 {
        let r = post_raw(
            m.addr(send_via),
            &voice_chunk(m, relay, &sid, &wk, &[i; 40]),
        )
        .await;
        assert_eq!(
            serde_json::from_str::<Value>(body(&r)).unwrap_or(Value::Null),
            json!({ "ok": true }),
            "chunk {i} via {send_via}: {r}"
        );
    }
    for i in 0..3u8 {
        let f = si_proto::voice::chunk_frame(&B64.encode([i; 40]));
        assert!(
            read_until(&mut l, &mut buf, &f, 10).await,
            "chunk {i} relayed by {relay}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn voice_v3_relay_across_implementations() {
    let m = mix!();
    voice(&m, "R1", "S1", "S2").await; // Rust relay, SI entries
    voice(&m, "S2", "R1", "R2").await; // SI relay, Rust entries
}

// ---------------------------------------------------------------- SilentPass exit

fn sock5(m: &Mix, signer: &EthKey, exit: &str, host: &str, port: u16, first: &[u8]) -> String {
    let cmd = json!({ "command": "SaaS_Sock5", "walletAddress": signer.address(), "requestData": [{ "host": host, "port": port, "buffer": B64.encode(first) }] });
    m.command(signer, cmd, exit)
}

async fn exit_echo(m: &Mix, exit: &str, entry: &str) {
    let target: SocketAddr = m.c["exitTarget"].as_str().unwrap().parse().unwrap();
    let payer = m.user_wallet("user1");
    let first = format!("hello via {exit} {}", now());
    let mut s = open(
        m.addr(entry),
        &sock5(
            m,
            &payer,
            exit,
            &target.ip().to_string(),
            target.port(),
            first.as_bytes(),
        ),
    )
    .await;
    let mut got = vec![0u8; first.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
        .await
        .unwrap_or_else(|_| panic!("exit {exit} via {entry}: no echo"))
        .unwrap();
    assert_eq!(got, first.as_bytes(), "echo through {exit}");
    s.write_all(b"more").await.unwrap();
    let mut more = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut more))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&more, b"more", "both directions");

    // An unpaid wallet gets the SI 402 page from either implementation.
    let unpaid = m.wallet("billing");
    let r = post_raw(
        m.addr(entry),
        &sock5(
            m,
            &unpaid,
            exit,
            &target.ip().to_string(),
            target.port(),
            b"x",
        ),
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 402"), "unpaid via {exit}: {r}");
}

#[tokio::test(flavor = "multi_thread")]
async fn silentpass_exit_across_implementations() {
    let m = mix!();
    exit_echo(&m, "R1", "S1").await; // Rust exit, SI entry
    exit_echo(&m, "S2", "R2").await; // SI exit, Rust entry
}

// ---------------------------------------------------------------- legacy chat presence

#[tokio::test(flavor = "multi_thread")]
async fn legacy_chat_listen_and_presence_query_across_implementations() {
    let m = mix!();
    for (user, entry, query_via) in [("user1", "S1", "R2"), ("user2", "R1", "S1")] {
        let w = m.user_wallet(user);
        let mailbox = m.mailbox_of(user);
        let cmd =
            json!({ "command": "mining", "listenKind": "chat", "walletAddress": w.address() });
        let mut legacy = open(m.addr(entry), &m.command(&w, cmd, &mailbox)).await;
        let mut buf = String::new();
        assert!(
            read_until(&mut legacy, &mut buf, "text/event-stream", 10).await,
            "legacy listen at {mailbox}: {buf}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        let asker = m.wallet("other");
        let q = json!({ "command": "wallet_online_query", "walletAddress": asker.address(), "targetWallet": w.address(), "timestamp": now() });
        let r = post_raw(m.addr(query_via), &m.command(&asker, q, &mailbox)).await;
        let v: Value = serde_json::from_str(body(&r)).unwrap_or(Value::Null);
        assert_eq!(v["online"], true, "{user} online at {mailbox}: {r}");
    }
}

//! W35 end-to-end: a WebRTC peer (str0m, playing the browser) dials entry A over ICE-lite,
//! opens one data channel per HTTP request and runs a mailbox listen plus a delivery to B.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{BoxFut, ChainError, UserRoutes};
use conet_node::route::RouteTable;
use conet_node::server::{self, NodeCtx};
use conet_node::store::MemoryStore;
use conet_node::webrtc::{serve_webrtc, statement, verify_statement, Endpoint, WebRtcOpts};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};
use si_crypto::{eth::EthKey, opgp};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use str0m::channel::{ChannelConfig, ChannelId};
use str0m::config::Fingerprint;
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
    user_wallet: String,
    node_b_key: String,
    node_b_wallet: String,
}

impl UserRoutes for Chain {
    fn route_of_user_key<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(k.eq_ignore_ascii_case(&self.user_key)
                .then(|| self.node_b_key.clone()))
        })
    }
    fn user_key_of_wallet<'a>(
        &'a self,
        w: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(w.eq_ignore_ascii_case(&self.user_wallet)
                .then(|| self.user_key.clone()))
        })
    }
    fn wallet_of_user_key<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            Ok(k.eq_ignore_ascii_case(&self.user_key)
                .then(|| self.user_wallet.to_lowercase()))
        })
    }
    fn is_my_route<'a>(&'a self, u: &'a str, n: &'a str) -> BoxFut<'a, Result<bool, ChainError>> {
        Box::pin(async move {
            Ok(u.eq_ignore_ascii_case(&self.user_wallet)
                && n.eq_ignore_ascii_case(&self.node_b_wallet))
        })
    }
}

struct Net {
    g: Value,
    a_tcp: SocketAddr,
    a_udp: SocketAddr,
    fingerprint: String,
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
    let ((ka, ida), (kb, idb)) = (load("nodeA"), load("nodeB"));
    let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
    let user_key = g["keys"]["user"]["encKeyId"].as_str().unwrap().to_string();
    let chain: Arc<dyn UserRoutes> = Arc::new(Chain {
        user_key,
        user_wallet: g["wallets"]["client"]["address"].as_str().unwrap().into(),
        node_b_key: idb.clone(),
        node_b_wallet: g["wallets"]["nodeB"]["address"].as_str().unwrap().into(),
    });
    let routes = |own: &str| {
        let r = RouteTable::new(own, Duration::from_secs(600));
        r.replace_nodes([(ida.clone(), aa), (idb.clone(), ab)]);
        Arc::new(r)
    };
    let mut ca = NodeCtx::new(
        ida.clone(),
        Arc::new(ka),
        Arc::new(wallet(&g, "nodeA")),
        Arc::new(wallet(&g, "nodeA")),
        routes(&ida),
        Arc::new(MemoryStore::default()),
    );
    ca.user_routes = Some(chain.clone());
    let mut cb = NodeCtx::new(
        idb.clone(),
        Arc::new(kb),
        Arc::new(wallet(&g, "nodeB")),
        Arc::new(wallet(&g, "nodeB")),
        routes(&idb),
        Arc::new(MemoryStore::default()),
    );
    cb.user_routes = Some(chain);
    let ca = Arc::new(ca);

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_udp = sock.local_addr().unwrap();
    let ep = Arc::new(Endpoint::ephemeral().unwrap());
    let st = statement(&ca, &ep, a_udp, Duration::from_secs(3600)).unwrap();
    *ca.webrtc.write().unwrap() = Some(st);
    let fingerprint = ep.fingerprint().to_string();
    tokio::spawn(serve_webrtc(sock, ca.clone(), ep, WebRtcOpts::new(a_udp)));
    tokio::spawn(server::serve(la, ca));
    tokio::spawn(server::serve(lb, Arc::new(cb)));
    Net {
        g,
        a_tcp: aa,
        a_udp,
        fingerprint,
    }
}

fn enc(seed: u8, text: &str, to: &opgp::PublicCert) -> String {
    opgp::encrypt(
        ChaCha20Rng::from_seed([seed; 32]),
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

fn command(g: &Value, signer: &str, cmd: Value, seed: u8) -> String {
    let message = cmd.to_string();
    let sig = wallet(g, signer).sign_message(&message).unwrap();
    enc(
        seed,
        &B64.encode(json!({ "message": message, "signMessage": sig }).to_string()),
        &pubkey(g, "nodeB"),
    )
}

fn post_request(armor: &str) -> Vec<u8> {
    let body = json!({ "data": armor }).to_string();
    format!(
        "POST /post HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The browser side: a full ICE agent (controlling), DTLS client, SCTP client, as Chrome is
/// after `setRemoteDescription(answer_sdp(..))`.
struct Peer {
    rtc: Rtc,
    sock: UdpSocket,
    local: SocketAddr,
    /// Bytes received per channel.
    got: HashMap<ChannelId, Vec<u8>>,
    opened: Vec<ChannelId>,
    closed: Vec<ChannelId>,
    /// Requests to send once the channel opens.
    pending: HashMap<ChannelId, Vec<u8>>,
}

impl Peer {
    async fn dial(server: SocketAddr, fingerprint: &str) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = sock.local_addr().unwrap();
        let ufrag = "conet1ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".to_string();
        let creds = IceCreds {
            ufrag: ufrag.clone(),
            pass: ufrag,
        };
        let provider = Arc::new(str0m::crypto::from_feature_flags());
        let mut rtc = RtcConfig::new()
            .set_crypto_provider(provider)
            .set_local_ice_credentials(creds.clone())
            .build(Instant::now());
        rtc.add_local_candidate(Candidate::host(local, "udp").unwrap());
        rtc.add_remote_candidate(Candidate::host(server, "udp").unwrap());
        let fp: Fingerprint = fingerprint.parse().unwrap();
        let mut api = rtc.direct_api();
        api.set_remote_ice_credentials(creds);
        api.set_remote_fingerprint(fp);
        api.set_ice_controlling(true);
        api.start_dtls(true).unwrap();
        api.start_sctp(true);
        Self {
            rtc,
            sock,
            local,
            got: HashMap::new(),
            opened: vec![],
            closed: vec![],
            pending: HashMap::new(),
        }
    }

    /// A new channel (DCEP open, as `pc.createDataChannel("post")`) that sends `req` once open.
    fn request(&mut self, req: Vec<u8>) -> ChannelId {
        let cid = self.rtc.direct_api().create_data_channel(ChannelConfig {
            label: "post".into(),
            ..Default::default()
        });
        self.pending.insert(cid, req);
        cid
    }

    /// Run the peer for `d`, or until `done` says stop.
    async fn run_until(&mut self, d: Duration, mut done: impl FnMut(&Peer) -> bool) -> bool {
        let end = Instant::now() + d;
        let mut buf = vec![0u8; 2048];
        loop {
            let mut wake = end;
            loop {
                let Ok(out) = self.rtc.poll_output() else {
                    return false; // DTLS failure, e.g. wrong fingerprint
                };
                match out {
                    Output::Timeout(t) => {
                        wake = wake.min(t);
                        break;
                    }
                    Output::Transmit(t) => {
                        self.sock.send_to(&t.contents, t.destination).await.unwrap();
                    }
                    Output::Event(e) => match e {
                        Event::ChannelOpen(cid, _) => self.opened.push(cid),
                        Event::ChannelData(d) => {
                            self.got.entry(d.id).or_default().extend_from_slice(&d.data)
                        }
                        Event::ChannelClose(cid) => self.closed.push(cid),
                        _ => {}
                    },
                }
            }
            // Send what SCTP accepts now; keep the rest for later (like bufferedAmount).
            let ready: Vec<ChannelId> = self
                .pending
                .keys()
                .copied()
                .filter(|c| self.opened.contains(c))
                .collect();
            let mut wrote = false;
            for cid in ready {
                let req = self.pending.get_mut(&cid).unwrap();
                while !req.is_empty() {
                    let n = req.len().min(si_proto::webrtc::MAX_MESSAGE);
                    if !self
                        .rtc
                        .channel(cid)
                        .unwrap()
                        .write(true, &req[..n])
                        .unwrap()
                    {
                        break;
                    }
                    req.drain(..n);
                    wrote = true;
                }
                // let str0m packetise the writes now (see the note in webrtc::drive)
                let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));
                if req.is_empty() {
                    self.pending.remove(&cid);
                } else {
                    wake = wake.min(Instant::now() + Duration::from_millis(5));
                }
            }
            if done(self) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            if wrote {
                continue; // transmit what was just written before sleeping
            }
            let sleep = wake.max(Instant::now()).min(end);
            tokio::select! {
                r = self.sock.recv_from(&mut buf) => {
                    let (n, src) = r.unwrap();
                    let input = Input::Receive(Instant::now(), Receive {
                        proto: Protocol::Udp,
                        source: src,
                        destination: self.local,
                        contents: DatagramRecv::try_from(&buf[..n]).unwrap(),
                    });
                    // A DTLS failure (wrong fingerprint) ends the peer, as in a browser.
                    if self.rtc.handle_input(input).is_err() {
                        return false;
                    }
                }
                _ = tokio::time::sleep_until(sleep.into()) => {
                    if self.rtc.handle_input(Input::Timeout(Instant::now())).is_err() {
                        return false;
                    }
                }
            }
        }
    }

    fn text(&self, cid: ChannelId) -> String {
        String::from_utf8_lossy(self.got.get(&cid).map(|v| v.as_slice()).unwrap_or(&[]))
            .into_owned()
    }
}

fn body(http: &str) -> String {
    http.split("\r\n\r\n")
        .skip(1)
        .collect::<Vec<_>>()
        .join("\r\n\r\n")
}

/// SSE frames on the listen channel, opened with the stream key.
fn frames(text: &str, key: &[u8; 32]) -> Vec<Value> {
    text.split("data: ")
        .skip(1)
        // only frames that arrived completely
        .filter_map(|f| f.find("\r\n\r\n").map(|end| &f[..end]))
        .map(|p| {
            let (json, _) = si_core::open_mailbox(p, key).expect("sealed frame opens");
            serde_json::from_str(&json).unwrap()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_and_deliver_over_webrtc() {
    let n = start().await;
    let mut p = Peer::dial(n.a_udp, &n.fingerprint).await;

    // channel 1: a mailbox listen, streamed (SSE) over the data channel
    let key = [7u8; 32];
    let cmd = json!({ "command": "mailbox_listen", "walletAddress": n.g["wallets"]["client"]["address"], "streamKey": B64.encode(key), "timestamp": now() });
    let listen = p.request(post_request(&command(&n.g, "client", cmd, 7)));
    assert!(
        p.run_until(Duration::from_secs(10), |p| p
            .text(listen)
            .contains("data: "))
            .await,
        "listen handshake over webrtc"
    );
    let hs = frames(&p.text(listen), &key);
    assert_eq!(hs[0]["kind"], "mailbox");

    // channel 2: deliver a message through entry A; it reaches the listen on B
    let m1 = enc(10, "over webrtc", &pubkey(&n.g, "user"));
    let deliver = p.request(post_request(&m1));
    assert!(
        p.run_until(Duration::from_secs(10), |p| frames(&p.text(listen), &key)
            .len()
            >= 2
            && p.closed.contains(&deliver))
            .await,
        "delivery answered and pushed to the listen"
    );
    assert!(p.text(deliver).starts_with("HTTP/1.1 200"));
    assert_eq!(body(&p.text(deliver)), "");
    assert_eq!(frames(&p.text(listen), &key)[1]["data"], m1);
    assert!(!p.closed.contains(&listen), "listen stays open");

    // OPTIONS preflight on a third channel
    let opt = p.request(b"OPTIONS /post HTTP/1.1\r\nHost: t\r\n\r\n".to_vec());
    assert!(
        p.run_until(Duration::from_secs(5), |p| p.closed.contains(&opt))
            .await
    );
    assert!(p.text(opt).starts_with("HTTP/1.1 204"));
}

#[tokio::test(flavor = "multi_thread")]
async fn statement_is_signed_by_node_wallet() {
    let n = start().await;
    let mut s = TcpStream::connect(n.a_tcp).await.unwrap();
    s.write_all(b"GET /webrtc HTTP/1.1\r\nHost: t\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    let json = body(&String::from_utf8_lossy(&out));
    let signer = verify_statement(&json).unwrap();
    assert_eq!(
        signer.to_lowercase(),
        n.g["wallets"]["nodeA"]["address"]
            .as_str()
            .unwrap()
            .to_lowercase()
    );
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["fingerprint"], n.fingerprint);
    assert_eq!(v["port"], n.a_udp.port());

    // any edit breaks the signature
    let mut forged = v.clone();
    forged["port"] = json!(n.a_udp.port().wrapping_add(1));
    assert!(verify_statement(&forged.to_string()).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_fingerprint_never_opens() {
    let n = start().await;
    let wrong = format!("sha-256 {}", vec!["00"; 32].join(":"));
    let mut p = Peer::dial(n.a_udp, &wrong).await;
    let c = p.request(b"OPTIONS /post HTTP/1.1\r\n\r\n".to_vec());
    assert!(
        !p.run_until(Duration::from_secs(4), |p| p.opened.contains(&c))
            .await,
        "DTLS fingerprint mismatch must stop the browser side"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn junk_and_bad_ufrag_open_no_session() {
    let n = start().await;
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // not STUN, then a STUN binding with a ufrag that breaks the rules: neither may answer
    s.send_to(b"hello", n.a_udp).await.unwrap();
    let user = b"bad:bad";
    let mut p = vec![0x00, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xA4, 0x42];
    p.extend_from_slice(&[1u8; 12]);
    p.extend_from_slice(&[0x00, 0x06, 0x00, user.len() as u8]);
    p.extend_from_slice(user);
    p.push(0);
    s.send_to(&p, n.a_udp).await.unwrap();
    let mut buf = [0u8; 512];
    let r = tokio::time::timeout(Duration::from_millis(800), s.recv_from(&mut buf)).await;
    assert!(r.is_err(), "no reply to junk");
}

#[tokio::test(flavor = "multi_thread")]
async fn large_message_crosses_in_chunks() {
    let n = start().await;
    let mut p = Peer::dial(n.a_udp, &n.fingerprint).await;
    let key = [9u8; 32];
    let cmd = json!({ "command": "mailbox_listen", "walletAddress": n.g["wallets"]["client"]["address"], "streamKey": B64.encode(key), "timestamp": now() });
    let listen = p.request(post_request(&command(&n.g, "client", cmd, 9)));
    assert!(
        p.run_until(Duration::from_secs(10), |p| p
            .text(listen)
            .contains("data: "))
            .await
    );
    // ~150 KB of incompressible text: many 16 KB messages each way
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let mut raw = vec![0u8; 110 * 1024];
    rand_core::RngCore::fill_bytes(&mut rng, &mut raw);
    let big = enc(11, &B64.encode(&raw), &pubkey(&n.g, "user"));
    assert!(big.len() > 140 * 1024);
    let deliver = p.request(post_request(&big));
    assert!(
        p.run_until(Duration::from_secs(15), |p| frames(&p.text(listen), &key)
            .len()
            >= 2
            && p.closed.contains(&deliver))
            .await,
        "large delivery reached the listen"
    );
    assert_eq!(frames(&p.text(listen), &key)[1]["data"], big);
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_per_ip_are_capped() {
    let n = start().await;
    let cap = WebRtcOpts::new(n.a_udp).max_sessions_per_ip;
    let mut peers = Vec::new();
    for _ in 0..cap {
        let mut p = Peer::dial(n.a_udp, &n.fingerprint).await;
        let c = p.request(b"OPTIONS /post HTTP/1.1\r\n\r\n".to_vec());
        assert!(
            p.run_until(Duration::from_secs(5), |p| p.opened.contains(&c))
                .await
        );
        peers.push(p);
    }
    let mut extra = Peer::dial(n.a_udp, &n.fingerprint).await;
    let c = extra.request(b"OPTIONS /post HTTP/1.1\r\n\r\n".to_vec());
    assert!(
        !extra
            .run_until(Duration::from_secs(3), |p| p.opened.contains(&c))
            .await,
        "one session over the per-IP cap gets no answer"
    );
}

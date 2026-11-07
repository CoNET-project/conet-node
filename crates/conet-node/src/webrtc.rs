//! WebRTC entry (decision W35): browsers deliver to the node over a WebRTC data channel instead
//! of HTTPS, so they need no CA certificate and no signalling server.
//!
//! - The node listens ICE-lite on one UDP port with a long-lived self-signed DTLS certificate.
//! - It publishes a wallet-signed endpoint statement (IP, port, DTLS fingerprint, expiry).
//! - The browser builds the node's SDP answer locally from that statement
//!   (`si_proto::webrtc::answer_sdp`), using one random `ufrag` as ICE username fragment and
//!   password on both sides. The node learns the `ufrag` from the first STUN binding request.
//! - The browser checks the DTLS fingerprint during the handshake, which ties the connection to
//!   the signed statement. The node does not check the browser's certificate (the requests carry
//!   their own authentication, as on `/post`).
//! - Every data channel the browser opens is one virtual connection carrying the same HTTP bytes
//!   as TCP :80, handed to `server::handle`. So `/post`, SSE listens, voice and the exit behave
//!   exactly as over TCP.
use crate::limits::ConnSlot;
use crate::server::{handle, NodeCtx};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use si_proto::webrtc as w;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use str0m::channel::ChannelId;
use str0m::config::{CryptoProvider, DtlsCert};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, IceCreds, Input, Output, Rtc, RtcConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct WebRtcOpts {
    /// Address in the SDP and the endpoint statement (IPv4). Packets are fed to str0m as if
    /// addressed to it, so a node behind 1:1 NAT works with a private bind address.
    pub public: SocketAddr,
    pub max_sessions: usize,
    pub max_sessions_per_ip: usize,
    /// New sessions per IP per minute (token bucket, burst = this value).
    pub new_sessions_per_ip_per_min: u32,
    pub max_channels_per_session: usize,
    /// A session must finish ICE + DTLS within this time.
    pub handshake_timeout: Duration,
    /// A session with no datagram for this long is dropped.
    pub idle_timeout: Duration,
    /// Bytes from the browser waiting for a slow handler, per channel; more closes the channel.
    pub max_inbound_backlog: usize,
}

impl WebRtcOpts {
    pub fn new(public: SocketAddr) -> Self {
        Self {
            public,
            max_sessions: 1024,
            max_sessions_per_ip: 8,
            new_sessions_per_ip_per_min: 30,
            max_channels_per_session: 32,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            max_inbound_backlog: 1024 * 1024,
        }
    }
}

/// The node's DTLS identity for WebRTC.
pub struct Endpoint {
    provider: Arc<CryptoProvider>,
    cert: DtlsCert,
    fingerprint: String,
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

impl Endpoint {
    fn from_cert(provider: Arc<CryptoProvider>, cert: DtlsCert) -> std::io::Result<Self> {
        let mut probe = RtcConfig::new()
            .set_crypto_provider(provider.clone())
            .set_dtls_cert(cert.clone())
            .build(Instant::now());
        let fingerprint = probe.direct_api().local_dtls_fingerprint().to_string();
        if !w::valid_fingerprint(&fingerprint) {
            return Err(io_err(format!("unexpected fingerprint form {fingerprint}")));
        }
        Ok(Self {
            provider,
            cert,
            fingerprint,
        })
    }

    /// New certificate kept in memory only (tests).
    pub fn ephemeral() -> std::io::Result<Self> {
        let provider = Arc::new(str0m::crypto::from_feature_flags());
        let cert = provider
            .dtls_provider
            .generate_certificate()
            .ok_or_else(|| io_err("dtls certificate"))?;
        Self::from_cert(provider, cert)
    }

    /// Load the certificate from `path`, or create it there on first start (mode 0600). It
    /// must survive restarts: the fingerprint is part of the signed endpoint statement.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        let provider = Arc::new(str0m::crypto::from_feature_flags());
        if let Ok(text) = std::fs::read_to_string(path) {
            let v: serde_json::Value = serde_json::from_str(&text).map_err(io_err)?;
            let field = |k: &str| -> std::io::Result<Vec<u8>> {
                B64.decode(v[k].as_str().unwrap_or_default())
                    .map_err(io_err)
            };
            let cert = DtlsCert {
                certificate: field("certificate")?,
                private_key: field("privateKey")?,
            };
            return Self::from_cert(provider, cert);
        }
        let ep = Self::ephemeral()?;
        let body = serde_json::json!({
            "certificate": B64.encode(&ep.cert.certificate),
            "privateKey": B64.encode(&ep.cert.private_key),
        })
        .to_string();
        write_private(path, body.as_bytes())?;
        Ok(ep)
    }

    /// `sha-256 AB:CD:…`
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

fn placeholder_fingerprint() -> str0m::config::Fingerprint {
    format!("sha-256 {}", ["00"; 32].join(":"))
        .parse()
        .expect("fingerprint literal")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Signed endpoint statement as JSON, valid for `valid` from now.
pub fn statement(
    ctx: &NodeCtx,
    ep: &Endpoint,
    public: SocketAddr,
    valid: Duration,
) -> Result<String, String> {
    let IpAddr::V4(ip) = public.ip() else {
        return Err("WebRTC endpoint must be IPv4".into());
    };
    let expires = now_secs() + valid.as_secs() as i64;
    let ip = ip.to_string();
    let sig = ctx
        .notices
        .sign_webrtc_endpoint(&ctx.key_id, &ip, public.port(), &ep.fingerprint, expires)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "v": 1,
        "keyId": ctx.key_id.to_ascii_uppercase(),
        "wallet": ctx.wallet.address().to_ascii_lowercase(),
        "ip": ip,
        "port": public.port(),
        "fingerprint": ep.fingerprint,
        "expires": expires,
        "signature": sig,
    })
    .to_string())
}

/// What a browser must check before dialling: signature by the claimed wallet, valid fields,
/// not expired. Returns the wallet. (The wallet still has to match the node table.)
pub fn verify_statement(json: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let port = v["port"].as_u64().unwrap_or(0);
    let expires = v["expires"].as_i64().unwrap_or(0);
    if v["v"] != 1
        || port == 0
        || port > u16::MAX as u64
        || !w::valid_fingerprint(&s("fingerprint"))
        || s("ip").parse::<std::net::Ipv4Addr>().is_err()
        || expires <= now_secs()
    {
        return Err("statement fields".into());
    }
    let text = w::endpoint_text(
        &s("keyId"),
        &s("wallet"),
        &s("ip"),
        port as u16,
        &s("fingerprint"),
        expires,
    );
    let signer =
        si_crypto::eth::recover_message(&text, &s("signature")).map_err(|e| e.to_string())?;
    if !signer.eq_ignore_ascii_case(&s("wallet")) {
        return Err("statement signer".into());
    }
    Ok(signer)
}

enum ToLoop {
    Data {
        peer: SocketAddr,
        cid: ChannelId,
        bytes: Vec<u8>,
        permit: OwnedSemaphorePermit,
    },
    Close {
        peer: SocketAddr,
        cid: ChannelId,
    },
}

struct Chan {
    /// Browser → handler.
    inbound: mpsc::Sender<Vec<u8>>,
    backlog: VecDeque<Vec<u8>>,
    backlog_bytes: usize,
    /// Handler → browser, waiting for SCTP buffer space. The permit limits the reader pump.
    outbound: VecDeque<(Vec<u8>, OwnedSemaphorePermit)>,
    /// The handler finished; close the channel once `outbound` is sent.
    closing: bool,
    _slot: ConnSlot,
}

struct Session {
    rtc: Rtc,
    ip: IpAddr,
    created: Instant,
    last_rx: Instant,
    next_timeout: Instant,
    chans: HashMap<ChannelId, Chan>,
    dead: bool,
}

struct Server {
    sock: Arc<UdpSocket>,
    ctx: Arc<NodeCtx>,
    ep: Arc<Endpoint>,
    opts: WebRtcOpts,
    tx: mpsc::Sender<ToLoop>,
    sessions: HashMap<SocketAddr, Session>,
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

/// Handler → browser chunks in flight per channel (× MAX_MESSAGE bytes).
const OUT_PERMITS: usize = 64;
const INBOUND_QUEUE: usize = 64;
const PIPE_BYTES: usize = 64 * 1024;

pub async fn serve_webrtc(
    sock: UdpSocket,
    ctx: Arc<NodeCtx>,
    ep: Arc<Endpoint>,
    opts: WebRtcOpts,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<ToLoop>(4096);
    let mut srv = Server {
        sock: Arc::new(sock),
        ctx,
        ep,
        opts,
        tx,
        sessions: HashMap::new(),
        buckets: HashMap::new(),
    };
    let mut buf = vec![0u8; 2048];
    let mut last_sweep = Instant::now();
    loop {
        let now = Instant::now();
        let wake = srv
            .sessions
            .values()
            .map(|s| s.next_timeout)
            .min()
            .unwrap_or(now + Duration::from_secs(1))
            .min(now + Duration::from_secs(1))
            .max(now);
        tokio::select! {
            r = srv.sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, src)) => srv.on_datagram(src, &buf[..n]),
                    // ICMP port unreachable surfaces here on some systems; not fatal.
                    Err(e) => debug!(?e, "webrtc recv"),
                }
            }
            Some(m) = rx.recv() => srv.on_loop(m),
            _ = tokio::time::sleep_until(wake.into()) => {}
        }
        let now = Instant::now();
        let due: Vec<SocketAddr> = srv
            .sessions
            .iter()
            .filter(|(_, s)| s.next_timeout <= now)
            .map(|(a, _)| *a)
            .collect();
        for peer in due {
            if let Some(s) = srv.sessions.get_mut(&peer) {
                if s.rtc.handle_input(Input::Timeout(now)).is_err() {
                    s.dead = true;
                }
            }
            srv.drive(peer);
        }
        if now.duration_since(last_sweep) >= Duration::from_secs(1) {
            last_sweep = now;
            srv.sweep(now);
        }
    }
}

impl Server {
    fn on_datagram(&mut self, src: SocketAddr, bytes: &[u8]) {
        let now = Instant::now();
        if !self.sessions.contains_key(&src) && !self.try_open(src, bytes, now) {
            return;
        }
        let Ok(contents) = DatagramRecv::try_from(bytes) else {
            return;
        };
        let input = Input::Receive(
            now,
            Receive {
                proto: Protocol::Udp,
                source: src,
                destination: self.opts.public,
                contents,
            },
        );
        let Some(s) = self.sessions.get_mut(&src) else {
            return;
        };
        s.last_rx = now;
        if s.rtc.accepts(&input) && s.rtc.handle_input(input).is_err() {
            s.dead = true;
        }
        self.drive(src);
    }

    /// First datagram from an address: only a STUN binding request with a valid `ufrag` opens a
    /// session, within the per-IP and global limits. Anything else is dropped silently.
    fn try_open(&mut self, src: SocketAddr, bytes: &[u8], now: Instant) -> bool {
        let Some(user) = w::stun_binding_username(bytes) else {
            return false;
        };
        let Some((local, remote)) = user.split_once(':') else {
            return false;
        };
        if !w::valid_ufrag(local) || local != remote {
            return false;
        }
        let ip = src.ip();
        if self.sessions.len() >= self.opts.max_sessions
            || self.sessions.values().filter(|s| s.ip == ip).count()
                >= self.opts.max_sessions_per_ip
            || !self.bucket_take(ip, now)
        {
            return false;
        }
        let creds = IceCreds {
            ufrag: local.to_string(),
            pass: local.to_string(),
        };
        let mut rtc = RtcConfig::new()
            .set_crypto_provider(self.ep.provider.clone())
            .set_dtls_cert(self.ep.cert.clone())
            .set_ice_lite(true)
            .set_fingerprint_verification(false)
            .set_local_ice_credentials(creds.clone())
            .build(now);
        let Ok(cand) = Candidate::host(self.opts.public, "udp") else {
            return false;
        };
        rtc.add_local_candidate(cand);
        let mut api = rtc.direct_api();
        api.set_remote_ice_credentials(creds);
        // str0m wants some remote fingerprint even with verification off; the browser's is
        // unknown here and not needed (see the module notes).
        api.set_remote_fingerprint(placeholder_fingerprint());
        api.set_ice_controlling(false);
        if api.start_dtls(false).is_err() {
            return false;
        }
        api.start_sctp(false);
        self.sessions.insert(
            src,
            Session {
                rtc,
                ip,
                created: now,
                last_rx: now,
                next_timeout: now,
                chans: HashMap::new(),
                dead: false,
            },
        );
        true
    }

    fn bucket_take(&mut self, ip: IpAddr, now: Instant) -> bool {
        let cap = self.opts.new_sessions_per_ip_per_min as f64;
        let (tokens, at) = self.buckets.entry(ip).or_insert((cap, now));
        let refill = now.duration_since(*at).as_secs_f64() * cap / 60.0;
        *tokens = (*tokens + refill).min(cap);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn on_loop(&mut self, m: ToLoop) {
        let peer = match m {
            ToLoop::Data {
                peer,
                cid,
                bytes,
                permit,
            } => {
                if let Some(c) = self
                    .sessions
                    .get_mut(&peer)
                    .and_then(|s| s.chans.get_mut(&cid))
                {
                    c.outbound.push_back((bytes, permit));
                }
                peer
            }
            ToLoop::Close { peer, cid } => {
                if let Some(c) = self
                    .sessions
                    .get_mut(&peer)
                    .and_then(|s| s.chans.get_mut(&cid))
                {
                    c.closing = true;
                }
                peer
            }
        };
        self.drive(peer);
    }

    /// Poll str0m until it wants a timeout; handle events; move queued bytes both ways.
    fn drive(&mut self, peer: SocketAddr) {
        let Some(s) = self.sessions.get_mut(&peer) else {
            return;
        };
        let mut opened: Vec<ChannelId> = Vec::new();
        loop {
            // str0m only turns channel writes into SCTP packets on input; a timeout tick "now"
            // sends them at once instead of at the next scheduled timeout (up to ~200 ms).
            if Self::flush(s) && s.rtc.handle_input(Input::Timeout(Instant::now())).is_err() {
                s.dead = true;
            }
            match s.rtc.poll_output() {
                Ok(Output::Timeout(t)) => {
                    s.next_timeout = t;
                    break;
                }
                Ok(Output::Transmit(t)) => {
                    // UDP is lossy anyway: a full socket buffer drops the datagram.
                    let _ = self.sock.try_send_to(&t.contents, t.destination);
                }
                Ok(Output::Event(e)) => match e {
                    Event::ChannelOpen(cid, _) => opened.push(cid),
                    Event::ChannelData(d) => {
                        if let Some(c) = s.chans.get_mut(&d.id) {
                            c.backlog_bytes += d.data.len();
                            c.backlog.push_back(d.data);
                            if c.backlog_bytes > self.opts.max_inbound_backlog {
                                warn!("webrtc channel backlog over limit; closing");
                                s.chans.remove(&d.id);
                                s.rtc.direct_api().close_data_channel(d.id);
                            }
                        }
                    }
                    Event::ChannelClose(cid) => {
                        s.chans.remove(&cid);
                    }
                    Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                        s.dead = true;
                    }
                    _ => {}
                },
                Err(e) => {
                    debug!(?e, "webrtc session error");
                    s.dead = true;
                    break;
                }
            }
        }
        if !opened.is_empty() {
            for cid in opened {
                self.open_channel(peer, cid);
            }
            // Send the DCEP ACK now (the browser waits for it before sending), then move any
            // bytes the new channels already have.
            if let Some(s) = self.sessions.get_mut(&peer) {
                if s.rtc.handle_input(Input::Timeout(Instant::now())).is_err() {
                    s.dead = true;
                }
            }
            self.drive(peer);
        }
    }

    /// Move queued bytes both ways. True when something was written to str0m or closed.
    fn flush(s: &mut Session) -> bool {
        let mut progressed = false;
        let mut done: Vec<ChannelId> = Vec::new();
        for (cid, c) in s.chans.iter_mut() {
            while let Some(front) = c.backlog.front() {
                let len = front.len();
                match c.inbound.try_reserve() {
                    Ok(permit) => {
                        let bytes = c.backlog.pop_front().expect("front");
                        c.backlog_bytes -= len;
                        permit.send(bytes);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        c.backlog.clear();
                        c.backlog_bytes = 0;
                        break;
                    }
                }
            }
            let Some(mut ch) = s.rtc.channel(*cid) else {
                continue;
            };
            while let Some((bytes, _)) = c.outbound.front() {
                match ch.write(true, bytes) {
                    Ok(true) => {
                        c.outbound.pop_front();
                        progressed = true;
                    }
                    Ok(false) => break,
                    Err(_) => {
                        c.outbound.clear();
                        c.closing = true;
                        break;
                    }
                }
            }
            if c.closing && c.outbound.is_empty() {
                done.push(*cid);
            }
        }
        for cid in done {
            s.chans.remove(&cid);
            s.rtc.direct_api().close_data_channel(cid);
            progressed = true;
        }
        progressed
    }

    fn open_channel(&mut self, peer: SocketAddr, cid: ChannelId) {
        let Some(s) = self.sessions.get_mut(&peer) else {
            return;
        };
        let slot = if s.chans.len() < self.opts.max_channels_per_session {
            self.ctx
                .ip_limiter
                .admit(s.ip, self.ctx.routes.is_node_ip(s.ip))
        } else {
            None
        };
        let Some(slot) = slot else {
            s.rtc.direct_api().close_data_channel(cid);
            return;
        };
        if let Some(mut ch) = s.rtc.channel(cid) {
            ch.set_buffered_amount_low_threshold(w::MAX_MESSAGE * 4);
        }
        let (conn, pipe) = tokio::io::duplex(PIPE_BYTES);
        let (mut pipe_rd, mut pipe_wr) = tokio::io::split(pipe);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(INBOUND_QUEUE);
        s.chans.insert(
            cid,
            Chan {
                inbound: in_tx,
                backlog: VecDeque::new(),
                backlog_bytes: 0,
                outbound: VecDeque::new(),
                closing: false,
                _slot: slot,
            },
        );
        let ctx = self.ctx.clone();
        tokio::spawn(async move { handle(Box::new(conn), peer, ctx).await });
        // Browser → handler.
        tokio::spawn(async move {
            while let Some(bytes) = in_rx.recv().await {
                if pipe_wr.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            let _ = pipe_wr.shutdown().await;
        });
        // Handler → browser, at most OUT_PERMITS chunks ahead of SCTP.
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(OUT_PERMITS));
            let mut chunk = vec![0u8; w::MAX_MESSAGE];
            loop {
                let Ok(permit) = permits.clone().acquire_owned().await else {
                    break;
                };
                match pipe_rd.read(&mut chunk).await {
                    Ok(n) if n > 0 => {
                        let m = ToLoop::Data {
                            peer,
                            cid,
                            bytes: chunk[..n].to_vec(),
                            permit,
                        };
                        if tx.send(m).await.is_err() {
                            return;
                        }
                    }
                    _ => break,
                }
            }
            let _ = tx.send(ToLoop::Close { peer, cid }).await;
        });
    }

    fn sweep(&mut self, now: Instant) {
        let o = &self.opts;
        self.sessions.retain(|_, s| {
            let keep = !s.dead
                && s.rtc.is_alive()
                && (s.rtc.is_connected() || now.duration_since(s.created) < o.handshake_timeout)
                && now.duration_since(s.last_rx) < o.idle_timeout;
            if !keep {
                s.rtc.disconnect();
            }
            keep
        });
        let cap = o.new_sessions_per_ip_per_min as f64;
        self.buckets
            .retain(|_, (t, at)| *t + now.duration_since(*at).as_secs_f64() * cap / 60.0 < cap);
    }
}

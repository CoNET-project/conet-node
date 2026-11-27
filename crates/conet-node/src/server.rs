//! Accept loop and `/post` handling: entry, onion, hop sigs (A1); user-route lookup, mailbox
//! delivery and commands (A2).
use crate::chain::UserRoutes;
use crate::http::{self, Limits, ReadError};
use crate::limits::{IpLimiter, IpPolicy};
use crate::mailbox::Mailbox;
use crate::push::{NoPush, Push};
use crate::route::{Resolved, RouteTable};
use crate::store::{MailboxStore, Stored};
use crate::watcher::ChainState;
use si_core::node::{Node, Step};
use si_core::{LocalRoute, NodeNotices, RouteDecryptor, WalletSigner, WriteKeys};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Any client connection: plain TCP (:80) or TLS (:443).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Conn = Box<dyn Io>;

pub struct NodeCtx {
    pub key_id: String,
    /// Retiring route keys (R11): still accepted as local, never published.
    pub old_key_ids: Vec<String>,
    pub decryptor: Arc<dyn RouteDecryptor>,
    pub wallet: Arc<dyn WalletSigner>,
    pub notices: Arc<dyn NodeNotices>,
    pub routes: Arc<RouteTable>,
    /// AddressPGP (or a test double). None = static routes only.
    pub user_routes: Option<Arc<dyn UserRoutes>>,
    pub mailbox: Arc<Mailbox>,
    pub voice: Arc<crate::voice::VoiceRelay>,
    pub offers: Arc<dyn crate::store::OfferStore>,
    /// SilentPass exit (`SaaS_Sock5*`); None = not an exit.
    pub exit: Option<Arc<crate::exit::Exit>>,
    pub push: Arc<dyn Push>,
    pub chain: Arc<ChainState>,
    pub limits: Limits,
    pub connect_timeout: Duration,
    pub max_connections: usize,
    pub ip_limiter: Arc<IpLimiter>,
    /// Accept the legacy `mining` + `listenKind:"chat"` presence listen (decision U3).
    pub legacy_chat_listen: bool,
    /// Signed WebRTC endpoint statement (W35), served on `GET /webrtc`; None = no WebRTC entry.
    pub webrtc: std::sync::RwLock<Option<String>>,
    /// Multi-mailbox delivery timing (§23.4) and the per-node network failure record.
    pub delivery: crate::deliver::DeliveryOpts,
    pub fail_cache: Arc<crate::deliver::FailCache>,
    /// CoNET chain RPC used for currentInfo by the signed mining_validator command. None = the
    /// route source has no RPC-backed epoch authority; the command reports unavailable.
    pub epoch_rpc: Option<crate::chain::Rpc>,
    #[cfg(test)]
    /// Optional injected validator wallet authority snapshot. None preserves the existing route
    /// table lookup; there is no production configuration or remote source wired by default.
    pub validator_wallet_source:
        Option<Arc<dyn crate::validator_wallet_source::ValidatorWalletSource>>,
    pub validator_pools: Arc<crate::validator_mining::Pools>,
    pub mining_liveness: Arc<crate::mining_liveness::MiningLiveness>,
    /// Explicitly opt into CoNET mining SSE publishing; disabled by default.
    pub mining_liveness_enabled: bool,
    /// Explicit address advertised in SI mining heartbeats. The remote connection peer's IP is
    /// not an authoritative substitute for this node's configured public address.
    pub mining_node_ip: Option<std::net::Ipv4Addr>,
    /// `--evidence-log`: node-side delivery evidence rows. None = off (default).
    pub evidence: Option<Arc<crate::evidence::EvidenceLog>>,
}

impl NodeCtx {
    /// Defaults: no API push, no chain user routes, default limits.
    pub fn new(
        key_id: String,
        decryptor: Arc<dyn RouteDecryptor>,
        wallet: Arc<dyn WalletSigner>,
        notices: Arc<dyn NodeNotices>,
        routes: Arc<RouteTable>,
        store: Arc<dyn MailboxStore>,
    ) -> Self {
        let push: Arc<dyn Push> = Arc::new(NoPush);
        Self {
            key_id,
            old_key_ids: vec![],
            decryptor,
            wallet,
            notices,
            routes,
            user_routes: None,
            mailbox: Arc::new(Mailbox::new(store, push.clone())),
            voice: Arc::new(crate::voice::VoiceRelay::default()),
            offers: Arc::new(crate::store::MemoryOffers::default()),
            exit: None,
            push,
            chain: Arc::new(ChainState::default()),
            limits: Limits::default(),
            connect_timeout: Duration::from_secs(8),
            max_connections: 4096,
            ip_limiter: IpLimiter::new(IpPolicy::default()),
            legacy_chat_listen: true,
            webrtc: std::sync::RwLock::new(None),
            delivery: crate::deliver::DeliveryOpts::default(),
            fail_cache: Arc::new(crate::deliver::FailCache::default()),
            epoch_rpc: None,
            #[cfg(test)]
            validator_wallet_source: None,
            validator_pools: Arc::new(crate::validator_mining::Pools::default()),
            mining_liveness: Arc::new(crate::mining_liveness::MiningLiveness::default()),
            mining_liveness_enabled: false,
            mining_node_ip: None,
            evidence: None,
        }
    }

    /// Cached route, else ask AddressPGP once (negative answers cached briefly).
    pub async fn resolve(&self, key_id: &str) -> Resolved {
        self.resolve_with_timeout(key_id, Duration::from_secs(5))
            .await
    }

    async fn resolve_with_timeout(&self, key_id: &str, timeout: Duration) -> Resolved {
        let r = self.routes.resolve(key_id);
        if r != Resolved::NoRoute || self.routes.recently_unknown(key_id) {
            return r;
        }
        let Some(ur) = &self.user_routes else {
            return r;
        };
        match resolve_user_route(&self.routes, ur.as_ref(), key_id, timeout).await {
            Ok(route) => route,
            Err(LookupFailure::Rpc(e)) => {
                warn!(%e, "route lookup failed");
                Resolved::LookupUnavailable
            }
            Err(LookupFailure::Timeout) => {
                warn!(key_id, "route lookup timed out");
                Resolved::LookupUnavailable
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LookupFailure {
    Rpc(String),
    Timeout,
}

async fn lookup_user_routes(
    routes: &dyn UserRoutes,
    key_id: &str,
    timeout: Duration,
) -> Result<Option<crate::route::UserRoute>, LookupFailure> {
    match tokio::time::timeout(timeout, routes.routes_of_user_key(key_id)).await {
        Ok(Ok(route)) => Ok(route),
        Ok(Err(e)) => Err(LookupFailure::Rpc(e.to_string())),
        Err(_) => Err(LookupFailure::Timeout),
    }
}

async fn resolve_user_route(
    table: &RouteTable,
    source: &dyn UserRoutes,
    key_id: &str,
    timeout: Duration,
) -> Result<Resolved, LookupFailure> {
    match lookup_user_routes(source, key_id, timeout).await? {
        Some(route) => {
            table.set_user_routes(key_id, route);
            Ok(table.resolve(key_id))
        }
        None => {
            table.mark_unknown(key_id);
            Ok(Resolved::NoRoute)
        }
    }
}

fn route_error_response(resolved: &Resolved) -> Option<Vec<u8>> {
    match resolved {
        Resolved::NoRoute => Some(http::ok_200(r#"{"ok":false,"error":"no_route"}"#)),
        Resolved::LookupUnavailable => Some(http::service_unavailable(
            r#"{"ok":false,"error":"route_lookup_unavailable"}"#,
        )),
        _ => None,
    }
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn serve(listener: TcpListener, ctx: Arc<NodeCtx>) -> std::io::Result<()> {
    tokio::spawn(ctx.voice.clone().sweep_loop());
    tokio::spawn(ctx.validator_pools.clone().sweep_loop());
    tokio::spawn(crate::mining_liveness::run_publisher(ctx.clone()));
    let slots = Arc::new(Semaphore::new(ctx.max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            // Over capacity: drop the connection instead of queueing without bound.
            drop(stream);
            continue;
        };
        let Some(slot) = ctx
            .ip_limiter
            .admit(peer.ip(), ctx.routes.is_node_ip(peer.ip()))
        else {
            drop(stream);
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _slot = slot;
            let _ = stream.set_nodelay(true);
            handle(Box::new(stream), peer, ctx).await;
        });
    }
}

pub(crate) async fn handle(mut stream: Conn, peer: SocketAddr, ctx: Arc<NodeCtx>) {
    let req = match http::read_request(&mut stream, &ctx.limits).await {
        Ok(r) => r,
        Err(ReadError::Closed) => return,
        Err(e) => {
            debug!(?e, "bad request");
            let _ = stream.write_all(&http::not_found()).await;
            return;
        }
    };
    if request_has_upgrade(&req) {
        let _ = stream.write_all(&http::upgrade_refused()).await;
        return;
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("OPTIONS", _) => {
            let _ = stream.write_all(&http::options_204()).await;
        }
        ("POST", p) if p.starts_with("/post") => post(stream, peer, req, ctx).await,
        ("GET", "/webrtc") => {
            let st = ctx.webrtc.read().expect("webrtc").clone();
            let resp = match st {
                Some(json) => http::ok_200(&json),
                None => http::not_found(),
            };
            let _ = stream.write_all(&resp).await;
        }
        _ => {
            let _ = stream.write_all(&http::not_found()).await;
        }
    }
}

fn request_has_upgrade(request: &http::Request) -> bool {
    request.method.eq_ignore_ascii_case("upgrade")
        || request.header_lines.iter().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("upgrade")
                || (name.trim().eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|v| v.trim().eq_ignore_ascii_case("upgrade")))
        })
}

async fn post(mut stream: Conn, peer: SocketAddr, req: http::Request, ctx: Arc<NodeCtx>) {
    let Ok(body) = String::from_utf8(req.body) else {
        let _ = stream.write_all(&http::not_found()).await;
        return;
    };
    // Evidence only: hashes of the armor as received (nothing is kept when the flag is off).
    let received = ctx
        .evidence
        .as_ref()
        .and_then(|_| crate::evidence::Received::of_body(&body));
    // PGP work is CPU-bound: keep it off the I/O threads.
    let c = ctx.clone();
    let lines = req.header_lines.clone();
    let step = tokio::task::spawn_blocking(move || {
        let node = Node {
            route: LocalRoute {
                key: &*c.decryptor,
                key_id: &c.key_id,
                old_key_ids: &c.old_key_ids,
            },
            wallet: &*c.wallet,
            write_keys: WriteKeys::new(),
        };
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        node.on_post(&refs, &body)
    })
    .await;
    let Ok(step) = step else {
        let _ = stream.write_all(&http::not_found()).await;
        return;
    };
    match step {
        Step::Route {
            key_id,
            armor,
            no_push,
            hops,
        } => {
            let resolved = ctx.resolve(&key_id).await;
            if let Some(response) = route_error_response(&resolved) {
                if let Some(ev) = &ctx.evidence {
                    let why = if resolved == Resolved::NoRoute {
                        "route_unknown"
                    } else {
                        "lookup_unavailable"
                    };
                    ev.post_refused(received.as_ref(), false, why);
                }
                let _ = stream.write_all(&response).await;
                return;
            }
            match resolved {
                Resolved::Plan(plan) => {
                    if let Some(ev) = &ctx.evidence {
                        ev.post_forward(
                            received.as_ref(),
                            &armor,
                            None,
                            hops.len(),
                            crate::evidence::Forward::Plan,
                        );
                    }
                    crate::deliver::deliver(stream, plan, key_id, armor, no_push, hops, ctx).await;
                }
                Resolved::Local => {
                    let hop_bytes = Node::verified_hop_bytes(&hops, now_secs());
                    let hops_len = hops.len();
                    let evidence_armor = ctx.evidence.is_some().then(|| armor.clone());
                    let report = ctx.mailbox.deliver_report(
                        &key_id,
                        Stored {
                            armor,
                            no_push,
                            hop_bytes,
                            hops: hops_len,
                        },
                    );
                    if let (Some(ev), Some(a)) = (&ctx.evidence, evidence_armor) {
                        ev.store(received.as_ref(), &a, report);
                    }
                    let _ = stream.write_all(&http::ok_200("")).await;
                }
                Resolved::Remote(addr) => {
                    // The wallet may be the signer client (blocking socket call): keep it off I/O threads.
                    let c = ctx.clone();
                    let hops_len = hops.len();
                    let (k, a, h) = (key_id.clone(), armor.clone(), hops);
                    let header = tokio::task::spawn_blocking(move || {
                        let node = Node {
                            route: LocalRoute {
                                key: &*c.decryptor,
                                key_id: &c.key_id,
                                old_key_ids: &c.old_key_ids,
                            },
                            wallet: &*c.wallet,
                            write_keys: WriteKeys::new(),
                        };
                        node.forward_header(&h, &k, &a, now_secs())
                    })
                    .await
                    .unwrap_or(Err("join"));
                    match header {
                        Ok(header) => {
                            if let Some(ev) = &ctx.evidence {
                                ev.post_forward(
                                    received.as_ref(),
                                    &armor,
                                    Some(addr),
                                    hops_len,
                                    crate::evidence::Forward::SameArmor,
                                );
                            }
                            forward(
                                stream,
                                addr,
                                &header,
                                &armor,
                                &req.leftover,
                                ctx.connect_timeout,
                            )
                            .await
                        }
                        Err(reason) => {
                            if let Some(ev) = &ctx.evidence {
                                ev.post_refused(received.as_ref(), true, reason);
                            }
                            debug!(reason, "forward refused");
                            let _ = stream.shutdown().await;
                        }
                    }
                }
                Resolved::NoRoute | Resolved::LookupUnavailable => unreachable!("handled above"),
            }
        }
        Step::Command {
            command, signed, ..
        } => crate::commands::dispatch(stream, peer, command, signed, ctx).await,
        Step::VoiceChunk { locator, mac, blob } => {
            crate::voice::chunk(stream, locator, mac, blob, ctx).await
        }
        Step::Close { reason, attack } => {
            if let Some(ev) = &ctx.evidence {
                ev.post_refused(received.as_ref(), attack, reason);
            }
            debug!(reason, attack, "close");
            if attack {
                let _ = stream.shutdown().await;
            } else {
                let _ = stream.write_all(&http::not_found()).await;
            }
        }
    }
}

/// SI `socketForward`: send the request to the next node and pipe both directions until
/// either side ends (the response may be a long SSE).
async fn forward(
    mut client: Conn,
    addr: SocketAddr,
    hop_header: &str,
    armor: &str,
    leftover: &[u8],
    connect_timeout: Duration,
) {
    let body = serde_json::json!({ "data": armor }).to_string();
    let upstream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await;
    let mut up = match upstream {
        Ok(Ok(s)) => s,
        _ => {
            warn!("forward connect failed");
            let _ = client.write_all(&http::not_found()).await;
            return;
        }
    };
    let _ = up.set_nodelay(true);
    let reqb = http::forward_request(&addr.ip().to_string(), addr.port(), hop_header, &body);
    if up.write_all(&reqb).await.is_err()
        || (!leftover.is_empty() && up.write_all(leftover).await.is_err())
    {
        let _ = client.write_all(&http::not_found()).await;
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

/// Local health endpoint for the updater and boot guard. Bind it to 127.0.0.1 only.
/// `GET /healthz` → `ok <version> nodes=<n> listens=<n>`; anything else → 404.
pub async fn serve_health(listener: TcpListener, ctx: Arc<NodeCtx>) -> std::io::Result<()> {
    loop {
        let (mut s, _) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let lim = Limits {
                max_body_bytes: 0,
                ..Limits::default()
            };
            let Ok(req) = http::read_request(&mut s, &lim).await else {
                return;
            };
            let body = if req.method == "GET" && req.path == "/healthz" {
                http::ok_200(&format!(
                    "ok {} nodes={} listens={}",
                    env!("CARGO_PKG_VERSION"),
                    ctx.routes.node_count(),
                    ctx.mailbox.listener_count()
                ))
            } else {
                http::not_found()
            };
            let _ = s.write_all(&body).await;
        });
    }
}

#[cfg(test)]
mod rpc_state_tests {
    use super::*;
    use crate::chain::BoxFut;
    use crate::route::UserRoute;

    #[derive(Clone, Copy)]
    enum Reply {
        Missing,
        Error,
        Wait,
        Route,
    }

    struct Routes(Reply);

    impl UserRoutes for Routes {
        fn route_of_user_key<'a>(
            &'a self,
            _: &'a str,
        ) -> BoxFut<'a, Result<Option<String>, crate::chain::ChainError>> {
            Box::pin(async { Ok(None) })
        }

        fn routes_of_user_key<'a>(
            &'a self,
            _: &'a str,
        ) -> BoxFut<'a, Result<Option<UserRoute>, crate::chain::ChainError>> {
            Box::pin(async move {
                match self.0 {
                    Reply::Missing => Ok(None),
                    Reply::Route => Ok(Some(UserRoute::single("node"))),
                    Reply::Error => Err(crate::chain::ChainError("rpc unavailable".into())),
                    Reply::Wait => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        Ok(None)
                    }
                }
            })
        }

        fn user_key_of_wallet<'a>(
            &'a self,
            _: &'a str,
        ) -> BoxFut<'a, Result<Option<String>, crate::chain::ChainError>> {
            Box::pin(async { Ok(None) })
        }

        fn wallet_of_user_key<'a>(
            &'a self,
            _: &'a str,
        ) -> BoxFut<'a, Result<Option<String>, crate::chain::ChainError>> {
            Box::pin(async { Ok(None) })
        }

        fn is_my_route<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> BoxFut<'a, Result<bool, crate::chain::ChainError>> {
            Box::pin(async { Ok(false) })
        }
    }

    struct TestDeps;
    impl RouteDecryptor for TestDeps {
        fn decrypt(&self, _: &str) -> si_crypto::Result<Vec<u8>> {
            panic!("not called by route resolution tests")
        }
    }
    impl WalletSigner for TestDeps {
        fn address(&self) -> String {
            "0x0000000000000000000000000000000000000001".into()
        }
        fn sign_message(&self, _: &str) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
    }
    impl NodeNotices for TestDeps {
        fn sign_validator_heartbeat(&self, _: u64, _: &str) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
        fn sign_epoch(&self, _: u64) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
        fn sign_offline_chat(&self, _: &str, _: &str, _: u64) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
        fn sign_native_wakeable(&self, _: &str, _: u64) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
        fn sign_voice_call_push(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: i64,
            _: i64,
        ) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
        fn sign_webrtc_endpoint(
            &self,
            _: &str,
            _: &str,
            _: u16,
            _: &str,
            _: i64,
        ) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
        fn sign_acme_dns01(&self, _: &str, _: &str, _: &str, _: i64) -> si_crypto::Result<String> {
            panic!("not called by route resolution tests")
        }
    }

    fn context(routes: Reply) -> NodeCtx {
        let table = Arc::new(RouteTable::new("self", Duration::from_secs(60)));
        table.replace_nodes([("node".into(), "127.0.0.1:9100".parse().unwrap())]);
        let deps = Arc::new(TestDeps);
        let mut ctx = NodeCtx::new(
            "self".into(),
            deps.clone(),
            deps.clone(),
            deps,
            table,
            Arc::new(crate::store::MemoryStore::default()),
        );
        ctx.user_routes = Some(Arc::new(Routes(routes)));
        ctx
    }

    async fn handle_raw_request(method: &str, path: &str, extra_headers: &[&str]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ctx = context(Reply::Missing);
        let (server_io, mut client_io) = tokio::io::duplex(8192);
        let task = tokio::spawn(handle(
            Box::new(server_io),
            "127.0.0.1:12345".parse().unwrap(),
            Arc::new(ctx),
        ));
        let body = if method.eq_ignore_ascii_case("POST") {
            br#"{"jsonrpc":"2.0","id":7,"method":"getBalance","params":["mock-wallet"]}"#.as_slice()
        } else {
            b"".as_slice()
        };
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
        if method.eq_ignore_ascii_case("POST") {
            request.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        for header in extra_headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        if !extra_headers.iter().any(|h| {
            h.split_once(':')
                .is_some_and(|(n, _)| n.eq_ignore_ascii_case("connection"))
        }) {
            request.push_str("Connection: close\r\n");
        }
        request.push_str("\r\n");
        client_io.write_all(request.as_bytes()).await.unwrap();
        client_io.write_all(body).await.unwrap();
        let mut response = Vec::new();
        client_io.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn removed_solana_rpc_paths_use_only_generic_fallbacks() {
        for (method, path, expected) in [
            ("GET", "/solana-rpc", "404 Not Found"),
            ("POST", "/solana-rpc", "404 Not Found"),
            ("GET", "/solana-rpc/", "404 Not Found"),
            ("POST", "/solana-rpc/nested?case=rpc&n=0", "404 Not Found"),
            ("GET", "/SOLANA-RPC?query=1", "404 Not Found"),
            ("POST", "/SoLaNa-RpC/child?x=y", "404 Not Found"),
            // OPTIONS remains the server's generic CORS response, not a proxy route.
            ("OPTIONS", "/solana-rpc", "204 No Content"),
            ("OPTIONS", "/solana-rpc/nested?x=y", "204 No Content"),
            ("OPTIONS", "/SOLANA-RPC?query=1", "204 No Content"),
        ] {
            let response = handle_raw_request(method, path, &[]).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected}")),
                "{method} {path}: {response:?}"
            );
        }
        // Unrelated generic routes retain their existing behavior.
        assert!(handle_raw_request("OPTIONS", "/ordinary", &[])
            .await
            .starts_with("HTTP/1.1 204"));
    }

    #[tokio::test]
    async fn websocket_upgrade_is_still_refused_before_generic_fallback() {
        let response = handle_raw_request(
            "GET",
            "/solana-rpc",
            &[
                "Connection: keep-alive, Upgrade",
                "Upgrade: websocket",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version: 13",
            ],
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("protocol_upgrade_unsupported"));
    }

    #[tokio::test]
    async fn route_lookup_failure_is_not_cached_and_explicit_missing_is_cached() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ErrorThenMissing(AtomicUsize);
        impl UserRoutes for ErrorThenMissing {
            fn route_of_user_key<'a>(
                &'a self,
                _: &'a str,
            ) -> BoxFut<'a, Result<Option<String>, crate::chain::ChainError>> {
                Box::pin(async { Ok(None) })
            }

            fn routes_of_user_key<'a>(
                &'a self,
                _: &'a str,
            ) -> BoxFut<'a, Result<Option<UserRoute>, crate::chain::ChainError>> {
                Box::pin(async move {
                    if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(crate::chain::ChainError("rpc unavailable".into()))
                    } else {
                        Ok(None)
                    }
                })
            }

            fn user_key_of_wallet<'a>(
                &'a self,
                _: &'a str,
            ) -> BoxFut<'a, Result<Option<String>, crate::chain::ChainError>> {
                Box::pin(async { Ok(None) })
            }

            fn wallet_of_user_key<'a>(
                &'a self,
                _: &'a str,
            ) -> BoxFut<'a, Result<Option<String>, crate::chain::ChainError>> {
                Box::pin(async { Ok(None) })
            }

            fn is_my_route<'a>(
                &'a self,
                _: &'a str,
                _: &'a str,
            ) -> BoxFut<'a, Result<bool, crate::chain::ChainError>> {
                Box::pin(async { Ok(false) })
            }
        }

        let table = RouteTable::new("own", Duration::from_secs(60));
        let source = ErrorThenMissing(AtomicUsize::new(0));
        assert_eq!(
            resolve_user_route(&table, &source, "key", Duration::from_secs(1)).await,
            Err(LookupFailure::Rpc("chain: rpc unavailable".into()))
        );
        assert!(!table.recently_unknown("key"));
        assert_eq!(
            resolve_user_route(&table, &source, "key", Duration::from_secs(1)).await,
            Ok(Resolved::NoRoute)
        );
        assert_eq!(source.0.load(Ordering::SeqCst), 2);
        assert!(table.recently_unknown("key"));

        assert_eq!(
            lookup_user_routes(&Routes(Reply::Missing), "key", Duration::from_secs(1)).await,
            Ok(None)
        );
        assert_eq!(
            lookup_user_routes(&Routes(Reply::Error), "key", Duration::from_secs(1)).await,
            Err(LookupFailure::Rpc("chain: rpc unavailable".into()))
        );
        assert_eq!(
            lookup_user_routes(&Routes(Reply::Wait), "key", Duration::from_millis(1)).await,
            Err(LookupFailure::Timeout)
        );
        let failed_table = RouteTable::new("own", Duration::from_secs(60));
        assert!(matches!(
            resolve_user_route(
                &failed_table,
                &Routes(Reply::Wait),
                "timeout-key",
                Duration::from_millis(1)
            )
            .await,
            Err(LookupFailure::Timeout)
        ));
        assert!(!failed_table.recently_unknown("timeout-key"));
    }

    #[tokio::test]
    async fn node_ctx_route_outcome_and_post_status_keep_three_states() {
        let valid = context(Reply::Route);
        assert_eq!(
            valid
                .resolve_with_timeout("user", Duration::from_secs(1))
                .await,
            Resolved::Remote("127.0.0.1:9100".parse().unwrap())
        );

        let missing = context(Reply::Missing);
        assert_eq!(
            missing
                .resolve_with_timeout("absent", Duration::from_secs(1))
                .await,
            Resolved::NoRoute
        );
        assert!(missing.routes.recently_unknown("absent"));
        let missing_response = route_error_response(&Resolved::NoRoute).unwrap();
        assert!(String::from_utf8_lossy(&missing_response).starts_with("HTTP/1.1 200 OK"));

        for source in [Reply::Error, Reply::Wait] {
            let ctx = context(source);
            let outcome = ctx
                .resolve_with_timeout("uncertain", Duration::from_millis(1))
                .await;
            assert_eq!(outcome, Resolved::LookupUnavailable);
            assert!(!ctx.routes.recently_unknown("uncertain"));
            let response = route_error_response(&outcome).unwrap();
            assert!(
                String::from_utf8_lossy(&response).starts_with("HTTP/1.1 503 Service Unavailable")
            );
        }
    }
}

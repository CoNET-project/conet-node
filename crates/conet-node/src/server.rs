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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

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
    pub push: Arc<dyn Push>,
    pub chain: Arc<ChainState>,
    pub limits: Limits,
    pub connect_timeout: Duration,
    pub max_connections: usize,
    pub ip_limiter: Arc<IpLimiter>,
    /// Accept the legacy `mining` + `listenKind:"chat"` presence listen (decision U3).
    pub legacy_chat_listen: bool,
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
            push,
            chain: Arc::new(ChainState::default()),
            limits: Limits::default(),
            connect_timeout: Duration::from_secs(8),
            max_connections: 4096,
            ip_limiter: IpLimiter::new(IpPolicy::default()),
            legacy_chat_listen: true,
        }
    }

    /// Cached route, else ask AddressPGP once (negative answers cached briefly).
    pub async fn resolve(&self, key_id: &str) -> Resolved {
        let r = self.routes.resolve(key_id);
        if r != Resolved::NoRoute || self.routes.recently_unknown(key_id) {
            return r;
        }
        let Some(ur) = &self.user_routes else {
            return r;
        };
        match tokio::time::timeout(Duration::from_secs(5), ur.route_of_user_key(key_id)).await {
            Ok(Ok(Some(node))) => {
                self.routes.set_user_route(key_id, &node);
                self.routes.resolve(key_id)
            }
            Ok(Ok(None)) => {
                self.routes.mark_unknown(key_id);
                Resolved::NoRoute
            }
            _ => Resolved::NoRoute,
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn serve(listener: TcpListener, ctx: Arc<NodeCtx>) -> std::io::Result<()> {
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
            handle(stream, peer, ctx).await;
        });
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<NodeCtx>) {
    let req = match http::read_request(&mut stream, &ctx.limits).await {
        Ok(r) => r,
        Err(ReadError::Closed) => return,
        Err(e) => {
            debug!(?e, "bad request");
            let _ = stream.write_all(&http::not_found()).await;
            return;
        }
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("OPTIONS", _) => {
            let _ = stream.write_all(&http::options_204()).await;
        }
        ("POST", p) if p.starts_with("/post") => post(stream, peer, req, ctx).await,
        _ => {
            let _ = stream.write_all(&http::not_found()).await;
        }
    }
}

async fn post(mut stream: TcpStream, peer: SocketAddr, req: http::Request, ctx: Arc<NodeCtx>) {
    let Ok(body) = String::from_utf8(req.body) else {
        let _ = stream.write_all(&http::not_found()).await;
        return;
    };
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
        } => match ctx.resolve(&key_id).await {
            Resolved::NoRoute => {
                let _ = stream
                    .write_all(&http::ok_200(r#"{"ok":false,"error":"no_route"}"#))
                    .await;
            }
            Resolved::Local => {
                let hop_bytes = Node::verified_hop_bytes(&hops, now_secs());
                ctx.mailbox.deliver(
                    &key_id,
                    Stored {
                        armor,
                        no_push,
                        hop_bytes,
                        hops: hops.len(),
                    },
                );
                let _ = stream.write_all(&http::ok_200("")).await;
            }
            Resolved::Remote(addr) => {
                // The wallet may be the signer client (blocking socket call): keep it off I/O threads.
                let c = ctx.clone();
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
                        debug!(reason, "forward refused");
                        let _ = stream.shutdown().await;
                    }
                }
            }
        },
        Step::Command { command, .. } => {
            crate::commands::dispatch(stream, peer, command, ctx).await
        }
        Step::VoiceChunk { .. } => {
            // line C.
            let _ = stream.write_all(&http::not_found()).await;
        }
        Step::Close { reason, attack } => {
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
    mut client: TcpStream,
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

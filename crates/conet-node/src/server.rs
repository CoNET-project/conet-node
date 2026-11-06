//! Accept loop and `/post` handling (line A, stage A1: entry, onion, hop sigs, local store).
use crate::http::{self, Limits, ReadError};
use crate::route::{Resolved, RouteTable};
use crate::store::{MailboxStore, Stored};
use si_core::node::{Node, Step};
use si_core::{LocalRoute, RouteDecryptor, WalletSigner, WriteKeys};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

pub struct NodeCtx {
    pub key_id: String,
    pub decryptor: Arc<dyn RouteDecryptor>,
    pub wallet: Arc<dyn WalletSigner>,
    pub routes: Arc<RouteTable>,
    pub store: Arc<dyn MailboxStore>,
    pub limits: Limits,
    pub connect_timeout: Duration,
    pub max_connections: usize,
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
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            handle(stream, peer, ctx).await;
        });
    }
}

async fn handle(mut stream: TcpStream, _peer: SocketAddr, ctx: Arc<NodeCtx>) {
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
        ("GET", p) if p.to_ascii_lowercase().starts_with("/nodewallet") => {
            let _ = stream.write_all(&http::ok_200(&ctx.wallet.address())).await;
        }
        ("POST", p) if p.starts_with("/post") => post(stream, req, ctx).await,
        _ => {
            let _ = stream.write_all(&http::not_found()).await;
        }
    }
}

async fn post(mut stream: TcpStream, req: http::Request, ctx: Arc<NodeCtx>) {
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
        } => match ctx.routes.resolve(&key_id) {
            Resolved::NoRoute => {
                let _ = stream
                    .write_all(&http::ok_200(r#"{"ok":false,"error":"no_route"}"#))
                    .await;
            }
            Resolved::Local => {
                let hop_bytes = Node::verified_hop_bytes(&hops, now_secs());
                ctx.store.save(
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
                let node = Node {
                    route: LocalRoute {
                        key: &*ctx.decryptor,
                        key_id: &ctx.key_id,
                    },
                    wallet: &*ctx.wallet,
                    write_keys: WriteKeys::new(),
                };
                match node.forward_header(&hops, &key_id, &armor, now_secs()) {
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
        Step::Command { .. } | Step::VoiceChunk { .. } => {
            // A2 / line C.
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

//! Mailbox delivery to several slots (design §23.2–§23.4, user decisions H-4, W56, W58).
//!
//! - Chain-invalid slots are skipped (they arrive as [`Target::Invalid`]).
//! - Valid primaries are sent in parallel, each with its own hop signature; the second one
//!   waits a random 0–3 s so the two copies are not trivially paired by time.
//! - The first primary that stores answers the sender; the others still finish in the
//!   background (every primary is a mailbox the user pays for).
//! - Only when no primary stored does the secondary get the message.
//! - "Recipient unpaid" is not a failure: it never justifies the secondary on its own merit, but
//!   when no primary stored the secondary is still tried; if nothing stored and any slot said
//!   unpaid, the sender gets `recipient_unpaid`.
//!
//! Failure (§23.4): connect or TLS failure, no reply within the deadline, a dropped connection,
//! a non-200 reply (network); `ok:false` with any other error, e.g. `no_route` (refused).
//! A node that failed three times in a row on the network is skipped for 60 s, then probed.
use crate::http;
use crate::route::{DeliveryPlan, Target};
use crate::server::{Conn, NodeCtx};
use crate::store::Stored;
use rand_core::{OsRng, RngCore};
use si_core::node::Node;
use si_proto::HopSig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// Timing (§23.4 defaults; W57: configuration now, DAO parameter later).
#[derive(Debug, Clone)]
pub struct DeliveryOpts {
    pub connect: Duration,
    /// Extra attempts after a connect failure (never after the request was sent).
    pub connect_retries: u32,
    /// Wait for the mailbox's reply after sending.
    pub reply: Duration,
    pub primary_deadline: Duration,
    pub secondary_deadline: Duration,
    /// Random delay before each primary after the first.
    pub spread: Duration,
    pub fail_after: u32,
    pub fail_ttl: Duration,
}

impl Default for DeliveryOpts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(3),
            connect_retries: 1,
            reply: Duration::from_secs(5),
            primary_deadline: Duration::from_secs(10),
            secondary_deadline: Duration::from_secs(10),
            spread: Duration::from_secs(3),
            fail_after: 3,
            fail_ttl: Duration::from_secs(60),
        }
    }
}

/// Result of one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Stored; the mailbox's raw HTTP reply, passed back to the sender.
    Stored(Vec<u8>),
    ChainInvalid,
    Network,
    Refused,
    Unpaid,
}

/// The reply error a mailbox sends when the recipient has not paid it (W56).
pub const UNPAID: &str = "recipient_unpaid";

/// Map a mailbox reply to an outcome.
pub fn classify(status: u16, body: &[u8]) -> Outcome {
    if status != 200 {
        return Outcome::Network;
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if v.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return if v.get("error").and_then(|e| e.as_str()) == Some(UNPAID) {
                Outcome::Unpaid
            } else {
                Outcome::Refused
            };
        }
    }
    Outcome::Stored(vec![])
}

/// Network failures per node: three in a row → skipped for a while, then one probe.
#[derive(Default)]
pub struct FailCache {
    m: Mutex<HashMap<SocketAddr, (u32, Option<Instant>)>>,
}

impl FailCache {
    /// True while the node is benched. When the bench expires, one request goes through; a
    /// failure benches it again at once.
    pub fn benched(&self, a: SocketAddr) -> bool {
        let mut m = self.m.lock().expect("fail cache");
        match m.get_mut(&a) {
            Some((_, Some(until))) if Instant::now() < *until => true,
            Some(e @ (_, Some(_))) => {
                e.1 = None; // half-open: the count stays at the threshold
                false
            }
            _ => false,
        }
    }

    pub fn record(&self, a: SocketAddr, ok: bool, opts: &DeliveryOpts) {
        let mut m = self.m.lock().expect("fail cache");
        if ok {
            m.remove(&a);
            return;
        }
        if m.len() > 10_000 {
            m.clear();
        }
        let e = m.entry(a).or_insert((0, None));
        e.0 = e.0.saturating_add(1);
        if e.0 >= opts.fail_after {
            e.1 = Some(Instant::now() + opts.fail_ttl);
        }
    }
}

fn rand_below(max: Duration) -> Duration {
    if max.is_zero() {
        return max;
    }
    Duration::from_millis(OsRng.next_u64() % (max.as_millis() as u64).max(1))
}

/// Read one HTTP response (status, body), at most 64 KiB, before `deadline`.
async fn read_reply(s: &mut TcpStream, deadline: Instant) -> Option<(u16, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        let n = tokio::time::timeout(left, s.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n > 0 {
            buf.extend_from_slice(&chunk[..n]);
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);
        if let Ok(httparse::Status::Complete(head)) = resp.parse(&buf) {
            let status = resp.code?;
            let len = resp
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| {
                    std::str::from_utf8(h.value)
                        .ok()?
                        .trim()
                        .parse::<usize>()
                        .ok()
                });
            match len {
                Some(l) if buf.len() >= head + l => {
                    return Some((status, buf[head..head + l].to_vec()));
                }
                None if n == 0 => return Some((status, buf[head..].to_vec())),
                _ => {}
            }
        }
        if n == 0 {
            return None;
        }
    }
}

/// The hop header for one branch (blocking signer call kept off the I/O threads).
async fn hop_header(
    ctx: &Arc<NodeCtx>,
    hops: &[HopSig],
    key_id: &str,
    armor: &str,
) -> Result<String, &'static str> {
    let c = ctx.clone();
    let (k, a, h) = (key_id.to_string(), armor.to_string(), hops.to_vec());
    tokio::task::spawn_blocking(move || {
        let node = Node {
            route: si_core::LocalRoute {
                key: &*c.decryptor,
                key_id: &c.key_id,
                old_key_ids: &c.old_key_ids,
            },
            wallet: &*c.wallet,
            write_keys: si_core::WriteKeys::new(),
        };
        node.forward_header(&h, &k, &a, crate::server::now_secs())
    })
    .await
    .unwrap_or(Err("join"))
}

/// Send to one remote mailbox and judge the reply.
async fn send_remote(
    ctx: &Arc<NodeCtx>,
    addr: SocketAddr,
    key_id: &str,
    armor: &str,
    hops: &[HopSig],
    deadline: Instant,
) -> Outcome {
    let opts = &ctx.delivery;
    if ctx.fail_cache.benched(addr) {
        return Outcome::Network;
    }
    let Ok(header) = hop_header(ctx, hops, key_id, armor).await else {
        return Outcome::Refused;
    };
    let mut up = None;
    for _ in 0..=opts.connect_retries {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .min(opts.connect);
        if let Ok(Ok(s)) = tokio::time::timeout(left, TcpStream::connect(addr)).await {
            up = Some(s);
            break;
        }
    }
    let Some(mut up) = up else {
        ctx.fail_cache.record(addr, false, opts);
        return Outcome::Network;
    };
    let _ = up.set_nodelay(true);
    let body = serde_json::json!({ "data": armor }).to_string();
    let reqb = http::forward_request(&addr.ip().to_string(), addr.port(), &header, &body);
    if up.write_all(&reqb).await.is_err() {
        ctx.fail_cache.record(addr, false, opts);
        return Outcome::Network;
    }
    let reply_by = deadline.min(Instant::now() + opts.reply);
    let out = match read_reply(&mut up, reply_by).await {
        Some((status, body)) => match classify(status, &body) {
            Outcome::Stored(_) => {
                // Pass the mailbox's reply on as it came (same shape as a single route).
                let mut raw = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                raw.extend_from_slice(&body);
                Outcome::Stored(if body.is_empty() {
                    http::ok_200("")
                } else {
                    raw
                })
            }
            o => o,
        },
        None => Outcome::Network,
    };
    ctx.fail_cache.record(addr, out != Outcome::Network, opts);
    out
}

async fn send_slot(
    ctx: &Arc<NodeCtx>,
    t: Target,
    key_id: &str,
    armor: &str,
    no_push: bool,
    hops: &[HopSig],
    deadline: Instant,
) -> Outcome {
    match t {
        Target::Invalid => Outcome::ChainInvalid,
        Target::Local => {
            let hop_bytes = Node::verified_hop_bytes(hops, crate::server::now_secs());
            ctx.mailbox.deliver(
                key_id,
                Stored {
                    armor: armor.to_string(),
                    no_push,
                    hop_bytes,
                    hops: hops.len(),
                },
            );
            Outcome::Stored(http::ok_200(""))
        }
        Target::Remote(a) => send_remote(ctx, a, key_id, armor, hops, deadline).await,
    }
}

/// What the sender is told when nothing stored.
pub fn failure_reply(outcomes: &[Outcome]) -> Vec<u8> {
    if outcomes.contains(&Outcome::Unpaid) {
        http::ok_200(&format!(r#"{{"ok":false,"error":"{UNPAID}"}}"#))
    } else if outcomes
        .iter()
        .all(|o| matches!(o, Outcome::ChainInvalid | Outcome::Refused))
    {
        http::ok_200(r#"{"ok":false,"error":"no_route"}"#)
    } else {
        http::not_found()
    }
}

/// Deliver per plan; returns every slot's outcome known before the reply (for tests and logs).
pub async fn deliver(
    mut stream: Conn,
    plan: DeliveryPlan,
    key_id: String,
    armor: String,
    no_push: bool,
    hops: Vec<HopSig>,
    ctx: Arc<NodeCtx>,
) -> Vec<Outcome> {
    let opts = ctx.delivery.clone();
    let mut outcomes = vec![];
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Outcome>(4);
    let deadline = Instant::now() + opts.primary_deadline;
    let mut pending = 0;
    let mut sent_any = false;
    for t in plan.primary {
        if t == Target::Invalid {
            outcomes.push(Outcome::ChainInvalid);
            continue;
        }
        let delay = if sent_any {
            rand_below(opts.spread)
        } else {
            Duration::ZERO
        };
        sent_any = true;
        pending += 1;
        let (c, k, a, h, tx) = (
            ctx.clone(),
            key_id.clone(),
            armor.clone(),
            hops.clone(),
            tx.clone(),
        );
        // Detached: a branch keeps going after another one answered the sender.
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let o = send_slot(&c, t, &k, &a, no_push, &h, deadline + delay).await;
            let _ = tx.send(o).await;
        });
    }
    drop(tx);
    while pending > 0 {
        let left = deadline.saturating_duration_since(Instant::now()) + opts.spread;
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(Outcome::Stored(reply))) => {
                let _ = stream.write_all(&reply).await;
                outcomes.push(Outcome::Stored(vec![]));
                return outcomes;
            }
            Ok(Some(o)) => {
                pending -= 1;
                outcomes.push(o);
            }
            _ => {
                outcomes.push(Outcome::Network);
                break;
            }
        }
    }
    // No primary stored: the secondary, if the user named one.
    if let Some(t) = plan.secondary {
        let o = send_slot(
            &ctx,
            t,
            &key_id,
            &armor,
            no_push,
            &hops,
            Instant::now() + opts.secondary_deadline,
        )
        .await;
        if let Outcome::Stored(reply) = o {
            let _ = stream.write_all(&reply).await;
            outcomes.push(Outcome::Stored(vec![]));
            return outcomes;
        }
        outcomes.push(o);
    }
    debug!(
        slots = outcomes.len(),
        "mailbox delivery failed on every slot"
    );
    let _ = stream.write_all(&failure_reply(&outcomes)).await;
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_are_classified() {
        assert_eq!(classify(200, b""), Outcome::Stored(vec![]));
        assert_eq!(classify(200, b"<html>"), Outcome::Stored(vec![]));
        assert_eq!(classify(200, br#"{"ok":true}"#), Outcome::Stored(vec![]));
        assert_eq!(
            classify(200, br#"{"ok":false,"error":"no_route"}"#),
            Outcome::Refused
        );
        assert_eq!(
            classify(200, br#"{"ok":false,"error":"recipient_unpaid"}"#),
            Outcome::Unpaid
        );
        assert_eq!(classify(404, b""), Outcome::Network);
        assert_eq!(classify(500, br#"{"ok":true}"#), Outcome::Network);
    }

    #[test]
    fn failure_replies() {
        let body = |v: Vec<u8>| String::from_utf8(v).unwrap();
        assert!(body(failure_reply(&[Outcome::Network, Outcome::Unpaid])).contains(UNPAID));
        assert!(
            body(failure_reply(&[Outcome::ChainInvalid, Outcome::Refused])).contains("no_route")
        );
        assert!(body(failure_reply(&[Outcome::Refused, Outcome::Network])).contains("404"));
    }

    #[test]
    fn three_failures_bench_a_node_then_one_probe() {
        let opts = DeliveryOpts {
            fail_ttl: Duration::from_millis(40),
            ..DeliveryOpts::default()
        };
        let c = FailCache::default();
        let a: SocketAddr = "127.0.0.1:9".parse().unwrap();
        c.record(a, false, &opts);
        c.record(a, false, &opts);
        assert!(!c.benched(a));
        c.record(a, false, &opts);
        assert!(c.benched(a));
        std::thread::sleep(Duration::from_millis(50));
        assert!(!c.benched(a), "probe allowed after the bench");
        c.record(a, false, &opts);
        assert!(c.benched(a), "a failed probe benches again at once");
        std::thread::sleep(Duration::from_millis(50));
        assert!(!c.benched(a));
        c.record(a, true, &opts);
        c.record(a, false, &opts);
        assert!(!c.benched(a), "a success resets the count");
    }
}

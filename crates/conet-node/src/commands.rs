//! Command dispatcher for line A stage A2 (SI `localNodeCommandSocket` subset needed at launch):
//! `mailbox_listen`, `gossip_delivery_ack`, `wallet_online_query`, `wallet_native_wake_query`,
//! `push_device_register`. Everything else is refused like SI's `default` branch, until its
//! line lands (voice/UDP: line C; proxy, mining: decided per Q3).
use crate::http;
use crate::mailbox::{random_instance_id, sealed_frame, Listener, LISTEN_QUEUE};
use crate::server::Conn;
use crate::server::NodeCtx;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use si_crypto::eth;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// SI `validRouteCommandTimestamp`: within ±600 s.
fn fresh(v: &Value) -> bool {
    v.as_f64()
        .map(|t| t.is_finite() && (now() as f64 - t.floor()).abs() <= 600.0)
        .unwrap_or(false)
}

fn s<'a>(c: &'a Value, k: &str) -> &'a str {
    c.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

async fn reply(stream: &mut Conn, v: Value) {
    let _ = stream.write_all(&http::ok_200(&v.to_string())).await;
}

async fn not_found(stream: &mut Conn) {
    let _ = stream.write_all(&http::not_found()).await;
}

async fn is_my_route(ctx: &NodeCtx, user: &str) -> bool {
    match &ctx.user_routes {
        Some(r) => r
            .is_my_route(user, &ctx.wallet.address())
            .await
            .unwrap_or(false),
        None => false,
    }
}

pub async fn dispatch(mut stream: Conn, peer: SocketAddr, command: Value, ctx: Arc<NodeCtx>) {
    match s(&command, "command") {
        "mailbox_listen" => mailbox_listen(stream, peer, command, ctx).await,
        "mining" if ctx.legacy_chat_listen && s(&command, "listenKind") == "chat" => {
            legacy_chat_listen(stream, peer, command, ctx).await
        }
        "voice_listen" => crate::voice::listen(stream, command, ctx).await,
        "voice_unlisten" => crate::voice::unlisten(stream, command, ctx).await,
        "voice_offer_store" => crate::voice::offer_store(stream, command, ctx).await,
        "voice_offer_fetch" => crate::voice::offer_fetch(stream, command, ctx).await,
        "gossip_delivery_ack" => delivery_ack(&mut stream, &command, &ctx).await,
        "wallet_online_query" => online_query(&mut stream, &command, &ctx).await,
        "wallet_native_wake_query" => native_wake_query(&mut stream, &command, &ctx).await,
        "push_device_register" => push_device_register(&mut stream, &command, &ctx).await,
        _ => not_found(&mut stream).await,
    }
}

async fn delivery_ack(stream: &mut Conn, c: &Value, ctx: &NodeCtx) {
    let wallet = s(c, "walletAddress").to_lowercase();
    let hash = s(c, "armorHash");
    let hash_ok = hash.len() == 66
        && hash.starts_with("0x")
        && hash[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if !eth::is_address(&wallet) || !hash_ok || !fresh(&c["timestamp"]) {
        return not_found(stream).await;
    }
    if !is_my_route(ctx, &wallet).await {
        return reply(stream, json!({ "ok": false, "error": "not_my_route" })).await;
    }
    let key = match &ctx.user_routes {
        Some(r) => r.user_key_of_wallet(&wallet).await.ok().flatten(),
        None => None,
    };
    let Some(key) = key else {
        return reply(stream, json!({ "ok": false, "error": "no_pgp" })).await;
    };
    let removed = ctx.mailbox.store.remove_by_hash(&key, hash);
    reply(stream, json!({ "ok": true, "removed": removed })).await
}

async fn online_query(stream: &mut Conn, c: &Value, ctx: &NodeCtx) {
    let requester = s(c, "walletAddress").to_lowercase();
    let target = s(c, "targetWallet").to_lowercase();
    if !eth::is_address(&requester) {
        return reply(
            stream,
            json!({ "ok": false, "error": "invalid_requester", "online": false }),
        )
        .await;
    }
    if !eth::is_address(&target) {
        return reply(
            stream,
            json!({ "ok": false, "error": "invalid_target", "online": false }),
        )
        .await;
    }
    if !fresh(&c["timestamp"]) {
        return reply(
            stream,
            json!({ "ok": false, "error": "timestamp", "online": false }),
        )
        .await;
    }
    if !is_my_route(ctx, &target).await {
        return reply(
            stream,
            json!({ "ok": false, "error": "not_my_route", "wallet": target, "online": false }),
        )
        .await;
    }
    let since = ctx.mailbox.online_since(&target);
    reply(
        stream,
        json!({
            "ok": true,
            "wallet": target,
            "online": since.is_some(),
            "listenAgeMs": since.map(|t| t.elapsed().as_millis() as u64),
            "nodeWallet": ctx.wallet.address().to_lowercase(),
        }),
    )
    .await
}

async fn native_wake_query(stream: &mut Conn, c: &Value, ctx: &NodeCtx) {
    let requester = s(c, "walletAddress");
    let target = s(c, "targetWallet");
    let zero = "0x0000000000000000000000000000000000000000";
    if !eth::is_address(requester) || requester.eq_ignore_ascii_case(zero) {
        return reply(
            stream,
            json!({ "ok": false, "error": "invalid_wallet", "nativeWakeable": false }),
        )
        .await;
    }
    if !eth::is_address(target) || target.eq_ignore_ascii_case(zero) {
        return reply(
            stream,
            json!({ "ok": false, "error": "invalid_target", "nativeWakeable": false }),
        )
        .await;
    }
    if !fresh(&c["timestamp"]) {
        return reply(
            stream,
            json!({ "ok": false, "error": "timestamp", "nativeWakeable": false }),
        )
        .await;
    }
    let target = target.to_lowercase();
    if !is_my_route(ctx, &target).await {
        return reply(stream, json!({ "ok": false, "error": "not_my_route", "wallet": target, "nativeWakeable": false })).await;
    }
    match ctx.push.native_wakeable(&target).await {
        Some(w) => reply(stream, json!({ "ok": true, "wallet": target, "nativeWakeable": w })).await,
        None => reply(stream, json!({ "ok": false, "error": "lookup_failed", "wallet": target, "nativeWakeable": false })).await,
    }
}

async fn push_device_register(stream: &mut Conn, c: &Value, ctx: &NodeCtx) {
    let eoa = s(c, "walletAddress");
    let token = s(c, "deviceToken");
    let platform = s(c, "platform").to_lowercase();
    let bundle = s(c, "bundleId");
    let sig = s(c, "registrationSignature");
    let valid = eth::is_address(eoa)
        && !token.is_empty()
        && token.len() <= 4096
        && ["ios", "ios_voip", "android"].contains(&platform.as_str())
        && !bundle.is_empty()
        && !sig.is_empty()
        && fresh(&c["timestamp"]);
    if !valid {
        return reply(
            stream,
            json!({ "ok": false, "error": "invalid_push_device_register" }),
        )
        .await;
    }
    if !is_my_route(ctx, eoa).await {
        return reply(stream, json!({ "ok": false, "error": "not_my_route" })).await;
    }
    let pgp = s(c, "pgpKeyId");
    let mut payload = json!({
        "eoa": eth::to_checksum(eoa),
        "deviceToken": token,
        "platform": platform,
        "bundleId": bundle,
        "timestamp": c["timestamp"].as_f64().map(|t| t.floor() as i64).unwrap_or(0),
        "signature": sig,
    });
    if !pgp.is_empty() {
        payload["pgpKeyId"] = json!(pgp);
    }
    if let Some(cap) = c.get("capabilities").filter(|v| v.is_object()) {
        payload["capabilities"] = cap.clone();
    }
    ctx.push.register_device(payload);
    reply(stream, json!({ "ok": true })).await
}

/// SI `parseMailboxStreamKey`.
fn stream_key(c: &Value) -> Option<[u8; 32]> {
    let v = c.get("streamKey")?.as_str()?;
    if v.len() < 40
        || v.len() > 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    B64.decode(v).ok()?.try_into().ok()
}

const SSE_HEADERS: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache, no-transform\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\nAccess-Control-Allow-Origin: *\r\n";

async fn mailbox_listen(mut stream: Conn, peer: SocketAddr, c: Value, ctx: Arc<NodeCtx>) {
    let Some(key) = stream_key(&c) else {
        return not_found(&mut stream).await;
    };
    let wallet = s(&c, "walletAddress").to_lowercase();
    let instance_id = Some(s(&c, "instanceId"))
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(str::to_string)
        .unwrap_or_else(random_instance_id);
    let user_key = match &ctx.user_routes {
        Some(r) => r.user_key_of_wallet(&wallet).await.ok().flatten(),
        None => None,
    };
    let epoch = ctx.chain.block.load(Ordering::Relaxed);
    let notices = ctx.notices.clone();
    let hash = tokio::task::spawn_blocking(move || notices.sign_epoch(epoch))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let handshake = json!({
        "ipaddress": peer.ip().to_string(),
        "status": 200,
        "kind": "mailbox",
        "instanceId": instance_id,
        "nodeWallet": ctx.wallet.address().to_lowercase(),
        "hash": hash,
    });
    let mut first = format!(
        "{SSE_HEADERS}Date: {}\r\n\r\n",
        httpdate::fmt_http_date(SystemTime::now())
    )
    .into_bytes();
    first.extend(sealed_frame(&handshake.to_string(), &key));
    first.extend_from_slice(b"\r\n\r\n"); // SI testMinerCOnnecting appends this
    if stream.write_all(&first).await.is_err() {
        return;
    }
    // Offline flush: everything not yet ACKed (kept until the client acknowledges it).
    if let Some(k) = &user_key {
        for item in ctx.mailbox.store.pending(k) {
            let f = sealed_frame(&json!({ "data": item.armor }).to_string(), &key);
            if stream.write_all(&f).await.is_err() {
                return;
            }
        }
    }
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(LISTEN_QUEUE);
    let id = ctx.mailbox.next_id();
    ctx.mailbox.register(Listener {
        id,
        wallet,
        user_key,
        stream_key: key,
        tx,
        connected_at: Instant::now(),
        legacy: false,
    });

    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut scratch = [0u8; 512];
    loop {
        let keepalive = Duration::from_millis(60_000 + OsRng.next_u64() % 120_000);
        tokio::select! {
            f = rx.recv() => {
                match f {
                    Some(f) => if wr.write_all(&f).await.is_err() { break },
                    None => break,
                }
            }
            _ = tokio::time::sleep(keepalive) => {
                let ka = json!({ "type": "mailbox_keepalive", "ts": now() * 1000 }).to_string();
                if wr.write_all(&sealed_frame(&ka, &key)).await.is_err() { break }
            }
            r = rd.read(&mut scratch) => {
                // The client never sends on a listen; EOF or error ends it.
                if matches!(r, Ok(0) | Err(_)) { break }
            }
        }
    }
    ctx.mailbox.remove(id);
}

/// Legacy presence listen (`mining` + `listenKind:"chat"`, old Alliance-style clients).
/// Since 2026-11-02 this pool gets no chat messages (its frames are not sealed), so it only
/// marks the wallet online and sends a plain epoch frame every 12–20 s like SI's liveness loop.
async fn legacy_chat_listen(mut stream: Conn, peer: SocketAddr, c: Value, ctx: Arc<NodeCtx>) {
    let wallet = s(&c, "walletAddress").to_lowercase();
    if !eth::is_address(&wallet) {
        return not_found(&mut stream).await;
    }
    let frame = |epoch: u64, hash: &str| {
        format!(
            "data: {}\r\n\r\n",
            json!({ "ipaddress": peer.ip().to_string(), "epoch": epoch, "status": 200, "nodeWallet": ctx.wallet.address().to_lowercase(), "hash": hash })
        )
        .into_bytes()
    };
    let sign = |epoch: u64| {
        let n = ctx.notices.clone();
        async move {
            tokio::task::spawn_blocking(move || n.sign_epoch(epoch))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        }
    };
    let epoch = ctx.chain.block.load(Ordering::Relaxed);
    let mut first = format!(
        "{SSE_HEADERS}Date: {}\r\n\r\n",
        httpdate::fmt_http_date(SystemTime::now())
    )
    .into_bytes();
    first.extend(frame(epoch, &sign(epoch).await));
    if stream.write_all(&first).await.is_err() {
        return;
    }
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
    let id = ctx.mailbox.next_id();
    ctx.mailbox.register(Listener {
        id,
        wallet,
        user_key: None,
        stream_key: [0; 32],
        tx,
        connected_at: Instant::now(),
        legacy: true,
    });
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut scratch = [0u8; 512];
    let mut last_epoch = epoch;
    let mut last_hash = String::new();
    loop {
        let tick = Duration::from_millis(12_000 + OsRng.next_u64() % 8_000);
        tokio::select! {
            f = rx.recv() => if f.is_none() { break },
            _ = tokio::time::sleep(tick) => {
                let e = ctx.chain.block.load(Ordering::Relaxed);
                if e != last_epoch || last_hash.is_empty() {
                    last_hash = sign(e).await;
                    last_epoch = e;
                }
                if wr.write_all(&frame(e, &last_hash)).await.is_err() { break }
            }
            r = rd.read(&mut scratch) => if matches!(r, Ok(0) | Err(_)) { break },
        }
    }
    ctx.mailbox.remove(id);
}

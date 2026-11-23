//! Command dispatcher for line A stage A2 (SI `localNodeCommandSocket` subset needed at launch):
//! `mailbox_listen`, `gossip_delivery_ack`, `wallet_online_query`, `wallet_native_wake_query`,
//! `push_device_register`. Everything else is refused like SI's `default` branch, until its
//! line lands (voice/UDP: line C; proxy, mining: decided per Q3).
use crate::chain::ChainError;
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
use tracing::warn;

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

async fn is_my_route(ctx: &NodeCtx, user: &str) -> Result<bool, ChainError> {
    match &ctx.user_routes {
        Some(r) => r.is_my_route(user, &ctx.wallet.address()).await,
        None => Ok(false),
    }
}

async fn route_status(stream: &mut Conn, ctx: &NodeCtx, user: &str) -> Option<bool> {
    match is_my_route(ctx, user).await {
        Ok(owned) => Some(owned),
        Err(e) => {
            warn!(%e, "route ownership lookup unavailable");
            let _ = stream
                .write_all(&http::service_unavailable(
                    r#"{"ok":false,"error":"route_lookup_unavailable"}"#,
                ))
                .await;
            None
        }
    }
}

async fn lookup_unavailable(stream: &mut Conn) {
    let _ = stream
        .write_all(&http::service_unavailable(
            r#"{"ok":false,"error":"route_lookup_unavailable"}"#,
        ))
        .await;
}

async fn validator_pool_full(stream: &mut Conn) {
    let _ = stream
        .write_all(&http::service_unavailable(
            r#"{"ok":false,"error":"validator_pool_full"}"#,
        ))
        .await;
}

async fn mining_liveness_unavailable(stream: &mut Conn) {
    let _ = stream
        .write_all(&http::service_unavailable(
            r#"{"ok":false,"error":"mining_liveness_unavailable"}"#,
        ))
        .await;
}

async fn mining_liveness_disabled(stream: &mut Conn) {
    let _ = stream
        .write_all(&http::service_unavailable(
            r#"{"ok":false,"error":"mining_liveness_disabled"}"#,
        ))
        .await;
}

pub async fn dispatch(
    mut stream: Conn,
    peer: SocketAddr,
    command: Value,
    signed: bool,
    ctx: Arc<NodeCtx>,
) {
    match s(&command, "command") {
        "mailbox_listen" => mailbox_listen(stream, peer, command, ctx).await,
        "mining" if matches!(s(&command, "listenKind"), "" | "mining") => {
            if !signed {
                not_found(&mut stream).await;
            } else if !ctx.mining_liveness_enabled {
                mining_liveness_disabled(&mut stream).await;
            } else {
                mining_liveness_listen(stream, peer, command, ctx).await;
            }
        }
        "mining" if ctx.legacy_chat_listen && s(&command, "listenKind") == "chat" => {
            legacy_chat_listen(stream, peer, command, ctx).await
        }
        "SaaS_Sock5" | "SaaS_Sock5_v2" if signed => crate::exit::handle(stream, command, ctx).await,
        "voice_listen" => crate::voice::listen(stream, command, ctx).await,
        "voice_unlisten" => crate::voice::unlisten(stream, command, ctx).await,
        "voice_offer_store" => crate::voice::offer_store(stream, command, ctx).await,
        "voice_offer_fetch" => crate::voice::offer_fetch(stream, command, ctx).await,
        "gossip_delivery_ack" => delivery_ack(&mut stream, &command, &ctx).await,
        "wallet_online_query" => online_query(&mut stream, &command, &ctx).await,
        "wallet_native_wake_query" => native_wake_query(&mut stream, &command, &ctx).await,
        "push_device_register" => push_device_register(&mut stream, &command, &ctx).await,
        "mining_validator" if signed => mining_validator(&mut stream, &command, &ctx).await,
        _ => not_found(&mut stream).await,
    }
}

async fn mining_validator(stream: &mut Conn, command: &Value, ctx: &NodeCtx) {
    let Some(rpc) = ctx.epoch_rpc.as_ref() else {
        return lookup_unavailable(stream).await;
    };
    match rpc.chain_id().await {
        Ok(crate::chain::CONET_CHAIN_ID) => {}
        Ok(_) | Err(_) => return lookup_unavailable(stream).await,
    }
    // CoNET-SI `CurrentEpoch` is the current CoNET block number. `currentInfo().epoch` is a
    // separate mining-rate field and must not be used for validator freshness.
    let current_epoch = match rpc.block_number().await {
        Ok(block) => block,
        Err(error) => {
            warn!(%error, "validatorMining current block unavailable");
            return lookup_unavailable(stream).await;
        }
    };
    let wallet = s(command, "walletAddress");
    let request_data = &command["requestData"];
    if !request_data.is_object() {
        return not_found(stream).await;
    }
    let domain = request_data["nodeDomain"].as_str().unwrap_or("").trim();
    let domain_wallet = match ctx.routes.node_wallet(domain) {
        crate::route::NodeWalletLookup::Known(wallet) => {
            crate::validator_mining::DomainWallet::Known(wallet)
        }
        crate::route::NodeWalletLookup::NoRecord => {
            return lookup_unavailable(stream).await;
        }
        crate::route::NodeWalletLookup::UnknownDomain => {
            return not_found(stream).await;
        }
    };
    let accepted =
        match crate::validator_mining::validate(request_data, wallet, domain_wallet, current_epoch)
        {
            Ok(accepted) => accepted,
            Err(crate::validator_mining::Refuse::Unavailable(_)) => {
                return lookup_unavailable(stream).await;
            }
            Err(crate::validator_mining::Refuse::UnknownDomain)
            | Err(crate::validator_mining::Refuse::Invalid(_)) => return not_found(stream).await,
        };
    if !ctx.validator_pools.record(&accepted, Instant::now()) {
        return validator_pool_full(stream).await;
    }
    let data = match accepted {
        crate::validator_mining::Accept::User { data, .. }
        | crate::validator_mining::Accept::Miner { data, .. } => data,
    };
    let _ = stream.write_all(&http::ok_200(&data.to_string())).await;
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
    let Some(is_route) = route_status(stream, ctx, &wallet).await else {
        return;
    };
    if !is_route {
        return reply(stream, json!({ "ok": false, "error": "not_my_route" })).await;
    }
    let key = match &ctx.user_routes {
        Some(r) => match r.user_key_of_wallet(&wallet).await {
            Ok(key) => key,
            Err(e) => {
                warn!(%e, "wallet PGP key lookup unavailable");
                lookup_unavailable(stream).await;
                return;
            }
        },
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
    let Some(is_route) = route_status(stream, ctx, &target).await else {
        return;
    };
    if !is_route {
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
    let Some(is_route) = route_status(stream, ctx, &target).await else {
        return;
    };
    if !is_route {
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
    let Some(is_route) = route_status(stream, ctx, eoa).await else {
        return;
    };
    if !is_route {
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

async fn mining_liveness_listen(
    mut stream: Conn,
    peer: SocketAddr,
    command: Value,
    ctx: Arc<NodeCtx>,
) {
    let wallet = s(&command, "walletAddress").to_ascii_lowercase();
    if !eth::is_address(&wallet) {
        return not_found(&mut stream).await;
    }
    if ctx.mining_node_ip.is_none() {
        return mining_liveness_unavailable(&mut stream).await;
    }
    let Some(rpc) = ctx.epoch_rpc.as_ref() else {
        return mining_liveness_unavailable(&mut stream).await;
    };
    match rpc.chain_id().await {
        Ok(crate::chain::CONET_CHAIN_ID) => {}
        Ok(_) | Err(_) => {
            return mining_liveness_unavailable(&mut stream).await;
        }
    }
    let epoch = match rpc.block_number().await {
        Ok(block) => block - block % 2,
        Err(_) => {
            return mining_liveness_unavailable(&mut stream).await;
        }
    };
    let notices = ctx.notices.clone();
    let hash = match tokio::task::spawn_blocking(move || notices.sign_epoch(epoch)).await {
        Ok(Ok(hash)) => hash,
        _ => {
            return mining_liveness_unavailable(&mut stream).await;
        }
    };
    let initial = json!({
        "ipaddress": peer.ip().to_string(),
        "epoch": epoch,
        "status": 200,
        "nodeWallet": ctx.wallet.address().to_ascii_lowercase(),
        "hash": hash,
    });
    let headers = format!(
        "{SSE_HEADERS}Date: {}\r\n\r\ndata: {initial}\r\n\r\n",
        httpdate::fmt_http_date(SystemTime::now())
    );
    let Some((id, mut frames)) = ctx.mining_liveness.register(wallet.clone()) else {
        return mining_liveness_unavailable(&mut stream).await;
    };
    if stream.write_all(headers.as_bytes()).await.is_err() {
        ctx.mining_liveness.remove(&wallet, id);
        return;
    }
    let (mut read, mut write) = tokio::io::split(stream);
    let mut scratch = [0u8; 512];
    loop {
        tokio::select! {
            frame = frames.recv() => match frame {
                Some(frame) if write.write_all(&frame).await.is_ok() => {}
                _ => break,
            },
            read_result = read.read(&mut scratch) => if matches!(read_result, Ok(0) | Err(_)) { break },
            _ = tokio::time::sleep(Duration::from_secs(25)) => {
                if write.write_all(b": keepalive\r\n\r\n").await.is_err() { break; }
            }
        }
    }
    ctx.mining_liveness.remove(&wallet, id);
}

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
        Some(r) => match r.user_key_of_wallet(&wallet).await {
            Ok(user_key) => user_key,
            Err(e) => {
                warn!(%e, "wallet PGP key lookup unavailable");
                lookup_unavailable(&mut stream).await;
                return;
            }
        },
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

#[cfg(test)]
mod validator_tests {
    use super::*;
    use si_core::{NodeNotices, RouteDecryptor, WalletSigner};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    struct UnusedDeps;
    impl RouteDecryptor for UnusedDeps {
        fn decrypt(&self, _: &str) -> si_crypto::Result<Vec<u8>> {
            unreachable!()
        }
    }
    impl WalletSigner for UnusedDeps {
        fn address(&self) -> String {
            "0x0000000000000000000000000000000000000001".into()
        }
        fn sign_message(&self, _: &str) -> si_crypto::Result<String> {
            unreachable!()
        }
    }
    impl NodeNotices for UnusedDeps {
        fn sign_validator_heartbeat(&self, _: u64, _: &str) -> si_crypto::Result<String> {
            unreachable!()
        }
        fn sign_epoch(&self, _: u64) -> si_crypto::Result<String> {
            unreachable!()
        }
        fn sign_offline_chat(&self, _: &str, _: &str, _: u64) -> si_crypto::Result<String> {
            unreachable!()
        }
        fn sign_native_wakeable(&self, _: &str, _: u64) -> si_crypto::Result<String> {
            unreachable!()
        }
        fn sign_voice_call_push(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: i64,
            _: i64,
        ) -> si_crypto::Result<String> {
            unreachable!()
        }
        fn sign_webrtc_endpoint(
            &self,
            _: &str,
            _: &str,
            _: u16,
            _: &str,
            _: i64,
        ) -> si_crypto::Result<String> {
            unreachable!()
        }
        fn sign_acme_dns01(&self, _: &str, _: &str, _: &str, _: i64) -> si_crypto::Result<String> {
            unreachable!()
        }
    }

    fn ctx() -> Arc<NodeCtx> {
        let deps = Arc::new(UnusedDeps);
        Arc::new(NodeCtx::new(
            "NODEKEY".into(),
            deps.clone(),
            deps.clone(),
            deps,
            Arc::new(crate::route::RouteTable::new(
                "NODEKEY",
                Duration::from_secs(60),
            )),
            Arc::new(crate::store::MemoryStore::default()),
        ))
    }

    #[tokio::test]
    async fn mining_validator_is_only_a_signed_command_and_requires_epoch_authority() {
        for (signed, status) in [(false, "HTTP/1.1 404"), (true, "HTTP/1.1 503")] {
            let (server, mut client) = tokio::io::duplex(2048);
            dispatch(
                Box::new(server),
                "127.0.0.1:1".parse().unwrap(),
                serde_json::json!({
                    "command":"mining_validator",
                    "walletAddress":"0x0000000000000000000000000000000000000002"
                }),
                signed,
                ctx(),
            )
            .await;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(String::from_utf8(response).unwrap().starts_with(status));
        }
    }

    #[tokio::test]
    async fn validator_pool_full_has_a_distinct_unavailable_reason() {
        let (server, mut client) = tokio::io::duplex(1024);
        let mut conn: Conn = Box::new(server);
        validator_pool_full(&mut conn).await;
        drop(conn);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.contains(r#""error":"validator_pool_full""#));
        assert!(!response.contains("route_lookup_unavailable"));
    }

    #[tokio::test]
    async fn mining_listener_without_node_ip_returns_unavailable() {
        let (server, mut client) = tokio::io::duplex(2048);
        let mut ctx = ctx();
        Arc::get_mut(&mut ctx).unwrap().mining_liveness_enabled = true;
        dispatch(
            Box::new(server),
            "127.0.0.1:1".parse().unwrap(),
            serde_json::json!({
                "command":"mining",
                "walletAddress":"0x0000000000000000000000000000000000000002"
            }),
            true,
            ctx,
        )
        .await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.contains(r#""error":"mining_liveness_unavailable""#));
        assert!(!response.contains("\"nodeIpAddr\":\"\""));
    }

    #[tokio::test]
    async fn mining_listener_is_disabled_by_default() {
        let (server, mut client) = tokio::io::duplex(2048);
        dispatch(
            Box::new(server),
            "127.0.0.1:1".parse().unwrap(),
            serde_json::json!({
                "command":"mining",
                "walletAddress":"0x0000000000000000000000000000000000000002"
            }),
            true,
            ctx(),
        )
        .await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.contains(r#""error":"mining_liveness_disabled""#));
    }

    async fn rpc_url(responses: Vec<(String, String)>) -> String {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let responses: std::collections::HashMap<String, String> =
                responses.into_iter().collect();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut tmp = [0u8; 2048];
                let body = loop {
                    let n = stream.read(&mut tmp).await.unwrap();
                    bytes.extend_from_slice(&tmp[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end + 4]);
                        let len = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            break bytes[end + 4..end + 4 + len].to_vec();
                        }
                    }
                };
                let req: Value = serde_json::from_slice(&body).unwrap();
                let method = req["method"].as_str().unwrap_or("");
                let body = responses.get(method).cloned().unwrap_or_else(|| {
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unexpected method"}}"#.into()
                });
                let out = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", body.len(), body);
                stream.write_all(out.as_bytes()).await.unwrap();
            }
        });
        format!("http://{addr}")
    }

    fn ctx_with_rpc(rpc: Option<crate::chain::Rpc>, node_wallet: Option<String>) -> Arc<NodeCtx> {
        let deps = Arc::new(UnusedDeps);
        let routes = Arc::new(crate::route::RouteTable::new(
            "NODEKEY",
            Duration::from_secs(60),
        ));
        routes.replace_node_records(
            [(
                "A1B2C3D4".into(),
                "127.0.0.1:9".parse().unwrap(),
                true,
                node_wallet,
            )],
            false,
        );
        let mut ctx = NodeCtx::new(
            "NODEKEY".into(),
            deps.clone(),
            deps.clone(),
            deps,
            routes,
            Arc::new(crate::store::MemoryStore::default()),
        );
        ctx.epoch_rpc = rpc;
        Arc::new(ctx)
    }

    #[tokio::test]
    async fn mining_validator_rpc_error_is_unavailable_and_block_number_controls_freshness() {
        let error_url = rpc_url(vec![
            (
                "eth_chainId".into(),
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":"0x{:x}"}}"#,
                    crate::chain::CONET_CHAIN_ID
                ),
            ),
            (
                "eth_blockNumber".into(),
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"offline"}}"#.into(),
            ),
        ])
        .await;
        let error_ctx = ctx_with_rpc(Some(crate::chain::Rpc::new(&error_url).unwrap()), None);
        let (server, mut client) = tokio::io::duplex(2048);
        dispatch(
            Box::new(server), "127.0.0.1:1".parse().unwrap(),
            serde_json::json!({"command":"mining_validator", "walletAddress":"0x0000000000000000000000000000000000000002", "requestData":{}}),
            true, error_ctx,
        ).await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 503"));

        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/epoch_readonly.json"
        )))
        .unwrap();
        let current_info_epoch = fixture["currentInfo"][0]["expect"]["epoch"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let head_block = 10u64;
        assert_ne!(current_info_epoch, head_block);
        let current_info = fixture["currentInfo"][0]["returndata"].as_str().unwrap();
        let success_url = rpc_url(vec![
            (
                "eth_chainId".into(),
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":"0x{:x}"}}"#,
                    crate::chain::CONET_CHAIN_ID
                ),
            ),
            (
                "eth_blockNumber".into(),
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":"0x{:x}"}}"#,
                    head_block
                ),
            ),
            (
                "eth_call".into(),
                format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{current_info}"}}"#),
            ),
        ])
        .await;
        let node_key =
            si_crypto::eth::EthKey::from_hex(&format!("0x{}", "00".repeat(31) + "01")).unwrap();
        let requester =
            si_crypto::eth::EthKey::from_hex(&format!("0x{}", "00".repeat(31) + "02")).unwrap();
        let message = crate::epoch::validator_message("5", &requester.address()).unwrap();
        let hash = node_key.sign_message(&message).unwrap();
        let response_hash = requester.sign_message(&hash).unwrap();
        let data = serde_json::json!({
            "epoch":"5", "nodeWallet":node_key.address(), "nodeDomain":"A1B2C3D4",
            "hash":hash, "minerResponseHash":response_hash, "isUser":true
        });
        let success_ctx = ctx_with_rpc(
            Some(crate::chain::Rpc::new(&success_url).unwrap()),
            Some(node_key.address()),
        );
        let (server, mut client) = tokio::io::duplex(4096);
        dispatch(
            Box::new(server), "127.0.0.1:1".parse().unwrap(),
            serde_json::json!({"command":"mining_validator", "walletAddress":requester.address(), "requestData":data}),
            true, success_ctx.clone(),
        ).await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(success_ctx
            .validator_pools
            .user_active(&requester.address(), Instant::now()));
    }
}

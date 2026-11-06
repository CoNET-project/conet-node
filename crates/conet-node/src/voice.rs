//! Voice relay v3 (SI `voiceForward.ts` and the voice parts of `localNodeCommand.ts`, rev 74c6cfd).
//!
//! A listen is a paid temporary SSE: the payer signs the temp wallet, the temp wallet signs the
//! listen bound to this relay's route key. Chunks are opaque blobs plus a 16-byte locator; the
//! relay checks the write-key MAC and forwards them. It never decrypts media, never stores it,
//! and never pushes it.
use crate::server::{Conn, NodeCtx};
use crate::store::Stored;
use crate::{http, route::Resolved};
use rand_core::RngCore;
use serde_json::{json, Map, Value};
use si_proto::voice as v;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Per-session frame queue. SI keeps at most 32 queued frames while the socket is paused and drops
/// the oldest; a write that cannot drain within 2 s ends the session.
struct Queue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    notify: Notify,
    closed: AtomicBool,
}

impl Queue {
    fn push(&self, f: Vec<u8>) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            return false;
        }
        let mut q = self.frames.lock().expect("voice queue");
        if q.len() >= v::QUEUE_MAX {
            q.pop_front();
        }
        q.push_back(f);
        drop(q);
        self.notify.notify_one();
        true
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_one();
    }
}

struct Session {
    write_key: [u8; 32],
    queue: Arc<Queue>,
    last_activity: Instant,
    rate_window: Instant,
    rate_chunks: u32,
    rate_bytes: usize,
}

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    /// temp wallet → (session, notAfter seconds); insertion order kept for eviction.
    temps: HashMap<String, (String, i64)>,
    temp_order: VecDeque<String>,
}

#[derive(Default)]
pub struct VoiceRelay {
    state: Mutex<State>,
}

impl VoiceRelay {
    pub fn session_count(&self) -> usize {
        self.state.lock().expect("voice").sessions.len()
    }

    fn remove(&self, session_id: &str) {
        if let Some(s) = self
            .state
            .lock()
            .expect("voice")
            .sessions
            .remove(session_id)
        {
            s.queue.close();
        }
    }

    /// SI `scheduleSweep`: idle sessions and expired temp wallets go away.
    pub async fn sweep_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_millis(v::SWEEP_MS)).await;
            let now = now_ms();
            let mut st = self.state.lock().expect("voice");
            st.temps.retain(|_, (_, na)| *na * 1000 > now);
            let temps = std::mem::take(&mut st.temp_order);
            st.temp_order = temps
                .into_iter()
                .filter(|t| st.temps.contains_key(t))
                .collect();
            let idle: Vec<String> = st
                .sessions
                .iter()
                .filter(|(_, s)| {
                    s.last_activity.elapsed() > Duration::from_millis(v::IDLE_MS)
                        || s.queue.closed.load(Ordering::Relaxed)
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in idle {
                if let Some(s) = st.sessions.remove(&k) {
                    s.queue.close();
                }
            }
        }
    }
}

async fn reply(stream: &mut Conn, v: Value) {
    let _ = stream.write_all(&http::ok_200(&v.to_string())).await;
}

/// The relay key IDs a listen may be bound to: current route key, then retiring ones (R11).
fn relay_ids(ctx: &NodeCtx) -> Vec<&str> {
    std::iter::once(ctx.key_id.as_str())
        .chain(ctx.old_key_ids.iter().map(String::as_str))
        .collect()
}

pub async fn listen(mut stream: Conn, command: Value, ctx: Arc<NodeCtx>) {
    let now = now_ms();
    let auth = match si_core::voice::verify_listen_v3(&command, &relay_ids(&ctx), now) {
        Ok(a) => a,
        Err(e) => return reply(&mut stream, json!({ "ok": false, "error": e })).await,
    };
    let relay = ctx.voice.clone();
    let queue = Arc::new(Queue {
        frames: Mutex::new(VecDeque::new()),
        notify: Notify::new(),
        closed: AtomicBool::new(false),
    });
    let refusal = {
        let st = relay.state.lock().expect("voice");
        match st.temps.get(&auth.temp) {
            Some((used, na)) if *na * 1000 > now && *used != auth.session_id => {
                Some("voice_temp_reused")
            }
            _ if st.sessions.len() >= v::MAX_GLOBAL => Some("pool_full"),
            _ if st.sessions.contains_key(&auth.session_id) => Some("session_conflict"),
            _ => None,
        }
    };
    if let Some(e) = refusal {
        return reply(&mut stream, json!({ "ok": false, "error": e })).await;
    }
    let head = format!(
        "{}{}",
        v::SSE_HEADERS,
        v::ready_frame(&auth.session_id, &ctx.wallet.address())
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    {
        let mut st = relay.state.lock().expect("voice");
        let n = Instant::now();
        st.sessions.insert(
            auth.session_id.clone(),
            Session {
                write_key: auth.write_key,
                queue: queue.clone(),
                last_activity: n,
                rate_window: n,
                rate_chunks: 0,
                rate_bytes: 0,
            },
        );
        if st
            .temps
            .insert(auth.temp.clone(), (auth.session_id.clone(), auth.not_after))
            .is_none()
        {
            st.temp_order.push_back(auth.temp.clone());
        }
        while st.temps.len() > v::TEMP_WALLET_MAX {
            let Some(oldest) = st.temp_order.pop_front() else {
                break;
            };
            st.temps.remove(&oldest);
        }
    }
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut scratch = [0u8; 256];
    loop {
        let next = queue.frames.lock().expect("voice queue").pop_front();
        if let Some(f) = next {
            match tokio::time::timeout(Duration::from_millis(v::DRAIN_TIMEOUT_MS), wr.write_all(&f))
                .await
            {
                Ok(Ok(())) => continue,
                _ => break, // drain timeout or closed socket
            }
        }
        if queue.closed.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            _ = queue.notify.notified() => {}
            r = rd.read(&mut scratch) => if matches!(r, Ok(0) | Err(_)) { break },
        }
    }
    queue.close();
    let mut st = relay.state.lock().expect("voice");
    if st
        .sessions
        .get(&auth.session_id)
        .map(|s| Arc::ptr_eq(&s.queue, &queue))
        .unwrap_or(false)
    {
        st.sessions.remove(&auth.session_id);
    }
}

/// SI `handleVoiceChunk`.
pub async fn chunk(
    mut stream: Conn,
    locator: String,
    mac: [u8; 16],
    blob: Vec<u8>,
    ctx: Arc<NodeCtx>,
) {
    if blob.is_empty() || blob.len() > si_proto::VOICE_CHUNK_MAX_BLOB {
        return reply(
            &mut stream,
            json!({ "ok": false, "error": "invalid_voice_chunk" }),
        )
        .await;
    }
    let outcome: Result<Arc<Queue>, &str> = {
        let mut st = ctx.voice.state.lock().expect("voice");
        match st.sessions.get_mut(&locator) {
            None => Err("target_voice_session_not_found"),
            Some(s) if s.queue.closed.load(Ordering::Relaxed) => {
                Err("target_voice_session_not_found")
            }
            Some(s) => {
                let loc = hex::decode(&locator).unwrap_or_default();
                if !si_crypto::sym::ct_eq(
                    &si_crypto::sym::chunk_mac(&s.write_key, &loc, &blob),
                    &mac,
                ) {
                    Err("voice_chunk_auth")
                } else {
                    if s.rate_window.elapsed() >= Duration::from_secs(1) {
                        s.rate_window = Instant::now();
                        s.rate_chunks = 0;
                        s.rate_bytes = 0;
                    }
                    s.rate_chunks += 1;
                    s.rate_bytes += blob.len();
                    if s.rate_chunks > v::MAX_PER_SEC || s.rate_bytes > v::MAX_BYTES_PER_SEC {
                        Err("voice_chunk_rate")
                    } else {
                        s.last_activity = Instant::now();
                        Ok(s.queue.clone())
                    }
                }
            }
        }
    };
    match outcome {
        Err(e) => reply(&mut stream, json!({ "ok": false, "error": e })).await,
        Ok(q) => {
            use base64::Engine;
            let frame = v::chunk_frame(&base64::engine::general_purpose::STANDARD.encode(&blob));
            if q.push(frame.into_bytes()) {
                reply(&mut stream, json!({ "ok": true })).await
            } else {
                ctx.voice.remove(&locator);
                reply(
                    &mut stream,
                    json!({ "ok": false, "error": "target_voice_session_closed" }),
                )
                .await
            }
        }
    }
}

/// SI `handleVoiceUnlisten`.
pub async fn unlisten(mut stream: Conn, command: Value, ctx: Arc<NodeCtx>) {
    let raw = command
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let valid =
        (16..=64).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    let session_id = if valid { raw } else { "" };
    if !session_id.is_empty() {
        ctx.voice.remove(session_id);
    }
    reply(&mut stream, json!({ "ok": true, "sessionId": session_id })).await
}

/// SI `storeVoiceOffer` validation and expiry rules. Returns (callId, sessionId, armor, expiresAt).
pub fn offer_fields(c: &Value, now: i64) -> Option<(String, String, String, i64)> {
    let call_id = c.get("callId").and_then(Value::as_str)?.trim().to_string();
    let session_id = c
        .get("sessionId")
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    let armor = c
        .get("offerArmor")
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if !(8..=128).contains(&call_id.len()) || !(16..=128).contains(&session_id.len()) {
        return None;
    }
    if armor.is_empty() || armor.len() > v::OFFER_ARMOR_MAX || !armor.contains(si_proto::PGP_BEGIN)
    {
        return None;
    }
    // SI reads expiresAt only when it is a JSON number.
    let mut exp = c
        .get("expiresAt")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    if !exp.is_finite() || exp <= now as f64 || exp > (now + v::OFFER_MAX_TTL_MS) as f64 {
        exp = (now + v::OFFER_DEFAULT_TTL_MS) as f64;
    }
    Some((call_id, session_id, armor, exp as i64))
}

/// SI `handleVoiceOfferStore`.
pub async fn offer_store(mut stream: Conn, c: Value, ctx: Arc<NodeCtx>) {
    let now = now_ms();
    let trim = |k: &str| {
        c.get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let (call_id, session_id) = (trim("callId"), trim("sessionId"));
    let fields = offer_fields(&c, now);
    let ok = match &fields {
        Some((cid, sid, armor, exp)) => ctx.offers.put(cid, sid, armor, *exp, now),
        None => false,
    };
    let mut out = Map::new();
    out.insert("ok".into(), json!(ok));
    if !ok {
        out.insert("error".into(), json!("invalid_voice_offer_store"));
    }
    out.insert("callId".into(), json!(call_id));
    out.insert("sessionId".into(), json!(session_id));
    if let (true, Some((cid, sid, armor, _))) = (ok, fields) {
        let key = si_crypto::opgp::recipient_key_ids(&armor)
            .ok()
            .filter(|k| k.len() == 1)
            .map(|mut k| k.remove(0));
        if let Some(key) = key {
            // Delivered only when the callee's mailbox is this node; stored without a chat push.
            if ctx.resolve(&key).await == Resolved::Local {
                ctx.mailbox.deliver(
                    &key,
                    Stored {
                        armor: armor.clone(),
                        no_push: true,
                        hop_bytes: 0,
                        hops: 0,
                    },
                );
                out.insert("delivered".into(), json!(true));
            }
            if si_proto::js_number(c.get("push")) == Some(1.0)
                && push_call(&c, &cid, &sid, &key, now, &ctx).await
            {
                out.insert("pushed".into(), json!(true));
            }
        }
    }
    reply(&mut stream, Value::Object(out)).await
}

/// SI `pushVoiceCallFromOffer`.
async fn push_call(
    c: &Value,
    call_id: &str,
    session_id: &str,
    key: &str,
    now: i64,
    ctx: &NodeCtx,
) -> bool {
    let Some(expires_at) = c.get("expiresAt").and_then(Value::as_f64) else {
        return false;
    };
    if expires_at <= now as f64 || expires_at > (now + 10 * 60_000) as f64 {
        return false;
    }
    let Some(ts) = si_proto::js_number(c.get("pushTimestamp")) else {
        return false;
    };
    if (now.div_euclid(1000) as f64 - ts).abs() > 600.0 {
        return false;
    }
    let Some(ur) = &ctx.user_routes else {
        return false;
    };
    let Ok(Some(callee)) = ur.wallet_of_user_key(key).await else {
        return false;
    };
    ctx.push.voice_call(crate::push::VoiceCall {
        call_id: call_id.into(),
        session_id: session_id.into(),
        callee_eoa: callee,
        expires_at: expires_at as i64,
        timestamp: ts as i64,
    });
    true
}

/// SI `handleVoiceOfferFetch`.
pub async fn offer_fetch(mut stream: Conn, c: Value, ctx: Arc<NodeCtx>) {
    let trim = |k: &str| {
        c.get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let (call_id, session_id) = (trim("callId"), trim("sessionId"));
    match ctx.offers.get(&call_id, &session_id, now_ms()) {
        Some(o) => reply(&mut stream, json!({ "ok": true, "callId": o.call_id, "sessionId": o.session_id, "expiresAt": o.expires_at, "offerArmor": o.offer_armor })).await,
        None => reply(&mut stream, json!({ "ok": false, "error": "not_found", "callId": call_id, "sessionId": session_id })).await,
    }
}

/// Random 32-hex session id (tests and tools).
pub fn random_session_id() -> String {
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

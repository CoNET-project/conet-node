//! Beamio API hooks (SI `util.ts`): offline-chat push, native-wake lookup, device registration.
//! Bodies carry key IDs and wallets only, never message content. Node-signed texts come from
//! the signer (`NodeNotices`).
use crate::chain::{BoxFut, UserRoutes};
use serde_json::{json, Value};
use si_core::NodeNotices;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

/// SI `notifyVoiceCallPush` payload (opaque ids and the callee wallet; nothing about the caller).
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceCall {
    pub call_id: String,
    pub session_id: String,
    pub callee_eoa: String,
    pub expires_at: i64,
    pub timestamp: i64,
}

pub trait Push: Send + Sync {
    /// Fire-and-forget VoIP/FCM wake for an offer (`voice_offer_store` with `push: 1`).
    fn voice_call(&self, call: VoiceCall);
    /// Fire-and-forget after a durable save (not for `NoPush` work).
    fn offline_chat(&self, user_key: String);
    /// None = lookup failed or untrusted answer.
    fn native_wakeable<'a>(&'a self, eoa: &'a str) -> BoxFut<'a, Option<bool>>;
    /// Forward a shell's own signed device registration.
    fn register_device(&self, payload: Value);
}

/// Disabled hooks (tests, nodes without API access).
pub struct NoPush;

impl Push for NoPush {
    fn voice_call(&self, _call: VoiceCall) {}
    fn offline_chat(&self, _user_key: String) {}
    fn native_wakeable<'a>(&'a self, _eoa: &'a str) -> BoxFut<'a, Option<bool>> {
        Box::pin(async { None })
    }
    fn register_device(&self, _payload: Value) {}
}

pub struct BeamioApi {
    base: String,
    http: reqwest::Client,
    notices: Arc<dyn NodeNotices>,
    routes: Arc<dyn UserRoutes>,
    /// Checksummed node wallet (SI sends `nodeWallet: nodeWallet.address`).
    node_wallet: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl BeamioApi {
    pub fn new(
        base: &str,
        notices: Arc<dyn NodeNotices>,
        routes: Arc<dyn UserRoutes>,
        node_wallet: String,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()?,
            notices,
            routes,
            node_wallet,
        })
    }
}

/// Run a blocking signer call off the async threads.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

impl Push for Arc<BeamioApi> {
    fn voice_call(&self, call: VoiceCall) {
        let me = self.clone();
        tokio::spawn(async move {
            let n = me.notices.clone();
            let c = call.clone();
            let Some(Ok(signature)) = blocking(move || {
                n.sign_voice_call_push(
                    &c.call_id,
                    &c.session_id,
                    &c.callee_eoa,
                    c.expires_at,
                    c.timestamp,
                )
            })
            .await
            else {
                return;
            };
            let node = me.node_wallet.clone();
            let body = json!({ "callId": call.call_id, "sessionId": call.session_id, "calleeEoa": call.callee_eoa, "expiresAt": call.expires_at, "timestamp": call.timestamp, "nodeWallet": node, "signature": signature });
            let r = me
                .http
                .post(format!("{}/api/voiceCallPush", me.base))
                .json(&body)
                .send()
                .await;
            debug!(
                ok = r.map(|r| r.status().is_success()).unwrap_or(false),
                "voiceCallPush"
            );
        });
    }

    fn offline_chat(&self, user_key: String) {
        let me = self.clone();
        tokio::spawn(async move {
            let Ok(Some(eoa)) = me.routes.wallet_of_user_key(&user_key).await else {
                return;
            };
            let ts = now();
            let n = me.notices.clone();
            let (k, e) = (user_key.clone(), eoa.clone());
            let Some(Ok(signature)) = blocking(move || n.sign_offline_chat(&k, &e, ts)).await
            else {
                return;
            };
            let body = json!({ "pgpKeyId": user_key, "eoa": eoa, "timestamp": ts, "signature": signature, "count": 1 });
            let r = me
                .http
                .post(format!("{}/api/notifyOfflineChat", me.base))
                .json(&body)
                .send()
                .await;
            debug!(
                ok = r.map(|r| r.status().is_success()).unwrap_or(false),
                "notifyOfflineChat"
            );
        });
    }

    fn native_wakeable<'a>(&'a self, eoa: &'a str) -> BoxFut<'a, Option<bool>> {
        Box::pin(async move {
            let ts = now();
            let eoa = eoa.to_lowercase();
            let n = self.notices.clone();
            let e = eoa.clone();
            let signature = blocking(move || n.sign_native_wakeable(&e, ts))
                .await?
                .ok()?;
            let body = json!({ "eoa": eoa, "timestamp": ts, "signature": signature });
            let r = self
                .http
                .post(format!("{}/api/nativeWakeable", self.base))
                .json(&body)
                .send()
                .await
                .ok()?;
            if !r.status().is_success() {
                return None;
            }
            let v: Value = r.json().await.ok()?;
            (v.get("success") == Some(&Value::Bool(true)))
                .then(|| v.get("nativeWakeable").and_then(Value::as_bool))
                .flatten()
        })
    }

    fn register_device(&self, payload: Value) {
        let me = self.clone();
        tokio::spawn(async move {
            let r = me
                .http
                .post(format!("{}/api/registerPushDevice", me.base))
                .json(&payload)
                .send()
                .await;
            debug!(
                ok = r.map(|r| r.status().is_success()).unwrap_or(false),
                "registerPushDevice"
            );
        });
    }
}

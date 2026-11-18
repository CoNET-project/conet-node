//! Beamio API hooks (SI `util.ts`): offline-chat push, native-wake lookup, device registration.
//! Bodies carry key IDs and wallets only, never message content. Node-signed texts come from
//! the signer (`NodeNotices`).
//!
//! Target rule (SI 215afb1 `src/util/beamioApi.ts`): every call goes to `BEAMIO_API_BASE`
//! (`https://beamio.ca`). The configured value is only audited; it never changes the target.
//! Redirects are never followed; any 3xx is an explicit error, and failures are never
//! reported as valid empty results.
use crate::chain::{BoxFut, UserRoutes};
use serde_json::{json, Value};
use si_core::NodeNotices;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// The only Beamio API base. The retired `beamio.app` and any other value are never used.
pub const BEAMIO_API_BASE: &str = "https://beamio.ca";
/// Per-request timeout of all four calls (SI: `8_000` ms).
const API_TIMEOUT: Duration = Duration::from_secs(8);

pub const PATH_VOICE_CALL_PUSH: &str = "/api/voiceCallPush";
pub const PATH_NOTIFY_OFFLINE_CHAT: &str = "/api/notifyOfflineChat";
pub const PATH_NATIVE_WAKEABLE: &str = "/api/nativeWakeable";
pub const PATH_REGISTER_PUSH_DEVICE: &str = "/api/registerPushDevice";

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

/// Why a call failed. Carries no URL, body or response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// Connection, TLS or timeout failure.
    Transport,
    /// Any 3xx. Never followed.
    Redirect(u16),
    /// Any other non-2xx status.
    Status(u16),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Transport => write!(f, "Beamio API transport error"),
            ApiError::Redirect(s) => write!(f, "Beamio API redirect refused (HTTP {s})"),
            ApiError::Status(s) => write!(f, "Beamio API HTTP {s}"),
        }
    }
}

/// Startup notices for Beamio API pushes that are off, one per missing setting. A missing
/// `--api-base` (absent or blank) and a missing `--rpc` (static routes, so no user routes) each
/// switch pushes off. The messages never include a configured value.
pub fn push_disabled_reasons(api_base: Option<&str>, has_user_routes: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if !matches!(api_base.map(str::trim), Some(v) if !v.is_empty()) {
        out.push("push disabled: --api-base not set");
    }
    if !has_user_routes {
        out.push("push disabled: --rpc not set");
    }
    out
}

/// Audit of a configured base (`--api-base`, from `BEAMIO_API_BASE`). Returns the reason it is
/// rejected, or None when it is acceptable (exactly `https://beamio.ca`, optional trailing `/`).
/// The value itself is never logged.
pub fn classify_api_base(raw: &str) -> Option<&'static str> {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return Some("unparseable");
    };
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    if host == "beamio.app" || host.ends_with(".beamio.app") {
        return Some("retired-domain");
    }
    if url.scheme() != "https" {
        return Some("not-https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Some("credentials");
    }
    if host != "beamio.ca" {
        return Some("not-allowed-host");
    }
    if url.port().is_some() {
        return Some("port");
    }
    let path = url.path();
    if (path != "/" && !path.is_empty()) || url.query().is_some() || url.fragment().is_some() {
        return Some("path");
    }
    None
}

/// Transport seam: `url` is always built from [`BEAMIO_API_BASE`] by [`ApiClient`].
pub trait ApiTransport: Send + Sync {
    /// POST `body` as JSON. Returns the status and body. For a 3xx the body is not read.
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a Value,
        timeout: Duration,
    ) -> BoxFut<'a, Result<(u16, Vec<u8>), ApiError>>;
}

/// Production transport. Redirects are not followed, so a 3xx comes back as a status.
pub struct ReqwestTransport {
    http: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

impl ApiTransport for ReqwestTransport {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a Value,
        timeout: Duration,
    ) -> BoxFut<'a, Result<(u16, Vec<u8>), ApiError>> {
        Box::pin(async move {
            let resp = self
                .http
                .post(url)
                .timeout(timeout)
                .json(body)
                .send()
                .await
                .map_err(|_| ApiError::Transport)?;
            let status = resp.status().as_u16();
            if (300..400).contains(&status) {
                return Ok((status, Vec::new()));
            }
            let bytes = resp.bytes().await.map_err(|_| ApiError::Transport)?;
            Ok((status, bytes.to_vec()))
        })
    }
}

fn check_status(status: u16) -> Result<(), ApiError> {
    match status {
        200..=299 => Ok(()),
        300..=399 => Err(ApiError::Redirect(status)),
        _ => Err(ApiError::Status(status)),
    }
}

/// The four Beamio API calls. The URL is fixed here; nothing else chooses the host.
pub struct ApiClient {
    transport: Arc<dyn ApiTransport>,
}

impl ApiClient {
    pub fn new(transport: Arc<dyn ApiTransport>) -> Self {
        Self { transport }
    }

    async fn post(&self, path: &'static str, body: &Value) -> Result<Vec<u8>, ApiError> {
        let url = format!("{BEAMIO_API_BASE}{path}");
        let (status, bytes) = self.transport.post_json(&url, body, API_TIMEOUT).await?;
        check_status(status)?;
        Ok(bytes)
    }

    pub async fn voice_call_push(&self, body: &Value) -> Result<(), ApiError> {
        self.post(PATH_VOICE_CALL_PUSH, body).await.map(|_| ())
    }

    pub async fn notify_offline_chat(&self, body: &Value) -> Result<(), ApiError> {
        self.post(PATH_NOTIFY_OFFLINE_CHAT, body).await.map(|_| ())
    }

    pub async fn register_push_device(&self, body: &Value) -> Result<(), ApiError> {
        self.post(PATH_REGISTER_PUSH_DEVICE, body).await.map(|_| ())
    }

    /// `None` for every failure, including 3xx, 5xx, transport errors and bad JSON.
    pub async fn native_wakeable(&self, body: &Value) -> Option<bool> {
        let bytes = match self.post(PATH_NATIVE_WAKEABLE, body).await {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "nativeWakeable failed");
                return None;
            }
        };
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        (v.get("success") == Some(&Value::Bool(true)))
            .then(|| v.get("nativeWakeable").and_then(Value::as_bool))
            .flatten()
    }
}

pub struct BeamioApi {
    client: ApiClient,
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
    /// `base` is the configured value, audited only. It never changes the target.
    pub fn new(
        base: &str,
        notices: Arc<dyn NodeNotices>,
        routes: Arc<dyn UserRoutes>,
        node_wallet: String,
    ) -> Result<Self, reqwest::Error> {
        let raw = base.trim();
        if !raw.is_empty() {
            if let Some(reason) = classify_api_base(raw) {
                warn!(
                    reason,
                    "BEAMIO_API_BASE rejected; using {BEAMIO_API_BASE}. Update the node environment config."
                );
            }
        }
        Ok(Self {
            client: ApiClient::new(Arc::new(ReqwestTransport::new()?)),
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
            match me.client.voice_call_push(&body).await {
                Ok(()) => debug!("voiceCallPush ok"),
                Err(e) => warn!(error = %e, "voiceCallPush failed"),
            }
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
            match me.client.notify_offline_chat(&body).await {
                Ok(()) => debug!("notifyOfflineChat ok"),
                Err(e) => warn!(error = %e, "notifyOfflineChat failed"),
            }
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
            self.client.native_wakeable(&body).await
        })
    }

    fn register_device(&self, payload: Value) {
        let me = self.clone();
        tokio::spawn(async move {
            match me.client.register_push_device(&payload).await {
                Ok(()) => debug!("registerPushDevice ok"),
                Err(e) => warn!(error = %e, "registerPushDevice failed"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Test-only transport that points `https://beamio.ca` at a loopback stub and records
    /// every URL the client built. It is injected in code; no config reads it.
    struct RewriteTransport {
        inner: ReqwestTransport,
        to: String,
        seen: Mutex<Vec<String>>,
    }

    impl RewriteTransport {
        fn new(to: String) -> Self {
            Self {
                inner: ReqwestTransport::new().unwrap(),
                to,
                seen: Mutex::new(Vec::new()),
            }
        }
        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl ApiTransport for RewriteTransport {
        fn post_json<'a>(
            &'a self,
            url: &'a str,
            body: &'a Value,
            timeout: Duration,
        ) -> BoxFut<'a, Result<(u16, Vec<u8>), ApiError>> {
            self.seen.lock().unwrap().push(url.to_string());
            let real = url.replacen(BEAMIO_API_BASE, &self.to, 1);
            Box::pin(async move { self.inner.post_json(&real, body, timeout).await })
        }
    }

    struct Stub {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
        /// (request line, content-type header, body) per hit
        requests: Arc<Mutex<Vec<(String, String, String)>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Stub {
        fn base(&self) -> String {
            format!("http://{}", self.addr)
        }
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    /// Loopback HTTP/1.1 stub. Replies with a fixed status, optional Location and body.
    async fn spawn_stub(status: u16, location: Option<String>, body: &'static str) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (h, r) = (hits.clone(), requests.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let (h, r, location) = (h.clone(), r.clone(), location.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let head_end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        let mut chunk = [0u8; 1024];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let clen: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + clen {
                        let mut chunk = [0u8; 1024];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let line = head.lines().next().unwrap_or("").to_string();
                    let ctype = head
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
                        .unwrap_or("")
                        .to_string();
                    let req_body = String::from_utf8_lossy(&buf[head_end..]).to_string();
                    r.lock().unwrap().push((line, ctype, req_body));
                    h.fetch_add(1, Ordering::SeqCst);
                    let loc = location
                        .map(|l| format!("Location: {l}\r\n"))
                        .unwrap_or_default();
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{loc}Connection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        Stub {
            addr,
            hits,
            requests,
            task,
        }
    }

    fn voice_body() -> Value {
        json!({ "callId": "c1", "sessionId": "s1", "calleeEoa": "0x00000000000000000000000000000000000000aa", "expiresAt": 1, "timestamp": 2, "nodeWallet": "0x00000000000000000000000000000000000000bb", "signature": "0xsig" })
    }
    fn offline_body() -> Value {
        json!({ "pgpKeyId": "K1", "eoa": "0x00000000000000000000000000000000000000aa", "timestamp": 3, "signature": "0xsig", "count": 1 })
    }
    fn wake_body() -> Value {
        json!({ "eoa": "0x00000000000000000000000000000000000000aa", "timestamp": 4, "signature": "0xsig" })
    }
    fn device_body() -> Value {
        json!({ "eoa": "0x00000000000000000000000000000000000000aa", "deviceToken": "t", "platform": "ios", "bundleId": "b", "pgpKeyId": "K1", "timestamp": 5, "signature": "0xsig", "capabilities": [] })
    }

    /// Calls each of the four API paths once through `client`.
    async fn call_all(client: &ApiClient) -> [Result<(), ApiError>; 4] {
        let a = client.voice_call_push(&voice_body()).await;
        let b = client.notify_offline_chat(&offline_body()).await;
        let c = client
            .native_wakeable(&wake_body())
            .await
            .map(|_| ())
            .ok_or(ApiError::Transport);
        let d = client.register_push_device(&device_body()).await;
        [a, b, c, d]
    }

    #[test]
    fn startup_warns_for_each_missing_push_setting() {
        let base = "push disabled: --api-base not set";
        let rpc = "push disabled: --rpc not set";
        // --api-base absent or blank.
        assert_eq!(push_disabled_reasons(None, true), vec![base]);
        assert_eq!(push_disabled_reasons(Some(""), true), vec![base]);
        assert_eq!(push_disabled_reasons(Some("   "), true), vec![base]);
        // A value, even a rejected one, is not a missing setting: the audit warns about it.
        assert_eq!(
            push_disabled_reasons(Some("https://beamio.ca"), true),
            Vec::<&str>::new()
        );
        assert_eq!(
            push_disabled_reasons(Some("https://beamio.app"), true),
            Vec::<&str>::new()
        );
        // --rpc absent (static routes): pushes are off whatever --api-base says.
        assert_eq!(
            push_disabled_reasons(Some("https://beamio.ca"), false),
            vec![rpc]
        );
        assert_eq!(push_disabled_reasons(None, false), vec![base, rpc]);
        // The messages carry no configured value.
        for m in push_disabled_reasons(None, false) {
            assert!(!m.contains("http") && !m.contains("beamio"), "{m}");
        }
    }

    #[test]
    fn configured_base_is_audited_and_only_canonical_is_accepted() {
        assert_eq!(BEAMIO_API_BASE, "https://beamio.ca");
        assert_eq!(classify_api_base("https://beamio.ca"), None);
        assert_eq!(classify_api_base("https://beamio.ca/"), None);
        for bad in [
            "https://beamio.app",
            "https://api.beamio.app",
            "https://BEAMIO.APP/",
            "http://beamio.ca",
            "https://beamio.ca.evil.test",
            "https://evil.test",
            "https://user:pw@beamio.ca",
            "https://beamio.ca:8443",
            "https://beamio.ca/x",
            "https://beamio.ca?x=1",
            "https://beamio.ca#frag",
            "not a url",
        ] {
            assert!(classify_api_base(bad).is_some(), "accepted {bad:?}");
        }
    }

    #[tokio::test]
    async fn four_paths_target_fixed_host_path_and_keep_body_and_type() {
        let stub = spawn_stub(200, None, r#"{"success":true,"nativeWakeable":true}"#).await;
        let t = Arc::new(RewriteTransport::new(stub.base()));
        let client = ApiClient::new(t.clone());
        let results = call_all(&client).await;
        assert!(results.iter().all(|r| r.is_ok()), "{results:?}");
        assert_eq!(
            t.seen(),
            vec![
                "https://beamio.ca/api/voiceCallPush",
                "https://beamio.ca/api/notifyOfflineChat",
                "https://beamio.ca/api/nativeWakeable",
                "https://beamio.ca/api/registerPushDevice",
            ]
        );
        let reqs = stub.requests.lock().unwrap().clone();
        assert_eq!(reqs.len(), 4);
        let expected = [
            ("POST /api/voiceCallPush HTTP/1.1", voice_body()),
            ("POST /api/notifyOfflineChat HTTP/1.1", offline_body()),
            ("POST /api/nativeWakeable HTTP/1.1", wake_body()),
            ("POST /api/registerPushDevice HTTP/1.1", device_body()),
        ];
        for ((line, ctype, body), (want_line, want_body)) in reqs.iter().zip(expected) {
            assert_eq!(line, want_line);
            assert!(
                ctype.to_ascii_lowercase().contains("application/json"),
                "{ctype}"
            );
            let got: Value = serde_json::from_str(body).unwrap();
            assert_eq!(got, want_body);
        }
    }

    #[tokio::test]
    async fn fixed_target_ignores_configured_value_and_old_domain() {
        // The constructor audits the value; the URL is composed only from BEAMIO_API_BASE.
        for raw in [
            "https://beamio.app",
            "http://127.0.0.1:9",
            "https://evil.test/",
        ] {
            assert!(classify_api_base(raw).is_some());
            let t = Arc::new(RewriteTransport::new("http://127.0.0.1:9".to_string()));
            let _ = ApiClient::new(t.clone())
                .voice_call_push(&voice_body())
                .await;
            assert!(
                t.seen()[0].starts_with("https://beamio.ca/api/"),
                "{:?}",
                t.seen()
            );
        }
    }

    #[tokio::test]
    async fn redirects_are_refused_and_never_followed() {
        for status in [301u16, 302, 307, 308] {
            let landing = spawn_stub(200, None, r#"{"success":true,"nativeWakeable":true}"#).await;
            let front = spawn_stub(status, Some(format!("{}/landing", landing.base())), "").await;
            let t = Arc::new(RewriteTransport::new(front.base()));
            let client = ApiClient::new(t.clone());
            let results = call_all(&client).await;
            for (i, r) in results.iter().enumerate() {
                if i == 2 {
                    continue;
                }
                assert_eq!(
                    *r,
                    Err(ApiError::Redirect(status)),
                    "path {i} status {status}"
                );
            }
            assert_eq!(
                client.native_wakeable(&wake_body()).await,
                None,
                "status {status}"
            );
            assert_eq!(
                front.hits(),
                5,
                "status {status}: one hit per call, no follow"
            );
            assert_eq!(
                landing.hits(),
                0,
                "status {status}: redirect target was contacted"
            );
        }
    }

    #[tokio::test]
    async fn production_transport_does_not_follow_redirects() {
        let landing = spawn_stub(200, None, "{}").await;
        let front = spawn_stub(302, Some(format!("{}/x", landing.base())), "").await;
        let url = format!("{}/api/nativeWakeable", front.base());
        let t = ReqwestTransport::new().unwrap();
        let (status, body) = t.post_json(&url, &wake_body(), API_TIMEOUT).await.unwrap();
        assert_eq!(status, 302);
        assert!(body.is_empty());
        assert_eq!(front.hits(), 1);
        assert_eq!(landing.hits(), 0);
    }

    #[tokio::test]
    async fn failures_are_never_valid_empty_results() {
        // Positive control: a valid answer is returned.
        let ok = spawn_stub(200, None, r#"{"success":true,"nativeWakeable":true}"#).await;
        let c = ApiClient::new(Arc::new(RewriteTransport::new(ok.base())));
        assert_eq!(c.native_wakeable(&wake_body()).await, Some(true));

        let ok_false = spawn_stub(200, None, r#"{"success":true,"nativeWakeable":false}"#).await;
        let c = ApiClient::new(Arc::new(RewriteTransport::new(ok_false.base())));
        assert_eq!(c.native_wakeable(&wake_body()).await, Some(false));

        // Unsuccessful or unparseable 2xx answers: unknown, not "false".
        for body in [
            r#"{"success":false,"nativeWakeable":false}"#,
            "not json",
            "{}",
        ] {
            let s = spawn_stub(200, None, Box::leak(body.to_string().into_boxed_str())).await;
            let c = ApiClient::new(Arc::new(RewriteTransport::new(s.base())));
            assert_eq!(c.native_wakeable(&wake_body()).await, None, "body {body:?}");
        }

        // 5xx.
        let s5 = spawn_stub(503, None, r#"{"success":true,"nativeWakeable":false}"#).await;
        let c = ApiClient::new(Arc::new(RewriteTransport::new(s5.base())));
        assert_eq!(c.native_wakeable(&wake_body()).await, None);
        assert_eq!(
            c.voice_call_push(&voice_body()).await,
            Err(ApiError::Status(503))
        );
        assert_eq!(
            c.notify_offline_chat(&offline_body()).await,
            Err(ApiError::Status(503))
        );
        assert_eq!(
            c.register_push_device(&device_body()).await,
            Err(ApiError::Status(503))
        );

        // Connection refused (port closed after bind).
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let c = ApiClient::new(Arc::new(RewriteTransport::new(format!("http://{closed}"))));
        assert_eq!(c.native_wakeable(&wake_body()).await, None);
        assert_eq!(
            c.voice_call_push(&voice_body()).await,
            Err(ApiError::Transport)
        );
    }

    // ---- review negatives (review copy only; not part of the commit) ----

    #[tokio::test]
    async fn review_full_3xx_matrix_refused_on_every_path() {
        for status in [300u16, 301, 302, 303, 304, 307, 308] {
            let landing = spawn_stub(200, None, r#"{"success":true,"nativeWakeable":true}"#).await;
            let front = spawn_stub(status, Some(format!("{}/landing", landing.base())), "").await;
            let client = ApiClient::new(Arc::new(RewriteTransport::new(front.base())));
            assert_eq!(
                client.voice_call_push(&voice_body()).await,
                Err(ApiError::Redirect(status))
            );
            assert_eq!(
                client.notify_offline_chat(&offline_body()).await,
                Err(ApiError::Redirect(status))
            );
            assert_eq!(
                client.register_push_device(&device_body()).await,
                Err(ApiError::Redirect(status))
            );
            assert_eq!(
                client.native_wakeable(&wake_body()).await,
                None,
                "status {status}"
            );
            assert_eq!(front.hits(), 4, "status {status}");
            assert_eq!(
                landing.hits(),
                0,
                "status {status}: redirect target contacted"
            );
        }
    }

    #[tokio::test]
    async fn review_3xx_without_location_is_still_refused() {
        let front = spawn_stub(302, None, "").await;
        let client = ApiClient::new(Arc::new(RewriteTransport::new(front.base())));
        assert_eq!(
            client.notify_offline_chat(&offline_body()).await,
            Err(ApiError::Redirect(302))
        );
        assert_eq!(front.hits(), 1);
    }

    #[tokio::test]
    async fn review_production_transport_refuses_each_redirect_status() {
        for status in [301u16, 307, 308] {
            let landing = spawn_stub(200, None, "{}").await;
            let front = spawn_stub(status, Some(format!("{}/x", landing.base())), "").await;
            let url = format!("{}/api/voiceCallPush", front.base());
            let t = ReqwestTransport::new().unwrap();
            let (got, _) = t.post_json(&url, &voice_body(), API_TIMEOUT).await.unwrap();
            assert_eq!(got, status);
            assert_eq!(front.hits(), 1, "status {status}");
            assert_eq!(landing.hits(), 0, "status {status}: followed");
        }
    }

    #[tokio::test]
    async fn review_nativewakeable_bad_answers_are_unknown_not_false() {
        let cases: [(u16, &'static str); 5] = [
            (404, r#"{"success":true,"nativeWakeable":false}"#),
            (400, r#"{"success":true,"nativeWakeable":false}"#),
            (200, r#"{"success":true}"#),
            (200, r#"{"success":true,"nativeWakeable":"true"}"#),
            (200, r#"{"success":true,"nativeWakeable":null}"#),
        ];
        for (status, body) in cases {
            let s = spawn_stub(status, None, body).await;
            let c = ApiClient::new(Arc::new(RewriteTransport::new(s.base())));
            assert_eq!(
                c.native_wakeable(&wake_body()).await,
                None,
                "{status} {body}"
            );
        }
    }

    #[tokio::test]
    async fn review_timeout_is_transport_error_not_empty_result() {
        // Accepts the connection, never answers.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        let c = ApiClient::new(Arc::new(RewriteTransport::new(format!("http://{addr}"))));
        assert_eq!(
            c.voice_call_push(&voice_body()).await,
            Err(ApiError::Transport)
        );
        assert_eq!(c.native_wakeable(&wake_body()).await, None);
        hold.abort();
    }
}

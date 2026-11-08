//! Signer service: policy checks, then the operation. Logs never contain payloads.
use crate::proto::{self, Request, Response};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use si_core::statement::{AnchorReceipt, BindNode, Domain};
use si_crypto::{eip712 as e7, eth, opgp};
use si_proto as sp;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};
use zeroize::Zeroizing;

pub struct Signer {
    wallet: eth::EthKey,
    route: opgp::SecretCert,
    key_id: String,
    /// Retiring route key (R11), if any.
    previous: Option<(opgp::SecretCert, String)>,
    domain: Domain,
    pub allow_bind: bool,
    /// When set, only this peer uid may connect.
    pub allow_uid: Option<u32>,
    /// This node's NodeRegistryV2 id; None = no anchor receipts.
    pub anchor_node_id: Option<String>,
}

/// Contract ceiling for an online window (`ONLINE_TTL_CEIL`, 7 days): a receipt never covers more.
pub const ANCHOR_MAX_TTL_SEC: i64 = 7 * 24 * 3600;

pub struct SignerConfig {
    pub keystore_file: String,
    pub kek: Zeroizing<[u8; 32]>,
    pub verifying_contract: String,
    pub allow_bind: bool,
    pub allow_uid: Option<u32>,
    /// `--anchor-node-id`: this node's NodeRegistryV2 id (decimal). None = no anchor receipts.
    pub anchor_node_id: Option<String>,
}

#[derive(Debug)]
pub struct StartError(pub String);

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Signer {
    pub fn start(cfg: SignerConfig) -> Result<Self, StartError> {
        let secrets = crate::keystore::open(&cfg.kek, &cfg.keystore_file)
            .map_err(|e| StartError(e.to_string()))?;
        let wallet =
            eth::EthKey::from_hex(&secrets.wallet_hex).map_err(|e| StartError(e.to_string()))?;
        let (route, key_id) = si_core::node::load_route(&secrets.pgp_armored, &secrets.pgp_pass)
            .map_err(|e| StartError(e.to_string()))?;
        let previous = if secrets.previous_pgp_armored.is_empty() {
            None
        } else {
            Some(
                si_core::node::load_route(
                    &secrets.previous_pgp_armored,
                    &secrets.previous_pgp_pass,
                )
                .map_err(|e| StartError(e.to_string()))?,
            )
        };
        drop(secrets);
        let domain = Domain::new(&cfg.verifying_contract).map_err(|e| StartError(e.to_string()))?;
        Ok(Self {
            wallet,
            route,
            key_id,
            previous,
            domain,
            allow_bind: cfg.allow_bind,
            allow_uid: cfg.allow_uid,
            anchor_node_id: cfg.anchor_node_id,
        })
    }

    pub fn handle(&self, req: Request) -> Response {
        let refused = |r: &str| Response::Refused {
            reason: r.to_string(),
        };
        let ok = |v: String| Response::Ok { value: v };
        match req {
            Request::Address => ok(self.wallet.address()),
            Request::RouteKeyId => ok(self.key_id.clone()),
            Request::OldRouteKeyIds => ok(self
                .previous
                .as_ref()
                .map(|(_, id)| id.clone())
                .unwrap_or_default()),
            Request::SignHop { t, n, h, k } => {
                let hh = h.strip_prefix("0x").unwrap_or("");
                if (now() - t).abs() > sp::HOP_SIG_TS_WINDOW_SEC
                    || !is_hex(hh, 64)
                    || !is_hex(&k, 16)
                    || n > 64 * 1024 * 1024
                {
                    return refused("hop_fields");
                }
                let payload = sp::hop_sig_payload(&self.wallet.address(), t, n, &h, &k);
                self.wallet
                    .sign_message(&payload)
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::SignEpoch { epoch } => self
                .wallet
                .sign_message(&epoch.to_string())
                .map(ok)
                .unwrap_or_else(|_| refused("sign")),
            Request::SignOfflineChat {
                pgp_key_id,
                eoa,
                timestamp,
            } => {
                if !is_hex(&pgp_key_id, 16)
                    || !eth::is_address(&eoa)
                    || (now() - timestamp as i64).abs() > 600
                {
                    return refused("notice_fields");
                }
                let text = sp::api_texts::notify_offline_chat(&pgp_key_id, &eoa, timestamp);
                self.wallet
                    .sign_message(&text)
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::SignNativeWakeable { eoa, timestamp } => {
                if !eth::is_address(&eoa) || (now() - timestamp as i64).abs() > 600 {
                    return refused("notice_fields");
                }
                let text = sp::api_texts::native_wakeable(&eoa, timestamp);
                self.wallet
                    .sign_message(&text)
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::SignVoiceCallPush {
                call_id,
                session_id,
                callee_eoa,
                expires_at,
                timestamp,
            } => {
                let now_ms = now() * 1000;
                let fields_ok = (8..=128).contains(&call_id.len())
                    && (16..=128).contains(&session_id.len())
                    && eth::is_address(&callee_eoa)
                    && expires_at > now_ms
                    && expires_at <= now_ms + 10 * 60_000
                    && (now() - timestamp).abs() <= 600;
                if !fields_ok {
                    return refused("notice_fields");
                }
                let text = sp::voice::call_push_text(
                    &call_id,
                    &session_id,
                    &callee_eoa,
                    expires_at,
                    timestamp,
                    &self.wallet.address(),
                );
                self.wallet
                    .sign_message(&text)
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::SignWebrtcEndpoint {
                key_id,
                ip,
                port,
                fingerprint,
                expires,
            } => {
                let ip_ok = ip
                    .parse::<std::net::Ipv4Addr>()
                    .map(|a| !a.is_unspecified() && !a.is_broadcast() && !a.is_multicast())
                    .unwrap_or(false);
                let fields_ok = ip_ok
                    && key_id.eq_ignore_ascii_case(&self.key_id)
                    && port != 0
                    && sp::webrtc::valid_fingerprint(&fingerprint)
                    && expires > now()
                    && expires <= now() + sp::webrtc::ENDPOINT_MAX_VALID_SEC;
                if !fields_ok {
                    return refused("webrtc_fields");
                }
                let text = sp::webrtc::endpoint_text(
                    &self.key_id,
                    &self.wallet.address(),
                    &ip,
                    port,
                    &fingerprint,
                    expires,
                );
                self.wallet
                    .sign_message(&text)
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::SignAcmeDns01 {
                key_id,
                value,
                dns_op: op,
                expires,
            } => {
                let fields_ok = key_id.eq_ignore_ascii_case(&self.key_id)
                    && sp::acme::valid_txt_value(&value)
                    && sp::acme::valid_op(&op)
                    && expires > now()
                    && expires <= now() + sp::acme::DNS01_MAX_VALID_SEC;
                if !fields_ok {
                    return refused("acme_fields");
                }
                let text = sp::acme::dns01_text(
                    &self.key_id,
                    &self.wallet.address(),
                    &value,
                    &op,
                    expires,
                );
                self.wallet
                    .sign_message(&text)
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::RouteSessionKey { pkesk } => {
                let Ok(bytes) = B64.decode(pkesk) else {
                    return refused("pkesk_fields");
                };
                let current = opgp::session_key_from_pkesk(&bytes, &self.route);
                let result = match (current, &self.previous) {
                    (Err(_), Some((old, _))) => opgp::session_key_from_pkesk(&bytes, old),
                    (r, _) => r,
                };
                match result {
                    Ok((alg, key)) => ok(format!(
                        "{alg}:{}",
                        B64.encode(zeroize::Zeroizing::new(key).as_slice())
                    )),
                    Err(_) => refused("decrypt"),
                }
            }
            Request::SignBind {
                operator,
                node_id,
                ip_hash,
                key_id,
                pgp_hash,
                nonce,
                deadline,
            } => {
                if !self.allow_bind {
                    return refused("bind_disabled");
                }
                let b = (|| -> si_crypto::Result<BindNode> {
                    Ok(BindNode {
                        operator: e7::address_word(&operator)?,
                        node_id: e7::u256_dec(&node_id)?,
                        ip_hash: e7::bytes32(&ip_hash)?,
                        key_id: e7::fixed_bytes_word(&key_id, 8)?,
                        pgp_hash: e7::bytes32(&pgp_hash)?,
                        nonce: e7::u256_dec(&nonce)?,
                        deadline: e7::u256_dec(&deadline)?,
                    })
                })();
                let Ok(b) = b else {
                    return refused("bind_fields");
                };
                // Only consent for our own route key.
                if e7::fixed_bytes_word(&format!("0x{}", self.key_id.to_lowercase()), 8).ok()
                    != Some(b.key_id)
                {
                    return refused("bind_key_mismatch");
                }
                self.wallet
                    .sign_digest(&b.digest(&self.domain))
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
            Request::SignAnchorReceipt {
                node_id,
                online_seq,
                online_until,
            } => {
                let Some(own) = &self.anchor_node_id else {
                    return refused("anchor_disabled");
                };
                let (Ok(node), Ok(anchor)) = (e7::u256_dec(&node_id), e7::u256_dec(own)) else {
                    return refused("anchor_fields");
                };
                // Never a receipt for ourselves, for node 0, or for an expired or overlong window.
                let t = now();
                if node == anchor
                    || node == [0u8; 32]
                    || (online_until as i64) <= t
                    || (online_until as i64) > t + ANCHOR_MAX_TTL_SEC
                    || online_seq == 0
                {
                    return refused("anchor_fields");
                }
                let r = AnchorReceipt {
                    node_id: node,
                    anchor_node_id: anchor,
                    online_seq,
                    online_until,
                };
                self.wallet
                    .sign_digest(&r.digest(&self.domain))
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
            }
        }
    }
}

pub async fn serve(listener: UnixListener, signer: Arc<Signer>) -> std::io::Result<()> {
    info!(wallet = %signer.wallet.address(), key_id = %signer.key_id, "signer ready");
    loop {
        let (stream, _) = listener.accept().await?;
        let s = signer.clone();
        tokio::spawn(async move {
            let _ = one(stream, s).await;
        });
    }
}

async fn one(mut stream: UnixStream, signer: Arc<Signer>) -> std::io::Result<()> {
    if let Some(uid) = signer.allow_uid {
        let ok = stream.peer_cred().map(|c| c.uid() == uid).unwrap_or(false);
        if !ok {
            warn!("signer: refused peer uid");
            return Ok(());
        }
    }
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > proto::MAX_FRAME {
        return Ok(());
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    let resp = match serde_json::from_slice::<Request>(&buf) {
        Ok(req) => {
            let s = signer.clone();
            tokio::task::spawn_blocking(move || s.handle(req))
                .await
                .unwrap_or(Response::Refused {
                    reason: "internal".into(),
                })
        }
        Err(_) => Response::Refused {
            reason: "bad_request".into(),
        },
    };
    stream.write_all(&proto::encode(&resp)).await
}

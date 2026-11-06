//! Signer service: policy checks, then the operation. Logs never contain payloads.
use crate::proto::{self, Request, Response};
use crate::state::{self, Records};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use si_core::statement::{BindNode, Domain, GuardDecision, NodeStatement, StatementGuard};
use si_crypto::{eip712 as e7, eth, opgp};
use si_proto as sp;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};
use zeroize::Zeroizing;

pub struct Signer {
    wallet: eth::EthKey,
    route: opgp::SecretCert,
    key_id: String,
    domain: Domain,
    kek: Zeroizing<[u8; 32]>,
    state_path: PathBuf,
    /// None = statement signing disabled (state missing or damaged, no floor given).
    statements: Mutex<Option<(Records, StatementGuard)>>,
    pub allow_bind: bool,
    /// When set, only this peer uid may connect.
    pub allow_uid: Option<u32>,
}

pub struct SignerConfig {
    pub keystore_file: String,
    pub kek: Zeroizing<[u8; 32]>,
    pub state_path: PathBuf,
    pub verifying_contract: String,
    /// Operator-set floor when the state file is missing (e.g. a rebuilt server).
    pub reset_floor: Option<u64>,
    pub allow_bind: bool,
    pub allow_uid: Option<u32>,
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
        drop(secrets);
        let domain = Domain::new(&cfg.verifying_contract).map_err(|e| StartError(e.to_string()))?;
        let statements = match (state::load(&cfg.state_path, &cfg.kek), cfg.reset_floor) {
            (Ok(r), _) => Some((r.clone(), state::guard_from(&r))),
            (Err(_), Some(floor)) => {
                let r = Records {
                    signed: vec![],
                    floor: Some(floor),
                };
                state::save(&cfg.state_path, &cfg.kek, &r)
                    .map_err(|e| StartError(format!("state write: {e}")))?;
                Some((r.clone(), state::guard_from(&r)))
            }
            (Err(e), None) => {
                warn!(?e, "statement state unavailable: statement signing disabled until --reset-statement-floor");
                None
            }
        };
        Ok(Self {
            wallet,
            route,
            key_id,
            domain,
            kek: cfg.kek,
            state_path: cfg.state_path,
            statements: Mutex::new(statements),
            allow_bind: cfg.allow_bind,
            allow_uid: cfg.allow_uid,
        })
    }

    /// Create an empty state file for a fresh keystore (first start of a new node).
    pub fn init_state(path: &std::path::Path, kek: &[u8; 32]) -> std::io::Result<()> {
        state::save(path, kek, &Records::default())
    }

    pub fn handle(&self, req: Request) -> Response {
        let refused = |r: &str| Response::Refused {
            reason: r.to_string(),
        };
        let ok = |v: String| Response::Ok { value: v };
        match req {
            Request::Address => ok(self.wallet.address()),
            Request::RouteKeyId => ok(self.key_id.clone()),
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
            Request::RouteSessionKey { pkesk } => {
                let Ok(bytes) = B64.decode(pkesk) else {
                    return refused("pkesk_fields");
                };
                match opgp::session_key_from_pkesk(&bytes, &self.route) {
                    Ok((alg, key)) => ok(format!(
                        "{alg}:{}",
                        B64.encode(zeroize::Zeroizing::new(key).as_slice())
                    )),
                    Err(_) => refused("decrypt"),
                }
            }
            Request::SignStatement {
                node_id,
                epoch,
                kind,
                payload_hash,
            } => {
                let (Ok(node_id), Ok(payload_hash)) =
                    (e7::u256_dec(&node_id), e7::bytes32(&payload_hash))
                else {
                    return refused("statement_fields");
                };
                let st = NodeStatement {
                    node_id,
                    epoch,
                    kind,
                    payload_hash,
                };
                if kind == sp::node_registry::KIND_ONLINE
                    && st != NodeStatement::online(node_id, epoch)
                {
                    return refused("online_payload");
                }
                let mut guard = self.statements.lock().expect("statement lock");
                let Some((records, g)) = guard.as_mut() else {
                    return refused("statement_state_unavailable");
                };
                match g.check(&st) {
                    GuardDecision::Refuse(r) => return refused(r),
                    GuardDecision::SameAsBefore => {}
                    GuardDecision::PersistThenSign { record } => {
                        let mut next = records.clone();
                        next.push(record.0, record.1, &record.2);
                        if state::save(&self.state_path, &self.kek, &next).is_err() {
                            return refused("state_write");
                        }
                        *records = next;
                        g.commit(record);
                    }
                }
                drop(guard);
                self.wallet
                    .sign_digest(&st.digest(&self.domain))
                    .map(ok)
                    .unwrap_or_else(|_| refused("sign"))
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

//! Sans-IO CoNET-SI core.
//!
//! No sockets, no files, no clock, no RNG: the host passes those in. The same code
//! is compiled natively (Linux node) and to wasm32 (browser node).
#![forbid(unsafe_code)]

pub mod node;
pub mod statement;
pub mod voice;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use serde_json::{Map, Value};
use si_crypto::{eth, opgp, sym};
use si_proto as proto;
use std::collections::HashMap;

/// What SI `postOpenpgpRouteSocket` does with one `/post` armor. Serialises to the same JSON
/// shape as the reference classifier in `vectors/gen.mjs`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    /// Entry role: key ID is not ours; forward the same armor untouched.
    Forward {
        #[serde(rename = "keyId")]
        key_id: String,
    },
    /// Peeled our layer; forward the inner armor.
    OnionForward {
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(skip)]
        inner: String,
    },
    /// Inner layer is ours again: SI ends the socket.
    AttackSameNode,
    /// `{ data, NoPush }` mailbox work: deliver inner user-PGP armor.
    MailboxWork {
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "noPush")]
        no_push: bool,
        #[serde(skip)]
        inner: String,
    },
    /// Binary `CVC2` voice chunk.
    VoiceChunk {
        locator: String,
        #[serde(rename = "macOk")]
        mac_ok: bool,
        #[serde(rename = "blobLen")]
        blob_len: usize,
        /// Raw MAC and blob, for the host to check against the live session's write key.
        #[serde(skip)]
        mac: [u8; 16],
        #[serde(skip)]
        blob: Vec<u8>,
    },
    /// Unsigned voice command (sessionId is the capability).
    VoiceCommand {
        command: Value,
    },
    /// EIP-191 checked command.
    SignedCommand {
        command: Value,
    },
    Reject {
        reason: &'static str,
    },
}

/// Decrypts PGP messages addressed to this node's route key. In the product this is a client
/// of the signer process, so the network process never holds the key (design v0.1 §6.2).
pub trait RouteDecryptor: Send + Sync {
    fn decrypt(&self, armor: &str) -> si_crypto::Result<Vec<u8>>;
}

/// In-process implementation, for tests and the conformance runner only.
impl RouteDecryptor for opgp::SecretCert {
    fn decrypt(&self, armor: &str) -> si_crypto::Result<Vec<u8>> {
        opgp::decrypt(armor, self, None).map(|d| d.data)
    }
}

/// Signs EIP-191 messages with the node wallet (hop signatures, gossip). Same remark as above.
pub trait WalletSigner: Send + Sync {
    fn address(&self) -> String;
    fn sign_message(&self, message: &str) -> si_crypto::Result<String>;
}

impl WalletSigner for eth::EthKey {
    fn address(&self) -> String {
        eth::EthKey::address(self)
    }
    fn sign_message(&self, message: &str) -> si_crypto::Result<String> {
        eth::EthKey::sign_message(self, message)
    }
}

/// Fixed-format notices the node wallet signs besides hop rows (the signer builds the text).
pub trait NodeNotices: Send + Sync {
    /// EIP-191 over the decimal epoch (block number), sent in the mailbox handshake.
    fn sign_epoch(&self, epoch: u64) -> si_crypto::Result<String>;
    fn sign_offline_chat(
        &self,
        pgp_key_id: &str,
        eoa: &str,
        timestamp: u64,
    ) -> si_crypto::Result<String>;
    fn sign_native_wakeable(&self, eoa: &str, timestamp: u64) -> si_crypto::Result<String>;
    /// SI `notifyVoiceCallPush` text; the signer adds its own wallet address.
    fn sign_voice_call_push(
        &self,
        call_id: &str,
        session_id: &str,
        callee_eoa: &str,
        expires_at: i64,
        timestamp: i64,
    ) -> si_crypto::Result<String>;
}

impl NodeNotices for eth::EthKey {
    fn sign_voice_call_push(
        &self,
        call_id: &str,
        session_id: &str,
        callee_eoa: &str,
        expires_at: i64,
        timestamp: i64,
    ) -> si_crypto::Result<String> {
        let text = proto::voice::call_push_text(
            call_id,
            session_id,
            callee_eoa,
            expires_at,
            timestamp,
            &eth::EthKey::address(self),
        );
        eth::EthKey::sign_message(self, &text)
    }
    fn sign_epoch(&self, epoch: u64) -> si_crypto::Result<String> {
        eth::EthKey::sign_message(self, &epoch.to_string())
    }
    fn sign_offline_chat(
        &self,
        pgp_key_id: &str,
        eoa: &str,
        timestamp: u64,
    ) -> si_crypto::Result<String> {
        eth::EthKey::sign_message(
            self,
            &proto::api_texts::notify_offline_chat(pgp_key_id, eoa, timestamp),
        )
    }
    fn sign_native_wakeable(&self, eoa: &str, timestamp: u64) -> si_crypto::Result<String> {
        eth::EthKey::sign_message(self, &proto::api_texts::native_wakeable(eoa, timestamp))
    }
}

pub struct LocalRoute<'a> {
    pub key: &'a dyn RouteDecryptor,
    /// Upper-case hex `getKeyIDs()[1]` of the current route key.
    pub key_id: &'a str,
    /// Route keys being retired (R11 transition): still decrypted, never published.
    pub old_key_ids: &'a [String],
}

impl LocalRoute<'_> {
    pub fn is_local(&self, k: &str) -> bool {
        k == self.key_id || self.old_key_ids.iter().any(|o| o == k)
    }
}

/// Voice channel write keys by 32-hex locator.
pub type WriteKeys = HashMap<String, Vec<u8>>;

fn single_key(ids: &[String]) -> Option<&str> {
    if ids.len() == 1 {
        Some(ids[0].as_str())
    } else {
        None
    }
}

/// Mirror of SI `postOpenpgpRouteSocket` branch order (rev 74c6cfd).
pub fn classify_post(armor: &str, local: &LocalRoute<'_>, write_keys: &WriteKeys) -> Decision {
    let ids = match opgp::recipient_key_ids(armor) {
        Ok(v) => v,
        Err(_) => return Decision::Reject { reason: "not_pgp" },
    };
    let Some(kid) = single_key(&ids) else {
        return Decision::Reject {
            reason: "recipient_count",
        };
    };
    if !local.is_local(kid) {
        return Decision::Forward {
            key_id: kid.to_string(),
        };
    }
    let bytes = match local.key.decrypt(armor) {
        Ok(d) => d,
        Err(_) => return Decision::Reject { reason: "decrypt" },
    };
    if bytes.len() > proto::VOICE_CHUNK_HEADER && &bytes[..4] == proto::VOICE_CHUNK_MAGIC {
        let loc = &bytes[4..20];
        let mac = &bytes[20..36];
        let blob = &bytes[36..];
        let loc_hex = hex::encode(loc);
        let mac_ok = write_keys
            .get(&loc_hex)
            .map(|k| sym::ct_eq(&sym::chunk_mac(k, loc, blob), mac))
            .unwrap_or(false);
        let mut mac16 = [0u8; 16];
        mac16.copy_from_slice(mac);
        return Decision::VoiceChunk {
            locator: loc_hex,
            mac_ok,
            blob_len: blob.len(),
            mac: mac16,
            blob: blob.to_vec(),
        };
    }
    let text = proto::crlf_to_lf(&String::from_utf8_lossy(&bytes));

    // 1. onion: plaintext is another armor
    if let Some(inner) = proto::as_pgp_message_armor(&text) {
        if let Ok(iids) = opgp::recipient_key_ids(inner) {
            let Some(ik) = single_key(&iids) else {
                return Decision::Reject {
                    reason: "inner_recipient_count",
                };
            };
            if local.is_local(ik) {
                return Decision::AttackSameNode;
            }
            return Decision::OnionForward {
                key_id: ik.to_string(),
                inner: inner.to_string(),
            };
        }
    }
    // 2. mailbox work
    if let Some((inner, no_push)) = parse_mailbox_work(&text) {
        let Ok(iids) = opgp::recipient_key_ids(&inner) else {
            return Decision::Reject {
                reason: "mailbox_work_inner",
            };
        };
        let Some(ik) = single_key(&iids) else {
            return Decision::Reject {
                reason: "inner_recipient_count",
            };
        };
        if local.is_local(ik) {
            return Decision::AttackSameNode;
        }
        return Decision::MailboxWork {
            key_id: ik.to_string(),
            no_push,
            inner,
        };
    }
    // 3. base64 JSON command
    let Some(content) = B64
        .decode(text.trim())
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    else {
        return Decision::Reject { reason: "format" };
    };
    let cmd_name = content.get("command").and_then(Value::as_str).unwrap_or("");
    if proto::UNSIGNED_VOICE_COMMANDS.contains(&cmd_name)
        && content
            .get("sessionId")
            .map(Value::is_string)
            .unwrap_or(false)
    {
        return Decision::VoiceCommand { command: content };
    }
    let (Some(message), Some(sig)) = (
        content.get("message").and_then(Value::as_str),
        content.get("signMessage").and_then(Value::as_str),
    ) else {
        return Decision::Reject { reason: "format" };
    };
    match check_sign(message, sig) {
        Some(cmd) => Decision::SignedCommand { command: cmd },
        None => Decision::Reject {
            reason: "signature",
        },
    }
}

/// SI `tryParseMailboxWorkEnvelope`.
pub fn parse_mailbox_work(plain: &str) -> Option<(String, bool)> {
    let t = plain.trim();
    if t.is_empty() {
        return None;
    }
    let rec: Value = serde_json::from_str(t).ok().or_else(|| {
        B64.decode(t)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    })?;
    let obj = rec.as_object()?;
    if obj.get("message").map(Value::is_string).unwrap_or(false) && truthy(obj.get("signMessage")) {
        return None;
    }
    let data = obj.get("data")?.as_str()?;
    let inner = proto::as_pgp_message_armor(data)?;
    Some((
        inner.to_string(),
        obj.get("NoPush") == Some(&Value::Bool(true)),
    ))
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        _ => true,
    }
}

/// SI `checkSign` (localNodeCommand.ts): EIP-191 or raw keccak digest, signer must be
/// `billingWallet || walletAddress`; voice commands skip the signature and drop wallets.
pub fn check_sign(message: &str, sig: &str) -> Option<Value> {
    let mut obj: Map<String, Value> = serde_json::from_str::<Value>(message)
        .ok()?
        .as_object()?
        .clone();
    let wallet = obj
        .get("walletAddress")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let command = obj.get("command").and_then(Value::as_str).unwrap_or("");
    let session_ok = obj
        .get("sessionId")
        .and_then(Value::as_str)
        .map(|s| s.chars().count() >= 16)
        .unwrap_or(false);
    if proto::UNSIGNED_VOICE_COMMANDS.contains(&command) && session_ok {
        obj.insert("walletAddress".into(), Value::String(String::new()));
        obj.insert("billingWallet".into(), Value::String(String::new()));
        return Some(Value::Object(obj));
    }
    let billing_field = obj
        .get("billingWallet")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let billing = billing_field.clone().unwrap_or_else(|| wallet.clone());
    let digest: [u8; 32] = eth::keccak256(message.as_bytes());
    let raw = eth::recover_digest(&digest, sig).ok()?.to_lowercase();
    let v = eth::recover_message(message, sig).ok()?.to_lowercase();
    if billing.is_empty() || !eth::is_address(&billing) {
        return None;
    }
    let bl = billing.to_lowercase();
    if v != bl && raw != bl {
        return None;
    }
    let wl = wallet.to_lowercase();
    if !wallet.is_empty()
        && eth::is_address(&wallet)
        && (billing_field.is_some() || v == wl || raw == wl)
    {
        obj.insert("walletAddress".into(), Value::String(wl));
        if let Some(b) = billing_field {
            obj.insert("billingWallet".into(), Value::String(b.to_lowercase()));
        }
        return Some(Value::Object(obj));
    }
    None
}

/// SI `verifyHopSig`.
pub fn verify_hop(h: &proto::HopSig, now: i64) -> bool {
    if (now - h.t).abs() > proto::HOP_SIG_TS_WINDOW_SEC || !eth::is_address(&h.w) {
        return false;
    }
    let payload = proto::hop_sig_payload(&h.w, h.t, h.n, &h.h, &h.k);
    eth::recover_message(&payload, &h.s)
        .map(|a| a.eq_ignore_ascii_case(&h.w))
        .unwrap_or(false)
}

/// SI `signAndAppendHop`, minus the clock (passed in as `t`).
pub fn sign_hop(
    key: &dyn WalletSigner,
    armor: &str,
    next_key_id: &str,
    t: i64,
) -> si_crypto::Result<proto::HopSig> {
    let w = key.address();
    let n = armor.len() as u64;
    let h = eth::keccak_hex(armor);
    let k = next_key_id.to_uppercase();
    let s = key.sign_message(&proto::hop_sig_payload(&w, t, n, &h, &k))?;
    Ok(proto::HopSig { w, t, n, h, k, s })
}

/// SI `sealMailboxStreamPayload` with an explicit IV (host supplies randomness).
pub fn seal_mailbox(json: &str, key: &[u8], iv: &[u8; 12]) -> si_crypto::Result<String> {
    let len = json.len();
    let padded_len = (len + 1).div_ceil(proto::MAILBOX_STREAM_PAD) * proto::MAILBOX_STREAM_PAD;
    let mut padded = vec![b' '; padded_len];
    padded[..len].copy_from_slice(json.as_bytes());
    Ok(B64.encode(sym::gcm_seal(key, iv, &padded)?))
}

/// Client side `openMailboxStreamFrame`: returns trimmed JSON text.
pub fn open_mailbox(sealed: &str, key: &[u8]) -> Option<(String, usize)> {
    let blob = B64.decode(sealed).ok()?;
    let plain = sym::gcm_open(key, &blob).ok()?;
    let n = plain.len();
    Some((String::from_utf8(plain).ok()?.trim().to_string(), n))
}

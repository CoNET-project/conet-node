//! CoNET-SI wire constants and plain data formats (no crypto, no I/O).
//! Every constant mirrors CoNET-SI rev 74c6cfd; the source file is named next to it.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

/// siHopSigs.ts
pub const MAX_SI_HOP_SIGS: usize = 3;
pub const SI_HOP_SIG_HEADER: &str = "X-CoNET-Hop-Sigs";
pub const HOP_SIG_DOMAIN: &str = "conet.l0.hop.v1";
pub const HOP_SIG_TS_WINDOW_SEC: i64 = 600;

/// mailboxStream.ts
pub const MAILBOX_STREAM_PAD: usize = 256;

/// voiceForward.ts
pub const VOICE_CHUNK_MAGIC: &[u8; 4] = b"CVC2";
pub const VOICE_CHUNK_HEADER: usize = 4 + 16 + 16;
pub const VOICE_CHUNK_MAX_BLOB: usize = 9_000;

/// localNodeCommand.ts: commands that run without an EOA signature (sessionId is the capability).
pub const UNSIGNED_VOICE_COMMANDS: [&str; 4] = [
    "voice_listen",
    "voice_unlisten",
    "voice_offer_store",
    "voice_offer_fetch",
];

/// define.d.ts `SICommandObj.command`. Anything else is closed by SI's `default` branch.
pub const KNOWN_COMMANDS: [&str; 24] = [
    "SilentPass",
    "SaaS_Sock5",
    "mining",
    "mailbox_listen",
    "mining_validator",
    "mining_gossip",
    "SaaS_Sock5_v2",
    "gossip_delivery_ack",
    "wallet_online_query",
    "wallet_native_wake_query",
    "push_device_register",
    "udp_listen",
    "udp_server_listen",
    "udp_subscribe",
    "udp_relay",
    "udp_uplink",
    "udp_unlisten",
    "voice_listen",
    "voice_uplink",
    "voice_downlink",
    "voice_unlisten",
    "voice_call_push",
    "voice_offer_store",
    "voice_offer_fetch",
];

pub const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----";
pub const PGP_END: &str = "-----END PGP MESSAGE-----";

/// SI `asPgpMessageArmor`: the trimmed text must start with the BEGIN line; cut after END.
pub fn as_pgp_message_armor(text: &str) -> Option<&str> {
    let t = text.trim();
    if !t.starts_with(PGP_BEGIN) {
        return None;
    }
    let end = t.find(PGP_END)?;
    Some(&t[..end + PGP_END.len()])
}

/// One SI-to-SI hop signature (`X-CoNET-Hop-Sigs` v1 row).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HopSig {
    pub w: String,
    pub t: i64,
    pub n: u64,
    pub h: String,
    pub k: String,
    pub s: String,
}

/// SI `hopSigPayload`.
pub fn hop_sig_payload(w: &str, t: i64, n: u64, h: &str, k: &str) -> String {
    [
        HOP_SIG_DOMAIN,
        &w.to_lowercase(),
        &t.to_string(),
        &n.to_string(),
        &h.to_lowercase(),
        &k.to_uppercase(),
    ]
    .join("|")
}

#[derive(Debug, PartialEq)]
pub enum HopHeader {
    Absent,
    Invalid,
    /// More than MAX_SI_HOP_SIGS rows: SI treats this as a flood (rows are not validated).
    TooMany(usize),
    Rows(Vec<HopSig>),
}

/// SI `parseHopSigsFromHeaders`, given the raw header lines.
/// Address and number checks that need crypto (`isAddress`) are left to the caller.
pub fn parse_hop_header(lines: &[&str]) -> HopHeader {
    let want = SI_HOP_SIG_HEADER.to_ascii_lowercase();
    let Some(line) = lines.iter().find(|l| {
        l.split_once(':')
            .map(|(n, _)| n.trim().to_ascii_lowercase() == want)
            .unwrap_or(false)
    }) else {
        return HopHeader::Absent;
    };
    let raw = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
    if raw.is_empty() {
        return HopHeader::Absent;
    }
    let json_text = if raw.starts_with('[') {
        raw.to_string()
    } else {
        match B64.decode(raw) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(_) => return HopHeader::Invalid,
        }
    };
    let Ok(serde_json::Value::Array(rows)) = serde_json::from_str::<serde_json::Value>(&json_text)
    else {
        return HopHeader::Invalid;
    };
    if rows.len() > MAX_SI_HOP_SIGS {
        return HopHeader::TooMany(rows.len());
    }
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        match serde_json::from_value::<HopSig>(r) {
            Ok(h) if !h.h.is_empty() && !h.k.is_empty() && !h.s.is_empty() => out.push(h),
            _ => return HopHeader::Invalid,
        }
    }
    HopHeader::Rows(out)
}

/// SI `serializeHopSigsHeaderValue`: base64(JSON.stringify(rows)).
pub fn serialize_hop_header_value(rows: &[HopSig]) -> String {
    B64.encode(serde_json::to_string(rows).expect("hop rows serialize"))
}

/// voiceForward.ts `voicePayText`.
pub fn voice_pay_text(temp: &str, not_after: u64, max_bytes: u64, max_seconds: u64) -> String {
    [
        "conet.voice.sse.pay.v3".to_string(),
        format!("temp={}", temp.to_lowercase()),
        format!("notAfter={not_after}"),
        format!("maxBytes={max_bytes}"),
        format!("maxSeconds={max_seconds}"),
    ]
    .join("\n")
}

/// voiceForward.ts `voiceListenText`.
pub fn voice_listen_text(session_id: &str, wk: &str, relay_key_id: &str, timestamp: u64) -> String {
    [
        "conet.voice.sse.listen.v3",
        session_id,
        wk,
        &relay_key_id.to_uppercase(),
        &timestamp.to_string(),
    ]
    .join("|")
}

/// openpgp.js `createMessage({ text })` stores text with CRLF line endings; SI decodes with
/// `.replace(/\r\n/g, '\n')`. These two helpers reproduce both sides.
pub fn to_crlf(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}
pub fn crlf_to_lf(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// NodeRegistryV2 EIP-712 (design v0.1.2 §6.2).
pub mod node_registry {
    pub const DOMAIN_NAME: &str = "CoNETNodeRegistry";
    pub const DOMAIN_VERSION: &str = "1";
    pub const CHAIN_ID: u64 = 224_422;
    pub const EIP712_DOMAIN_TYPE: &str =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    pub const NODE_STATEMENT_TYPE: &str =
        "NodeStatement(uint256 nodeId,uint64 epoch,uint8 kind,bytes32 payloadHash)";
    pub const NODE_STATEMENT_TYPEHASH: &str =
        "0x777931cef703365b5622fddecd9d7e860372412bbe578d0b1628957c3a6220b5";
    pub const BIND_NODE_TYPE: &str =
        "BindNode(address operator,uint256 nodeId,bytes32 ipHash,bytes8 keyId,bytes32 pgpHash,uint256 nonce,uint256 deadline)";
    pub const BIND_NODE_TYPEHASH: &str =
        "0x578569fb8156d106c3abea91cae98010b24ba8ebef4a028965f06553c1ea2d03";
    /// kind 1 payload: keccak256("CONET_NODE_ONLINE_V1").
    pub const ONLINE_PAYLOAD_TEXT: &str = "CONET_NODE_ONLINE_V1";
    pub const KIND_ONLINE: u8 = 1;
    pub const KIND_SERVICE: u8 = 2;
    pub const KIND_CAPABILITY: u8 = 3;
}

/// Texts the node wallet signs for the Beamio API (CoNET-SI `util.ts`, rev 74c6cfd).
pub mod api_texts {
    pub fn notify_offline_chat(pgp_key_id: &str, eoa: &str, timestamp: u64) -> String {
        [
            "Beamio notifyOfflineChat".to_string(),
            format!("pgpKeyId:{pgp_key_id}"),
            format!("eoa:{}", eoa.to_lowercase()),
            format!("timestamp:{timestamp}"),
        ]
        .join("\n")
    }
    pub fn native_wakeable(eoa: &str, timestamp: u64) -> String {
        [
            "Beamio nativeWakeable".to_string(),
            format!("eoa:{}", eoa.to_lowercase()),
            format!("timestamp:{timestamp}"),
        ]
        .join("\n")
    }
}

/// Node `Buffer.from(s, 'base64')`: skips characters outside the alphabet, accepts the URL-safe
/// alphabet and missing padding, and drops a trailing incomplete 6-bit group.
pub fn node_base64_decode(s: &str) -> Vec<u8> {
    let mut clean: String = s
        .chars()
        .filter_map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => Some(c),
            '-' => Some('+'),
            '_' => Some('/'),
            _ => None,
        })
        .collect();
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(clean)
        .unwrap_or_default()
}

/// JavaScript `Number(value)` for JSON values (NaN as None).
pub fn js_number(v: Option<&serde_json::Value>) -> Option<f64> {
    use serde_json::Value;
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                Some(0.0)
            } else {
                t.parse::<f64>().ok().filter(|f| f.is_finite())
            }
        }
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        _ => None,
    }
}

/// JavaScript `Number.isSafeInteger`.
pub fn js_safe_int(f: f64) -> Option<i64> {
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

/// Voice relay v3 (CoNET-SI `voiceForward.ts`, rev 74c6cfd).
pub mod voice {
    pub const TIMESTAMP_SKEW_SEC: i64 = 600;
    pub const PAY_MAX_VALID_MS: i64 = 48 * 60 * 60 * 1000;
    pub const MAX_GLOBAL: usize = 256;
    pub const TEMP_WALLET_MAX: usize = 50_000;
    pub const IDLE_MS: u64 = 2 * 60 * 1000;
    pub const SWEEP_MS: u64 = 30_000;
    pub const MAX_PER_SEC: u32 = 100;
    pub const MAX_BYTES_PER_SEC: usize = 600_000;
    pub const QUEUE_MAX: usize = 32;
    pub const DRAIN_TIMEOUT_MS: u64 = 2_000;
    pub const OFFER_ARMOR_MAX: usize = 48_000;
    pub const OFFER_DEFAULT_TTL_MS: i64 = 5 * 60_000;
    pub const OFFER_MAX_TTL_MS: i64 = 24 * 60 * 60_000;
    pub const OFFER_MEMORY_MAX: usize = 256;

    /// SSE response head for a voice listen (no Date header, as in SI).
    pub const SSE_HEADERS: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache, no-transform\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\nAccess-Control-Allow-Origin: *\r\n\r\n";

    /// SI `frameLine(handshake)` for a voice listen.
    pub fn ready_frame(session_id: &str, node_wallet: &str) -> String {
        format!(
            "data: {}\r\n\r\n",
            serde_json::json!({ "type": "voice_ready", "ok": true, "sessionId": session_id, "nodeWallet": node_wallet.to_lowercase(), "v": 2, "listen": 3 })
        )
    }

    /// SI `frameLine({ t: 'c', d: blob.toString('base64') })`.
    pub fn chunk_frame(blob_b64: &str) -> String {
        format!(
            "data: {}\r\n\r\n",
            serde_json::json!({ "t": "c", "d": blob_b64 })
        )
    }

    /// SI `notifyVoiceCallPush` signed text.
    pub fn call_push_text(
        call_id: &str,
        session_id: &str,
        callee_eoa: &str,
        expires_at: i64,
        timestamp: i64,
        node_wallet: &str,
    ) -> String {
        [
            "CoNET voiceCallPush relay".to_string(),
            format!("callId:{call_id}"),
            format!("sessionId:{session_id}"),
            format!("calleeEoa:{}", callee_eoa.to_lowercase()),
            format!("expiresAt:{expires_at}"),
            format!("timestamp:{timestamp}"),
            format!("nodeWallet:{}", node_wallet.to_lowercase()),
        ]
        .join("\n")
    }
}

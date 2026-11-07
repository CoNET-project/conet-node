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
    pub const BIND_NODE_TYPE: &str =
        "BindNode(address operator,uint256 nodeId,bytes32 ipHash,bytes8 keyId,bytes32 pgpHash,uint256 nonce,uint256 deadline)";
    pub const BIND_NODE_TYPEHASH: &str =
        "0x578569fb8156d106c3abea91cae98010b24ba8ebef4a028965f06553c1ea2d03";

    // NodeRegistryV2 v0.1 (node line, Q77). Type strings copied from NodeRegistryTypes.sol.
    pub const REGISTER_REQUEST_TYPE: &str = "RegisterRequest(address operator,address beneficiary,address nodeWallet,uint8 nodeType,bytes32 ipHash,uint16 tcpPort,uint16 udpPort,bytes32 pgpHash,bytes8 keyId,uint16 services,uint256 sponsorNodeId,uint256 nonce,uint256 deadline)";
    pub const REGISTER_REQUEST_TYPEHASH: &str =
        "0x1e7bf51b93c245e42df224425850ab516fe6b1879477a4adbf507799bc34bd3c";
    pub const ONLINE_DECLARATION_TYPE: &str = "OnlineDeclaration(uint256 nodeId,uint8 mode,bytes32 anchorsHash,uint16 servicesNow,uint64 onlineUntil,uint64 onlineSeq,uint256 deadline)";
    pub const ONLINE_DECLARATION_TYPEHASH: &str =
        "0x3d7ff6cd3e2108bebd3524b93794bb8787aa55077bdd71d30b31eb6160245e04";
    pub const ANCHOR_RECEIPT_TYPE: &str =
        "AnchorReceipt(uint256 nodeId,uint256 anchorNodeId,uint64 onlineSeq,uint64 onlineUntil)";
    pub const ANCHOR_RECEIPT_TYPEHASH: &str =
        "0xdff513776e6931a9796b834a206d67e27166ffa7957c3480cd8deb840814fe6d";
    pub const EXTEND_DECLARATION_TYPE: &str =
        "ExtendDeclaration(uint256 nodeId,uint64 onlineSeq,uint64 newUntil,uint256 deadline)";
    pub const EXTEND_DECLARATION_TYPEHASH: &str =
        "0x23f07b2ecda1b0fd223f87579b25fbc91bc345460efe0f4bbd624f752d4bc96f";
    pub const PAUSE_DECLARATION_TYPE: &str =
        "PauseDeclaration(uint256 nodeId,uint64 onlineSeq,uint64 pauseAt,uint256 deadline)";
    pub const PAUSE_DECLARATION_TYPEHASH: &str =
        "0x1d48dc7dcc124e4fddd97ee9669f8e23c8358ab7afc634a783bcfe262241c7b1";
    pub const TYPE_TCP: u8 = 1;
    pub const TYPE_BROWSER: u8 = 2;
    pub const TYPE_MOBILE: u8 = 3;
    pub const MODE_WEBRTC: u8 = 1;
    pub const MODE_SSE: u8 = 2;

    /// Canonical IP text (node line v0.1.47 §8.4.38, Q77-3); `ipHash` is keccak256 of it.
    /// IPv4: four dotted decimal parts 0-255 without leading zeros. IPv6: RFC 5952 (lower
    /// case, no leading zeros in a group, the longest run of two or more zero groups, leftmost
    /// on a tie, as `::`). No port, brackets or zone; no embedded IPv4 (register the IPv4).
    pub fn canonical_ip(ip: std::net::IpAddr) -> Result<String, &'static str> {
        match ip {
            std::net::IpAddr::V4(a) => Ok(a.to_string()),
            std::net::IpAddr::V6(a) => {
                if a.to_ipv4_mapped().is_some() {
                    return Err("embedded_ipv4");
                }
                let t = a.to_string();
                // std prints RFC 5952 except for IPv4-mapped (refused above).
                if t.contains('.') {
                    return Err("embedded_ipv4");
                }
                Ok(t)
            }
        }
    }

    /// Accept only text already in canonical form (what the contract accepts).
    pub fn check_canonical_ip(text: &str) -> Result<std::net::IpAddr, &'static str> {
        if text.contains('.') && text.contains(':') {
            return Err("embedded_ipv4");
        }
        let ip: std::net::IpAddr = text.parse().map_err(|_| "not_an_ip")?;
        if canonical_ip(ip)? != text {
            return Err("not_canonical");
        }
        Ok(ip)
    }

    #[cfg(test)]
    mod ip_tests {
        use super::*;
        #[test]
        fn canonical_forms() {
            for ok in [
                "192.0.2.10",
                "0.0.0.0",
                "255.255.255.255",
                "2001:db8::1",
                "2001:db8::1:0:0:1",
                "2001:db8:0:1:1:1:1:1",
                "::1",
                "::",
                "fe80::1",
                "1::",
            ] {
                assert_eq!(check_canonical_ip(ok).map(|_| ()), Ok(()), "{ok}");
            }
            for (bad, why) in [
                ("192.168.001.1", "not_an_ip"),
                ("1.2.3", "not_an_ip"),
                ("256.1.1.1", "not_an_ip"),
                ("2001:DB8::1", "not_canonical"),
                ("2001:0db8::1", "not_canonical"),
                ("2001:db8:0:0:1:0:0:1", "not_canonical"),
                ("2001:db8::0:1", "not_canonical"),
                ("2001:db8::1:1:1:1:1", "not_canonical"),
                ("::ffff:1.2.3.4", "embedded_ipv4"),
                ("::ffff:102:304", "embedded_ipv4"),
                ("::1.2.3.4", "embedded_ipv4"),
                ("[2001:db8::1]", "not_an_ip"),
                ("2001:db8::1%eth0", "not_an_ip"),
                ("192.0.2.10:443", "embedded_ipv4"),
                (" 192.0.2.10", "not_an_ip"),
                ("", "not_an_ip"),
            ] {
                assert_eq!(check_canonical_ip(bad).map(|_| ()), Err(why), "{bad}");
            }
        }
    }
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

/// SI `distorySocketPayment` page body (passport missing or expired).
pub fn payment_required_html() -> String {
    let title = "402 Payment Required";
    let body = "CoNET Passport has expired Please purchase a new certificate\r\nCoNETパスポートの有効期限が切れています。新しいを購入してください。\r\nCoNET通证已过期请购买新证书";
    format!("<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n<center><h1>{body}</h1></center>\r\n<hr><center>nginx/1.18.0</center>\r\n</body>\r\n</html>\r\n")
}

/// WebRTC entry without signalling (decision W35): the node listens ICE-lite on one UDP port
/// with a long-lived self-signed DTLS certificate and publishes a wallet-signed endpoint
/// statement. A browser builds the node's SDP answer locally from that statement, so no HTTPS
/// and no CA certificate is involved. Both sides use the same random `ufrag` as ICE username
/// fragment and password; the node learns it from the first STUN binding request.
pub mod webrtc {
    pub const ENDPOINT_DOMAIN: &str = "conet.webrtc.endpoint.v1";
    /// Longest validity the signer accepts for one endpoint statement.
    pub const ENDPOINT_MAX_VALID_SEC: i64 = 7 * 24 * 60 * 60;
    pub const UFRAG_PREFIX: &str = "conet1";
    const UFRAG_RANDOM_LEN: usize = 32;
    /// Data-channel message size both sides use (chunks of HTTP bytes).
    pub const MAX_MESSAGE: usize = 16 * 1024;
    /// SCTP port in the SDP (fixed, both sides).
    pub const SCTP_PORT: u16 = 5000;

    /// `conet1` + 32 ASCII letters or digits (ICE needs ≥ 22 chars for the password).
    pub fn valid_ufrag(u: &str) -> bool {
        u.len() == UFRAG_PREFIX.len() + UFRAG_RANDOM_LEN
            && u.starts_with(UFRAG_PREFIX)
            && u[UFRAG_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
    }

    /// `sha-256 AB:CD:…` with 32 upper-case hex bytes, as SDP `a=fingerprint` carries it.
    pub fn valid_fingerprint(fp: &str) -> bool {
        let Some(hex) = fp.strip_prefix("sha-256 ") else {
            return false;
        };
        let parts: Vec<&str> = hex.split(':').collect();
        parts.len() == 32
            && parts.iter().all(|p| {
                p.len() == 2
                    && p.bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            })
    }

    /// Text the node wallet signs (EIP-191). The signer fills in its own key ID and wallet.
    pub fn endpoint_text(
        key_id: &str,
        wallet: &str,
        ip: &str,
        port: u16,
        fingerprint: &str,
        expires: i64,
    ) -> String {
        format!(
            "{ENDPOINT_DOMAIN}\nkeyId:{}\nwallet:{}\naddr:{ip}:{port}\nfp:{fingerprint}\nexp:{expires}",
            key_id.to_ascii_uppercase(),
            wallet.to_ascii_lowercase()
        )
    }

    /// The node's SDP answer, built by the browser from the endpoint statement (IPv4 only).
    pub fn answer_sdp(ip: &str, port: u16, ufrag: &str, fingerprint: &str) -> String {
        [
            "v=0".to_string(),
            format!("o=- 0 0 IN IP4 {ip}"),
            "s=-".into(),
            "t=0 0".into(),
            "a=group:BUNDLE 0".into(),
            "a=ice-lite".into(),
            format!("m=application {port} UDP/DTLS/SCTP webrtc-datachannel"),
            format!("c=IN IP4 {ip}"),
            "a=mid:0".into(),
            format!("a=ice-ufrag:{ufrag}"),
            format!("a=ice-pwd:{ufrag}"),
            format!("a=fingerprint:{fingerprint}"),
            "a=setup:passive".into(),
            format!("a=sctp-port:{SCTP_PORT}"),
            format!("a=max-message-size:{MAX_MESSAGE}"),
            format!("a=candidate:1467250027 1 UDP 1467250027 {ip} {port} typ host"),
            "a=end-of-candidates".into(),
            String::new(),
        ]
        .join("\r\n")
    }

    /// Replace the browser offer's ICE credentials with `ufrag` (username and password).
    pub fn munge_offer(offer: &str, ufrag: &str) -> String {
        let mut out: Vec<String> = Vec::new();
        for line in offer.split("\r\n") {
            if line.starts_with("a=ice-ufrag:") {
                out.push(format!("a=ice-ufrag:{ufrag}"));
            } else if line.starts_with("a=ice-pwd:") {
                out.push(format!("a=ice-pwd:{ufrag}"));
            } else {
                out.push(line.to_string());
            }
        }
        out.join("\r\n")
    }

    /// Username of a STUN binding request (`<node ufrag>:<browser ufrag>`), without checking
    /// integrity (str0m does that). None for anything else.
    pub fn stun_binding_username(pkt: &[u8]) -> Option<&str> {
        if pkt.len() < 20
            || pkt[0] != 0x00
            || pkt[1] != 0x01
            || pkt[4..8] != [0x21, 0x12, 0xA4, 0x42]
        {
            return None;
        }
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let body = pkt.get(20..20 + len)?;
        let mut i = 0;
        while i + 4 <= body.len() {
            let t = u16::from_be_bytes([body[i], body[i + 1]]);
            let l = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
            let v = body.get(i + 4..i + 4 + l)?;
            if t == 0x0006 {
                return std::str::from_utf8(v).ok();
            }
            i += 4 + l.div_ceil(4) * 4;
        }
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ufrag_rules() {
            assert!(valid_ufrag("conet1ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
            assert!(!valid_ufrag("conet1ABCDEFGHIJKLMNOPQRSTUVWXYZ01234"));
            assert!(!valid_ufrag("conet1ABCDEFGHIJKLMNOPQRSTUVWXYZ01234+"));
            assert!(!valid_ufrag("xonet1ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
        }

        #[test]
        fn fingerprint_rules() {
            let ok = format!("sha-256 {}", vec!["AB"; 32].join(":"));
            assert!(valid_fingerprint(&ok));
            assert!(!valid_fingerprint(&ok.to_lowercase()));
            assert!(!valid_fingerprint(&format!(
                "sha-1 {}",
                vec!["AB"; 20].join(":")
            )));
        }

        #[test]
        fn stun_username() {
            let user = b"conet1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:abcd";
            let mut attr = vec![0x00, 0x06, 0, user.len() as u8];
            attr.extend_from_slice(user);
            while attr.len() % 4 != 0 {
                attr.push(0);
            }
            let mut p = vec![0x00, 0x01];
            p.extend_from_slice(&(attr.len() as u16).to_be_bytes());
            p.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
            p.extend_from_slice(&[7u8; 12]);
            p.extend_from_slice(&attr);
            assert_eq!(
                stun_binding_username(&p),
                Some("conet1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:abcd")
            );
            p[1] = 0x11; // not a binding request
            assert_eq!(stun_binding_username(&p), None);
            assert_eq!(stun_binding_username(&[0u8; 8]), None);
        }

        #[test]
        fn munge_keeps_other_lines() {
            let o = "v=0\r\na=ice-ufrag:x\r\na=ice-pwd:y\r\na=mid:0\r\n";
            let m = munge_offer(o, "U");
            assert_eq!(m, "v=0\r\na=ice-ufrag:U\r\na=ice-pwd:U\r\na=mid:0\r\n");
        }
    }
}

/// ACME DNS-01 through the project's DNS daemon (decision W42; Q74: nodes on :443 keep
/// TLS-ALPN-01, others use DNS-01). The node keeps its certificate key; it only asks the daemon,
/// with a wallet-signed request, to set or delete the TXT record
/// `_acme-challenge.{keyId}.conet.network`. The daemon derives the name from the key ID.
pub mod acme {
    pub const DNS01_DOMAIN: &str = "conet.acme.dns01.v1";
    /// Longest validity the signer accepts for one daemon request.
    pub const DNS01_MAX_VALID_SEC: i64 = 600;
    pub const OP_SET: &str = "set";
    pub const OP_DELETE: &str = "delete";

    /// The DNS-01 TXT value: base64url (no padding) of a SHA-256 digest, so 43 characters.
    pub fn valid_txt_value(v: &str) -> bool {
        v.len() == 43
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    pub fn valid_op(op: &str) -> bool {
        op == OP_SET || op == OP_DELETE
    }

    /// Text the node wallet signs (EIP-191). The signer fills in its own key ID and wallet.
    pub fn dns01_text(key_id: &str, wallet: &str, value: &str, op: &str, expires: i64) -> String {
        format!(
            "{DNS01_DOMAIN}\nkeyId:{}\nwallet:{}\nvalue:{value}\nop:{op}\nexp:{expires}",
            key_id.to_ascii_uppercase(),
            wallet.to_ascii_lowercase()
        )
    }

    /// TXT record name the daemon writes for a key ID.
    pub fn challenge_name(key_id: &str) -> String {
        format!(
            "_acme-challenge.{}.conet.network",
            key_id.to_ascii_lowercase()
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn values_and_text() {
            let v = "A".repeat(42) + "_";
            assert!(valid_txt_value(&v));
            assert!(!valid_txt_value(&("A".repeat(42) + "=")));
            assert!(!valid_txt_value(&"A".repeat(44)));
            assert!(valid_op("set") && valid_op("delete") && !valid_op("SET"));
            assert_eq!(
                dns01_text("ab12", "0xAbC", &v, "set", 7),
                format!("conet.acme.dns01.v1\nkeyId:AB12\nwallet:0xabc\nvalue:{v}\nop:set\nexp:7")
            );
            assert_eq!(challenge_name("AB12"), "_acme-challenge.ab12.conet.network");
        }
    }
}

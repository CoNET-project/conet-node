//! Voice listen v3 verification (SI `verifyVoiceListenV3`, rev 74c6cfd), sans-IO and stateless.
//! The temp-wallet reuse check needs the relay's state and lives in the host.
use serde_json::Value;
use si_crypto::eth;
use si_proto::{
    js_number, js_safe_int, node_base64_decode, voice, voice_listen_text, voice_pay_text,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ListenAuth {
    pub session_id: String,
    pub write_key: [u8; 32],
    /// Lowercase temporary wallet.
    pub temp: String,
    /// Seconds.
    pub not_after: i64,
}

/// SI `recoverSigner`: lowercase address or empty.
fn recover(text: &str, sig: Option<&Value>) -> String {
    match sig.and_then(Value::as_str) {
        Some(s) if !s.is_empty() => eth::recover_message(text, s)
            .map(|a| a.to_lowercase())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn non_negative_int(v: Option<&Value>) -> Option<i64> {
    js_number(v).and_then(js_safe_int).filter(|n| *n >= 0)
}

fn trimmed<'a>(c: &'a Value, k: &str) -> &'a str {
    c.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// `relay_key_ids`: the current route key ID first, then retiring ones (R11 transition).
pub fn verify_listen_v3(
    command: &Value,
    relay_key_ids: &[&str],
    now_ms: i64,
) -> Result<ListenAuth, &'static str> {
    if js_number(command.get("v")) != Some(3.0) {
        return Err("voice_listen_v3_required");
    }
    let session_id = trimmed(command, "sessionId");
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_voice_session");
    }
    let wk = trimmed(command, "wk");
    let write_key: [u8; 32] = node_base64_decode(wk)
        .try_into()
        .map_err(|_| "invalid_voice_session")?;
    let timestamp = js_number(command.get("timestamp"))
        .and_then(js_safe_int)
        .ok_or("invalid_voice_timestamp")?;
    if (now_ms.div_euclid(1000) - timestamp).abs() > voice::TIMESTAMP_SKEW_SEC {
        return Err("invalid_voice_timestamp");
    }
    let temp = command
        .get("temp")
        .and_then(Value::as_str)
        .filter(|t| eth::is_address(t))
        .map(str::to_lowercase)
        .unwrap_or_default();
    if temp.is_empty() || relay_key_ids.iter().all(|k| k.is_empty()) {
        return Err("voice_temp_auth");
    }
    let signed_for_us = relay_key_ids.iter().filter(|k| !k.is_empty()).any(|k| {
        recover(
            &voice_listen_text(session_id, wk, k, timestamp as u64),
            command.get("tempSig"),
        ) == temp
    });
    if !signed_for_us {
        return Err("voice_temp_auth");
    }
    let empty = Value::Object(Default::default());
    let pay = command
        .get("pay")
        .filter(|p| p.is_object())
        .unwrap_or(&empty);
    let payer = pay
        .get("payer")
        .and_then(Value::as_str)
        .filter(|p| eth::is_address(p))
        .map(str::to_lowercase)
        .unwrap_or_default();
    let (not_after, max_bytes, max_seconds) = (
        non_negative_int(pay.get("notAfter")),
        non_negative_int(pay.get("maxBytes")),
        non_negative_int(pay.get("maxSeconds")),
    );
    let (Some(not_after), Some(max_bytes), Some(max_seconds)) = (not_after, max_bytes, max_seconds)
    else {
        return Err("voice_pay_auth");
    };
    if payer.is_empty() {
        return Err("voice_pay_auth");
    }
    if not_after * 1000 <= now_ms || not_after * 1000 > now_ms + voice::PAY_MAX_VALID_MS {
        return Err("voice_pay_expired");
    }
    if recover(
        &voice_pay_text(
            &temp,
            not_after as u64,
            max_bytes as u64,
            max_seconds as u64,
        ),
        pay.get("sig"),
    ) != payer
    {
        return Err("voice_pay_auth");
    }
    Ok(ListenAuth {
        session_id: session_id.to_string(),
        write_key,
        temp,
        not_after,
    })
}

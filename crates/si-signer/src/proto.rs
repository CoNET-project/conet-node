//! Signer wire: u32 big-endian length, then one JSON object. One request per connection.
use serde::{Deserialize, Serialize};

pub const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Address,
    RouteKeyId,
    /// Retiring route key IDs (comma separated, may be empty).
    OldRouteKeyIds,
    /// The signer builds `conet.l0.hop.v1|w|t|n|h|k` itself with its own wallet.
    SignHop {
        t: i64,
        n: u64,
        h: String,
        k: String,
    },
    /// Decrypt one PKESK addressed to the route key. Returns `"<sym alg id>:<base64 session key>"`.
    RouteSessionKey {
        /// base64 of one serialized v3 PKESK packet (header included); never the payload.
        pkesk: String,
    },
    /// EIP-191 over the decimal epoch (mailbox handshake `hash`).
    SignEpoch {
        epoch: u64,
    },
    /// CoNET-SI mining SSE heartbeat. The signer builds the fixed `{epoch,wallet}` JSON text.
    SignValidatorHeartbeat {
        epoch: u64,
        wallet: String,
    },
    /// Beamio API notices; the signer builds the fixed text.
    SignOfflineChat {
        #[serde(rename = "pgpKeyId")]
        pgp_key_id: String,
        eoa: String,
        timestamp: u64,
    },
    SignNativeWakeable {
        eoa: String,
        timestamp: u64,
    },
    SignVoiceCallPush {
        #[serde(rename = "callId")]
        call_id: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "calleeEoa")]
        callee_eoa: String,
        #[serde(rename = "expiresAt")]
        expires_at: i64,
        timestamp: i64,
    },
    /// WebRTC endpoint statement (W35); the signer adds its own route key ID and wallet.
    SignWebrtcEndpoint {
        #[serde(rename = "keyId")]
        key_id: String,
        ip: String,
        port: u16,
        fingerprint: String,
        expires: i64,
    },
    /// ACME DNS-01 daemon request (W42); the signer adds its own route key ID and wallet.
    SignAcmeDns01 {
        #[serde(rename = "keyId")]
        key_id: String,
        value: String,
        #[serde(rename = "dnsOp")]
        dns_op: String,
        expires: i64,
    },
    /// NodeRegistryV2 BindNode consent. Refused unless the signer runs with `--allow-bind`.
    SignBind {
        operator: String,
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "ipHash")]
        ip_hash: String,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "pgpHash")]
        pgp_hash: String,
        nonce: String,
        deadline: String,
    },
    /// NodeRegistryV2 `AnchorReceipt` for a browser or mobile node's online declaration. The
    /// signer fills in its own node id; refused unless it runs with `--anchor-node-id`.
    SignAnchorReceipt {
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "onlineSeq")]
        online_seq: u64,
        #[serde(rename = "onlineUntil")]
        online_until: u64,
    },
    /// AUTO-TOPUP (approved 2026-11-09): the main wallet's `topUp(own nodeId)` as a signed type-2
    /// transaction. The signer builds `to` and `data` itself; refused unless it runs with
    /// `--topup-config` and `--topup-state`. Amounts in wei as decimal strings. Returns the raw
    /// transaction (hex).
    SignTopUp {
        nonce: u64,
        #[serde(rename = "gasLimit")]
        gas_limit: u64,
        #[serde(rename = "maxFeePerGas")]
        max_fee_wei: String,
        #[serde(rename = "maxPriorityFeePerGas")]
        priority_fee_wei: String,
        value: String,
        /// `minStakeAt(termEnd) - stakeOf(nodeId)` as conet-node read it.
        #[serde(rename = "statedMissing")]
        stated_missing: String,
        /// Wallet balance as conet-node read it.
        #[serde(rename = "statedWallet")]
        stated_wallet: String,
        #[serde(rename = "replacesNonce", default)]
        replaces_nonce: Option<u64>,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok { value: String },
    Refused { reason: String },
}

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let body = serde_json::to_vec(v).expect("frame json");
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

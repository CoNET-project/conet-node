//! Signer wire: u32 big-endian length, then one JSON object. One request per connection.
use serde::{Deserialize, Serialize};

pub const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Address,
    RouteKeyId,
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
    /// NodeRegistryV2 NodeStatement (one per epoch and kind).
    SignStatement {
        #[serde(rename = "nodeId")]
        node_id: String,
        epoch: u64,
        kind: u8,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
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

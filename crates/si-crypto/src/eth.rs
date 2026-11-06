//! EIP-191 personal_sign / recover and keccak, byte-compatible with ethers v6.
use crate::{Error, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// ethers `id(text)` / `keccak256(toUtf8Bytes(text))`, 0x-prefixed lowercase hex.
pub fn keccak_hex(text: &str) -> String {
    format!("0x{}", hex::encode(keccak256(text.as_bytes())))
}

/// ethers `hashMessage`: keccak256("\x19Ethereum Signed Message:\n" + len + message).
pub fn eip191_hash(message: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    h.update(message);
    h.finalize().into()
}

pub struct EthKey(SigningKey);

impl EthKey {
    pub fn from_hex(private_key: &str) -> Result<Self> {
        let raw = hex::decode(private_key.trim_start_matches("0x"))
            .map_err(|e| Error::Eth(e.to_string()))?;
        SigningKey::from_slice(&raw)
            .map(Self)
            .map_err(|e| Error::Eth(e.to_string()))
    }
    pub fn address(&self) -> String {
        address_of(self.0.verifying_key())
    }
    /// Signs a 32-byte digest (RFC 6979, low-s), returns 65-byte r||s||v (v = 27/28) as 0x hex.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<String> {
        let (sig, rec): (Signature, RecoveryId) = self
            .0
            .sign_prehash_recoverable(digest)
            .map_err(|e| Error::Eth(e.to_string()))?;
        let (sig, rec) = match sig.normalize_s() {
            Some(n) => (n, RecoveryId::from_byte(rec.to_byte() ^ 1).expect("recid")),
            None => (sig, rec),
        };
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + rec.to_byte());
        Ok(format!("0x{}", hex::encode(out)))
    }
    /// ethers `Wallet.signMessage(text)`.
    pub fn sign_message(&self, message: &str) -> Result<String> {
        self.sign_digest(&eip191_hash(message.as_bytes()))
    }
}

/// ethers `recoverAddress(digest, sig)`; returns checksummed address.
pub fn recover_digest(digest: &[u8; 32], sig_hex: &str) -> Result<String> {
    let raw =
        hex::decode(sig_hex.trim_start_matches("0x")).map_err(|e| Error::Eth(e.to_string()))?;
    if raw.len() != 65 {
        return Err(Error::Eth("signature length".into()));
    }
    let v = raw[64];
    let rec = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => return Err(Error::Eth("bad v".into())),
    };
    let sig = Signature::from_slice(&raw[..64]).map_err(|e| Error::Eth(e.to_string()))?;
    let rec = RecoveryId::from_byte(rec).ok_or_else(|| Error::Eth("recid".into()))?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec)
        .map_err(|e| Error::Eth(e.to_string()))?;
    Ok(address_of(&vk))
}

/// ethers `verifyMessage(text, sig)`.
pub fn recover_message(message: &str, sig_hex: &str) -> Result<String> {
    recover_digest(&eip191_hash(message.as_bytes()), sig_hex)
}

fn address_of(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    to_checksum(&hex::encode(&hash[12..]))
}

/// EIP-55 checksum of 40 hex chars (any case, with or without 0x).
pub fn to_checksum(addr: &str) -> String {
    let lower = addr.trim_start_matches("0x").to_ascii_lowercase();
    let hash = hex::encode(keccak256(lower.as_bytes()));
    let mut out = String::from("0x");
    for (c, h) in lower.chars().zip(hash.chars()) {
        if c.is_ascii_alphabetic() && h.to_digit(16).unwrap_or(0) >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// ethers `isAddress`: 0x + 40 hex; mixed case must match the checksum.
pub fn is_address(addr: &str) -> bool {
    let Some(body) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) else {
        return false;
    };
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let all_lower = body.chars().all(|c| !c.is_ascii_uppercase());
    let all_upper = body.chars().all(|c| !c.is_ascii_lowercase());
    all_lower || all_upper || to_checksum(body) == format!("0x{body}")
}

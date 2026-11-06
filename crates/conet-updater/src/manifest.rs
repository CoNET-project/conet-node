//! Signed release manifest (M0 report §9).
//!
//! `manifest.json` is signed as exact bytes by k-of-n offline Ed25519 release keys; the
//! signatures travel in `manifest.json.sig`. Mirrors cannot change anything that passes.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Artifact {
    /// Rust target triple, e.g. `x86_64-unknown-linux-gnu`.
    pub target: String,
    /// Mirrors; any of them may be used, all are untrusted.
    pub urls: Vec<String>,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    /// Must be `conet-node`; stops a manifest for another product being replayed here.
    pub product: String,
    pub version: String,
    pub released_at: u64,
    /// Share of nodes (0–100) that take this version; picked by hash(node wallet, version).
    pub rollout_percent: u8,
    /// Versions that must not run. A node on a revoked version rolls back to its previous one.
    #[serde(default)]
    pub revoked: Vec<String>,
    pub artifacts: Vec<Artifact>,
    /// Reserved for N5 (shorter window for urgent releases). Parsed, not acted on until decided.
    #[serde(default)]
    pub urgent: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigEntry {
    /// Hex of the 32-byte public key that made this signature.
    pub key: String,
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigFile {
    pub sigs: Vec<SigEntry>,
}

#[derive(Debug, PartialEq)]
pub enum VerifyError {
    BadSigFile,
    NotEnoughSignatures { valid: usize, need: usize },
    BadManifest,
    WrongProduct,
}

pub const PRODUCT: &str = "conet-node";

/// Verify ≥ `threshold` distinct trusted keys signed exactly `manifest_bytes`, then parse.
pub fn verify(
    manifest_bytes: &[u8],
    sig_file: &[u8],
    trusted: &[VerifyingKey],
    threshold: usize,
) -> Result<Manifest, VerifyError> {
    let sf: SigFile = serde_json::from_slice(sig_file).map_err(|_| VerifyError::BadSigFile)?;
    let mut ok_keys: Vec<[u8; 32]> = vec![];
    for e in &sf.sigs {
        let (Ok(k), Ok(s)) = (hex::decode(&e.key), B64.decode(&e.sig)) else {
            continue;
        };
        let Ok(k): Result<[u8; 32], _> = k.try_into() else {
            continue;
        };
        let Some(vk) = trusted.iter().find(|t| t.to_bytes() == k) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(&s) else {
            continue;
        };
        if vk.verify(manifest_bytes, &sig).is_ok() && !ok_keys.contains(&k) {
            ok_keys.push(k);
        }
    }
    if threshold == 0 || ok_keys.len() < threshold {
        return Err(VerifyError::NotEnoughSignatures {
            valid: ok_keys.len(),
            need: threshold.max(1),
        });
    }
    let m: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| VerifyError::BadManifest)?;
    if m.product != PRODUCT {
        return Err(VerifyError::WrongProduct);
    }
    semver::Version::parse(&m.version).map_err(|_| VerifyError::BadManifest)?;
    Ok(m)
}

/// Release tool side: add one signature over the manifest bytes.
pub fn sign(manifest_bytes: &[u8], key: &SigningKey) -> SigEntry {
    SigEntry {
        key: hex::encode(key.verifying_key().to_bytes()),
        sig: B64.encode(key.sign(manifest_bytes).to_bytes()),
    }
}

/// Stable cohort in 0..100 for a node and a version (no clock, no randomness).
pub fn cohort(node_id: &str, version: &str) -> u8 {
    let h = Sha256::digest(
        format!("conet-node rollout|{}|{}", node_id.to_lowercase(), version).as_bytes(),
    );
    (u16::from_be_bytes([h[0], h[1]]) % 100) as u8
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

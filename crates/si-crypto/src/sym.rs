//! AES-256-GCM `iv(12) || ciphertext || tag(16)` and truncated HMAC-SHA256,
//! as used by SI mailbox stream sealing, UDP payloads and voice chunk MACs.
use crate::{Error, Result};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn gcm_seal(key: &[u8], iv: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Sym("key length"))?;
    let body = cipher
        .encrypt(Nonce::from_slice(iv), plaintext)
        .map_err(|_| Error::Sym("seal"))?;
    let mut out = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn gcm_open(key: &[u8], packed: &[u8]) -> Result<Vec<u8>> {
    if packed.len() < 12 + 16 {
        return Err(Error::Sym("short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Sym("key length"))?;
    cipher
        .decrypt(Nonce::from_slice(&packed[..12]), &packed[12..])
        .map_err(|_| Error::Sym("open"))
}

/// voiceForward.ts `chunkMac`: HMAC-SHA256(key, locator || blob)[..16].
pub fn chunk_mac(key: &[u8], locator: &[u8], blob: &[u8]) -> [u8; 16] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(locator);
    m.update(blob);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Constant-time compare for MACs.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

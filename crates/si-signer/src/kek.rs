//! Key-encryption key. Production: systemd-creds puts the decrypted credential at
//! `$CREDENTIALS_DIRECTORY/conet-node-kek` (unit: `LoadCredentialEncrypted=conet-node-kek:...`).
//! Tests and local networks may pass a file explicitly (flagged insecure by the binary).
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const CREDENTIAL_NAME: &str = "conet-node-kek";

#[derive(Debug)]
pub enum KekError {
    NotProvided,
    Read(std::io::Error),
    Format,
}

impl std::fmt::Display for KekError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KekError::NotProvided => write!(
                f,
                "no KEK: start under systemd with LoadCredentialEncrypted={CREDENTIAL_NAME}"
            ),
            KekError::Read(e) => write!(f, "KEK read: {e}"),
            KekError::Format => write!(f, "KEK must be 32 raw bytes or 64 hex characters"),
        }
    }
}

pub fn systemd_credential_path() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(|d| Path::new(&d).join(CREDENTIAL_NAME))
}

pub fn load(path: Option<&Path>) -> Result<Zeroizing<[u8; 32]>, KekError> {
    let p = match path {
        Some(p) => p.to_path_buf(),
        None => systemd_credential_path().ok_or(KekError::NotProvided)?,
    };
    let raw = Zeroizing::new(std::fs::read(&p).map_err(KekError::Read)?);
    parse(&raw)
}

pub fn parse(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>, KekError> {
    let mut out = Zeroizing::new([0u8; 32]);
    if raw.len() == 32 {
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let t = std::str::from_utf8(raw)
        .map_err(|_| KekError::Format)?
        .trim();
    if t.len() == 64 {
        hex::decode_to_slice(t, &mut out[..]).map_err(|_| KekError::Format)?;
        return Ok(out);
    }
    Err(KekError::Format)
}

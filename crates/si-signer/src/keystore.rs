//! Keystore file: node wallet + route PGP key, sealed with AES-256-GCM under a KEK subkey.
use crate::subkey;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use si_crypto::sym;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const LABEL: &str = "conet-node keystore v1";

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Secrets {
    /// Node wallet private key, 0x hex.
    pub wallet_hex: String,
    /// Route PGP secret key (armored) and its passphrase (may be empty).
    pub pgp_armored: String,
    pub pgp_pass: String,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    v: u32,
    /// Public, for operators: which wallet and route key this file holds.
    wallet: String,
    #[serde(rename = "keyId")]
    key_id: String,
    sealed: String,
}

#[derive(Debug)]
pub struct KeystoreError(pub String);

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keystore: {}", self.0)
    }
}

fn err<E: std::fmt::Display>(e: E) -> KeystoreError {
    KeystoreError(e.to_string())
}

/// Check the secrets load, then seal them. Returns the file contents.
pub fn seal(kek: &[u8; 32], secrets: &Secrets) -> Result<String, KeystoreError> {
    let wallet = si_crypto::eth::EthKey::from_hex(&secrets.wallet_hex)
        .map_err(err)?
        .address();
    let (_, key_id) =
        si_core::node::load_route(&secrets.pgp_armored, &secrets.pgp_pass).map_err(err)?;
    let plain = Zeroizing::new(serde_json::to_vec(secrets).map_err(err)?);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let k = Zeroizing::new(subkey(kek, LABEL));
    let ct = sym::gcm_seal(&k[..], &iv, &plain).map_err(err)?;
    serde_json::to_string_pretty(&Sealed {
        v: 1,
        wallet,
        key_id,
        sealed: B64.encode(ct),
    })
    .map_err(err)
}

pub fn open(kek: &[u8; 32], file: &str) -> Result<Secrets, KeystoreError> {
    let s: Sealed = serde_json::from_str(file).map_err(err)?;
    if s.v != 1 {
        return Err(KeystoreError("unknown version".into()));
    }
    let ct = B64.decode(s.sealed).map_err(err)?;
    let k = Zeroizing::new(subkey(kek, LABEL));
    let plain = Zeroizing::new(
        sym::gcm_open(&k[..], &ct)
            .map_err(|_| KeystoreError("wrong KEK or damaged file".into()))?,
    );
    serde_json::from_slice(&plain).map_err(err)
}

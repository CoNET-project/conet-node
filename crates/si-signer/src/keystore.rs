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
    /// Route key being retired (R11 transition): still decrypts, never published. Empty = none.
    #[serde(default)]
    pub previous_pgp_armored: String,
    #[serde(default)]
    pub previous_pgp_pass: String,
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

/// New node keys generated inside the signer (decision U1 "new keys"): a random secp256k1 wallet
/// and a curve25519 route key whose user ID is the wallet address. Nothing goes through a shell
/// and there is no passphrase; the KEK seals the result. Returns the secrets and the route
/// public key (for GuardianNodesInfoV6 / NodeRegistryV2 registration).
pub fn generate() -> Result<(Secrets, String), KeystoreError> {
    let mut sk = Zeroizing::new([0u8; 32]);
    let wallet = loop {
        OsRng.fill_bytes(&mut sk[..]);
        if let Ok(w) = si_crypto::eth::EthKey::from_hex(&hex::encode(&sk[..])) {
            break w;
        }
    };
    let address = wallet.address();
    let (pgp_armored, public, _) =
        si_crypto::opgp::generate_route_key(OsRng, &address).map_err(err)?;
    Ok((
        Secrets {
            wallet_hex: format!("0x{}", hex::encode(&sk[..])),
            pgp_armored,
            pgp_pass: String::new(),
            previous_pgp_armored: String::new(),
            previous_pgp_pass: String::new(),
        },
        public,
    ))
}

/// R11 route-key rotation, step 1: a new route key becomes current (same wallet and user ID);
/// the old one moves to `previous` and keeps decrypting until [`retire_previous`].
/// Refuses while a previous key is still being retired. Returns the new public key.
pub fn rotate_route(s: &mut Secrets) -> Result<String, KeystoreError> {
    if !s.previous_pgp_armored.is_empty() {
        return Err(KeystoreError(
            "a previous route key is still being retired".into(),
        ));
    }
    let address = si_crypto::eth::EthKey::from_hex(&s.wallet_hex)
        .map_err(err)?
        .address();
    let (new_armored, public, _) =
        si_crypto::opgp::generate_route_key(OsRng, &address).map_err(err)?;
    s.previous_pgp_armored = std::mem::replace(&mut s.pgp_armored, new_armored);
    s.previous_pgp_pass = std::mem::take(&mut s.pgp_pass);
    Ok(public)
}

/// R11 rotation, step 2: end of the transition; the old route key is dropped.
pub fn retire_previous(s: &mut Secrets) {
    s.previous_pgp_armored.zeroize();
    s.previous_pgp_pass.zeroize();
}

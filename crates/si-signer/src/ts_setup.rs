//! Import of a CoNET-SI (TypeScript) node identity from its `nodeSetup.json` (project decision
//! 2026-11-27: the Rust node keeps the identity the TS node already has on chain).
//!
//! TS layout (CoNET-SI `ICoNET_NodeSetup`, loader `getSetup` in `localNodeCommand.ts`), field names
//! only:
//! - `keychain`: the node wallet as an ethers encrypted JSON keystore (object, or a string holding
//!   that JSON). Opened with `passwd`.
//! - `passwd`: the one password for both the keystore and the route PGP key.
//! - `pgpKey.privateKey` (armored, passphrase `passwd`), `pgpKey.publicKey`, `pgpKey.keyID`.
//!
//! Nothing here prints, logs or returns a secret in an error. Errors carry a fixed code only.
//! The caller supplies the PUBLIC values it expects (wallet address, route encryption sub-key ID,
//! taken from the on-chain node table); a mismatch refuses the import before anything is sealed.
use crate::{keystore, scrypt};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use serde_json::Value;
use si_crypto::eth;
use zeroize::{Zeroize, Zeroizing};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Largest setup file read. The real files are about 2.6 KB.
pub const MAX_SETUP_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct ImportError(pub &'static str);

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ts-setup import refused: {}", self.0)
    }
}

impl std::error::Error for ImportError {}

fn e(code: &'static str) -> ImportError {
    ImportError(code)
}

pub struct Imported {
    /// Ready to `keystore::seal`.
    pub secrets: keystore::Secrets,
    /// Public values, safe to print.
    pub wallet: String,
    pub key_id: String,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn norm_addr(a: &str) -> String {
    format!(
        "0x{}",
        a.trim().trim_start_matches("0x").trim_start_matches("0X")
    )
    .to_ascii_lowercase()
}

fn str_field<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v.get(name).and_then(Value::as_str)
}

fn hex_field(v: &Value, name: &str) -> Result<Vec<u8>, ImportError> {
    let s = str_field(v, name).ok_or(e("keystore_field"))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|_| e("keystore_field"))
}

/// Opens the ethers v3 keystore (scrypt + aes-128-ctr + keccak MAC) and returns the 32-byte key.
fn open_keystore(
    ks: &Value,
    password: &str,
) -> Result<(Zeroizing<Vec<u8>>, Option<String>), ImportError> {
    if ks.get("version").and_then(Value::as_u64) != Some(3) {
        return Err(e("keystore_version"));
    }
    let crypto = ks
        .get("crypto")
        .or_else(|| ks.get("Crypto"))
        .ok_or(e("keystore_field"))?;
    if str_field(crypto, "kdf") != Some("scrypt") {
        return Err(e("keystore_kdf"));
    }
    if str_field(crypto, "cipher") != Some("aes-128-ctr") {
        return Err(e("keystore_cipher"));
    }
    let kp = crypto.get("kdfparams").ok_or(e("keystore_field"))?;
    let num = |n: &str| kp.get(n).and_then(Value::as_u64).ok_or(e("keystore_field"));
    let (n, r, p, dklen) = (num("n")?, num("r")?, num("p")?, num("dklen")?);
    if dklen != 32 || r > 64 || p > 64 {
        return Err(e("keystore_params"));
    }
    let salt = hex_field(kp, "salt")?;
    let iv = hex_field(crypto.get("cipherparams").ok_or(e("keystore_field"))?, "iv")?;
    let ciphertext = hex_field(crypto, "ciphertext")?;
    let mac = hex_field(crypto, "mac")?;
    if iv.len() != 16 || ciphertext.len() != 32 || mac.len() != 32 {
        return Err(e("keystore_shape"));
    }
    let dk = scrypt::scrypt(password.as_bytes(), &salt, n, r as u32, p as u32, 32)
        .map_err(|_| e("keystore_params"))?;
    let mut tag_input = Zeroizing::new(dk[16..32].to_vec());
    tag_input.extend_from_slice(&ciphertext);
    let want = eth::keccak256(&tag_input);
    if !ct_eq(&want, &mac) {
        // Same answer for a wrong password and a damaged file: do not say which.
        return Err(e("keystore_password_or_mac"));
    }
    let mut key = Zeroizing::new(ciphertext);
    let mut c = Aes128Ctr::new_from_slices(&dk[..16], &iv).map_err(|_| e("keystore_shape"))?;
    c.apply_keystream(&mut key);
    Ok((key, str_field(ks, "address").map(norm_addr)))
}

/// `setup`: the file bytes. `expect_wallet` and `expect_key_id` are public values from the chain.
pub fn import(
    setup: &[u8],
    expect_wallet: &str,
    expect_key_id: &str,
) -> Result<Imported, ImportError> {
    if setup.len() > MAX_SETUP_BYTES {
        return Err(e("file_too_large"));
    }
    if !eth::is_address(expect_wallet) {
        return Err(e("expect_wallet_format"));
    }
    let want_id = expect_key_id.trim().to_ascii_uppercase();
    if want_id.len() != 16 || !want_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(e("expect_key_id_format"));
    }
    let root: Value = serde_json::from_slice(setup).map_err(|_| e("not_json"))?;
    let passwd = Zeroizing::new(
        str_field(&root, "passwd")
            .ok_or(e("missing_passwd"))?
            .to_string(),
    );
    let keychain = root.get("keychain").ok_or(e("missing_keychain"))?;
    let parsed;
    let ks: &Value = match keychain {
        Value::String(s) => {
            parsed = serde_json::from_str::<Value>(s).map_err(|_| e("keychain_not_json"))?;
            &parsed
        }
        Value::Object(_) => keychain,
        _ => return Err(e("keychain_type")),
    };
    let pgp = root.get("pgpKey").ok_or(e("missing_pgpkey"))?;
    let pgp_armored = str_field(pgp, "privateKey")
        .ok_or(e("missing_pgp_private"))?
        .to_string();

    let (mut key32, ks_address) = open_keystore(ks, &passwd)?;
    if key32.len() != 32 {
        return Err(e("keystore_shape"));
    }
    let mut wallet_hex = Zeroizing::new(format!("0x{}", hex::encode(&key32[..])));
    key32.zeroize();
    let wallet = eth::EthKey::from_hex(&wallet_hex)
        .map_err(|_| e("wallet_key_invalid"))?
        .address();
    if let Some(a) = ks_address {
        if a != norm_addr(&wallet) {
            return Err(e("keystore_address_mismatch"));
        }
    }
    if norm_addr(&wallet) != norm_addr(expect_wallet) {
        wallet_hex.zeroize();
        return Err(e("wallet_mismatch"));
    }
    let (_, key_id) =
        si_core::node::load_route(&pgp_armored, &passwd).map_err(|_| e("pgp_unlock"))?;
    if !key_id.eq_ignore_ascii_case(&want_id) {
        return Err(e("key_id_mismatch"));
    }
    if let Some(declared) = str_field(pgp, "keyID") {
        if !declared.eq_ignore_ascii_case(&key_id) {
            return Err(e("declared_key_id_mismatch"));
        }
    }
    let secrets = keystore::Secrets {
        wallet_hex: wallet_hex.to_string(),
        pgp_armored,
        pgp_pass: passwd.to_string(),
        previous_pgp_armored: String::new(),
        previous_pgp_pass: String::new(),
    };
    Ok(Imported {
        secrets,
        wallet,
        key_id,
    })
}

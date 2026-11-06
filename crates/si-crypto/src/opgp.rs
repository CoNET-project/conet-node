//! OpenPGP on rPGP, shaped after what CoNET-SI does with openpgp.js 6.
use crate::{Error, Result, Rng};
use pgp::{
    composed::{
        ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Esk, Message,
        MessageBuilder, SignedPublicKey, SignedSecretKey,
    },
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::DataMode,
    types::{CompressionAlgorithm, KeyDetails, Password},
};

fn e<E: std::fmt::Display>(err: E) -> Error {
    Error::Pgp(err.to_string())
}

fn hex_id(id: impl AsRef<[u8]>) -> String {
    hex::encode_upper(id.as_ref())
}

/// A public certificate (`readKey`).
pub struct PublicCert {
    pub cert: SignedPublicKey,
}

impl PublicCert {
    pub fn from_armor(armor: &str) -> Result<Self> {
        let (cert, _) = SignedPublicKey::from_string(armor).map_err(e)?;
        cert.verify_bindings().map_err(e)?;
        Ok(Self { cert })
    }
    /// openpgp.js `getKeyIDs()`: primary first, then subkeys.
    pub fn key_ids(&self) -> Vec<String> {
        let mut v = vec![hex_id(self.cert.primary_key.legacy_key_id())];
        v.extend(
            self.cert
                .public_subkeys
                .iter()
                .map(|s| hex_id(s.legacy_key_id())),
        );
        v
    }
    /// SI `getPublicKeyArmoredKeyID`: `getKeyIDs()[1]` (the first subkey = ECDH).
    pub fn enc_key_id(&self) -> Option<String> {
        self.key_ids().get(1).cloned()
    }
    pub fn fingerprint(&self) -> String {
        format!("{:X}", self.cert.primary_key.fingerprint())
    }
}

/// A secret key plus its passphrase. Prototype only: in the product the key lives
/// in the signer process and never in the network process (design v0.1 §6.2).
pub struct SecretCert {
    pub key: SignedSecretKey,
    pass: String,
}

impl SecretCert {
    pub fn from_armor(armor: &str, passphrase: &str) -> Result<Self> {
        let (key, _) = SignedSecretKey::from_string(armor).map_err(e)?;
        Ok(Self {
            key,
            pass: passphrase.to_string(),
        })
    }
    /// Unlock once and keep the plain key in memory, as live SI does after start-up
    /// (`makeOpenpgpObj`). Saves the S2K cost on every decrypt.
    pub fn unlock(mut self) -> Result<Self> {
        let pw = self.pw();
        self.key.primary_key.remove_password(&pw).map_err(e)?;
        for sub in &mut self.key.secret_subkeys {
            sub.key.remove_password(&pw).map_err(e)?;
        }
        self.pass.clear();
        Ok(self)
    }
    fn pw(&self) -> Password {
        Password::from(self.pass.as_str())
    }
    pub fn public(&self) -> PublicCert {
        PublicCert {
            cert: self.key.to_public_key(),
        }
    }
}

/// openpgp.js `readMessage(...).getEncryptionKeyIDs()` without decrypting.
pub fn recipient_key_ids(armor: &str) -> Result<Vec<String>> {
    let (msg, _) = Message::from_string(armor).map_err(e)?;
    match &msg {
        Message::Encrypted { esk, .. } => Ok(esk
            .iter()
            .filter_map(|k| match k {
                Esk::PublicKeyEncryptedSessionKey(p) => p.id().ok().map(hex_id),
                _ => None,
            })
            .collect()),
        _ => Ok(vec![]),
    }
}

pub struct Decrypted {
    pub data: Vec<u8>,
    /// Some(true/false) when a signer was given and the message carried a signature.
    pub verified: Option<bool>,
}

/// Decrypt (and decompress) like `openpgp.decrypt({ format: 'binary' })`.
/// When `signer` is given, also verify the inner signature against it.
pub fn decrypt(armor: &str, key: &SecretCert, signer: Option<&PublicCert>) -> Result<Decrypted> {
    let (msg, _) = Message::from_string(armor).map_err(e)?;
    let mut m = msg.decrypt(&key.pw(), &key.key).map_err(e)?;
    if m.is_compressed() {
        m = m.decompress().map_err(e)?;
    }
    let data = m.as_data_vec().map_err(e)?;
    let verified = match signer {
        Some(s) if m.is_signed() => Some(m.verify(&s.cert).is_ok()),
        Some(_) => Some(false),
        None => None,
    };
    Ok(Decrypted { data, verified })
}

pub struct EncryptOpts<'a> {
    /// Literal mode 'u' with CRLF line endings, like openpgp.js `createMessage({ text })`.
    /// false = binary literal (`createMessage({ binary })`).
    pub text: bool,
    pub zlib: bool,
    pub sign_with: Option<&'a SecretCert>,
}

/// Encrypt to the certificate's first subkey (the ECDH subkey of SI/PWA keys), SEIPDv1 AES-256,
/// the same container openpgp.js 6 produces for these keys with default config.
pub fn encrypt<R: Rng>(
    mut rng: R,
    data: &[u8],
    to: &PublicCert,
    opts: EncryptOpts<'_>,
) -> Result<String> {
    let sub = to
        .cert
        .public_subkeys
        .first()
        .ok_or_else(|| Error::Pgp("certificate has no subkey".into()))?;
    let payload = if opts.text {
        let s = std::str::from_utf8(data).map_err(e)?;
        si_crlf(s).into_bytes()
    } else {
        data.to_vec()
    };
    let mut b =
        MessageBuilder::from_bytes("", payload).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    b.encrypt_to_key(&mut rng, sub).map_err(e)?;
    if opts.text {
        b.data_mode(DataMode::Utf8).map_err(e)?;
        b.sign_text();
    }
    if opts.zlib {
        b.compression(CompressionAlgorithm::ZLIB);
    }
    if let Some(s) = opts.sign_with {
        b.sign(&s.key.primary_key, s.pw(), HashAlgorithm::Sha256);
    }
    b.to_armored_string(&mut rng, ArmorOptions::default())
        .map_err(e)
}

fn si_crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// openpgp.js `sign({ message: createMessage({ text }), detached: true })`: a text signature.
pub fn sign_detached_text<R: Rng>(mut rng: R, text: &str, key: &SecretCert) -> Result<String> {
    let sig = DetachedSignature::sign_text_data(
        &mut rng,
        &key.key.primary_key,
        &key.pw(),
        HashAlgorithm::Sha256,
        si_crlf(text).as_bytes(),
    )
    .map_err(e)?;
    sig.to_armored_string(ArmorOptions::default()).map_err(e)
}

pub fn verify_detached(text: &str, sig_armor: &str, signer: &PublicCert) -> bool {
    let Ok((sig, _)) = DetachedSignature::from_string(sig_armor) else {
        return false;
    };
    sig.verify(&signer.cert, text.as_bytes()).is_ok()
        || sig.verify(&signer.cert, si_crlf(text).as_bytes()).is_ok()
}

pub fn sign_cleartext<R: Rng>(rng: R, text: &str, key: &SecretCert) -> Result<String> {
    let m = CleartextSignedMessage::sign(rng, text, &key.key.primary_key, &key.pw()).map_err(e)?;
    m.to_armored_string(ArmorOptions::default()).map_err(e)
}

pub fn verify_cleartext(armor: &str, signer: &PublicCert) -> Option<(String, bool)> {
    let (m, _) = CleartextSignedMessage::from_string(armor).ok()?;
    let ok = m.verify(&signer.cert).is_ok();
    Some((m.signed_text(), ok))
}

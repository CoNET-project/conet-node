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
        check_curve25519(&key)?;
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

/// Node secret keys must be curve25519 (Ed25519 primary, X25519 encryption subkey), the type
/// SI and the PWA generate. Refusing everything else means no RSA or NIST-curve private-key
/// operation can run in this process, which keeps RUSTSEC-2023-0071 (rsa) and RUSTSEC-2026-0387
/// (crypto-bigint 0.5 via rPGP's NIST curves) out of reach. Public keys of other types are fine.
fn check_curve25519(key: &SignedSecretKey) -> Result<()> {
    use pgp::types::{EcdhPublicParams, PublicParams};
    let primary_ok = matches!(
        key.primary_key.public_key().public_params(),
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_)
    );
    let subs_ok = key.secret_subkeys.iter().all(|s| {
        matches!(
            s.key.public_key().public_params(),
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { .. })
                | PublicParams::X25519(_)
                | PublicParams::EdDSALegacy(_)
                | PublicParams::Ed25519(_)
        )
    });
    if primary_ok && subs_ok {
        Ok(())
    } else {
        Err(Error::Pgp(
            "only curve25519 secret keys are accepted".into(),
        ))
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

/// Network side: the message's single PKESK packet, serialized with its header. This is all
/// the signer needs; the encrypted payload never leaves the network process.
pub fn pkesk_packet(armor: &str) -> Result<Vec<u8>> {
    use pgp::packet::PacketTrait;
    let (msg, _) = Message::from_string(armor).map_err(e)?;
    let Message::Encrypted { esk, .. } = &msg else {
        return Err(Error::Pgp("not encrypted".into()));
    };
    let mut pk = esk.iter().filter_map(|x| match x {
        Esk::PublicKeyEncryptedSessionKey(p) => Some(p),
        _ => None,
    });
    let (Some(p), None) = (pk.next(), pk.next()) else {
        return Err(Error::Pgp("need exactly one PKESK".into()));
    };
    let mut out = vec![];
    p.to_writer_with_header(&mut out).map_err(e)?;
    Ok(out)
}

/// Signer side: decrypt one v3 PKESK with the route key. Returns (symmetric algorithm id, key).
/// Parses a single small packet; never sees, decompresses or parses the payload.
pub fn session_key_from_pkesk(pkesk: &[u8], key: &SecretCert) -> Result<(u8, Vec<u8>)> {
    use pgp::composed::PlainSessionKey;
    use pgp::packet::{Packet, PacketParser};
    use pgp::types::{DecryptionKey, EskType, PkeskVersion};
    if pkesk.len() > 4096 {
        return Err(Error::Pgp("pkesk too large".into()));
    }
    let mut parser = PacketParser::new(pkesk);
    let p = match parser.next() {
        Some(Ok(Packet::PublicKeyEncryptedSessionKey(p))) => p,
        _ => return Err(Error::Pgp("not a PKESK packet".into())),
    };
    if parser.next().is_some() {
        return Err(Error::Pgp("trailing packets".into()));
    }
    if p.version() != PkeskVersion::V3 {
        return Err(Error::Pgp("only v3 PKESK".into()));
    }
    let values = p.values().map_err(e)?;
    for sub in &key.key.secret_subkeys {
        if !p.match_identity(&sub.key.public_key()) {
            continue;
        }
        let sk = sub
            .key
            .decrypt(&key.pw(), values, EskType::V3_4)
            .map_err(e)?
            .map_err(e)?;
        return match &sk {
            PlainSessionKey::V3_4 { sym_alg, key } => {
                Ok((u8::from(*sym_alg), key.as_ref().to_vec()))
            }
            _ => Err(Error::Pgp("unexpected session key version".into())),
        };
    }
    Err(Error::Pgp("PKESK is not for this key".into()))
}

/// Network side: decrypt (and decompress) with a session key from the signer.
pub fn decrypt_with_session_key(armor: &str, sym_alg: u8, session_key: &[u8]) -> Result<Vec<u8>> {
    use pgp::composed::PlainSessionKey;
    let (msg, _) = Message::from_string(armor).map_err(e)?;
    let sk = PlainSessionKey::V3_4 {
        sym_alg: SymmetricKeyAlgorithm::from(sym_alg),
        key: session_key.into(),
    };
    let mut m = msg.decrypt_with_session_key(sk).map_err(e)?;
    if m.is_compressed() {
        m = m.decompress().map_err(e)?;
    }
    m.as_data_vec().map_err(e)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_curve25519_secret_keys_load() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/vectors/non-curve25519-test-keys.json"
        ))
        .unwrap();
        assert!(
            SecretCert::from_armor(v["rsa"].as_str().unwrap(), "").is_err(),
            "RSA refused"
        );
        assert!(
            SecretCert::from_armor(v["p256"].as_str().unwrap(), "").is_err(),
            "P-256 refused"
        );
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../../../conformance/vectors/golden.json")).unwrap();
        let k = &g["keys"]["nodeA"];
        assert!(SecretCert::from_armor(
            k["armoredPrivate"].as_str().unwrap(),
            k["passphrase"].as_str().unwrap()
        )
        .is_ok());
    }

    #[test]
    fn session_key_path_matches_full_decrypt() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../../../conformance/vectors/golden.json")).unwrap();
        let k = &g["keys"]["nodeA"];
        let key = SecretCert::from_armor(
            k["armoredPrivate"].as_str().unwrap(),
            k["passphrase"].as_str().unwrap(),
        )
        .unwrap()
        .unlock()
        .unwrap();
        let other = SecretCert::from_armor(
            g["keys"]["nodeB"]["armoredPrivate"].as_str().unwrap(),
            g["keys"]["nodeB"]["passphrase"].as_str().unwrap(),
        )
        .unwrap();
        let mut checked = 0;
        for v in g["vectors"].as_array().unwrap() {
            let local = v["kind"] == "pgp_decrypt"
                || (v["kind"] == "post_classify" && v["input"]["localKey"] == "nodeA");
            let skip =
                ["post-not-local", "post-multi-recipient"].contains(&v["id"].as_str().unwrap());
            if !local || skip {
                continue;
            }
            let armor = v["input"]["armor"].as_str().unwrap();
            let pk = pkesk_packet(armor).unwrap();
            assert!(pk.len() < 200, "only the PKESK leaves the network process");
            let (alg, sk) = session_key_from_pkesk(&pk, &key).unwrap();
            assert_eq!(
                decrypt_with_session_key(armor, alg, &sk).unwrap(),
                decrypt(armor, &key, None).unwrap().data,
                "{}",
                v["id"]
            );
            assert!(session_key_from_pkesk(&pk, &other).is_err(), "wrong key");
            checked += 1;
        }
        assert!(checked >= 15, "{checked}");
        let multi = g["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "post-multi-recipient")
            .unwrap();
        assert!(
            pkesk_packet(multi["input"]["armor"].as_str().unwrap()).is_err(),
            "multi-recipient refused"
        );
        assert!(session_key_from_pkesk(b"\xc1\x01\x00", &key).is_err());
    }
}

//! Client of the CoNET IPFS API (`https://ipfs.conet.network/api`: `POST /storageFragment`, `GET /getFragment?hash=`) with VERIFIED acceptance, and the node-local
//! authenticated layer that must wrap every message before it leaves the node. Isolated building blocks; nothing here is wired into the node's start path.
//!
//! Why verified: a 200 is not taken as proof that the object was stored; an acceptance requires an equal hash and a byte-for-byte equal read-back. [`FragmentClient::put_verified`]
//! returns Ok only when (1) the status is 200 and ok is true, (2) the answer's hash equals the local Keccak-256 of the uploaded string's UTF-8 (the content address of the API is
//! not a Kubo CID) and (3) the object read back is byte-for-byte equal to what was uploaded. Anything else is an error and no acceptance may be confirmed to the sender.
//!
//! Why a local layer: the inner armor a mailbox stores is encrypted to the recipient's user key and its OpenPGP packet header carries that key's ID; anything uploaded is
//! retrievable by whoever learns its hash. [`LocalSeal`] wraps the WHOLE armor in AES-256-GCM with a fresh random nonce and encodes it as base64: the uploaded string holds no
//! key ID, wallet, time or label, and the original armor is restored byte for byte (its keccak256, the ACK hash of the mailbox, stays valid).
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_core::{OsRng, RngCore};
use si_crypto::eth::{keccak_hex, EthKey};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum PutError {
    /// The request did not complete (connection, TLS, timeout).
    Transport(String),
    /// A non-200 status (403: the signature is refused; 402: payment is asked; 5xx).
    Status(u16),
    /// 200 but not `{"ok":true,"hash":…}`.
    NotOk,
    /// The answer's hash is not the local Keccak-256 of the uploaded string.
    HashMismatch { got: String, want: String },
    /// The object could not be read back (the status of the read).
    ReadBackMissing(u16),
    /// The object read back differs from what was uploaded.
    ReadBackMismatch,
}

impl PutError {
    /// The stop conditions of the live check: payment is asked, or a good signature is refused or the service fails.
    pub fn is_stop_condition(&self) -> bool {
        matches!(
            self,
            PutError::Status(402) | PutError::Status(403) | PutError::Status(500..=599)
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GetError {
    Transport(String),
    Status(u16),
    /// The bytes returned do not hash to the address that was asked for (a forged or damaged object).
    HashMismatch,
}

pub struct FragmentClient {
    base: String,
    wallet: EthKey,
    http: reqwest::Client,
    timeout: Duration,
}

impl FragmentClient {
    /// `base` without a trailing slash, e.g. `https://ipfs.conet.network/api`. `wallet` is the uploader; the API authenticates it with an EIP-191 signature of its own address.
    pub fn new(base: &str, wallet: EthKey) -> Result<Self, reqwest::Error> {
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            wallet,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            timeout: Duration::from_secs(20),
        })
    }

    pub fn uploader_address(&self) -> String {
        self.wallet.address()
    }

    /// Uploads `image` (the encoded ciphertext) and returns its content address only after the answer's hash AND a byte-equal read-back agree with the local values.
    pub async fn put_verified(&self, image: &str) -> Result<String, PutError> {
        let want = keccak_hex(image);
        let wallet = self.wallet.address().to_lowercase();
        let sign = self
            .wallet
            .sign_message(&wallet)
            .map_err(|e| PutError::Transport(format!("sign: {e}")))?;
        let resp = self
            .http
            .post(format!("{}/storageFragment", self.base))
            .timeout(self.timeout)
            .json(&serde_json::json!({ "wallet": wallet, "signMessage": sign, "image": image }))
            .send()
            .await
            .map_err(|e| PutError::Transport(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(PutError::Status(status));
        }
        let body: serde_json::Value = resp.json().await.map_err(|_| PutError::NotOk)?;
        if body["ok"] != serde_json::Value::Bool(true) {
            return Err(PutError::NotOk);
        }
        let got = body["hash"].as_str().unwrap_or("").to_string();
        if !got.eq_ignore_ascii_case(&want) {
            return Err(PutError::HashMismatch { got, want });
        }
        let back = self
            .http
            .get(format!("{}/getFragment?hash={}", self.base, want))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| PutError::Transport(e.without_url().to_string()))?;
        let rs = back.status().as_u16();
        if rs != 200 {
            return Err(PutError::ReadBackMissing(rs));
        }
        let bytes = back
            .bytes()
            .await
            .map_err(|e| PutError::Transport(e.without_url().to_string()))?;
        if bytes.as_ref() != image.as_bytes() {
            return Err(PutError::ReadBackMismatch);
        }
        Ok(want)
    }

    /// Reads an object and checks that it hashes to the address asked for.
    pub async fn get_verified(&self, hash: &str) -> Result<String, GetError> {
        // the address goes into a URL unescaped: only 0x and hex digits are accepted
        if !(hash.starts_with("0x") && hash[2..].bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(GetError::Status(400));
        }
        let r = self
            .http
            .get(format!("{}/getFragment?hash={}", self.base, hash))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| GetError::Transport(e.without_url().to_string()))?;
        let s = r.status().as_u16();
        if s != 200 {
            return Err(GetError::Status(s));
        }
        let bytes = r
            .bytes()
            .await
            .map_err(|e| GetError::Transport(e.without_url().to_string()))?;
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| GetError::HashMismatch)?;
        if !keccak_hex(&text).eq_ignore_ascii_case(hash) {
            return Err(GetError::HashMismatch);
        }
        Ok(text)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// Not valid base64, too short, or the authentication failed (wrong key or a changed byte).
    Open,
}

/// The node-local authenticated layer. The key is held by the node (a systemd credential in the packaged unit), never uploaded, never part of an object.
pub struct LocalSeal {
    cipher: Aes256Gcm,
}

impl LocalSeal {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// base64( nonce(12) ‖ AES-256-GCM(armor) ‖ tag(16) ), a fresh random nonce per call, no associated data and no label.
    pub fn seal(&self, armor: &str) -> String {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        self.seal_with_nonce(armor, nonce)
    }

    pub fn seal_with_nonce(&self, armor: &str, nonce: [u8; 12]) -> String {
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), armor.as_bytes())
            .expect("aes-gcm encrypt");
        let mut out = nonce.to_vec();
        out.extend(ct);
        B64.encode(out)
    }

    /// Restores the original armor byte for byte, or fails if the key is wrong or any byte changed.
    pub fn open(&self, sealed: &str) -> Result<String, SealError> {
        let raw = B64.decode(sealed).map_err(|_| SealError::Open)?;
        if raw.len() < 12 + 16 {
            return Err(SealError::Open);
        }
        let (nonce, ct) = raw.split_at(12);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| SealError::Open)?;
        String::from_utf8(pt).map_err(|_| SealError::Open)
    }
}

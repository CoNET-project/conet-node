//! CoNET node signer process (design v0.1 §6.2, M1 line B).
//!
//! The network process never holds node keys. It asks this process, over a Unix socket, for a
//! closed list of operations: wallet address, hop signature (the signer builds the payload),
//! route-key decryption, NodeRegistryV2 statements (one per epoch and kind, persisted before
//! release) and, only when enabled, BindNode consent. There is no "sign arbitrary message".
//!
//! Keys sit in a keystore file sealed with a KEK that systemd-creds hands over at start
//! (`LoadCredentialEncrypted=`), so the passphrase never lives next to the key (issue S1).
#![forbid(unsafe_code)]

pub mod client;
pub mod kek;
pub mod keystore;
pub mod proto;
pub mod server;
pub mod state;

/// Derive a purpose key from the KEK (HMAC-SHA256(KEK, label)).
pub fn subkey(kek: &[u8; 32], label: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(kek).expect("hmac key");
    m.update(label.as_bytes());
    m.finalize().into_bytes().into()
}

//! Pure crypto for the node: OpenPGP (rPGP), Ethereum signatures (k256), AES-GCM, HMAC.
//! No key storage and no I/O. Randomness always comes from the caller.
#![forbid(unsafe_code)]

pub mod eip712;
pub mod eth;
pub mod opgp;
pub mod sym;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("pgp: {0}")]
    Pgp(String),
    #[error("eth: {0}")]
    Eth(String),
    #[error("sym: {0}")]
    Sym(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Rand traits as rPGP expects them (rand_core 0.6).
pub trait Rng: rand_core::RngCore + rand_core::CryptoRng {}
impl<T: rand_core::RngCore + rand_core::CryptoRng> Rng for T {}

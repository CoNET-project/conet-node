//! EIP-712 for the NodeRegistryV2 statements, byte-compatible with ethers `TypedDataEncoder`.
//! Only static types are needed, so this is a small hand encoder rather than a generic one.
use crate::{eth::keccak256, Error, Result};

pub type Word = [u8; 32];

fn err(m: &str) -> Error {
    Error::Eth(m.to_string())
}

/// Decimal string to a 32-byte big-endian uint256.
pub fn u256_dec(s: &str) -> Result<Word> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err("uint256 decimal"));
    }
    let mut out = [0u8; 32];
    for d in s.bytes() {
        let mut carry = (d - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let v = (*byte as u32) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(err("uint256 overflow"));
        }
    }
    Ok(out)
}

pub fn u64_word(v: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

pub fn hex_bytes(s: &str, len: usize) -> Result<Vec<u8>> {
    let b = hex::decode(s.trim_start_matches("0x")).map_err(|_| err("hex"))?;
    if b.len() != len {
        return Err(err("hex length"));
    }
    Ok(b)
}

/// address: left-padded to 32 bytes.
pub fn address_word(addr: &str) -> Result<Word> {
    let b = hex_bytes(addr, 20)?;
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&b);
    Ok(w)
}

/// bytesN (N < 32): right-padded to 32 bytes.
pub fn fixed_bytes_word(s: &str, n: usize) -> Result<Word> {
    let b = hex_bytes(s, n)?;
    let mut w = [0u8; 32];
    w[..n].copy_from_slice(&b);
    Ok(w)
}

pub fn bytes32(s: &str) -> Result<Word> {
    let b = hex_bytes(s, 32)?;
    let mut w = [0u8; 32];
    w.copy_from_slice(&b);
    Ok(w)
}

pub fn type_hash(type_string: &str) -> Word {
    keccak256(type_string.as_bytes())
}

pub fn hash_words(type_string: &str, fields: &[Word]) -> Word {
    let mut buf = Vec::with_capacity(32 * (fields.len() + 1));
    buf.extend_from_slice(&type_hash(type_string));
    for f in fields {
        buf.extend_from_slice(f);
    }
    keccak256(&buf)
}

/// `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`.
pub fn domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: &str,
) -> Result<Word> {
    Ok(hash_words(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        &[
            keccak256(name.as_bytes()),
            keccak256(version.as_bytes()),
            u64_word(chain_id),
            address_word(verifying_contract)?,
        ],
    ))
}

/// keccak256(0x1901 ‖ domainSeparator ‖ structHash).
pub fn digest(domain_separator: &Word, struct_hash: &Word) -> Word {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator);
    buf[34..].copy_from_slice(struct_hash);
    keccak256(&buf)
}

pub fn to_hex(w: &Word) -> String {
    format!("0x{}", hex::encode(w))
}

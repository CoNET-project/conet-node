//! scrypt (RFC 7914) on the SHA-256 and HMAC crates this workspace already uses, so reading a
//! CoNET-SI keystore needs no new dependency. Used only to open the ethers keystore JSON in
//! `nodeSetup.json` (`ts_setup`). Checked against the RFC 7914 test vectors and against Node's
//! `crypto.scryptSync` (see the tests).
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum ScryptError {
    /// N must be a power of two above 1; r and p at least 1; output length 1..=1024.
    Params,
    /// The working memory would exceed the cap (128 * N * r bytes).
    TooLarge,
}

/// Largest working memory accepted (128 * N * r). ethers' default is N=131072, r=8 = 128 MiB.
pub const MAX_MEMORY_BYTES: usize = 512 * 1024 * 1024;

fn pbkdf2_one_iteration(password: &[u8], salt: &[u8], out: &mut [u8]) {
    let base = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut m = base.clone();
        m.update(salt);
        m.update(&((i as u32) + 1).to_be_bytes());
        let t = m.finalize().into_bytes();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! q {
        ($a:expr, $b:expr, $c:expr, $r:expr) => {
            x[$a] ^= x[$b].wrapping_add(x[$c]).rotate_left($r);
        };
    }
    for _ in 0..4 {
        q!(4, 0, 12, 7);
        q!(8, 4, 0, 9);
        q!(12, 8, 4, 13);
        q!(0, 12, 8, 18);
        q!(9, 5, 1, 7);
        q!(13, 9, 5, 9);
        q!(1, 13, 9, 13);
        q!(5, 1, 13, 18);
        q!(14, 10, 6, 7);
        q!(2, 14, 10, 9);
        q!(6, 2, 14, 13);
        q!(10, 6, 2, 18);
        q!(3, 15, 11, 7);
        q!(7, 3, 15, 9);
        q!(11, 7, 3, 13);
        q!(15, 11, 7, 18);
        q!(1, 0, 3, 7);
        q!(2, 1, 0, 9);
        q!(3, 2, 1, 13);
        q!(0, 3, 2, 18);
        q!(6, 5, 4, 7);
        q!(7, 6, 5, 9);
        q!(4, 7, 6, 13);
        q!(5, 4, 7, 18);
        q!(11, 10, 9, 7);
        q!(8, 11, 10, 9);
        q!(9, 8, 11, 13);
        q!(10, 9, 8, 18);
        q!(12, 15, 14, 7);
        q!(13, 12, 15, 9);
        q!(14, 13, 12, 13);
        q!(15, 14, 13, 18);
    }
    for i in 0..16 {
        b[i] = b[i].wrapping_add(x[i]);
    }
}

/// BlockMix over `32 * r` words, result into `out`.
fn block_mix(input: &[u32], out: &mut [u32], r: usize) {
    let mut x = [0u32; 16];
    x.copy_from_slice(&input[(2 * r - 1) * 16..2 * r * 16]);
    for i in 0..2 * r {
        for k in 0..16 {
            x[k] ^= input[i * 16 + k];
        }
        salsa20_8(&mut x);
        // Even blocks go to the first half, odd blocks to the second half.
        let dst = if i % 2 == 0 {
            (i / 2) * 16
        } else {
            (r + i / 2) * 16
        };
        out[dst..dst + 16].copy_from_slice(&x);
    }
}

fn ro_mix(block: &mut [u32], n: usize, r: usize) {
    let words = 32 * r;
    let mut v = Zeroizing::new(vec![0u32; n * words]);
    let mut x = Zeroizing::new(block.to_vec());
    let mut y = Zeroizing::new(vec![0u32; words]);
    for i in 0..n {
        v[i * words..(i + 1) * words].copy_from_slice(&x);
        block_mix(&x, &mut y, r);
        std::mem::swap(&mut *x, &mut *y);
    }
    for _ in 0..n {
        let j = (x[(2 * r - 1) * 16] as usize) & (n - 1);
        for k in 0..words {
            x[k] ^= v[j * words + k];
        }
        block_mix(&x, &mut y, r);
        std::mem::swap(&mut *x, &mut *y);
    }
    block.copy_from_slice(&x);
}

pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    dk_len: usize,
) -> Result<Zeroizing<Vec<u8>>, ScryptError> {
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 || dk_len == 0 || dk_len > 1024 {
        return Err(ScryptError::Params);
    }
    let (r, p) = (r as usize, p as usize);
    let mem = (n as u128) * 128 * (r as u128);
    if mem > MAX_MEMORY_BYTES as u128 || (p as u128) * 128 * (r as u128) > MAX_MEMORY_BYTES as u128
    {
        return Err(ScryptError::TooLarge);
    }
    let n = n as usize;
    let mut b = Zeroizing::new(vec![0u8; p * 128 * r]);
    pbkdf2_one_iteration(password, salt, &mut b);
    for chunk in b.chunks_mut(128 * r) {
        let mut words = Zeroizing::new(vec![0u32; 32 * r]);
        for (i, w) in words.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        ro_mix(&mut words, n, r);
        for (i, w) in words.iter().enumerate() {
            chunk[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
    }
    let mut dk = Zeroizing::new(vec![0u8; dk_len]);
    pbkdf2_one_iteration(password, &b, &mut dk);
    Ok(dk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // RFC 7914 section 12 (the same values come out of Node's crypto.scryptSync).
    #[test]
    fn rfc7914_vector_1() {
        let dk = scrypt(b"", b"", 16, 1, 1, 64).unwrap();
        assert_eq!(hex(&dk), "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
    }

    #[test]
    fn rfc7914_vector_2() {
        let dk = scrypt(b"password", b"NaCl", 1024, 8, 16, 64).unwrap();
        assert_eq!(hex(&dk), "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
    }

    #[test]
    fn rfc7914_vector_3() {
        let dk = scrypt(b"pleaseletmein", b"SodiumChloride", 16384, 8, 1, 64).unwrap();
        assert_eq!(hex(&dk), "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
    }

    #[test]
    fn bad_parameters_are_refused_before_any_work() {
        assert_eq!(
            scrypt(b"x", b"y", 0, 8, 1, 32).unwrap_err(),
            ScryptError::Params
        );
        assert_eq!(
            scrypt(b"x", b"y", 3, 8, 1, 32).unwrap_err(),
            ScryptError::Params
        );
        assert_eq!(
            scrypt(b"x", b"y", 16, 0, 1, 32).unwrap_err(),
            ScryptError::Params
        );
        assert_eq!(
            scrypt(b"x", b"y", 16, 8, 0, 32).unwrap_err(),
            ScryptError::Params
        );
        assert_eq!(
            scrypt(b"x", b"y", 16, 8, 1, 0).unwrap_err(),
            ScryptError::Params
        );
        assert_eq!(
            scrypt(b"x", b"y", 1 << 40, 8, 1, 32).unwrap_err(),
            ScryptError::TooLarge
        );
        assert_eq!(
            scrypt(b"x", b"y", 1 << 20, 8, 1, 32).unwrap_err(),
            ScryptError::TooLarge
        );
    }
}

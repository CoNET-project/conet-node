//! EIP-1559 (type 2) transaction encoding and signing, for the signer's own transaction paths.
//! The signer builds `to` and `data` itself from its configuration; callers only give nonce, fees,
//! gas and value. Checked byte for byte against ethers 6 (`conformance/vectors/tx1559.json`).
use si_crypto::eth::{keccak256, EthKey};

fn rlp_bytes(b: &[u8], out: &mut Vec<u8>) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        rlp_len(b.len(), 0x80, out);
        out.extend_from_slice(b);
    }
}

fn rlp_len(len: usize, base: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(base + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|&&x| x == 0).count();
        out.push(base + 55 + (8 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

fn rlp_uint(v: u128, out: &mut Vec<u8>) {
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|&&x| x == 0).count();
    rlp_bytes(&be[skip..], out);
}

fn rlp_list(items: &[u8], out: &mut Vec<u8>) {
    rlp_len(items.len(), 0xc0, out);
    out.extend_from_slice(items);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

impl Tx1559 {
    fn fields(&self, out: &mut Vec<u8>) {
        rlp_uint(self.chain_id as u128, out);
        rlp_uint(self.nonce as u128, out);
        rlp_uint(self.max_priority_fee_per_gas, out);
        rlp_uint(self.max_fee_per_gas, out);
        rlp_uint(self.gas_limit as u128, out);
        rlp_bytes(&self.to, out);
        rlp_uint(self.value, out);
        rlp_bytes(&self.data, out);
        rlp_list(&[], out); // empty access list
    }

    /// keccak256(0x02 || rlp(fields)): what the wallet signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut f = Vec::new();
        self.fields(&mut f);
        let mut body = vec![0x02];
        rlp_list(&f, &mut body);
        keccak256(&body)
    }

    /// Signed raw transaction (0x02 || rlp(fields, yParity, r, s)) and its hash.
    pub fn sign(&self, key: &EthKey) -> Result<(Vec<u8>, [u8; 32]), String> {
        let sig = key
            .sign_digest(&self.signing_hash())
            .map_err(|e| e.to_string())?;
        let sig = hex::decode(sig.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        if sig.len() != 65 {
            return Err("signature length".into());
        }
        let y = sig[64].checked_sub(27).ok_or("recovery id")?;
        let mut f = Vec::new();
        self.fields(&mut f);
        rlp_uint(y as u128, &mut f);
        let strip = |b: &[u8]| {
            let skip = b.iter().take_while(|&&x| x == 0).count();
            b[skip..].to_vec()
        };
        rlp_bytes(&strip(&sig[..32]), &mut f);
        rlp_bytes(&strip(&sig[32..64]), &mut f);
        let mut raw = vec![0x02];
        rlp_list(&f, &mut raw);
        let hash = keccak256(&raw);
        Ok((raw, hash))
    }
}

pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let b = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "address length".to_string())
}

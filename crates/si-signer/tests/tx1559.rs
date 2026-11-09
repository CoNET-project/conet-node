//! Type-2 transaction encoding and signing vs ethers 6 (conformance/vectors/tx1559.json).
use serde_json::Value;
use si_crypto::eth::EthKey;
use si_signer::tx1559::*;

#[test]
fn signed_raw_matches_ethers_byte_for_byte() {
    let p = format!(
        "{}/../../conformance/vectors/tx1559.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let key = EthKey::from_hex(&format!("0x{}", "22".repeat(32))).unwrap();
    let n = |c: &Value, k: &str| c[k].as_str().unwrap().parse::<u128>().unwrap();
    for c in v.as_array().unwrap() {
        let tx = Tx1559 {
            chain_id: n(c, "chainId") as u64,
            nonce: n(c, "nonce") as u64,
            max_priority_fee_per_gas: n(c, "maxPriorityFeePerGas"),
            max_fee_per_gas: n(c, "maxFeePerGas"),
            gas_limit: n(c, "gasLimit") as u64,
            to: parse_address(c["to"].as_str().unwrap()).unwrap(),
            value: n(c, "value"),
            data: hex::decode(c["data"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
        };
        let (raw, hash) = tx.sign(&key).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(&raw)),
            c["raw"].as_str().unwrap()
        );
        assert_eq!(
            format!("0x{}", hex::encode(hash)),
            c["hash"].as_str().unwrap()
        );
        assert_eq!(
            key.address().to_lowercase(),
            c["from"].as_str().unwrap().to_lowercase()
        );
    }
}

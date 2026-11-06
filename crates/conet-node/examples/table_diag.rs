//! Read-only: why do some node rows fail the key-ID check? Prints categories and counts only.
use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::chain::{GuardianV6, NodeSource, Rpc, GUARDIAN_NODES_INFO_V6};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyDetails;
use std::collections::BTreeMap;

sol! {
    struct nodeInfo { uint256 id; string PGP; string PGPKey; string ip_addr; string regionName; }
    function getAllNodes(uint256 start, uint256 length) external view returns (nodeInfo[] memory allNodes);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc = Rpc::new(&std::env::args().nth(1).ok_or("rpc url")?)?;
    let (_, block) = GuardianV6::new(rpc.clone()).version().await?;
    let mut cats: BTreeMap<String, usize> = BTreeMap::new();
    let mut start = 0u64;
    loop {
        let raw = rpc
            .eth_call(
                GUARDIAN_NODES_INFO_V6,
                getAllNodesCall {
                    start: U256::from(start),
                    length: U256::from(100),
                }
                .abi_encode(),
                Some(block),
            )
            .await?;
        let rows = getAllNodesCall::abi_decode_returns(&raw)?;
        if rows.is_empty() {
            break;
        }
        start += rows.len() as u64;
        for r in rows {
            let cat = (|| {
                let t = r.PGP.trim();
                let Ok(bytes) = B64.decode(t) else {
                    let ws = t.chars().any(|c| c.is_whitespace());
                    let urlsafe = t.contains('-') || t.contains('_');
                    let armor = t.starts_with("-----BEGIN");
                    let bad: std::collections::BTreeSet<char> = t
                        .chars()
                        .filter(|c| !(c.is_ascii_alphanumeric() || "+/=".contains(*c)))
                        .collect();
                    let stripped: String = t
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || "+/".contains(*c))
                        .collect();
                    let lenient = base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(stripped.trim_end_matches('='))
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .map(|x| SignedPublicKey::from_string(&x).is_ok());
                    return format!("base64_fail len={} mod4={} ws={ws} urlsafe={urlsafe} armor={armor} badchars={:?} lenient_parse={:?}", t.len(), t.len() % 4, bad, lenient);
                };
                let Ok(text) = String::from_utf8(bytes) else {
                    return "utf8_fail".into();
                };
                let (cert, _) = match SignedPublicKey::from_string(&text) {
                    Ok(c) => c,
                    Err(e) => {
                        return format!(
                            "parse_fail:{}",
                            e.to_string().chars().take(60).collect::<String>()
                        )
                    }
                };
                let ids: Vec<String> =
                    std::iter::once(hex::encode_upper(cert.primary_key.legacy_key_id().as_ref()))
                        .chain(
                            cert.public_subkeys
                                .iter()
                                .map(|s| hex::encode_upper(s.legacy_key_id().as_ref())),
                        )
                        .collect();
                let bind = cert.verify_bindings().is_ok();
                let decl = r.PGPKey.trim().to_uppercase();
                let pos = ids.iter().position(|i| *i == decl);
                format!(
                    "bindings_ok={bind} subkeys={} declared_at={:?} declared_len={}",
                    cert.public_subkeys.len(),
                    pos,
                    decl.len()
                )
            })();
            *cats.entry(cat).or_default() += 1;
        }
    }
    for (k, v) in cats {
        println!("{v:4}  {k}");
    }
    Ok(())
}

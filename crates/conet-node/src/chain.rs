//! Chain reads behind replaceable interfaces.
//!
//! - [`NodeSource`]: the node table. First implementation reads GuardianNodesInfoV6 (change
//!   detection by storage root, like SI's watcher); NodeRegistryV2 will add a `tableVersion`
//!   source with the same interface.
//! - [`UserRoutes`]: user key ↔ wallet ↔ mailbox node (AddressPGP today).
//!
//! Calls never set `from`, so the RPC does not learn which wallet asks (privacy audit gap 1).
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};
use base64::Engine;
use serde_json::{json, Value};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub struct ChainError(pub String);

impl std::error::Error for ChainError {}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chain: {}", self.0)
    }
}

fn ce<E: std::fmt::Display>(e: E) -> ChainError {
    ChainError(e.to_string())
}

sol! {
    struct nodeInfo { uint256 id; string PGP; string PGPKey; string ip_addr; string regionName; }
    function getAllNodes(uint256 start, uint256 length) external view returns (nodeInfo[] memory allNodes);
    function getRouteKeyIDByUserPgpKeyID(string userPgpKeyID) external view returns (string);
    function getUserByPgpKeyID(string userPgpKeyID) external view returns (address);
    function searchKey(address to) external view returns (string, string, string, string, bool);
    function nodeWallet2KeyHash(address node) external view returns (bytes32);
    function nodeKeyExists(bytes32 h) external view returns (bool);
    function userRouteHash(address user) external view returns (bytes32);
}

/// GuardianNodesInfoV6 on CoNET mainnet (explorer-verified, not a proxy).
pub const GUARDIAN_NODES_INFO_V6: &str = "0xBC6b53065b5647261396d002bDBA0d3396E0722f";
/// AddressPGP (live, not upgradeable).
pub const ADDRESS_PGP: &str = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2";
pub const CONET_CHAIN_ID: u64 = 224_422;

/// Minimal JSON-RPC client.
#[derive(Clone)]
pub struct Rpc {
    url: String,
    http: reqwest::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Result<Self, ChainError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(ce)?;
        Ok(Self {
            url: url.to_string(),
            http,
        })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let v: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(ce)?
            .json()
            .await
            .map_err(ce)?;
        if let Some(e) = v.get("error") {
            return Err(ChainError(e.to_string()));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| ChainError("no result".into()))
    }

    pub async fn block_number(&self) -> Result<u64, ChainError> {
        let v = self.call("eth_blockNumber", json!([])).await?;
        u64::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).map_err(ce)
    }

    /// `eth_call` without `from`. `block` = None means latest.
    pub async fn eth_call(
        &self,
        to: &str,
        data: Vec<u8>,
        block: Option<u64>,
    ) -> Result<Vec<u8>, ChainError> {
        let tag = block
            .map(|b| format!("0x{b:x}"))
            .unwrap_or_else(|| "latest".into());
        let v = self
            .call(
                "eth_call",
                json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }, tag]),
            )
            .await?;
        hex::decode(v.as_str().unwrap_or("0x").trim_start_matches("0x")).map_err(ce)
    }

    /// Contract storage root at a block (any write changes it).
    pub async fn storage_root(&self, addr: &str, block: u64) -> Result<String, ChainError> {
        let v = self
            .call("eth_getProof", json!([addr, [], format!("0x{block:x}")]))
            .await?;
        v.get("storageHash")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ChainError("no storageHash".into()))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainNode {
    pub id: u64,
    pub key_id: String,
    pub ip: String,
    pub pgp_armored: String,
}

#[derive(Debug, Clone)]
pub struct TableSnapshot {
    /// Opaque version: storage root (V6) or tableVersion (V2).
    pub version: String,
    pub block: u64,
    pub nodes: Vec<ChainNode>,
    /// Rows dropped because the declared key ID does not match the key (K-A local check).
    pub rejected: usize,
}

pub trait NodeSource: Send + Sync {
    /// Cheap check: has the table changed? Returns (version, block).
    fn version(&self) -> BoxFut<'_, Result<(String, u64), ChainError>>;
    /// Full read pinned to `block`; must fail rather than return a partial table.
    fn read(&self, block: u64) -> BoxFut<'_, Result<TableSnapshot, ChainError>>;
}

pub struct GuardianV6 {
    pub rpc: Rpc,
    pub address: String,
    pub page: u64,
    pub confirmations: u64,
}

impl GuardianV6 {
    pub fn new(rpc: Rpc) -> Self {
        Self {
            rpc,
            address: GUARDIAN_NODES_INFO_V6.into(),
            page: 100,
            confirmations: 2,
        }
    }
}

/// Node `Buffer.from(s, 'base64')`: skips characters outside the alphabet, accepts the
/// URL-safe alphabet and missing padding, and drops a trailing incomplete 6-bit group.
/// 17 of 472 live rows store unpadded base64, so strict decoding would drop them.
pub fn node_base64_decode(s: &str) -> Vec<u8> {
    let mut clean: String = s
        .chars()
        .filter_map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => Some(c),
            '-' => Some('+'),
            '_' => Some('/'),
            _ => None,
        })
        .collect();
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(clean)
        .unwrap_or_default()
}

/// Decode one chain row. The armored key is base64 on chain. Rows whose declared key ID is
/// not the key's first subkey (`getKeyIDs()[1]`) are rejected.
pub fn check_row(id: u64, pgp_b64: &str, declared: &str, ip: &str) -> Option<ChainNode> {
    let ip = ip.trim();
    if ip.is_empty() {
        return None;
    }
    let armored = String::from_utf8(node_base64_decode(pgp_b64)).ok()?;
    let cert = si_crypto::opgp::PublicCert::from_armor(&armored).ok()?;
    let key_id = cert.enc_key_id()?;
    if !key_id.eq_ignore_ascii_case(declared.trim()) {
        return None;
    }
    Some(ChainNode {
        id,
        key_id,
        ip: ip.to_string(),
        pgp_armored: armored,
    })
}

impl NodeSource for GuardianV6 {
    fn version(&self) -> BoxFut<'_, Result<(String, u64), ChainError>> {
        Box::pin(async move {
            let head = self.rpc.block_number().await?;
            let block = head.saturating_sub(self.confirmations);
            Ok((self.rpc.storage_root(&self.address, block).await?, block))
        })
    }

    fn read(&self, block: u64) -> BoxFut<'_, Result<TableSnapshot, ChainError>> {
        Box::pin(async move {
            let version = self.rpc.storage_root(&self.address, block).await?;
            let mut nodes = vec![];
            let mut seen = std::collections::HashSet::new();
            let mut rejected = 0;
            let mut start = 0u64;
            for _ in 0..1000 {
                let data = getAllNodesCall {
                    start: U256::from(start),
                    length: U256::from(self.page),
                }
                .abi_encode();
                let raw = self.rpc.eth_call(&self.address, data, Some(block)).await?;
                let rows = getAllNodesCall::abi_decode_returns(&raw).map_err(ce)?;
                if rows.is_empty() {
                    // Pinned to one block: the root must not have moved under us.
                    return Ok(TableSnapshot {
                        version,
                        block,
                        nodes,
                        rejected,
                    });
                }
                start += rows.len() as u64;
                for r in rows {
                    let id: u64 = r.id.try_into().unwrap_or(u64::MAX);
                    if !seen.insert(r.ip_addr.trim().to_ascii_lowercase()) {
                        continue;
                    }
                    match check_row(id, &r.PGP, &r.PGPKey, &r.ip_addr) {
                        Some(n) => nodes.push(n),
                        None => rejected += 1,
                    }
                }
            }
            Err(ChainError(
                "getAllNodes did not end after 1000 pages".into(),
            ))
        })
    }
}

pub trait UserRoutes: Send + Sync {
    /// User PGP key ID → mailbox node route key ID.
    fn route_of_user_key<'a>(
        &'a self,
        user_key: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>>;
    /// Wallet → its user PGP key ID (AddressPGP `searchKey`).
    fn user_key_of_wallet<'a>(
        &'a self,
        wallet: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>>;
    /// User PGP key ID → wallet (lowercase).
    fn wallet_of_user_key<'a>(
        &'a self,
        user_key: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>>;
    /// Is `user`'s mailbox on the node with wallet `node`? (SI `isMyRoute`).
    fn is_my_route<'a>(
        &'a self,
        user: &'a str,
        node: &'a str,
    ) -> BoxFut<'a, Result<bool, ChainError>>;
}

pub struct AddressPgp {
    pub rpc: Rpc,
    pub address: String,
}

impl AddressPgp {
    pub fn new(rpc: Rpc) -> Self {
        Self {
            rpc,
            address: ADDRESS_PGP.into(),
        }
    }
    async fn call<C: SolCall>(&self, c: C) -> Result<C::Return, ChainError> {
        let raw = self
            .rpc
            .eth_call(&self.address, c.abi_encode(), None)
            .await?;
        C::abi_decode_returns(&raw).map_err(ce)
    }
}

fn addr(s: &str) -> Result<Address, ChainError> {
    s.parse::<Address>().map_err(ce)
}

impl UserRoutes for AddressPgp {
    fn route_of_user_key<'a>(
        &'a self,
        user_key: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            // AddressPGP reverts for an unknown key instead of returning "".
            match self
                .call(getRouteKeyIDByUserPgpKeyIDCall {
                    userPgpKeyID: user_key.to_string(),
                })
                .await
            {
                Ok(r) => Ok(Some(r.to_uppercase()).filter(|s| !s.is_empty())),
                Err(e) if e.0.contains("execution reverted") => Ok(None),
                Err(e) => Err(e),
            }
        })
    }
    fn user_key_of_wallet<'a>(
        &'a self,
        wallet: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            let r = self.call(searchKeyCall { to: addr(wallet)? }).await?;
            Ok(Some(r._0.to_uppercase()).filter(|s| !s.is_empty()))
        })
    }
    fn wallet_of_user_key<'a>(
        &'a self,
        user_key: &'a str,
    ) -> BoxFut<'a, Result<Option<String>, ChainError>> {
        Box::pin(async move {
            let a = self
                .call(getUserByPgpKeyIDCall {
                    userPgpKeyID: user_key.to_string(),
                })
                .await?;
            Ok(Some(a)
                .filter(|a| *a != Address::ZERO)
                .map(|a| format!("{a:#x}")))
        })
    }
    fn is_my_route<'a>(
        &'a self,
        user: &'a str,
        node: &'a str,
    ) -> BoxFut<'a, Result<bool, ChainError>> {
        Box::pin(async move {
            let nh: FixedBytes<32> = self
                .call(nodeWallet2KeyHashCall { node: addr(node)? })
                .await?;
            if nh == FixedBytes::ZERO || !self.call(nodeKeyExistsCall { h: nh }).await? {
                return Ok(false);
            }
            let uh: FixedBytes<32> = self.call(userRouteHashCall { user: addr(user)? }).await?;
            Ok(uh != FixedBytes::ZERO && uh == nh)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_compatible_base64() {
        assert_eq!(node_base64_decode("aGVsbG8="), b"hello");
        assert_eq!(node_base64_decode("aGVsbG8"), b"hello");
        assert_eq!(node_base64_decode("aGVs\nbG8"), b"hello");
        assert_eq!(node_base64_decode("aGVsbG8hZ"), b"hello!");
        assert_eq!(node_base64_decode("_-8"), vec![0xff, 0xef]);
    }
}

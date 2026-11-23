//! Chain reads behind replaceable interfaces.
//!
//! - [`NodeSource`]: the node table. First implementation reads GuardianNodesInfoV6 (change
//!   detection by storage root, like SI's watcher); NodeRegistryV2 is [`crate::nr2::Nr2Source`].
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
/// Default TCP forwarding port when a node registry row specifies port zero.
pub const DEFAULT_NODE_FORWARD_PORT: u16 = 80;

/// Minimal JSON-RPC client.
#[derive(Clone)]
pub struct Rpc {
    url: String,
    http: reqwest::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Result<Self, ChainError> {
        // Redirects are never followed: a 3xx would send the read to a host the operator did not
        // configure. A non-2xx answer is an error, never read as a result.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(ce)?;
        Ok(Self {
            url: url.to_string(),
            http,
        })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(ce)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(ce)?;
        if !status.is_success() {
            // A JSON-RPC error object keeps its message (revert data is read from it), the same as
            // on a 200. Any other non-2xx body is not echoed: only the HTTP code is reported.
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                if let Some(response) = v.as_object() {
                    if response.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                        && response.get("id").and_then(Value::as_i64) == Some(1)
                        && !response.contains_key("result")
                    {
                        if let Some(e) = response.get("error") {
                            if valid_rpc_error(e) {
                                return Err(ChainError(e.to_string()));
                            }
                        }
                    }
                }
            }
            return Err(ChainError(format!("rpc HTTP {}", status.as_u16())));
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(ce)?;
        let response = v
            .as_object()
            .ok_or_else(|| ChainError("JSON-RPC response is not an object".into()))?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(ChainError(
                "JSON-RPC response has invalid jsonrpc version".into(),
            ));
        }
        if response.get("id").and_then(Value::as_i64) != Some(1) {
            return Err(ChainError(
                "JSON-RPC response id does not match request".into(),
            ));
        }
        match (response.get("result"), response.get("error")) {
            (Some(result), None) => Ok(result.clone()),
            (None, Some(error)) => {
                if !valid_rpc_error(error) {
                    return Err(ChainError("JSON-RPC error has invalid shape".into()));
                }
                Err(ChainError(error.to_string()))
            }
            (Some(_), Some(_)) => Err(ChainError(
                "JSON-RPC response contains both result and error".into(),
            )),
            (None, None) => Err(ChainError(
                "JSON-RPC response has neither result nor error".into(),
            )),
        }
    }

    pub async fn block_number(&self) -> Result<u64, ChainError> {
        let v = self.call("eth_blockNumber", json!([])).await?;
        checked_u64(
            parse_rpc_quantity(&v, "eth_blockNumber")?,
            "eth_blockNumber",
        )
    }

    /// The configured RPC endpoint's chain identity. Callers that use chain-specific contract
    /// addresses must compare this value with their expected chain before making those calls.
    pub async fn chain_id(&self) -> Result<u64, ChainError> {
        let v = self.call("eth_chainId", json!([])).await?;
        checked_u64(parse_rpc_quantity(&v, "eth_chainId")?, "eth_chainId")
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
        parse_rpc_data(&v, "eth_call")
    }

    /// Contract storage root at a block (any write changes it).
    pub async fn storage_root(&self, addr: &str, block: u64) -> Result<String, ChainError> {
        let v = self
            .call("eth_getProof", json!([addr, [], format!("0x{block:x}")]))
            .await?;
        let hash = v
            .get("storageHash")
            .ok_or_else(|| ChainError("no storageHash".into()))?;
        let bytes = parse_rpc_data(hash, "eth_getProof.storageHash")?;
        if bytes.len() != 32 {
            return Err(ChainError(
                "eth_getProof.storageHash is not 32 bytes".into(),
            ));
        }
        Ok(format!("0x{}", hex::encode(bytes)))
    }
}

fn valid_rpc_error(error: &Value) -> bool {
    error.as_object().is_some_and(|e| {
        e.get("code").and_then(Value::as_i64).is_some()
            && e.get("message").and_then(Value::as_str).is_some()
    })
}

/// Decode an Ethereum JSON-RPC Quantity. Missing, non-string, unprefixed, empty, non-hex, and
/// non-canonical leading-zero values are errors; a valid `0x0` remains a real zero.
pub(crate) fn parse_rpc_quantity(v: &Value, method: &str) -> Result<U256, ChainError> {
    let s = v
        .as_str()
        .ok_or_else(|| ChainError(format!("{method} result is not a hex quantity string")))?;
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| ChainError(format!("{method} result is not 0x-prefixed")))?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ChainError(format!(
            "{method} result is not a canonical hex quantity"
        )));
    }
    U256::from_str_radix(digits, 16).map_err(ce)
}

pub(crate) fn checked_u64(value: U256, field: &str) -> Result<u64, ChainError> {
    u64::try_from(value).map_err(|_| ChainError(format!("{field} exceeds u64")))
}

/// Decode Ethereum JSON-RPC DATA. `0x` is a valid empty byte string (for example, no contract
/// code); a missing or non-string result is an error and must not be treated as empty data.
pub(crate) fn parse_rpc_data(v: &Value, method: &str) -> Result<Vec<u8>, ChainError> {
    let s = v
        .as_str()
        .ok_or_else(|| ChainError(format!("{method} result is not a hex data string")))?;
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| ChainError(format!("{method} result is not 0x-prefixed")))?;
    hex::decode(digits).map_err(ce)
}

// AddressPGP.sol::getRouteKeyIDByUserPgpKeyID uses `require(user != address(0), "user not found")`.
// Only its exact ABI Error(string) data proves a missing user; provider prose is not evidence.
const ADDRESS_PGP_UNKNOWN_USER_REVERT_DATA: &str = "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e75736572206e6f7420666f756e64000000000000000000000000000000000000";

fn address_pgp_unknown_user_revert(error: &ChainError) -> bool {
    serde_json::from_str::<Value>(&error.0)
        .ok()
        .and_then(|value| value.get("data").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|data| data.eq_ignore_ascii_case(ADDRESS_PGP_UNKNOWN_USER_REVERT_DATA))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainNode {
    pub id: u64,
    pub key_id: String,
    pub ip: String,
    pub pgp_armored: String,
    /// Forward port (NodeRegistryV2 `tcpPort`); None = the watcher's default (V6 rows).
    pub port: Option<u16>,
    /// Service bits (V2); V6 rows carry none.
    pub services: u16,
    /// May hold mailboxes. V6 has no service bits, so every V6 node may.
    pub mailbox: bool,
    pub wallet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TableSnapshot {
    /// Opaque version: storage root (V6) or tableVersion (V2).
    pub version: String,
    pub block: u64,
    pub nodes: Vec<ChainNode>,
    /// Rows dropped because the declared key ID does not match the key (K-A local check).
    pub rejected: usize,
    /// The source lists every active node with its mailbox bit (NodeRegistryV2): a node missing
    /// from it may not hold mailboxes now.
    pub lists_all_active: bool,
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
        port: None,
        services: 0,
        mailbox: true,
        wallet: None,
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
                        lists_all_active: false,
                    });
                }
                start += rows.len() as u64;
                for r in rows {
                    let id = checked_u64(r.id, "GuardianNodesInfoV6 node id")?;
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
    /// User PGP key ID → all mailbox slots (primary and secondary). AddressPGP has one slot;
    /// AddressPGPV2 `getRoutes` (not final yet) will override this.
    fn routes_of_user_key<'a>(
        &'a self,
        user_key: &'a str,
    ) -> BoxFut<'a, Result<Option<crate::route::UserRoute>, ChainError>> {
        Box::pin(async move {
            Ok(self
                .route_of_user_key(user_key)
                .await?
                .map(|n| crate::route::UserRoute::single(&n)))
        })
    }
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
                Err(e) if address_pgp_unknown_user_revert(&e) => Ok(None),
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
    fn rpc_quantity_requires_a_typed_canonical_value_and_preserves_zero() {
        assert_eq!(
            parse_rpc_quantity(&json!("0x0"), "eth_blockNumber").unwrap(),
            U256::ZERO
        );
        assert_eq!(
            parse_rpc_quantity(&json!("0x2a"), "eth_blockNumber").unwrap(),
            U256::from(42)
        );
        for malformed in [
            json!(null),
            json!(false),
            json!(0),
            json!({}),
            json!([]),
            json!("0x"),
            json!("2a"),
            json!("0x00"),
            json!("0xgg"),
        ] {
            assert!(
                parse_rpc_quantity(&malformed, "eth_blockNumber").is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn u64_conversion_keeps_zero_and_rejects_overflow() {
        assert_eq!(checked_u64(U256::ZERO, "id").unwrap(), 0);
        assert_eq!(checked_u64(U256::from(u64::MAX), "id").unwrap(), u64::MAX);
        assert!(checked_u64(U256::from(u64::MAX) + U256::from(1), "id").is_err());
    }

    #[test]
    fn rpc_data_distinguishes_empty_data_from_malformed_results() {
        assert_eq!(
            parse_rpc_data(&json!("0x"), "eth_call").unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            parse_rpc_data(&json!("0x6080"), "eth_getCode").unwrap(),
            vec![0x60, 0x80]
        );
        for malformed in [
            json!(null),
            json!(false),
            json!(0),
            json!({}),
            json!([]),
            json!("6080"),
            json!("0x0g"),
        ] {
            assert!(
                parse_rpc_data(&malformed, "eth_call").is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn node_compatible_base64() {
        assert_eq!(node_base64_decode("aGVsbG8="), b"hello");
        assert_eq!(node_base64_decode("aGVsbG8"), b"hello");
        assert_eq!(node_base64_decode("aGVs\nbG8"), b"hello");
        assert_eq!(node_base64_decode("aGVsbG8hZ"), b"hello!");
        assert_eq!(node_base64_decode("_-8"), vec![0xff, 0xef]);
    }
}

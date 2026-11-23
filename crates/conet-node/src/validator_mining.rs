//! SignedCommand implementation of CoNET-SI `mining_validator` validation.
//!
//! Domain wallet identity is supplied by the already refreshed node table. NR2 provides that
//! mapping on-chain; Guardian V6/static tables explicitly have no wallet field and therefore
//! cannot authorize this command. Current epoch is fetched by the dispatcher from the configured
//! CoNET RPC before calling this pure validation layer.
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainWallet {
    Known(String),
    NoRecord,
    UnknownDomain,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Accept {
    User { wallet: String, data: Value },
    Miner { wallet: String, data: Value },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refuse {
    Invalid(&'static str),
    Unavailable(&'static str),
    UnknownDomain,
}

fn epoch_string(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            return Some(s.to_owned());
        }
    }
    v.as_u64().map(|n| n.to_string())
}

/// Check the two EIP-191 signatures, authoritative domain-to-wallet mapping, and TS epoch rules.
pub fn validate(
    request_data: &Value,
    requester_wallet: &str,
    domain_wallet: DomainWallet,
    current_epoch: u64,
) -> Result<Accept, Refuse> {
    let wallet = requester_wallet.trim().to_ascii_lowercase();
    if !si_crypto::eth::is_address(&wallet) {
        return Err(Refuse::Invalid("walletAddress"));
    }
    let epoch = epoch_string(&request_data["epoch"]).ok_or(Refuse::Invalid("epoch"))?;
    let node_wallet = request_data["nodeWallet"]
        .as_str()
        .map(str::trim)
        .filter(|s| si_crypto::eth::is_address(s))
        .ok_or(Refuse::Invalid("nodeWallet"))?
        .to_ascii_lowercase();
    let _node_domain = request_data["nodeDomain"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(Refuse::Invalid("nodeDomain"))?;
    let hash = request_data["hash"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(Refuse::Invalid("hash"))?;
    let response_hash = request_data["minerResponseHash"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(Refuse::Invalid("minerResponseHash"))?;

    let message =
        crate::epoch::validator_message(&epoch, &wallet).map_err(|_| Refuse::Invalid("hash"))?;
    let signer = si_crypto::eth::recover_message(&message, hash)
        .map_err(|_| Refuse::Invalid("hash"))?
        .to_ascii_lowercase();
    if signer != node_wallet {
        return Err(Refuse::Invalid("node_signature"));
    }
    match domain_wallet {
        DomainWallet::Known(authoritative) => {
            if !si_crypto::eth::is_address(&authoritative)
                || authoritative.to_ascii_lowercase() != node_wallet
            {
                return Err(Refuse::Invalid("domain_wallet_mismatch"));
            }
        }
        DomainWallet::NoRecord => return Err(Refuse::Unavailable("domain_wallet_unavailable")),
        DomainWallet::UnknownDomain => return Err(Refuse::UnknownDomain),
    }

    let response_signer = si_crypto::eth::recover_message(hash, response_hash)
        .map_err(|_| Refuse::Invalid("minerResponseHash"))?
        .to_ascii_lowercase();
    if response_signer != wallet {
        return Err(Refuse::Invalid("response_signature"));
    }

    let epoch_number = epoch.parse::<u64>().map_err(|_| Refuse::Invalid("epoch"))?;
    if current_epoch.saturating_sub(epoch_number) > 5 {
        return Err(Refuse::Invalid("stale_epoch"));
    }
    let is_user = request_data["isUser"].as_bool().unwrap_or(false);
    if !is_user && epoch_number < current_epoch {
        return Err(Refuse::Invalid("old_miner_epoch"));
    }

    Ok(if is_user {
        Accept::User {
            wallet,
            data: request_data.clone(),
        }
    } else {
        Accept::Miner {
            wallet,
            data: request_data.clone(),
        }
    })
}

#[derive(Default)]
pub struct Pools {
    users: std::sync::Mutex<HashMap<String, Instant>>,
    miners: std::sync::Mutex<HashSet<String>>,
}

impl Pools {
    pub fn record(&self, accepted: &Accept, now: Instant) {
        match accepted {
            Accept::User { wallet, .. } => {
                self.users
                    .lock()
                    .expect("validator user pool")
                    .insert(wallet.clone(), now);
            }
            Accept::Miner { wallet, .. } => {
                self.miners
                    .lock()
                    .expect("validator miner pool")
                    .insert(wallet.clone());
            }
        }
    }

    pub fn user_active(&self, wallet: &str, now: Instant) -> bool {
        let mut users = self.users.lock().expect("validator user pool");
        users.retain(|_, seen| now.duration_since(*seen) < std::time::Duration::from_secs(300));
        users.contains_key(&wallet.to_ascii_lowercase())
    }

    pub fn miner_active(&self, wallet: &str) -> bool {
        self.miners
            .lock()
            .expect("validator miner pool")
            .contains(&wallet.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use si_crypto::eth::EthKey;

    fn key(byte: u8) -> EthKey {
        let mut raw = [0u8; 32];
        raw[31] = byte;
        EthKey::from_hex(&format!("0x{}", hex::encode(raw))).unwrap()
    }

    fn data(epoch: &str, is_user: bool, node: &EthKey, requester: &EthKey) -> Value {
        let message = crate::epoch::validator_message(epoch, &requester.address()).unwrap();
        let hash = node.sign_message(&message).unwrap();
        let response_hash = requester.sign_message(&hash).unwrap();
        serde_json::json!({
            "status": 200,
            "epoch": epoch,
            "hash": hash,
            "nodeWallet": node.address(),
            "minerResponseHash": response_hash,
            "nodeDomain": "A1B2C3D4",
            "isUser": is_user,
        })
    }

    #[test]
    fn signed_validator_request_checks_both_signatures_mapping_and_epoch() {
        let node = key(1);
        let requester = key(2);
        let valid_data = data("10", false, &node, &requester);
        let accepted = validate(
            &valid_data,
            &requester.address(),
            DomainWallet::Known(node.address()),
            10,
        )
        .unwrap();
        assert!(matches!(accepted, Accept::Miner { .. }));

        assert_eq!(
            validate(
                &valid_data,
                &requester.address(),
                DomainWallet::NoRecord,
                10
            ),
            Err(Refuse::Unavailable("domain_wallet_unavailable"))
        );
        assert_eq!(
            validate(
                &valid_data,
                &requester.address(),
                DomainWallet::UnknownDomain,
                10
            ),
            Err(Refuse::UnknownDomain)
        );
        assert!(matches!(
            validate(
                &valid_data,
                &requester.address(),
                DomainWallet::Known(key(3).address()),
                10
            ),
            Err(Refuse::Invalid("domain_wallet_mismatch"))
        ));

        let stale = data("4", false, &node, &requester);
        assert!(matches!(
            validate(
                &stale,
                &requester.address(),
                DomainWallet::Known(node.address()),
                10
            ),
            Err(Refuse::Invalid("stale_epoch"))
        ));
    }

    #[test]
    fn user_and_miner_pools_match_ts_lifetime_and_eligibility() {
        let node = key(1);
        let requester = key(2);
        let user = data("5", true, &node, &requester);
        let accepted_user = validate(
            &user,
            &requester.address(),
            DomainWallet::Known(node.address()),
            10,
        )
        .unwrap();
        let pools = Pools::default();
        let now = Instant::now();
        pools.record(&accepted_user, now);
        assert!(pools.user_active(&requester.address(), now));
        assert!(!pools.user_active(
            &requester.address(),
            now + std::time::Duration::from_secs(301)
        ));

        let miner = data("10", false, &node, &requester);
        let accepted_miner = validate(
            &miner,
            &requester.address(),
            DomainWallet::Known(node.address()),
            10,
        )
        .unwrap();
        pools.record(&accepted_miner, now);
        assert!(pools.miner_active(&requester.address()));

        let explicit_zero = data("0", false, &node, &requester);
        assert!(matches!(
            validate(
                &explicit_zero,
                &requester.address(),
                DomainWallet::Known(node.address()),
                0
            ),
            Ok(Accept::Miner { .. })
        ));
    }
}

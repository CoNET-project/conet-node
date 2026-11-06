//! Route table: key ID → this node, another node, or nothing.
//!
//! Two kinds of key ID arrive in `/post`: a node's route key (onion layers, commands) and a
//! user's PGP key (mailbox delivery, resolved through AddressPGP to a node route key).
//! Sources (GuardianNodesInfoV6 / NodeRegistryV2, AddressPGP) fill the table; user routes
//! expire (SI's `clientRoute` cache never did, issue S6).
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    Local,
    Remote(SocketAddr),
    NoRoute,
}

pub struct RouteTable {
    own_key: String,
    nodes: RwLock<HashMap<String, SocketAddr>>,
    users: RwLock<HashMap<String, (String, Instant)>>,
    user_ttl: Duration,
    /// Keys AddressPGP did not know, so one stranger cannot make us hit the RPC per request.
    unknown: RwLock<HashMap<String, Instant>>,
}

/// Static table, for local test networks (`--routes routes.json`).
#[derive(Debug, Deserialize)]
pub struct StaticRoutes {
    pub nodes: Vec<StaticNode>,
    #[serde(default)]
    pub users: Vec<StaticUser>,
}
#[derive(Debug, Deserialize)]
pub struct StaticNode {
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub addr: SocketAddr,
}
#[derive(Debug, Deserialize)]
pub struct StaticUser {
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// Route key ID of the user's mailbox node.
    pub node: String,
}

impl RouteTable {
    pub fn new(own_key: &str, user_ttl: Duration) -> Self {
        Self {
            own_key: own_key.to_uppercase(),
            nodes: RwLock::default(),
            users: RwLock::default(),
            user_ttl,
            unknown: RwLock::default(),
        }
    }

    pub fn from_static(own_key: &str, s: &StaticRoutes) -> Self {
        let t = Self::new(own_key, Duration::from_secs(365 * 24 * 3600));
        t.replace_nodes(s.nodes.iter().map(|n| (n.key_id.clone(), n.addr)));
        for u in &s.users {
            t.set_user_route(&u.key_id, &u.node);
        }
        t
    }

    /// Replace the whole node table at once (a partial read must never get here).
    pub fn replace_nodes(&self, nodes: impl IntoIterator<Item = (String, SocketAddr)>) {
        let map = nodes
            .into_iter()
            .map(|(k, a)| (k.to_uppercase(), a))
            .collect();
        *self.nodes.write().expect("route lock") = map;
    }

    pub fn set_user_route(&self, user_key: &str, node_key: &str) {
        self.users.write().expect("route lock").insert(
            user_key.to_uppercase(),
            (node_key.to_uppercase(), Instant::now()),
        );
    }

    pub fn mark_unknown(&self, key: &str) {
        let mut u = self.unknown.write().expect("route lock");
        if u.len() > 100_000 {
            u.clear();
        }
        u.insert(key.to_uppercase(), Instant::now());
    }

    pub fn recently_unknown(&self, key: &str) -> bool {
        self.unknown
            .read()
            .expect("route lock")
            .get(&key.to_uppercase())
            .map(|t| t.elapsed() < Duration::from_secs(60))
            .unwrap_or(false)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.read().expect("route lock").len()
    }

    fn node(&self, node_key: &str) -> Resolved {
        if node_key == self.own_key {
            return Resolved::Local;
        }
        match self.nodes.read().expect("route lock").get(node_key) {
            Some(a) => Resolved::Remote(*a),
            None => Resolved::NoRoute,
        }
    }

    /// Resolve from cached data only. `NoRoute` for a user key may mean "not cached yet";
    /// the host then asks AddressPGP and calls [`Self::set_user_route`].
    pub fn resolve(&self, key_id: &str) -> Resolved {
        let k = key_id.to_uppercase();
        if k == self.own_key || self.nodes.read().expect("route lock").contains_key(&k) {
            return self.node(&k);
        }
        let user = self.users.read().expect("route lock").get(&k).cloned();
        match user {
            Some((node, at)) if at.elapsed() < self.user_ttl => self.node(&node),
            Some(_) => {
                self.users.write().expect("route lock").remove(&k);
                Resolved::NoRoute
            }
            None => Resolved::NoRoute,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_nodes_users_and_expiry() {
        let t = RouteTable::new("aaaa", Duration::from_millis(50));
        t.replace_nodes([("BBBB".to_string(), "127.0.0.1:9".parse().unwrap())]);
        t.set_user_route("u1", "aaaa");
        t.set_user_route("u2", "bbbb");
        assert_eq!(t.resolve("AAAA"), Resolved::Local);
        assert_eq!(
            t.resolve("bbbb"),
            Resolved::Remote("127.0.0.1:9".parse().unwrap())
        );
        assert_eq!(t.resolve("U1"), Resolved::Local);
        assert_eq!(
            t.resolve("u2"),
            Resolved::Remote("127.0.0.1:9".parse().unwrap())
        );
        assert_eq!(t.resolve("zz"), Resolved::NoRoute);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(t.resolve("u1"), Resolved::NoRoute);
    }
}

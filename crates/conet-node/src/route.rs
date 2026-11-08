//! Route table: key ID → this node, another node, or nothing.
//!
//! Two kinds of key ID arrive in `/post`: a node's route key (onion layers, commands) and a
//! user's PGP key (mailbox delivery, resolved through AddressPGP to a node route key).
//! Sources (GuardianNodesInfoV6 / NodeRegistryV2, AddressPGP) fill the table; user routes
//! expire (SI's `clientRoute` cache never did, issue S6).
//!
//! A user may name up to two primary mailboxes and one secondary (design §23). A slot is
//! chain-invalid when its node is not in the table or may not hold mailboxes (NodeRegistryV2
//! service bit 1, active); invalid slots are skipped at once (Q89). One valid primary and no
//! secondary resolves exactly as before; anything else becomes a [`DeliveryPlan`].
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    Local,
    Remote(SocketAddr),
    NoRoute,
    /// A user key with more than one mailbox slot.
    Plan(DeliveryPlan),
}

/// Primary mailboxes per user (security line H.5.1, H5-1).
pub const MAX_PRIMARY: usize = 2;

/// One mailbox slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Local,
    Remote(SocketAddr),
    /// Chain-invalid: not in the table, not active, or no mailbox bit.
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPlan {
    pub primary: Vec<Target>,
    pub secondary: Option<Target>,
}

/// A user's mailbox nodes, by node route key ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoute {
    pub primary: Vec<String>,
    pub secondary: Option<String>,
}

impl UserRoute {
    pub fn single(node: &str) -> Self {
        Self {
            primary: vec![node.to_uppercase()],
            secondary: None,
        }
    }

    /// 1..=2 primaries, at most one secondary, all distinct; keys upper-cased.
    pub fn new(primary: Vec<String>, secondary: Option<String>) -> Option<Self> {
        let primary: Vec<String> = primary.iter().map(|k| k.to_uppercase()).collect();
        let secondary = secondary.map(|k| k.to_uppercase());
        if primary.is_empty() || primary.len() > MAX_PRIMARY {
            return None;
        }
        let mut all: Vec<&String> = primary.iter().chain(secondary.iter()).collect();
        let n = all.len();
        all.sort();
        all.dedup();
        (all.len() == n).then_some(Self { primary, secondary })
    }
}

#[derive(Debug, Clone, Copy)]
struct NodeEntry {
    addr: SocketAddr,
    mailbox: bool,
}

pub struct RouteTable {
    own_key: String,
    nodes: RwLock<HashMap<String, NodeEntry>>,
    users: RwLock<HashMap<String, (UserRoute, Instant)>>,
    /// May this node hold mailboxes (false once NodeRegistryV2 says it may not).
    own_mailbox: RwLock<bool>,
    user_ttl: Duration,
    /// Keys AddressPGP did not know, so one stranger cannot make us hit the RPC per request.
    unknown: RwLock<HashMap<String, Instant>>,
    node_ips: RwLock<HashSet<IpAddr>>,
    /// Retiring own route keys (R11): resolve as local during the transition.
    own_aliases: RwLock<HashSet<String>>,
    /// Upper bound on cached user routes (R10); the oldest entry goes first.
    pub max_users: usize,
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
    /// Route key ID of the user's mailbox node (single-mailbox form).
    #[serde(default)]
    pub node: Option<String>,
    /// Dual-mailbox form.
    #[serde(default)]
    pub primary: Vec<String>,
    #[serde(default)]
    pub secondary: Option<String>,
}

impl RouteTable {
    pub fn new(own_key: &str, user_ttl: Duration) -> Self {
        Self {
            own_key: own_key.to_uppercase(),
            nodes: RwLock::default(),
            users: RwLock::default(),
            own_mailbox: RwLock::new(true),
            user_ttl,
            unknown: RwLock::default(),
            node_ips: RwLock::default(),
            own_aliases: RwLock::default(),
            max_users: 200_000,
        }
    }

    pub fn from_static(own_key: &str, s: &StaticRoutes) -> Self {
        let t = Self::new(own_key, Duration::from_secs(365 * 24 * 3600));
        t.replace_nodes(s.nodes.iter().map(|n| (n.key_id.clone(), n.addr)));
        for u in &s.users {
            let route = if u.primary.is_empty() {
                u.node.as_deref().map(UserRoute::single)
            } else {
                UserRoute::new(u.primary.clone(), u.secondary.clone())
            };
            if let Some(r) = route {
                t.set_user_routes(&u.key_id, r);
            }
        }
        t
    }

    /// Replace the whole node table at once (a partial read must never get here). Every node
    /// may hold mailboxes (V6, static tables).
    pub fn replace_nodes(&self, nodes: impl IntoIterator<Item = (String, SocketAddr)>) {
        self.replace_node_entries(nodes.into_iter().map(|(k, a)| (k, a, true)), false);
    }

    /// Replace the table with per-node mailbox flags. `own_must_be_listed`: the source lists
    /// every active node (NodeRegistryV2), so a missing own entry means this node may not hold
    /// mailboxes now.
    pub fn replace_node_entries(
        &self,
        nodes: impl IntoIterator<Item = (String, SocketAddr, bool)>,
        own_must_be_listed: bool,
    ) {
        let map: HashMap<String, NodeEntry> = nodes
            .into_iter()
            .map(|(k, addr, mailbox)| (k.to_uppercase(), NodeEntry { addr, mailbox }))
            .collect();
        let own = match map.get(&self.own_key) {
            Some(e) => e.mailbox,
            None => !own_must_be_listed,
        };
        *self.own_mailbox.write().expect("route lock") = own;
        *self.node_ips.write().expect("route lock") = map.values().map(|e| e.addr.ip()).collect();
        *self.nodes.write().expect("route lock") = map;
    }

    pub fn set_own_aliases(&self, keys: &[String]) {
        *self.own_aliases.write().expect("route lock") =
            keys.iter().map(|k| k.to_uppercase()).collect();
    }

    pub fn is_node_ip(&self, ip: IpAddr) -> bool {
        self.node_ips.read().expect("route lock").contains(&ip)
    }

    pub fn set_user_route(&self, user_key: &str, node_key: &str) {
        self.set_user_routes(user_key, UserRoute::single(node_key));
    }

    pub fn set_user_routes(&self, user_key: &str, route: UserRoute) {
        let mut users = self.users.write().expect("route lock");
        if users.len() >= self.max_users && !users.contains_key(&user_key.to_uppercase()) {
            if let Some(oldest) = users
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                users.remove(&oldest);
            }
        }
        users.insert(user_key.to_uppercase(), (route, Instant::now()));
    }

    pub fn user_count(&self) -> usize {
        self.users.read().expect("route lock").len()
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
        if self.is_own(node_key) {
            return Resolved::Local;
        }
        match self.nodes.read().expect("route lock").get(node_key) {
            Some(e) => Resolved::Remote(e.addr),
            None => Resolved::NoRoute,
        }
    }

    fn is_own(&self, node_key: &str) -> bool {
        node_key == self.own_key
            || self
                .own_aliases
                .read()
                .expect("route lock")
                .contains(node_key)
    }

    /// A mailbox slot: the node must be listed and allowed to hold mailboxes.
    fn mailbox_target(&self, node_key: &str) -> Target {
        if self.is_own(node_key) {
            return if *self.own_mailbox.read().expect("route lock") {
                Target::Local
            } else {
                Target::Invalid
            };
        }
        match self.nodes.read().expect("route lock").get(node_key) {
            Some(e) if e.mailbox => Target::Remote(e.addr),
            _ => Target::Invalid,
        }
    }

    fn plan(&self, r: &UserRoute) -> Resolved {
        let primary: Vec<Target> = r.primary.iter().map(|k| self.mailbox_target(k)).collect();
        let secondary = r.secondary.as_deref().map(|k| self.mailbox_target(k));
        if primary.len() == 1 && secondary.is_none() {
            return match primary[0] {
                Target::Local => Resolved::Local,
                Target::Remote(a) => Resolved::Remote(a),
                Target::Invalid => Resolved::NoRoute,
            };
        }
        let any_valid = primary
            .iter()
            .chain(secondary.iter())
            .any(|t| *t != Target::Invalid);
        if !any_valid {
            return Resolved::NoRoute;
        }
        Resolved::Plan(DeliveryPlan { primary, secondary })
    }

    /// Resolve from cached data only. `NoRoute` for a user key may mean "not cached yet";
    /// the host then asks AddressPGP and calls [`Self::set_user_route`].
    pub fn resolve(&self, key_id: &str) -> Resolved {
        let k = key_id.to_uppercase();
        if k == self.own_key
            || self.own_aliases.read().expect("route lock").contains(&k)
            || self.nodes.read().expect("route lock").contains_key(&k)
        {
            return self.node(&k);
        }
        let user = self.users.read().expect("route lock").get(&k).cloned();
        match user {
            Some((route, at)) if at.elapsed() < self.user_ttl => self.plan(&route),
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
        assert!(t.is_node_ip("127.0.0.1".parse().unwrap()));
        assert!(!t.is_node_ip("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn user_cache_is_bounded() {
        let mut t = RouteTable::new("aaaa", Duration::from_secs(60));
        t.max_users = 3;
        for i in 0..10 {
            t.set_user_route(&format!("u{i}"), "aaaa");
        }
        assert_eq!(t.user_count(), 3);
        assert_eq!(t.resolve("u9"), Resolved::Local, "newest kept");
        assert_eq!(t.resolve("u0"), Resolved::NoRoute, "oldest evicted");
    }

    #[test]
    fn user_route_shape() {
        let k = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(UserRoute::new(k(&["a"]), None).is_some());
        assert!(UserRoute::new(k(&["a", "b"]), Some("c".into())).is_some());
        assert!(
            UserRoute::new(k(&[]), Some("c".into())).is_none(),
            "needs a primary"
        );
        assert!(
            UserRoute::new(k(&["a", "b", "c"]), None).is_none(),
            "at most two"
        );
        assert!(UserRoute::new(k(&["a", "A"]), None).is_none(), "distinct");
        assert!(
            UserRoute::new(k(&["a"]), Some("A".into())).is_none(),
            "distinct"
        );
    }

    #[test]
    fn mailbox_slots_and_chain_invalid() {
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let t = RouteTable::new("own", Duration::from_secs(60));
        t.replace_node_entries(
            [
                ("own".to_string(), a, true),
                ("mb".to_string(), b, true),
                ("nomb".to_string(), b, false),
            ],
            true,
        );
        // One valid primary, no secondary: exactly the old behaviour.
        t.set_user_route("u1", "mb");
        assert_eq!(t.resolve("u1"), Resolved::Remote(b));
        t.set_user_route("u2", "nomb");
        assert_eq!(t.resolve("u2"), Resolved::NoRoute, "no mailbox bit");
        t.set_user_route("u3", "gone");
        assert_eq!(t.resolve("u3"), Resolved::NoRoute, "not listed");
        // Node keys still resolve for forwarding, mailbox bit or not.
        assert_eq!(t.resolve("nomb"), Resolved::Remote(b));
        // Plans keep slot order and mark invalid slots.
        let r = UserRoute::new(vec!["own".into(), "nomb".into()], Some("mb".into())).unwrap();
        t.set_user_routes("u4", r);
        assert_eq!(
            t.resolve("u4"),
            Resolved::Plan(DeliveryPlan {
                primary: vec![Target::Local, Target::Invalid],
                secondary: Some(Target::Remote(b)),
            })
        );
        let r = UserRoute::new(vec!["nomb".into(), "gone".into()], None).unwrap();
        t.set_user_routes("u5", r);
        assert_eq!(t.resolve("u5"), Resolved::NoRoute, "every slot invalid");
        // This node drops out of the V2 table: it may not hold mailboxes any more.
        t.replace_node_entries([("mb".to_string(), b, true)], true);
        t.set_user_route("u6", "own");
        assert_eq!(t.resolve("u6"), Resolved::NoRoute);
        assert_eq!(
            t.resolve("own"),
            Resolved::Local,
            "still itself for onion layers"
        );
        // A V6 or static table does not list mailbox bits: own stays allowed.
        t.replace_nodes([("mb".to_string(), b)]);
        assert_eq!(t.resolve("u6"), Resolved::Local);
    }
}

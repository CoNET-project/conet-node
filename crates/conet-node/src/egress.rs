//! Provider egress policy (Q66, design §23.6–§23.7, §23.10).
//!
//! Three layers, strictest wins:
//! 1. rules compiled into the node (exit.rs: global unicast only, no local addresses, strict
//!    literals, DNS once, ports 0 and 25, silent refusal) and the resource ceilings below;
//! 2. the operator's command-line limits;
//! 3. the provider's policy file (targets, ports, limits), published on IPFS.
//!
//! The exit is off unless a policy file is given. A policy that opens arbitrary destinations
//! (`open`, `denylist`) needs a second confirmation flag. With NodeRegistryV2 configured, the
//! exit only serves while the chain pointer `egressPolicyOf(nodeId)` equals the 36-byte CID of
//! the loaded file (CIDv1/raw/sha2-256, W59); a change on chain closes it to new connections.
use crate::exit::Refusal;
use crate::nr2::Nr2Reader;
use crate::register::{policy_cid, MAX_POLICY_BYTES};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Ceilings compiled into the node; operator flags and the policy may only go lower.
pub const HARD_MAX_PER_WALLET: usize = 256;
pub const HARD_MAX_CONNS: usize = 4096;
pub const HARD_IDLE: Duration = Duration::from_secs(120);
pub const HARD_CONNECT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Off,
    Allowlist,
    Denylist,
    Open,
}

impl Mode {
    /// Modes that let users reach destinations nobody listed.
    pub fn is_open_type(self) -> bool {
        matches!(self, Mode::Open | Mode::Denylist)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitSet {
    pub max_conns_per_wallet: Option<usize>,
    pub max_conns: Option<usize>,
    pub idle_secs: Option<u64>,
    pub connect_secs: Option<u64>,
}

/// Policy file, version 1 (JSON).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default)]
    pub operator: Option<String>,
    pub mode: Mode,
    /// Allowed TCP ports; absent = any port the node allows.
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// `example.com`, `*.example.com`, `203.0.113.0/24` or a single IPv4 address.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub limits: LimitSet,
    /// Free text for users (logging, data handling). Not enforced and not verifiable.
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Host(String),
    /// `*.example.com`: any subdomain, not the bare name.
    Suffix(String),
    Cidr(u32, u8),
}

impl Pattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some((ip, len)) = s.split_once('/') {
            let ip = crate::exit::parse_ipv4_strict(ip).ok_or(format!("bad CIDR: {s}"))?;
            let len: u8 = len.parse().map_err(|_| format!("bad CIDR: {s}"))?;
            if len > 32 {
                return Err(format!("bad CIDR: {s}"));
            }
            return Ok(Pattern::Cidr(u32::from(ip) & mask(len), len));
        }
        if let Some(ip) = crate::exit::parse_ipv4_strict(&s) {
            return Ok(Pattern::Cidr(u32::from(ip), 32));
        }
        let host_ok = |h: &str| {
            !h.is_empty()
                && h.len() <= 253
                && h.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        };
        if let Some(rest) = s.strip_prefix("*.") {
            if host_ok(rest) && rest.contains('.') {
                return Ok(Pattern::Suffix(rest.to_string()));
            }
        } else if host_ok(&s) {
            return Ok(Pattern::Host(s));
        }
        Err(format!("bad pattern: {s}"))
    }

    fn matches(&self, host: Option<&str>, ip: Ipv4Addr) -> bool {
        match self {
            Pattern::Cidr(net, len) => u32::from(ip) & mask(*len) == *net,
            Pattern::Host(h) => host == Some(h.as_str()),
            Pattern::Suffix(sfx) => host
                .map(|h| h.len() > sfx.len() + 1 && h.ends_with(&format!(".{sfx}")))
                .unwrap_or(false),
        }
    }
}

fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len)
    }
}

/// The policy's target rules, ready to check.
#[derive(Debug, Clone)]
pub struct PolicyRules {
    pub mode: Mode,
    pub ports: Option<HashSet<u16>>,
    pub allow: Vec<Pattern>,
    pub deny: Vec<Pattern>,
}

impl PolicyRules {
    /// No provider restrictions (tests and the compiled rules alone).
    pub fn allow_all() -> Self {
        Self {
            mode: Mode::Open,
            ports: None,
            allow: vec![],
            deny: vec![],
        }
    }

    /// `host` is the requested name (None for an IP literal); `ip` the address to dial.
    pub fn check(&self, host: Option<&str>, ip: Ipv4Addr, port: u16) -> Result<(), Refusal> {
        let host = host.map(|h| h.trim_end_matches('.').to_ascii_lowercase());
        let host = host.as_deref();
        if self.mode == Mode::Off {
            return Err(Refusal::Policy);
        }
        if let Some(p) = &self.ports {
            if !p.contains(&port) {
                return Err(Refusal::Policy);
            }
        }
        if self.deny.iter().any(|p| p.matches(host, ip)) {
            return Err(Refusal::Policy);
        }
        if self.mode == Mode::Allowlist && !self.allow.iter().any(|p| p.matches(host, ip)) {
            return Err(Refusal::Policy);
        }
        Ok(())
    }
}

impl PolicyFile {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err("policy file over 256 KiB".into());
        }
        let p: PolicyFile = serde_json::from_slice(bytes).map_err(|e| format!("policy: {e}"))?;
        if p.version != 1 {
            return Err(format!("policy version {} (want 1)", p.version));
        }
        if let Some(ports) = &p.ports {
            if ports.iter().any(|&x| x == 0 || x == 25) {
                return Err("policy may not open port 0 or 25".into());
            }
        }
        p.rules()?;
        Ok(p)
    }

    pub fn rules(&self) -> Result<PolicyRules, String> {
        Ok(PolicyRules {
            mode: self.mode,
            ports: self.ports.as_ref().map(|v| v.iter().copied().collect()),
            allow: self
                .allow
                .iter()
                .map(|s| Pattern::parse(s))
                .collect::<Result<_, _>>()?,
            deny: self
                .deny
                .iter()
                .map(|s| Pattern::parse(s))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Effective resource limits: compiled ceiling, then operator, then policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_per_wallet: usize,
    pub max_conns: usize,
    pub idle: Duration,
    pub connect: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_per_wallet: HARD_MAX_PER_WALLET,
            max_conns: HARD_MAX_CONNS,
            idle: HARD_IDLE,
            connect: HARD_CONNECT,
        }
    }
}

impl Limits {
    pub fn layered(operator: &LimitSet, policy: &LimitSet) -> Self {
        let pick = |hard: u64, a: Option<u64>, b: Option<u64>| {
            [Some(hard), a, b]
                .into_iter()
                .flatten()
                .filter(|v| *v > 0)
                .min()
                .unwrap_or(hard)
        };
        Self {
            max_per_wallet: pick(
                HARD_MAX_PER_WALLET as u64,
                operator.max_conns_per_wallet.map(|v| v as u64),
                policy.max_conns_per_wallet.map(|v| v as u64),
            ) as usize,
            max_conns: pick(
                HARD_MAX_CONNS as u64,
                operator.max_conns.map(|v| v as u64),
                policy.max_conns.map(|v| v as u64),
            ) as usize,
            idle: Duration::from_secs(pick(
                HARD_IDLE.as_secs(),
                operator.idle_secs,
                policy.idle_secs,
            )),
            connect: Duration::from_secs(pick(
                HARD_CONNECT.as_secs(),
                operator.connect_secs,
                policy.connect_secs,
            )),
        }
    }
}

/// Printed (stderr and log) when an operator turns the exit on.
pub const RISK_NOTICE: &str =
    "EXIT ENABLED: users reach the internet from this node's IP address. \
Abuse complaints and legal exposure fall on the operator. The compiled rules keep your own \
network and this host out of reach, but everything else the policy allows is reachable. \
Privacy promises in the policy file cannot be verified by users.";

/// Why the exit cannot start with this configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum StartRefusal {
    NeedsOpenConfirm,
    PolicyOff,
}

/// Checks before the exit may start (the rest of the node runs either way).
pub fn start_check(p: &PolicyFile, open_confirmed: bool) -> Result<(), StartRefusal> {
    if p.mode == Mode::Off {
        return Err(StartRefusal::PolicyOff);
    }
    if p.mode.is_open_type() && !open_confirmed {
        return Err(StartRefusal::NeedsOpenConfirm);
    }
    Ok(())
}

/// Serving switch tied to the chain pointer.
pub struct ChainGate {
    pub local_cid: [u8; 36],
    open: AtomicBool,
    /// Set after the first comparison, so the first result is always logged.
    checked: AtomicBool,
}

impl ChainGate {
    /// `open_now`: no chain check configured (explicit operator choice); otherwise closed until
    /// the first successful comparison.
    pub fn new(local_cid: [u8; 36], open_now: bool) -> Arc<Self> {
        Arc::new(Self {
            local_cid,
            open: AtomicBool::new(open_now),
            checked: AtomicBool::new(false),
        })
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }

    /// Compare with the chain value; returns the new state.
    pub fn update(&self, chain_cid: &[u8]) -> bool {
        let ok = chain_cid == self.local_cid;
        let was = self.open.swap(ok, Ordering::Relaxed);
        let first = !self.checked.swap(true, Ordering::Relaxed);
        if was != ok || first {
            if ok {
                info!("egress policy matches the chain pointer; exit open");
            } else {
                warn!(
                    "egress policy differs from the chain pointer (or none on chain); exit closed to new connections"
                );
            }
        }
        ok
    }
}

/// Load the policy file and its CID.
pub fn load(path: &str) -> Result<(PolicyFile, [u8; 36]), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let p = PolicyFile::parse(&bytes)?;
    let cid = policy_cid(&bytes).map_err(|e| e.0)?;
    Ok((p, cid))
}

/// Keep the gate in step with `egressPolicyOf(nodeId)` (polled; the call is cheap and covers
/// `EgressPolicySet` without a log subscription). A read failure keeps the current state.
pub async fn sync_loop(reader: Nr2Reader, wallet: String, gate: Arc<ChainGate>, every: Duration) {
    let mut node_id = 0u64;
    loop {
        if node_id == 0 {
            match reader.node_id_of_wallet(&wallet).await {
                Ok(0) => {
                    gate.update(&[]);
                }
                Ok(id) => node_id = id,
                Err(e) => warn!(%e, "egress: node id read failed"),
            }
        }
        if node_id != 0 {
            match reader.egress_policy(node_id).await {
                Ok((cid, _version, _at)) => {
                    gate.update(&cid);
                }
                Err(e) => warn!(%e, "egress: policy pointer read failed"),
            }
        }
        tokio::time::sleep(every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn patterns() {
        assert_eq!(
            Pattern::parse("Example.COM.").unwrap(),
            Pattern::Host("example.com".into())
        );
        assert_eq!(
            Pattern::parse("*.example.com").unwrap(),
            Pattern::Suffix("example.com".into())
        );
        assert_eq!(
            Pattern::parse("203.0.113.7/24").unwrap(),
            Pattern::Cidr(u32::from(ip("203.0.113.0")), 24)
        );
        assert_eq!(
            Pattern::parse("203.0.113.7").unwrap(),
            Pattern::Cidr(u32::from(ip("203.0.113.7")), 32)
        );
        for bad in [
            "*.com",
            "a..b",
            "1.2.3.4/33",
            "01.2.3.4/8",
            "ex ample.com",
            "",
            "*.",
        ] {
            assert!(Pattern::parse(bad).is_err(), "{bad}");
        }
        let s = Pattern::parse("*.example.com").unwrap();
        assert!(s.matches(Some("a.example.com"), ip("1.1.1.1")));
        assert!(!s.matches(Some("example.com"), ip("1.1.1.1")));
        assert!(!s.matches(Some("badexample.com"), ip("1.1.1.1")));
        assert!(!s.matches(None, ip("1.1.1.1")));
    }

    #[test]
    fn rules_by_mode() {
        let file = |mode: &str, extra: &str| {
            PolicyFile::parse(format!(r#"{{"version":1,"mode":"{mode}"{extra}}}"#).as_bytes())
                .unwrap()
                .rules()
                .unwrap()
        };
        let a = file(
            "allowlist",
            r#","allow":["example.com","*.cdn.example.net","198.51.100.0/24"],"deny":["bad.example.com"],"ports":[443]"#,
        );
        assert!(a.check(Some("example.com"), ip("8.8.8.8"), 443).is_ok());
        assert!(a
            .check(Some("x.cdn.example.net"), ip("8.8.8.8"), 443)
            .is_ok());
        assert!(
            a.check(None, ip("198.51.100.9"), 443).is_ok(),
            "CIDR on a literal"
        );
        assert!(
            a.check(Some("any.org"), ip("198.51.100.9"), 443).is_ok(),
            "CIDR on the resolved IP"
        );
        assert_eq!(
            a.check(Some("other.org"), ip("8.8.8.8"), 443),
            Err(Refusal::Policy)
        );
        assert_eq!(
            a.check(Some("example.com"), ip("8.8.8.8"), 80),
            Err(Refusal::Policy),
            "port"
        );
        let d = file("denylist", r#","deny":["*.ads.example","192.0.2.1"]"#);
        assert!(d.check(Some("news.example"), ip("8.8.8.8"), 80).is_ok());
        assert_eq!(
            d.check(Some("x.ads.example"), ip("8.8.8.8"), 80),
            Err(Refusal::Policy)
        );
        assert_eq!(
            d.check(Some("fine.example"), ip("192.0.2.1"), 80),
            Err(Refusal::Policy)
        );
        assert_eq!(
            file("off", "").check(Some("a.b"), ip("8.8.8.8"), 80),
            Err(Refusal::Policy)
        );
        assert!(file("open", "")
            .check(Some("a.b"), ip("8.8.8.8"), 80)
            .is_ok());
    }

    #[test]
    fn file_checks() {
        assert!(PolicyFile::parse(br#"{"version":2,"mode":"open"}"#).is_err());
        assert!(PolicyFile::parse(br#"{"version":1,"mode":"open","ports":[25]}"#).is_err());
        assert!(PolicyFile::parse(br#"{"version":1,"mode":"open","ports":[0]}"#).is_err());
        assert!(
            PolicyFile::parse(br#"{"version":1,"mode":"open","allow":["1.2.3.4/40"]}"#).is_err()
        );
        assert!(PolicyFile::parse(br#"{"version":1,"mode":"open","surprise":1}"#).is_err());
        assert!(PolicyFile::parse(br#"{"version":1,"mode":"sideways"}"#).is_err());
        let big = format!(
            r#"{{"version":1,"mode":"open","notes":"{}"}}"#,
            "x".repeat(MAX_POLICY_BYTES)
        );
        assert!(PolicyFile::parse(big.as_bytes())
            .unwrap_err()
            .contains("256"));
    }

    #[test]
    fn open_types_need_a_second_confirmation() {
        let p = |m: &str| {
            PolicyFile::parse(format!(r#"{{"version":1,"mode":"{m}"}}"#).as_bytes()).unwrap()
        };
        assert_eq!(
            start_check(&p("open"), false),
            Err(StartRefusal::NeedsOpenConfirm)
        );
        assert_eq!(
            start_check(&p("denylist"), false),
            Err(StartRefusal::NeedsOpenConfirm)
        );
        assert_eq!(start_check(&p("open"), true), Ok(()));
        assert_eq!(start_check(&p("allowlist"), false), Ok(()));
        assert_eq!(start_check(&p("off"), true), Err(StartRefusal::PolicyOff));
    }

    #[test]
    fn limits_take_the_minimum_of_three_layers() {
        let none = LimitSet::default();
        assert_eq!(Limits::layered(&none, &none), Limits::default());
        let op = LimitSet {
            max_conns_per_wallet: Some(64),
            max_conns: Some(10_000),
            idle_secs: Some(60),
            connect_secs: None,
        };
        let pol = LimitSet {
            max_conns_per_wallet: Some(100),
            max_conns: Some(500),
            idle_secs: Some(0),
            connect_secs: Some(5),
        };
        let l = Limits::layered(&op, &pol);
        assert_eq!(l.max_per_wallet, 64, "operator lower");
        assert_eq!(
            l.max_conns, 500,
            "policy lower; operator cannot raise the ceiling"
        );
        assert_eq!(l.idle, Duration::from_secs(60), "0 means unset, not zero");
        assert_eq!(l.connect, Duration::from_secs(5));
        let high = LimitSet {
            max_conns_per_wallet: Some(1_000_000),
            ..LimitSet::default()
        };
        assert_eq!(
            Limits::layered(&high, &high).max_per_wallet,
            HARD_MAX_PER_WALLET
        );
    }

    #[test]
    fn gate_follows_the_chain_pointer() {
        let cid = policy_cid(b"{}").unwrap();
        let g = ChainGate::new(cid, false);
        assert!(!g.is_open());
        assert!(g.update(&cid));
        assert!(g.is_open());
        let mut text_bytes = crate::register::cid_text(&cid).into_bytes();
        assert!(
            !g.update(&text_bytes),
            "the text CID's UTF-8 bytes are not the CID"
        );
        text_bytes.clear();
        assert!(!g.update(&text_bytes), "cleared on chain");
        assert!(!g.is_open());
    }
}

//! SilentPass exit (M2 line E): `SaaS_Sock5` and `SaaS_Sock5_v2` (CoNET-SI rev 74c6cfd), with the
//! security line's egress rules (`rust-node-facts-and-interfaces.md` §E). Live SI checks none of
//! these, so its exit could reach the node itself and private networks.
//!
//! - `SaaS_Sock5` is always handled as V1 (the `type` field is ignored; no known client sends it).
//! - Targets: global-unicast IPv4 only; 168.63.129.16 and every local address refused; strict
//!   dotted-quad literals; ports 0 and 25 refused; a name is resolved once (DNS only, no hosts
//!   file) and the checked address is the one dialled; refusals close silently and the log never
//!   carries the target.
//! - On top of those compiled rules: the provider's policy file and the layered limits
//!   (`egress.rs`, Q66); the exit closes to new connections while the policy differs from the
//!   chain pointer.
use crate::chain::{BoxFut, Rpc};
use crate::http;
use crate::server::{Conn, NodeCtx};
use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

// ---------------------------------------------------------------- target policy

/// Why a target was refused (logged instead of the target itself).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Refusal {
    Port,
    Literal,
    NotGlobal,
    Local,
    Resolve,
    /// The provider's policy file does not allow it (egress.rs).
    Policy,
}

/// Strict dotted quad: four decimal octets 0-255, no leading zeros, nothing else.
pub fn parse_ipv4_strict(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty()
            || p.len() > 3
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return None;
        }
        o[i] = p.parse().ok()?;
    }
    Some(Ipv4Addr::from(o))
}

/// Global unicast IPv4 (allow-list thinking: everything special-purpose is out).
pub fn is_global_unicast_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let special = a == 0                                  // this network
        || a == 10                                        // private
        || (a == 100 && (64..=127).contains(&b))          // CGNAT
        || a == 127                                       // loopback
        || (a == 169 && b == 254)                         // link local
        || (a == 172 && (16..=31).contains(&b))           // private
        || (a == 192 && b == 0 && c == 0)                 // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)                 // TEST-NET-1
        || (a == 192 && b == 88 && c == 99)               // 6to4 relay anycast
        || (a == 192 && b == 168)                         // private
        || (a == 198 && (b == 18 || b == 19))             // benchmarking
        || (a == 198 && b == 51 && c == 100)              // TEST-NET-2
        || (a == 203 && b == 0 && c == 113)               // TEST-NET-3
        || a >= 224; // multicast, reserved, broadcast
    !special && ip != Ipv4Addr::new(168, 63, 129, 16) // Azure host/metadata endpoint
}

pub struct EgressPolicy {
    /// Interface addresses at start plus the configured public IPs.
    pub local: HashSet<IpAddr>,
    /// Tests only: allow loopback targets so an echo server can stand in for the internet.
    pub allow_loopback_for_tests: bool,
    /// The provider's policy (layer 3); checked after the compiled rules.
    pub rules: crate::egress::PolicyRules,
}

impl EgressPolicy {
    pub fn from_system(extra_public: &[IpAddr], rules: crate::egress::PolicyRules) -> Self {
        let mut local: HashSet<IpAddr> = if_addrs::get_if_addrs()
            .map(|v| v.into_iter().map(|i| i.ip()).collect())
            .unwrap_or_default();
        local.extend(extra_public.iter().copied());
        Self {
            local,
            allow_loopback_for_tests: false,
            rules,
        }
    }

    pub fn check_ip(&self, ip: Ipv4Addr, port: u16) -> Result<(), Refusal> {
        if port == 0 || port == 25 {
            return Err(Refusal::Port);
        }
        if self.allow_loopback_for_tests && ip.is_loopback() {
            return Ok(());
        }
        if self.local.contains(&IpAddr::V4(ip)) {
            return Err(Refusal::Local);
        }
        if !is_global_unicast_v4(ip) {
            return Err(Refusal::NotGlobal);
        }
        Ok(())
    }
}

/// Name → IPv4 addresses, queried once per request.
pub trait Resolver: Send + Sync {
    fn resolve_v4<'a>(&'a self, host: &'a str) -> BoxFut<'a, Vec<Ipv4Addr>>;
}

/// System DNS servers (resolv.conf) but never the hosts file.
pub struct DnsResolver(hickory_resolver::TokioResolver);

impl DnsResolver {
    pub fn new() -> Result<Self, String> {
        let mut b = hickory_resolver::Resolver::builder_tokio().map_err(|e| e.to_string())?;
        b.options_mut().use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        Ok(Self(b.build().map_err(|e| e.to_string())?))
    }
}

impl Resolver for DnsResolver {
    fn resolve_v4<'a>(&'a self, host: &'a str) -> BoxFut<'a, Vec<Ipv4Addr>> {
        Box::pin(async move {
            match tokio::time::timeout(Duration::from_secs(5), self.0.lookup_ip(host)).await {
                Ok(Ok(l)) => l
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(v) => Some(v),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            }
        })
    }
}

/// Resolve (once) and check. Returns the exact address to dial.
pub async fn vet_target(
    policy: &EgressPolicy,
    resolver: &dyn Resolver,
    host: &str,
    port: i64,
) -> Result<SocketAddr, Refusal> {
    let port: u16 = u16::try_from(port).map_err(|_| Refusal::Port)?;
    let host = host.trim();
    // WHATWG URL rule: a host whose last label is numeric (decimal or 0x-hex) is an IPv4 attempt;
    // anything but a canonical dotted quad is refused (127.1, 0177.0.0.1, 2130706433, 0x7f…).
    let last = host.trim_end_matches('.').rsplit('.').next().unwrap_or("");
    let numeric_last = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || ((last.starts_with("0x") || last.starts_with("0X"))
                && last[2..].bytes().all(|b| b.is_ascii_hexdigit())));
    let mut name = None;
    let ip = if let Some(ip) = parse_ipv4_strict(host) {
        ip
    } else if host.is_empty() || host.contains(':') || host.starts_with('[') || numeric_last {
        // IPv6 literal (v1 is IPv4-only) or a non-canonical IPv4 spelling.
        return Err(Refusal::Literal);
    } else {
        // A name: one DNS query, first A record (SI takes ipv4s[0]).
        name = Some(host);
        *resolver
            .resolve_v4(host)
            .await
            .first()
            .ok_or(Refusal::Resolve)?
    };
    policy.check_ip(ip, port)?;
    policy.rules.check(name, ip, port)?;
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

// ---------------------------------------------------------------- payment

sol! {
    function getCurrentPassport(address to) external view returns (uint256, uint256, uint256, bool);
}

/// CoNET mainnet passport contracts SI checks (duplicateFactory and passport distributor).
pub const PASSPORT_CONTRACTS: [&str; 2] = [
    "0x87A70eD480a2b904c607Ee68e6C3f8c54D58FB08",
    "0x40d64D88A86D6efb721042225B812379dc97bc89",
];

pub trait Passport: Send + Sync {
    fn is_paid<'a>(&'a self, wallet: &'a str) -> BoxFut<'a, bool>;
}

/// SI `_checkNFT`: an NFT id and `expires` (seconds) not in the past.
pub fn passport_valid(nft_id: U256, expires: U256, now_secs: u64) -> bool {
    !nft_id.is_zero() && expires >= U256::from(now_secs)
}

pub struct ChainPassport {
    pub rpc: Rpc,
    /// Positive answers cached 30 minutes (SI `setToUssrPool` window).
    cache: Mutex<HashMap<String, Instant>>,
}

impl ChainPassport {
    pub fn new(rpc: Rpc) -> Self {
        Self {
            rpc,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Passport for ChainPassport {
    fn is_paid<'a>(&'a self, wallet: &'a str) -> BoxFut<'a, bool> {
        Box::pin(async move {
            let w = wallet.to_lowercase();
            if self
                .cache
                .lock()
                .expect("passport")
                .get(&w)
                .map(|t| t.elapsed() < Duration::from_secs(1800))
                .unwrap_or(false)
            {
                return true;
            }
            let Ok(to) = w.parse::<Address>() else {
                return false;
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for c in PASSPORT_CONTRACTS {
                let Ok(raw) = self
                    .rpc
                    .eth_call(c, getCurrentPassportCall { to }.abi_encode(), None)
                    .await
                else {
                    continue;
                };
                if let Ok(r) = getCurrentPassportCall::abi_decode_returns(&raw) {
                    if passport_valid(r._0, r._1, now) {
                        let mut cache = self.cache.lock().expect("passport");
                        if cache.len() > 100_000 {
                            cache.clear();
                        }
                        cache.insert(w, Instant::now());
                        return true;
                    }
                }
            }
            false
        })
    }
}

// ---------------------------------------------------------------- exit service

pub struct Exit {
    pub policy: EgressPolicy,
    pub resolver: Arc<dyn Resolver>,
    pub passport: Arc<dyn Passport>,
    /// SaaS_Sock5_v2 pairs waiting for their second leg, by Securitykey.
    pending: Mutex<HashMap<String, Pending>>,
    /// Open exit connections per paying wallet.
    per_wallet: Mutex<HashMap<String, usize>>,
    total: std::sync::atomic::AtomicUsize,
    /// Compiled ceiling, operator and policy limits (strictest).
    pub limits: crate::egress::Limits,
    /// Closed while the loaded policy differs from the chain pointer; None = no chain check.
    pub gate: Option<Arc<crate::egress::ChainGate>>,
}

struct Pending {
    /// Target → client download half, waiting for the second leg.
    target_read: tokio::net::tcp::OwnedReadHalf,
    created: Instant,
}

impl Exit {
    pub fn new(
        policy: EgressPolicy,
        resolver: Arc<dyn Resolver>,
        passport: Arc<dyn Passport>,
    ) -> Self {
        Self {
            policy,
            resolver,
            passport,
            pending: Mutex::new(HashMap::new()),
            per_wallet: Mutex::new(HashMap::new()),
            total: std::sync::atomic::AtomicUsize::new(0),
            limits: crate::egress::Limits::default(),
            gate: None,
        }
    }

    pub fn with_limits(mut self, l: crate::egress::Limits) -> Self {
        self.limits = l;
        self
    }

    pub fn with_gate(mut self, g: Arc<crate::egress::ChainGate>) -> Self {
        self.gate = Some(g);
        self
    }

    /// Serving now? (false while the policy differs from the chain pointer)
    pub fn open(&self) -> bool {
        self.gate.as_ref().map(|g| g.is_open()).unwrap_or(true)
    }
}

/// Released when a connection ends.
struct WalletSlot {
    exit: Arc<Exit>,
    wallet: String,
}

impl Drop for WalletSlot {
    fn drop(&mut self) {
        self.exit
            .total
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let mut m = self.exit.per_wallet.lock().expect("exit");
        if let Some(n) = m.get_mut(&self.wallet) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.wallet);
            }
        }
    }
}

fn take_slot(exit: &Arc<Exit>, wallet: &str) -> Option<WalletSlot> {
    let mut m = exit.per_wallet.lock().expect("exit");
    let n = m.entry(wallet.to_string()).or_insert(0);
    if *n >= exit.limits.max_per_wallet
        || exit.total.load(std::sync::atomic::Ordering::Relaxed) >= exit.limits.max_conns
    {
        return None;
    }
    *n += 1;
    exit.total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Some(WalletSlot {
        exit: exit.clone(),
        wallet: wallet.to_string(),
    })
}

fn wallet_tag(w: &str) -> String {
    if w.len() > 10 {
        format!("{}…{}", &w[..6], &w[w.len() - 4..])
    } else {
        w.to_string()
    }
}

/// `requestData[0]`: (host, port, initial bytes).
fn request_target(c: &Value) -> Option<(String, i64, Vec<u8>)> {
    let r = c.get("requestData")?.as_array()?.first()?;
    let host = r
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let port = si_proto::js_number(r.get("port")).and_then(si_proto::js_safe_int)?;
    let buffer =
        si_proto::node_base64_decode(r.get("buffer").and_then(Value::as_str).unwrap_or(""));
    Some((host, port, buffer))
}

async fn connect(exit: &Exit, host: &str, port: i64, wallet: &str) -> Option<TcpStream> {
    match vet_target(&exit.policy, &*exit.resolver, host, port).await {
        Ok(addr) => tokio::time::timeout(exit.limits.connect, TcpStream::connect(addr))
            .await
            .ok()?
            .ok(),
        Err(r) => {
            debug!(refusal = ?r, wallet = %wallet_tag(wallet), "exit target refused");
            None
        }
    }
}

/// Entry point for both commands (after `checkSign`).
pub async fn handle(mut stream: Conn, command: Value, ctx: Arc<NodeCtx>) {
    let Some(exit) = ctx.exit.clone().filter(|e| e.open()) else {
        let _ = stream.write_all(&http::not_found()).await;
        return;
    };
    let wallet = command
        .get("walletAddress")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    if !exit.passport.is_paid(&wallet).await {
        let _ = stream.write_all(&http::payment_required()).await;
        let _ = stream.shutdown().await;
        return;
    }
    let Some((host, port, buffer)) = request_target(&command) else {
        let _ = stream.write_all(&http::not_found()).await;
        return;
    };
    let Some(slot) = take_slot(&exit, &wallet) else {
        let _ = stream.shutdown().await;
        return;
    };
    match command.get("command").and_then(Value::as_str) {
        Some("SaaS_Sock5_v2") => v2(stream, command, exit, host, port, buffer, wallet, slot).await,
        _ => v1(stream, exit, host, port, buffer, wallet, slot).await,
    }
}

/// SI `socks5Connect`: connect, write the first bytes, pipe both ways; 120 s idle on the target.
async fn v1(
    mut stream: Conn,
    exit: Arc<Exit>,
    host: String,
    port: i64,
    buffer: Vec<u8>,
    wallet: String,
    _slot: WalletSlot,
) {
    let Some(mut target) = connect(&exit, &host, port, &wallet).await else {
        let _ = stream.shutdown().await;
        return;
    };
    let _ = target.set_nodelay(true);
    if !buffer.is_empty() && target.write_all(&buffer).await.is_err() {
        return;
    }
    pipe_with_idle(stream, target, exit.limits.idle).await;
}

async fn pipe_with_idle(mut a: Conn, mut b: TcpStream, idle: Duration) {
    // copy_bidirectional has no idle timeout; re-arm a deadline on each chunk instead.
    let (mut ar, mut aw) = tokio::io::split(&mut a);
    let (mut br, mut bw) = b.split();
    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            use tokio::io::AsyncReadExt;
            match tokio::time::timeout(idle, ar.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    if bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = bw.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            use tokio::io::AsyncReadExt;
            match tokio::time::timeout(idle, br.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    if aw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = aw.shutdown().await;
    };
    tokio::join!(up, down);
}

/// SI `SaaS_Sock5_v2`: two requests share a Securitykey. The first (with a non-empty buffer)
/// connects the target and carries the upload; the second, within 30 s, carries the download.
#[allow(clippy::too_many_arguments)]
async fn v2(
    mut stream: Conn,
    command: Value,
    exit: Arc<Exit>,
    host: String,
    port: i64,
    buffer: Vec<u8>,
    wallet: String,
    slot: WalletSlot,
) {
    let key = command
        .get("Securitykey")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if key.is_empty() || host.is_empty() || port == 0 {
        let _ = stream.write_all(&http::not_found()).await;
        return;
    }
    // Second leg?
    let waiting = {
        let mut p = exit.pending.lock().expect("exit");
        p.retain(|_, v| v.created.elapsed() < Duration::from_secs(30));
        p.remove(&key)
    };
    if let Some(Pending {
        mut target_read, ..
    }) = waiting
    {
        let _ = tokio::io::copy(&mut target_read, &mut stream).await;
        let _ = stream.shutdown().await;
        return;
    }
    // First leg: needs initial data to open the target (SI refuses the pair otherwise).
    if buffer.is_empty() {
        let _ = stream.shutdown().await;
        return;
    }
    let Some(target) = connect(&exit, &host, port, &wallet).await else {
        let _ = stream.shutdown().await;
        return;
    };
    let _ = target.set_nodelay(true);
    let (target_read, mut target_write) = target.into_split();
    if target_write.write_all(&buffer).await.is_err() {
        return;
    }
    exit.pending.lock().expect("exit").insert(
        key.clone(),
        Pending {
            target_read,
            created: Instant::now(),
        },
    );
    let exit2 = exit.clone();
    let k2 = key.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        exit2.pending.lock().expect("exit").remove(&k2);
    });
    let _slot = slot;
    let _ = tokio::io::copy(&mut stream, &mut target_write).await;
    let _ = target_write.shutdown().await;
}

/// Base64 helper for tests building `requestData`.
pub fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_literals() {
        assert_eq!(
            parse_ipv4_strict("8.8.8.8"),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
        for bad in [
            "127.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f.0.0.1",
            "1.2.3",
            "1.2.3.4.5",
            "1.2.3.256",
            "01.2.3.4",
            " 1.2.3.4",
            "1..3.4",
        ] {
            assert_eq!(parse_ipv4_strict(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_global_unicast() {
        for bad in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.9.9",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.1",
            "198.51.100.2",
            "203.0.113.9",
            "224.0.0.1",
            "239.1.1.1",
            "240.0.0.1",
            "255.255.255.255",
            "168.63.129.16",
        ] {
            assert!(!is_global_unicast_v4(bad.parse().unwrap()), "{bad}");
        }
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.0.1",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "168.63.129.17",
        ] {
            assert!(is_global_unicast_v4(ok.parse().unwrap()), "{ok}");
        }
    }

    struct Fixed(Vec<Ipv4Addr>);
    impl Resolver for Fixed {
        fn resolve_v4<'a>(&'a self, _h: &'a str) -> BoxFut<'a, Vec<Ipv4Addr>> {
            let v = self.0.clone();
            Box::pin(async move { v })
        }
    }

    #[tokio::test]
    async fn vetting_rules() {
        let me: IpAddr = "203.0.114.7".parse().unwrap(); // pretend public address of this node
        let p = EgressPolicy {
            rules: crate::egress::PolicyRules::allow_all(),
            local: [me].into(),
            allow_loopback_for_tests: false,
        };
        let public = Fixed(vec!["93.184.216.34".parse().unwrap()]);
        assert_eq!(
            vet_target(&p, &public, "example.com", 443).await,
            Ok("93.184.216.34:443".parse().unwrap())
        );
        assert_eq!(
            vet_target(&p, &public, "8.8.8.8", 53).await,
            Ok("8.8.8.8:53".parse().unwrap())
        );
        assert_eq!(
            vet_target(&p, &public, "8.8.8.8", 25).await,
            Err(Refusal::Port)
        );
        assert_eq!(
            vet_target(&p, &public, "8.8.8.8", 0).await,
            Err(Refusal::Port)
        );
        assert_eq!(
            vet_target(&p, &public, "8.8.8.8", 70000).await,
            Err(Refusal::Port)
        );
        assert_eq!(
            vet_target(&p, &public, "203.0.114.7", 80).await,
            Err(Refusal::Local),
            "own public IP"
        );
        for lit in [
            "127.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
            "::1",
            "[::1]",
            "2606:4700::1111",
        ] {
            assert_eq!(
                vet_target(&p, &public, lit, 80).await,
                Err(Refusal::Literal),
                "{lit}"
            );
        }
        let private = Fixed(vec!["10.0.0.5".parse().unwrap()]);
        assert_eq!(
            vet_target(&p, &private, "intranet.example", 80).await,
            Err(Refusal::NotGlobal),
            "name resolving to a private address"
        );
        assert_eq!(
            vet_target(&p, &public, "deadbeef.cafe", 443).await,
            Ok("93.184.216.34:443".parse().unwrap()),
            "hex-looking name is a name"
        );
        let none = Fixed(vec![]);
        assert_eq!(
            vet_target(&p, &none, "nx.example", 80).await,
            Err(Refusal::Resolve)
        );
        assert_eq!(
            vet_target(&p, &public, "168.63.129.16", 80).await,
            Err(Refusal::NotGlobal)
        );
    }

    #[test]
    fn passport_rule() {
        assert!(passport_valid(U256::from(5), U256::from(2_000), 1_000));
        assert!(!passport_valid(U256::ZERO, U256::from(2_000), 1_000));
        assert!(!passport_valid(U256::from(5), U256::from(999), 1_000));
    }
}

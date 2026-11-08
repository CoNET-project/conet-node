//! `conet-node` daemon (M1).
//!
//! Production: `--signer-socket <path>`; keys stay in the `conet-signer` process.
//! `--insecure-dev-keys` reads a TEST route key and wallet for local networks only.
//!
//! Routes: `--rpc <url>` reads the node table (GuardianNodesInfoV6, or NodeRegistryV2 with
//! `--node-registry <addr> --node-lens <addr>`) and AddressPGP from chain;
//! `--routes <routes.json>` uses a static table (local test networks).
//!
//! Exit (SilentPass `SaaS_Sock5*`): off unless `--egress-policy <file>` is given. Open-type
//! policies also need `--egress-open-confirm`. With `--node-registry` the exit serves only while
//! the chain pointer `egressPolicyOf(nodeId)` equals the file's CID; without a registry the
//! operator must say `--egress-no-chain-check` (V6 era). Operator limits:
//! `--exit-max-per-wallet`, `--exit-max-conns`, `--exit-idle-secs`, `--exit-connect-secs`.
use conet_node::chain::{AddressPgp, GuardianV6, NodeSource, Rpc, UserRoutes};
use conet_node::push::{BeamioApi, Push};
use conet_node::route::{RouteTable, StaticRoutes};
use conet_node::store::{DiskStore, MailboxStore, MemoryOffers, MemoryStore, OfferStore};
use conet_node::{mailbox::Mailbox, server, watcher};
use si_core::{NodeNotices, RouteDecryptor, WalletSigner};
use std::sync::Arc;
use std::time::Duration;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}

/// (decryptor, wallet, notices, route key ID, retiring route key IDs)
type Keys = (
    Arc<dyn RouteDecryptor>,
    Arc<dyn WalletSigner>,
    Arc<dyn NodeNotices>,
    String,
    Vec<String>,
);

fn keys() -> Result<Keys, Box<dyn std::error::Error>> {
    if let Some(sock) = arg("--signer-socket") {
        let c = Arc::new(si_signer::client::SignerClient::connect(sock)?);
        let id = c.route_key_id().to_string();
        let old = c.old_route_key_ids().to_vec();
        return Ok((c.clone(), c.clone(), c, id, old));
    }
    if std::env::args().any(|a| a == "--insecure-dev-keys") {
        eprintln!("WARNING: --insecure-dev-keys is for local test networks with test keys only");
        let armor = std::fs::read_to_string(
            arg("--dev-route-key").ok_or("--dev-route-key <armored test key>")?,
        )?;
        let (key, id) = si_core::node::load_route(
            &armor,
            &std::env::var("CONET_DEV_ROUTE_PASS").unwrap_or_default(),
        )?;
        let hex = std::env::var("CONET_DEV_WALLET_KEY").map_err(|_| "CONET_DEV_WALLET_KEY")?;
        let w = Arc::new(si_crypto::eth::EthKey::from_hex(&hex)?);
        return Ok((Arc::new(key), w.clone(), w, id, vec![]));
    }
    Err("need --signer-socket <path> (or --insecure-dev-keys for local tests)".into())
}

/// `--selftest`: known-answer checks the updater runs on a staged binary before switching to it.
/// The key is derived from a public test string; the answers were produced with ethers v6.
fn selftest() -> Result<(), String> {
    let k = si_crypto::eth::EthKey::from_hex(
        "0x18eff4d5aacc32afd0160623fbee160db5840f3746844094c55a23488a2f906b",
    )
    .map_err(|e| e.to_string())?;
    let want = "0xb56b6cdc61461439053570978e7e197fba28b7b267481b1dea5305b0ce5a88a916854ee8b216a251e51117292b1b13b4db7934c2cc39d91ef8d70e533022dc4c1b";
    if k.sign_message("conet-node selftest")
        .map_err(|e| e.to_string())?
        != want
    {
        return Err("eip191 signature".into());
    }
    if si_crypto::eth::recover_message("conet-node selftest", want).map_err(|e| e.to_string())?
        != "0xdfd105A6202b5e52913735c5C5B1915da08F25e5"
    {
        return Err("eip191 recover".into());
    }
    let sealed =
        si_core::seal_mailbox("{\"t\":1}", &[7u8; 32], &[1u8; 12]).map_err(|e| e.to_string())?;
    if si_core::open_mailbox(&sealed, &[7u8; 32]) != Some(("{\"t\":1}".into(), 256)) {
        return Err("mailbox seal".into());
    }
    if si_crypto::eth::keccak_hex("")
        != "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    {
        return Err("keccak".into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--selftest") {
        return match selftest() {
            Ok(()) => {
                println!("selftest ok {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            Err(e) => Err(format!("selftest failed: {e}").into()),
        };
    }
    // One TLS crypto backend for the whole process (several may be compiled in through deps).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let (decryptor, wallet, notices, key_id, old_key_ids) = keys()?;
    // One redb file holds the offline mailbox and the voice offer index.
    let (store, offers): (Arc<dyn MailboxStore>, Arc<dyn OfferStore>) = match arg("--mailbox-db") {
        Some(p) => {
            let d = Arc::new(DiskStore::open(std::path::Path::new(&p))?);
            (d.clone(), d)
        }
        None => {
            eprintln!(
                "WARNING: no --mailbox-db; offline mail and voice offers are kept in memory only"
            );
            (
                Arc::new(MemoryStore::default()),
                Arc::new(MemoryOffers::default()),
            )
        }
    };

    let mut source: Option<Arc<dyn NodeSource>> = None;
    let (routes, user_routes): (Arc<RouteTable>, Option<Arc<dyn UserRoutes>>) =
        if let Some(url) = arg("--rpc") {
            let rpc = Rpc::new(&url)?;
            source = Some(match (arg("--node-registry"), arg("--node-lens")) {
                (Some(reg), Some(lens)) => {
                    Arc::new(conet_node::nr2::Nr2Source::new(rpc.clone(), &reg, &lens))
                        as Arc<dyn NodeSource>
                }
                (None, None) => Arc::new(GuardianV6::new(rpc.clone())),
                _ => return Err("--node-registry and --node-lens go together".into()),
            });
            (
                Arc::new(RouteTable::new(&key_id, Duration::from_secs(600))),
                Some(Arc::new(AddressPgp::new(rpc))),
            )
        } else {
            let s: StaticRoutes = serde_json::from_str(&std::fs::read_to_string(
                arg("--routes").ok_or("--rpc <url> or --routes <file>")?,
            )?)?;
            (Arc::new(RouteTable::from_static(&key_id, &s)), None)
        };

    let mut ctx = server::NodeCtx::new(
        key_id,
        decryptor,
        wallet,
        notices.clone(),
        routes.clone(),
        store.clone(),
    );
    if let (Some(base), Some(ur)) = (arg("--api-base"), user_routes.clone()) {
        let node_wallet = ctx.wallet.address();
        let api: Arc<dyn Push> =
            Arc::new(Arc::new(BeamioApi::new(&base, notices, ur, node_wallet)?));
        ctx.mailbox = Arc::new(Mailbox::new(store, api.clone()));
        ctx.push = api;
    }
    // SilentPass exit: needs a policy file and the chain (passport checks); off otherwise.
    if let (Some(url), Some(path)) = (arg("--rpc"), arg("--egress-policy")) {
        if let Some(exit) = egress_exit(&url, &path, ctx.wallet.address())? {
            ctx.exit = Some(Arc::new(exit));
        }
    } else if arg("--egress-policy").is_some() {
        eprintln!("exit off: --egress-policy needs --rpc (passport checks)");
    }
    ctx.user_routes = user_routes;
    ctx.offers = offers;
    ctx.old_key_ids = old_key_ids;
    routes.set_own_aliases(&ctx.old_key_ids);
    if let Some(b) = arg("--max-body").and_then(|v| v.parse().ok()) {
        ctx.limits.max_body_bytes = b;
    }
    if std::env::args().any(|a| a == "--no-legacy-chat-listen") {
        ctx.legacy_chat_listen = false;
    }
    let ctx = Arc::new(ctx);
    let health = arg("--health-listen").unwrap_or_else(|| "127.0.0.1:9180".into());
    tokio::spawn(server::serve_health(
        tokio::net::TcpListener::bind(&health).await?,
        ctx.clone(),
    ));
    if let Some(src) = source {
        let mut opts = watcher::WatchOpts::default();
        if arg("--node-registry").is_some() {
            // V2 reads are paged through the Lens and change detection is event based: react
            // sooner, and re-read hourly because time alone can change `active`.
            opts.jitter = Duration::from_secs(15);
            opts.force_full = Duration::from_secs(3600);
        }
        tokio::spawn(watcher::run(src, routes, ctx.chain.clone(), opts));
    }
    // HTTPS: in-process ACME for {keyID}.conet.network (Q13), or fixed PEM files for tests.
    // ACME mode (Q74): TLS-ALPN-01 on :443, DNS-01 through the DNS daemon on other ports (W42).
    if let Some(tls_listen) = arg("--tls-listen") {
        use conet_node::acme_dns::{self, choose_mode, AcmeMode, Dns01Opts};
        use conet_node::tls::{node_domain, serve_tls, TlsSource};
        let tls_port = tls_listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "--tls-listen <ip:port>")?
            .port();
        let staging = std::env::args().any(|a| a == "--acme-staging");
        let cache = || -> Result<std::path::PathBuf, &'static str> {
            Ok(arg("--acme-cache")
                .ok_or("--acme-cache <dir> (keeps the certificate across restarts)")?
                .into())
        };
        let src = match (arg("--tls-cert"), arg("--tls-key")) {
            (Some(c), Some(k)) => TlsSource::Static {
                cert_pem: std::fs::read(c)?,
                key_pem: std::fs::read(k)?,
            },
            _ => match choose_mode(arg("--acme-mode").as_deref(), tls_port)? {
                AcmeMode::Alpn => TlsSource::Acme {
                    domain: arg("--tls-domain").unwrap_or_else(|| node_domain(&ctx.key_id)),
                    cache: cache()?,
                    contact: arg("--acme-contact").into_iter().collect(),
                    production: !staging,
                },
                AcmeMode::Dns01 => {
                    // The daemon derives the TXT name from the key ID, so no --tls-domain here.
                    let domain = node_domain(&ctx.key_id);
                    if arg("--tls-domain").is_some_and(|d| !d.eq_ignore_ascii_case(&domain)) {
                        return Err(
                            "--tls-domain cannot differ from {keyId}.conet.network with DNS-01"
                                .into(),
                        );
                    }
                    let daemon = arg("--acme-dns-daemon")
                        .ok_or("--acme-dns-daemon <url> (DNS-01: the project's DNS daemon)")?;
                    let mut opts = Dns01Opts::new(domain, cache()?, daemon.clone());
                    opts.contact = arg("--acme-contact").into_iter().collect();
                    opts.directory = arg("--acme-directory").unwrap_or_else(|| {
                        if staging {
                            acme_dns::LETS_ENCRYPT_STAGING.into()
                        } else {
                            acme_dns::LETS_ENCRYPT.into()
                        }
                    });
                    opts.directory_root = arg("--acme-directory-root").map(Into::into);
                    TlsSource::Dns01 {
                        daemon: acme_dns::daemon_for(&ctx, &daemon),
                        opts,
                    }
                }
            },
        };
        let l = tokio::net::TcpListener::bind(&tls_listen).await?;
        tracing::info!(%tls_listen, "https listening");
        tokio::spawn(serve_tls(l, ctx.clone(), src));
    }
    // WebRTC entry (W35): ICE-lite on one UDP port; browsers build the SDP from GET /webrtc
    // (or the published statement) and need no HTTPS.
    if let Some(rtc_listen) = arg("--webrtc-listen") {
        use conet_node::webrtc::{serve_webrtc, statement, Endpoint, WebRtcOpts};
        let bind: std::net::SocketAddr = rtc_listen.parse()?;
        let public: std::net::SocketAddr = match arg("--webrtc-public") {
            Some(p) => p.parse()?,
            None => bind,
        };
        if !public.is_ipv4() || public.ip().is_unspecified() {
            return Err("--webrtc-public <ipv4:port> (the address browsers dial)".into());
        }
        let ep = Arc::new(Endpoint::load_or_create(std::path::Path::new(
            &arg("--webrtc-cert").ok_or("--webrtc-cert <file> (kept across restarts)")?,
        ))?);
        // Valid 24 h, re-signed every 12 h.
        let (c, e) = (ctx.clone(), ep.clone());
        tokio::spawn(async move {
            loop {
                match statement(&c, &e, public, Duration::from_secs(24 * 3600)) {
                    Ok(s) => *c.webrtc.write().expect("webrtc") = Some(s),
                    Err(err) => tracing::warn!(%err, "webrtc endpoint statement"),
                }
                tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
            }
        });
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        tracing::info!(fingerprint = %ep.fingerprint(), "webrtc listening");
        tokio::spawn(serve_webrtc(sock, ctx.clone(), ep, WebRtcOpts::new(public)));
    }
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, key_id = %ctx.key_id, "conet-node listening");
    server::serve(listener, ctx).await?;
    Ok(())
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

/// Build the exit from the policy file and the operator's limits; None = stays off (reason
/// printed). Errors only for unreadable or invalid policy files.
fn egress_exit(
    rpc_url: &str,
    policy_path: &str,
    own_wallet: String,
) -> Result<Option<conet_node::exit::Exit>, Box<dyn std::error::Error>> {
    use conet_node::egress::{self, ChainGate, LimitSet, Limits, StartRefusal};
    use conet_node::exit::{ChainPassport, DnsResolver, EgressPolicy, Exit};
    let (policy, cid) = egress::load(policy_path)?;
    match egress::start_check(&policy, flag("--egress-open-confirm")) {
        Ok(()) => {}
        Err(StartRefusal::NeedsOpenConfirm) => {
            eprintln!("exit off: the policy lets users reach unlisted destinations (mode {:?}); start again with --egress-open-confirm to accept that", policy.mode);
            return Ok(None);
        }
        Err(StartRefusal::PolicyOff) => {
            eprintln!("exit off: policy mode is off");
            return Ok(None);
        }
    }
    let gate = match arg("--node-registry") {
        Some(registry) => {
            let g = ChainGate::new(cid, false);
            tokio::spawn(egress::sync_loop(
                conet_node::nr2::Nr2Reader {
                    rpc: Rpc::new(rpc_url)?,
                    registry,
                },
                own_wallet,
                g.clone(),
                Duration::from_secs(30),
            ));
            g
        }
        None if flag("--egress-no-chain-check") => {
            eprintln!(
                "WARNING: exit policy is not checked against the chain (--egress-no-chain-check)"
            );
            ChainGate::new(cid, true)
        }
        None => {
            eprintln!("exit off: no --node-registry to check the policy pointer against; use --egress-no-chain-check to run without it");
            return Ok(None);
        }
    };
    let num = |n: &str| arg(n).and_then(|v| v.parse().ok());
    let operator = LimitSet {
        max_conns_per_wallet: num("--exit-max-per-wallet"),
        max_conns: num("--exit-max-conns"),
        idle_secs: num("--exit-idle-secs").map(|v: usize| v as u64),
        connect_secs: num("--exit-connect-secs").map(|v: usize| v as u64),
    };
    let limits = Limits::layered(&operator, &policy.limits);
    let public: Vec<std::net::IpAddr> = arg("--public-ip")
        .into_iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    eprintln!("{}", egress::RISK_NOTICE);
    tracing::warn!(
        cid = %conet_node::register::cid_text(&cid),
        mode = ?policy.mode,
        ?limits,
        "exit configured (with a registry it serves only while the chain pointer matches)"
    );
    Ok(Some(
        Exit::new(
            EgressPolicy::from_system(&public, policy.rules()?),
            Arc::new(DnsResolver::new()?),
            Arc::new(ChainPassport::new(Rpc::new(rpc_url)?)),
        )
        .with_limits(limits)
        .with_gate(gate),
    ))
}

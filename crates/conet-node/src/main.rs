//! `conet-node` daemon (M1).
//!
//! Production: `--signer-socket <path>`; keys stay in the `conet-signer` process.
//! `--insecure-dev-keys` reads a TEST route key and wallet for local networks only.
//!
//! Routes: `--rpc <url>` reads the node table (GuardianNodesInfoV6, or NodeRegistryV2 with
//! `--node-registry <addr> --node-lens <addr>`) and AddressPGP from chain;
//! `--routes <routes.json>` uses a static table (local test networks).
//!
//! Term watch: with `--node-registry` the node reads its own stake term every
//! `--term-watch-secs` (default 600, at least 30) and logs renewal reminders and stops; read-only.
//!
//! Exit (SilentPass `SaaS_Sock5*`): off unless `--egress-policy <file>` is given. Open-type
//! policies also need `--egress-open-confirm`. With `--node-registry` the exit serves only while
//! the chain pointer `egressPolicyOf(nodeId)` equals the file's CID; without a registry the
//! operator must say `--egress-no-chain-check` (V6 era). Operator limits:
//! `--exit-max-per-wallet`, `--exit-max-conns`, `--exit-idle-secs`, `--exit-connect-secs`.
use conet_node::chain::{AddressPgp, GuardianV6, NodeSource, Rpc, UserRoutes};
use conet_node::push::{push_disabled_reasons, push_enabled, setting_is_set, BeamioApi, Push};
use conet_node::route::{RouteTable, StaticRoutes};
use conet_node::store::{DiskStore, MailboxStore, MemoryOffers, MemoryStore, OfferStore};
use conet_node::{mailbox::Mailbox, server, watcher};
use si_core::{NodeNotices, RouteDecryptor, WalletSigner};
use std::sync::Arc;
use std::time::Duration;

/// The value of flag `name`: the token after it. A flag with no value never takes the next flag
/// (`--…`) as its value; that is what an empty `${VAR}` expanded by systemd looks like.
fn arg(name: &str) -> Option<String> {
    arg_in(argv(), name)
}

/// The argument vector every reader below uses: the command line, plus (only when `--init-config`
/// was given) the settings merged in from `init.json` and `node.env` (see `init_args`).
static ARGV: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

fn argv() -> &'static [String] {
    ARGV.get_or_init(|| std::env::args().collect())
}

/// Load `--init-config` (if given) and fix the merged argument vector for the rest of the process.
/// A damaged config refuses to start; an absent file (and only that) means "no node-provided
/// config", so the defaults and `node.env` apply.
fn init_argv() -> Result<(), Box<dyn std::error::Error>> {
    use conet_node::init_args::{self, EnvSettings};
    let raw: Vec<String> = std::env::args().collect();
    let merged = match init_args::config_path(&raw)? {
        None => init_args::Merged {
            argv: raw,
            notes: vec![],
        },
        Some(path) => {
            let cfg = si_signer::init_config::load(std::path::Path::new(&path))
                .map_err(|e| e.to_string())?;
            init_args::merge(
                &raw,
                cfg.as_ref(),
                &EnvSettings::from_env(),
                &init_args::probe_global_ipv4,
            )?
        }
    };
    for n in &merged.notes {
        eprintln!("{n}");
    }
    let _ = ARGV.set(merged.argv);
    Ok(())
}

fn arg_in(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|x| x == name)?;
    let v = args.get(i + 1)?;
    (!v.starts_with("--")).then(|| v.clone())
}

/// `--public-ip`: a comma-separated list of IP addresses. Every entry must parse. An empty, blank
/// or unparseable value refuses to start. With `--egress-policy` the list is required.
fn public_ips_from(value: Option<&str>, egress_on: bool) -> Result<Vec<std::net::IpAddr>, String> {
    let Some(v) = value else {
        return if egress_on {
            Err("--public-ip <ip[,ip...]> is required with --egress-policy".into())
        } else {
            Ok(vec![])
        };
    };
    v.split(',')
        .map(|entry| {
            entry
                .trim()
                .parse()
                .map_err(|_| "--public-ip: every entry must be an IP address".to_string())
        })
        .collect()
}

/// Explicit public address advertised by the mining heartbeat. Never substitute a client's IP.
fn mining_node_ip_from(value: Option<&str>) -> Result<Option<std::net::Ipv4Addr>, String> {
    value
        .map(|v| {
            v.parse::<std::net::Ipv4Addr>()
                .map_err(|_| "--node-ip-address must be one IPv4 address".to_string())
        })
        .transpose()
}

/// `--max-body`: a byte count. Absent keeps the default (256 KiB). Given but empty or not a
/// number refuses to start, instead of silently keeping the default.
fn max_body_from(value: Option<&str>) -> Result<Option<usize>, String> {
    match value {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse::<usize>()
            .map(Some)
            .map_err(|_| "--max-body must be a byte count".to_string()),
    }
}

/// Value flags that fail closed. Each one, when given without a usable value (last in argv,
/// followed by another flag, empty, or blank), would otherwise fall back to a default, to a
/// different route, key, storage or certificate source, or to a built-in address. The node
/// refuses to start instead. Only the flag name is printed, never a value.
const FAIL_CLOSED_FLAGS: [&str; 29] = [
    "--ts-mailbox-digest",
    "--import-ts-mailbox",
    "--export-ts-mailbox",
    "--init-config",
    "--signer-socket",
    "--rpc",
    "--node-registry",
    "--node-lens",
    "--mailbox-db",
    "--node-ip-address",
    "--listen",
    "--health-listen",
    "--tls-cert",
    "--tls-key",
    "--acme-mode",
    "--tls-domain",
    "--acme-contact",
    "--acme-directory",
    "--acme-directory-root",
    "--webrtc-public",
    "--public-ip",
    "--max-body",
    "--treasury-v3-address",
    "--treasury-v3-base-rpc",
    "--treasury-v3-conet-rpc",
    "--treasury-v3-base-deploy-block",
    "--treasury-v3-conet-deploy-block",
    "--runtime-state-dir",
    "--evidence-log",
];

/// True when a value is present and usable: not missing, not another flag, not blank.
fn has_value(v: Option<&String>) -> bool {
    v.is_some_and(|v| !v.starts_with("--") && !v.trim().is_empty())
}

/// The first fail-closed value flag that appears without a usable value. Name only.
fn valueless_flag(args: &[String]) -> Option<&'static str> {
    FAIL_CLOSED_FLAGS.iter().copied().find(|f| {
        args.iter()
            .enumerate()
            .any(|(i, a)| a == f && !has_value(args.get(i + 1)))
    })
}

/// A flag whose value counts only when it is non-blank. Used for `--rpc` and `--api-base`, so a
/// blank value is treated as absent by the route choice and by the Beamio push gate alike.
fn setting(name: &str) -> Option<String> {
    arg(name).filter(|v| setting_is_set(Some(v.as_str())))
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
    if flag("--insecure-dev-keys") {
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

/// `--import-ts-mailbox DIR --mailbox-db FILE`: takes over the TS offline mailbox files of DIR (idempotent; the source is only read).
/// `--export-ts-mailbox DIR --mailbox-db FILE`: at a rollback, writes what the Rust store holds back into DIR in the TS format. Neither starts the node; a running node
/// holds the database lock, so both refuse to run next to it. Only counts are printed, never a file name, key or message text.
fn run_ts_mailbox(
    import_dir: Option<String>,
    export_dir: Option<String>,
    db: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if import_dir.is_some() && export_dir.is_some() {
        return Err(
            "--import-ts-mailbox and --export-ts-mailbox are separate steps; give one".into(),
        );
    }
    let Some(db) = db else {
        return Err("--mailbox-db is required for the TS mailbox migration".into());
    };
    let store = conet_node::store::DiskStore::open(std::path::Path::new(&db))?;
    if let Some(dir) = import_dir {
        let r = conet_node::ts_mailbox::import_ts_dir(&store, std::path::Path::new(&dir))?;
        println!(
            "import-ts-mailbox: files={} keys={} read={} imported={} already_present={} already_imported={} failed_files={} skipped_non_string={}",
            r.files, r.keys, r.read, r.imported, r.already_present, r.already_imported, r.failed_files, r.skipped_non_string
        );
        if r.failed_files > 0 {
            return Err(format!(
                "{} TS mailbox file(s) did not parse; nothing of them was imported",
                r.failed_files
            )
            .into());
        }
    }
    if let Some(dir) = export_dir {
        let r = conet_node::ts_mailbox::export_ts_dir(&store, std::path::Path::new(&dir))?;
        println!(
            "export-ts-mailbox: keys={} written={} unchanged={} failed_keys={} skipped_keys={}",
            r.keys, r.written, r.unchanged, r.failed_keys, r.skipped_keys
        );
        if r.failed_keys > 0 {
            return Err(format!(
                "{} key(s) have a TS file that does not parse and were left alone",
                r.failed_keys
            )
            .into());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_argv()?;
    if flag("--selftest") {
        return match selftest() {
            Ok(()) => {
                println!("selftest ok {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            Err(e) => Err(format!("selftest failed: {e}").into()),
        };
    }
    // The Treasury V3 backfill is not implemented here: a non-zero value refuses the start.
    let backfill =
        std::env::var_os("TREASURY_V3_BACKFILL_BLOCKS").map(|v| v.to_string_lossy().into_owned());
    if let Err(e) = conet_node::treasury_v3::check_backfill_env(backfill.as_deref()) {
        return Err(e.into());
    }
    if let Some(flag) = valueless_flag(argv()) {
        return Err(format!("{flag} is given without a value; refusing to start").into());
    }
    // The one-shot mailbox migration steps of a cutover or a rollback (TS stopped, this node not running): counts only are printed.
    // The reconciliation views: only the number of keys, the number of messages and one SHA-256 over the sorted (key, armor hash) pairs are printed.
    if let Some(dir) = arg("--ts-mailbox-digest") {
        let d = conet_node::ts_mailbox::ts_dir_digest(std::path::Path::new(&dir))?;
        println!(
            "ts-mailbox-digest: keys={} messages={} sha256={}",
            d.keys, d.messages, d.sha256
        );
        return Ok(());
    }
    if flag("--mailbox-digest") {
        let Some(db) = setting("--mailbox-db") else {
            return Err("--mailbox-db is required for --mailbox-digest".into());
        };
        if !std::path::Path::new(&db).is_file() {
            return Err("the mailbox database does not exist; the digest never creates one".into());
        }
        // a READ-ONLY open of the file: no write transaction, nothing created or changed
        let d = conet_node::ts_mailbox::store_digest_at(std::path::Path::new(&db))?;
        println!(
            "mailbox-digest: keys={} messages={} sha256={}",
            d.keys, d.messages, d.sha256
        );
        return Ok(());
    }
    let (import_dir, export_dir) = (arg("--import-ts-mailbox"), arg("--export-ts-mailbox"));
    if import_dir.is_some() || export_dir.is_some() {
        return run_ts_mailbox(import_dir, export_dir, setting("--mailbox-db"));
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
    let mut epoch_rpc = None;
    let (routes, user_routes): (Arc<RouteTable>, Option<Arc<dyn UserRoutes>>) =
        if let Some(url) = setting("--rpc") {
            let rpc = Rpc::new(&url)?;
            epoch_rpc = Some(rpc.clone());
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
    ctx.epoch_rpc = epoch_rpc;
    ctx.mining_node_ip = mining_node_ip_from(arg("--node-ip-address").as_deref())?;
    // Off unless asked: node-side delivery evidence for tests (see `evidence`).
    if let Some(path) = arg("--evidence-log") {
        let log =
            conet_node::evidence::EvidenceLog::open(std::path::Path::new(&path), &ctx.key_id)?;
        log.start(env!("CARGO_PKG_VERSION"));
        ctx.evidence = Some(Arc::new(log));
    }
    ctx.mining_liveness_enabled = flag("--mining-liveness");
    let api_base = setting("--api-base");
    if let (true, Some(base), Some(ur)) = (
        push_enabled(api_base.as_deref(), user_routes.is_some()),
        api_base.as_deref(),
        user_routes.clone(),
    ) {
        let node_wallet = ctx.wallet.address();
        let api: Arc<dyn Push> =
            Arc::new(Arc::new(BeamioApi::new(base, notices, ur, node_wallet)?));
        ctx.mailbox = Arc::new(Mailbox::new(store, api.clone()));
        ctx.push = api;
    }
    for msg in push_disabled_reasons(api_base.as_deref(), user_routes.is_some()) {
        eprintln!("{msg}");
    }
    // Public addresses: every entry must parse; with --egress-policy they are required. Checked
    // here so a bad value stops the start even when the exit itself stays off.
    let public_ips = public_ips_from(
        arg("--public-ip").as_deref(),
        arg("--egress-policy").is_some(),
    )?;
    // SilentPass exit: needs a policy file and the chain (passport checks); off otherwise.
    if let (Some(url), Some(path)) = (setting("--rpc"), arg("--egress-policy")) {
        if let Some(exit) = egress_exit(&url, &path, ctx.wallet.address(), public_ips)? {
            ctx.exit = Some(Arc::new(exit));
        }
    } else if arg("--egress-policy").is_some() {
        eprintln!("exit off: --egress-policy needs --rpc (passport checks)");
    }
    ctx.user_routes = user_routes;
    ctx.offers = offers;
    ctx.old_key_ids = old_key_ids;
    routes.set_own_aliases(&ctx.old_key_ids);
    if let Some(b) = max_body_from(arg("--max-body").as_deref())? {
        ctx.limits.max_body_bytes = b;
    }
    if flag("--no-legacy-chat-listen") {
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
    // Optional chain observers are deliberately opt-in. They use HTTP JSON-RPC only and never
    // request signatures or submit transactions. In particular, this keeps a normal node start
    // from unexpectedly scanning Treasury history or calling the Epoch contracts.
    if flag("--epoch-watch") {
        let url = setting("--rpc").ok_or("--epoch-watch requires --rpc <http-url>")?;
        tokio::spawn(conet_node::runtime::run_epoch_watch(
            Rpc::new(&url)?,
            Duration::from_secs(12),
        ));
    }
    if flag("--treasury-v3-watch") {
        let address_override = arg("--treasury-v3-address");
        let address = conet_node::runtime::treasury_address_from_os(
            address_override.as_deref(),
            std::env::var_os("TREASURY_V3_ADDRESS"),
        )?;
        let base_rpc = setting("--treasury-v3-base-rpc")
            .ok_or("--treasury-v3-watch requires --treasury-v3-base-rpc <http-url>")?;
        let conet_rpc = setting("--treasury-v3-conet-rpc")
            .ok_or("--treasury-v3-watch requires --treasury-v3-conet-rpc <http-url>")?;
        let base_deploy = arg("--treasury-v3-base-deploy-block")
            .ok_or("--treasury-v3-base-deploy-block <block>")?
            .parse::<u64>()
            .map_err(|_| "--treasury-v3-base-deploy-block must be a u64")?;
        let conet_deploy = arg("--treasury-v3-conet-deploy-block")
            .ok_or("--treasury-v3-conet-deploy-block <block>")?
            .parse::<u64>()
            .map_err(|_| "--treasury-v3-conet-deploy-block must be a u64")?;
        let state_dir = arg("--runtime-state-dir").ok_or("--runtime-state-dir <directory>")?;
        for (chain, rpc, deploy, chain_id) in [
            ("base", base_rpc, base_deploy, 8_453),
            (
                "conet",
                conet_rpc,
                conet_deploy,
                conet_node::chain::CONET_CHAIN_ID,
            ),
        ] {
            tokio::spawn(conet_node::runtime::run_treasury_v3_scan(
                Rpc::new(&rpc)?,
                address,
                chain_id,
                ctx.wallet.address().parse::<alloy_primitives::Address>()?,
                std::path::PathBuf::from(&state_dir),
                chain,
                deploy,
                Duration::from_secs(12),
            ));
        }
    }
    // Stake term watch (read-only, log lines only): with a NodeRegistryV2.
    if let (Some(url), Some(reg)) = (setting("--rpc"), arg("--node-registry")) {
        let every = arg("--term-watch-secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(600u64)
            .max(30);
        let reader = conet_node::nr2::Nr2Reader {
            rpc: Rpc::new(&url)?,
            registry: reg,
        };
        tokio::spawn(conet_node::term_watch::run(
            reader,
            ctx.wallet.address(),
            Duration::from_secs(every),
        ));
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
        let staging = flag("--acme-staging");
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
    flag_in(argv(), name)
}

fn flag_in(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Build the exit from the policy file and the operator's limits; None = stays off (reason
/// printed). Errors only for unreadable or invalid policy files.
fn egress_exit(
    rpc_url: &str,
    policy_path: &str,
    own_wallet: String,
    public: Vec<std::net::IpAddr>,
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

#[cfg(test)]
mod arg_tests {
    use super::{arg_in, flag_in, mining_node_ip_from};

    /// Every flag `main` reads through `arg()`.
    const FLAGS: [&str; 33] = [
        "--acme-cache",
        "--acme-contact",
        "--acme-directory",
        "--acme-directory-root",
        "--acme-dns-daemon",
        "--acme-mode",
        "--api-base",
        "--dev-route-key",
        "--egress-policy",
        "--evidence-log",
        "--export-ts-mailbox",
        "--health-listen",
        "--import-ts-mailbox",
        "--init-config",
        "--listen",
        "--mailbox-db",
        "--max-body",
        "--node-lens",
        "--node-ip-address",
        "--node-registry",
        "--public-ip",
        "--routes",
        "--rpc",
        "--signer-socket",
        "--term-watch-secs",
        "--tls-cert",
        "--tls-domain",
        "--tls-key",
        "--tls-listen",
        "--ts-mailbox-digest",
        "--webrtc-cert",
        "--webrtc-listen",
        "--webrtc-public",
    ];

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn mining_node_ip_is_explicit_and_strict() {
        assert_eq!(mining_node_ip_from(None), Ok(None));
        assert_eq!(
            mining_node_ip_from(Some("203.0.113.7")),
            Ok(Some("203.0.113.7".parse().unwrap()))
        );
        assert!(mining_node_ip_from(Some("203.0.113.7:80")).is_err());
        assert!(mining_node_ip_from(Some("2001:db8::1")).is_err());
        assert!(mining_node_ip_from(Some(" ")).is_err());
    }

    #[test]
    fn mining_liveness_requires_an_explicit_flag() {
        assert!(!flag_in(&argv(&["bin"]), "--mining-liveness"));
        assert!(flag_in(
            &argv(&["bin", "--mining-liveness"]),
            "--mining-liveness"
        ));
    }

    #[test]
    fn every_flag_takes_a_normal_value() {
        for f in FLAGS {
            assert_eq!(
                arg_in(&argv(&["bin", f, "v1"]), f),
                Some("v1".into()),
                "{f}"
            );
        }
    }

    #[test]
    fn every_flag_missing_from_argv_is_none() {
        for f in FLAGS {
            assert_eq!(arg_in(&argv(&["bin", "--other", "x"]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_at_the_end_has_no_value() {
        for f in FLAGS {
            assert_eq!(arg_in(&argv(&["bin", "--other", "x", f]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_followed_by_a_flag_takes_no_value_and_the_next_flag_still_parses() {
        for f in FLAGS {
            let next = if f == "--public-ip" {
                "--listen"
            } else {
                "--public-ip"
            };
            let a = argv(&["bin", f, next, "203.0.113.7"]);
            assert_eq!(arg_in(&a, f), None, "{f} took the next flag");
            assert_eq!(
                arg_in(&a, next),
                Some("203.0.113.7".into()),
                "{next} after {f}"
            );
        }
    }

    #[test]
    fn a_single_dash_value_is_kept() {
        assert_eq!(
            arg_in(&argv(&["bin", "--max-body", "-1"]), "--max-body"),
            Some("-1".into())
        );
    }

    #[test]
    fn an_empty_value_is_kept_for_the_caller_to_judge() {
        // A blank value is still a value here; push_disabled_reason treats it as not set.
        assert_eq!(
            arg_in(&argv(&["bin", "--api-base", ""]), "--api-base"),
            Some(String::new())
        );
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::{valueless_flag, FAIL_CLOSED_FLAGS};

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_fail_closed_flag_without_a_value_refuses_to_start() {
        for f in FAIL_CLOSED_FLAGS {
            assert_eq!(valueless_flag(&argv(&["bin", f])), Some(f), "{f} at end");
            assert_eq!(
                valueless_flag(&argv(&["bin", f, "--public-ip", "203.0.113.7"])),
                Some(f),
                "{f} then flag"
            );
            assert_eq!(valueless_flag(&argv(&["bin", f, ""])), Some(f), "{f} empty");
            assert_eq!(
                valueless_flag(&argv(&["bin", f, " \t"])),
                Some(f),
                "{f} blank"
            );
        }
    }

    #[test]
    fn every_fail_closed_flag_with_a_usable_value_starts() {
        for f in FAIL_CLOSED_FLAGS {
            assert_eq!(valueless_flag(&argv(&["bin", f, "v1"])), None, "{f}");
            assert_eq!(valueless_flag(&argv(&["bin", f, "-1"])), None, "{f} -1");
        }
    }

    #[test]
    fn an_absent_flag_still_starts() {
        for f in FAIL_CLOSED_FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "--other", "x"])),
                None,
                "{f} absent"
            );
        }
    }

    #[test]
    fn a_blank_rpc_is_refused_not_turned_into_static_routes() {
        assert_eq!(
            valueless_flag(&argv(&["bin", "--rpc", "  ", "--routes", "/x"])),
            Some("--rpc")
        );
    }

    #[test]
    fn flags_that_stay_off_or_keep_their_default_are_not_refused_here() {
        // Valueless, these turn a feature off (stricter) or keep the value they had before, so
        // the refusal list leaves them out. --api-base blank turns pushes off (see push gate).
        for f in [
            "--egress-policy",
            "--tls-listen",
            "--webrtc-listen",
            "--api-base",
            "--term-watch-secs",
            "--acme-staging",
        ] {
            assert_eq!(valueless_flag(&argv(&["bin", f])), None, "{f}");
        }
    }

    #[test]
    fn public_ip_is_strict_and_required_with_the_egress_policy() {
        use super::public_ips_from;
        // Absent: fine without the egress policy, required with it.
        assert_eq!(public_ips_from(None, false), Ok(vec![]));
        assert!(public_ips_from(None, true).is_err());
        // A valid address, or a comma-separated list of them.
        assert_eq!(
            public_ips_from(Some("203.0.113.7"), true),
            Ok(vec!["203.0.113.7".parse().unwrap()])
        );
        assert_eq!(
            public_ips_from(Some("203.0.113.7, 2001:db8::1"), false)
                .unwrap()
                .len(),
            2
        );
        // Empty, blank, unparseable, or any single bad entry refuses.
        for bad in [
            "",
            "   ",
            "not-an-ip",
            "203.0.113.7,",
            "203.0.113.7,bogus",
            "203.0.113.999",
        ] {
            assert!(
                public_ips_from(Some(bad), false).is_err(),
                "{bad:?} was accepted"
            );
        }
    }

    #[test]
    fn max_body_is_strict_and_defaults_only_when_absent() {
        use super::max_body_from;
        assert_eq!(max_body_from(None), Ok(None));
        assert_eq!(max_body_from(Some("1024")), Ok(Some(1024)));
        for bad in ["", "   ", "abc", "-1", "1.5"] {
            assert!(max_body_from(Some(bad)).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn the_default_max_body_is_256_kib() {
        assert_eq!(
            conet_node::http::Limits::default().max_body_bytes,
            256 * 1024
        );
    }

    #[test]
    fn the_refusal_names_the_flag_and_no_value() {
        let secret = "0xSECRETpath";
        let got = valueless_flag(&argv(&["bin", "--signer-socket", secret, "--rpc"]));
        assert_eq!(got, Some("--rpc"));
        assert!(!got.unwrap().contains(secret));
    }
}

//! `conet-node` daemon (M1).
//!
//! Production: `--signer-socket <path>`; keys stay in the `conet-signer` process.
//! `--insecure-dev-keys` reads a TEST route key and wallet for local networks only.
//!
//! Routes: `--rpc <url>` reads the node table (GuardianNodesInfoV6) and AddressPGP from chain;
//! `--routes <routes.json>` uses a static table (local test networks).
use conet_node::chain::{AddressPgp, GuardianV6, NodeSource, Rpc, UserRoutes};
use conet_node::push::{BeamioApi, Push};
use conet_node::route::{RouteTable, StaticRoutes};
use conet_node::store::{DiskStore, MailboxStore, MemoryStore};
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

type Keys = (
    Arc<dyn RouteDecryptor>,
    Arc<dyn WalletSigner>,
    Arc<dyn NodeNotices>,
    String,
);

fn keys() -> Result<Keys, Box<dyn std::error::Error>> {
    if let Some(sock) = arg("--signer-socket") {
        let c = Arc::new(si_signer::client::SignerClient::connect(sock)?);
        let id = c.route_key_id().to_string();
        return Ok((c.clone(), c.clone(), c, id));
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
        return Ok((Arc::new(key), w.clone(), w, id));
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let (decryptor, wallet, notices, key_id) = keys()?;
    let store: Arc<dyn MailboxStore> = match arg("--mailbox-db") {
        Some(p) => Arc::new(DiskStore::open(std::path::Path::new(&p))?),
        None => {
            eprintln!("WARNING: no --mailbox-db; offline mail is kept in memory only");
            Arc::new(MemoryStore::default())
        }
    };

    let mut source: Option<Arc<dyn NodeSource>> = None;
    let (routes, user_routes): (Arc<RouteTable>, Option<Arc<dyn UserRoutes>>) =
        if let Some(url) = arg("--rpc") {
            let rpc = Rpc::new(&url)?;
            source = Some(Arc::new(GuardianV6::new(rpc.clone())));
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
        let api: Arc<dyn Push> = Arc::new(Arc::new(BeamioApi::new(&base, notices, ur)?));
        ctx.mailbox = Arc::new(Mailbox::new(store, api.clone()));
        ctx.push = api;
    }
    ctx.user_routes = user_routes;
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
        tokio::spawn(watcher::run(
            src,
            routes,
            ctx.chain.clone(),
            watcher::WatchOpts::default(),
        ));
    }
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, key_id = %ctx.key_id, "conet-node listening");
    server::serve(listener, ctx).await?;
    Ok(())
}

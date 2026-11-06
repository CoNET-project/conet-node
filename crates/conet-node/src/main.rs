//! `conet-node` daemon (M1).
//!
//! Production: `--signer-socket <path>`; keys stay in the `conet-signer` process.
//! `--insecure-dev-keys` reads a TEST route key and wallet from files/env for local networks only.
use conet_node::{
    http::Limits,
    route::{RouteTable, StaticRoutes},
    server,
    store::MemoryStore,
};
use si_core::{RouteDecryptor, WalletSigner};
use std::sync::Arc;
use std::time::Duration;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}

type Keys = (Arc<dyn RouteDecryptor>, Arc<dyn WalletSigner>, String);

fn keys() -> Result<Keys, Box<dyn std::error::Error>> {
    if let Some(sock) = arg("--signer-socket") {
        let c = Arc::new(si_signer::client::SignerClient::connect(sock)?);
        let id = c.route_key_id().to_string();
        return Ok((c.clone(), c, id));
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
        let wallet = si_crypto::eth::EthKey::from_hex(
            &std::env::var("CONET_DEV_WALLET_KEY").map_err(|_| "CONET_DEV_WALLET_KEY")?,
        )?;
        return Ok((Arc::new(key), Arc::new(wallet), id));
    }
    Err("need --signer-socket <path> (or --insecure-dev-keys for local tests)".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let routes: StaticRoutes = serde_json::from_str(&std::fs::read_to_string(
        arg("--routes").ok_or("--routes <routes.json>")?,
    )?)?;
    let (decryptor, wallet, key_id) = keys()?;
    let ctx = Arc::new(server::NodeCtx {
        routes: Arc::new(RouteTable::from_static(&key_id, &routes)),
        key_id,
        decryptor,
        wallet,
        store: Arc::new(MemoryStore::default()),
        limits: Limits::default(),
        connect_timeout: Duration::from_secs(8),
        max_connections: 4096,
    });
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, key_id = %ctx.key_id, "conet-node listening");
    server::serve(listener, ctx).await?;
    Ok(())
}

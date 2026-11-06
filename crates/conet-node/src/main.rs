//! `conet-node` daemon (M1 stage A1).
//!
//! Stage A1 has no signer process yet, so it only runs with `--insecure-dev-keys`, reading
//! a test route key and test wallet from environment variables. Never use it with real keys:
//! the product loads keys inside the signer process (line B).
use conet_node::{
    http::Limits,
    route::{RouteTable, StaticRoutes},
    server,
    store::MemoryStore,
};
use std::sync::Arc;
use std::time::Duration;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    if !std::env::args().any(|a| a == "--insecure-dev-keys") {
        eprintln!("stage A1 needs --insecure-dev-keys (test keys only; the signer process comes with line B)");
        std::process::exit(2);
    }
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:8080".into());
    let routes_path = arg("--routes").ok_or("--routes <routes.json> required")?;
    let key_armor = std::fs::read_to_string(
        arg("--dev-route-key").ok_or("--dev-route-key <armored test key> required")?,
    )?;
    let pass = std::env::var("CONET_DEV_ROUTE_PASS").unwrap_or_default();
    let wallet_hex = std::env::var("CONET_DEV_WALLET_KEY")
        .map_err(|_| "CONET_DEV_WALLET_KEY (test wallet) required")?;

    let (key, key_id) = si_core::node::load_route(&key_armor, &pass)?;
    let wallet = si_crypto::eth::EthKey::from_hex(&wallet_hex)?;
    let routes: StaticRoutes = serde_json::from_str(&std::fs::read_to_string(routes_path)?)?;
    let ctx = Arc::new(server::NodeCtx {
        routes: Arc::new(RouteTable::from_static(&key_id, &routes)),
        key_id,
        decryptor: Arc::new(key),
        wallet: Arc::new(wallet),
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

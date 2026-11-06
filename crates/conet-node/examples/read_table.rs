//! Read-only check against a CoNET RPC: node table size and key-ID checks. Prints counts only.
//! Usage: cargo run --example read_table -- <rpc url>
use conet_node::chain::{AddressPgp, GuardianV6, NodeSource, Rpc, UserRoutes};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).ok_or("rpc url")?;
    let rpc = Rpc::new(&url)?;
    let src = GuardianV6::new(rpc.clone());
    let t0 = std::time::Instant::now();
    let (version, block) = src.version().await?;
    let snap = src.read(block).await?;
    println!(
        "block={block} version={}… nodes={} rejected={} in {:?}",
        &version[..10],
        snap.nodes.len(),
        snap.rejected,
        t0.elapsed()
    );
    // AddressPGP: resolve the route of the first node's own key (expected: none) to exercise decoding.
    let apgp = AddressPgp::new(rpc);
    let r = apgp.route_of_user_key(&snap.nodes[0].key_id).await?;
    println!(
        "addresspgp decode ok (route of a node key: {})",
        if r.is_some() { "some" } else { "none" }
    );
    Ok(())
}

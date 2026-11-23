//! CoNET-SI `mining` SSE presence publisher. Pool snapshots contain only successfully verified
//! `mining_validator` messages; fields without a Rust source are intentionally omitted.

use crate::chain::Rpc;
use crate::epoch;
use crate::server::NodeCtx;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};

const CHANNEL_CAPACITY: usize = 4;
const MAX_LISTENERS: usize = 100_000;
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct MiningLiveness {
    next_id: AtomicU64,
    listeners: Mutex<HashMap<String, (u64, mpsc::Sender<Vec<u8>>)>>,
}

impl MiningLiveness {
    pub fn register(&self, wallet: String) -> Option<(u64, mpsc::Receiver<Vec<u8>>)> {
        let mut listeners = self.listeners.lock().expect("mining liveness listeners");
        if !listeners.contains_key(&wallet) && listeners.len() >= MAX_LISTENERS {
            return None;
        }
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        listeners.insert(wallet, (id, tx));
        Some((id, rx))
    }

    pub fn remove(&self, wallet: &str, id: u64) {
        let mut listeners = self.listeners.lock().expect("mining liveness listeners");
        if listeners
            .get(wallet)
            .is_some_and(|(current, _)| *current == id)
        {
            listeners.remove(wallet);
        }
    }

    fn wallets(&self) -> Vec<String> {
        let listeners = self.listeners.lock().expect("mining liveness listeners");
        let mut wallets: Vec<_> = listeners.keys().cloned().collect();
        wallets.sort_unstable();
        wallets
    }

    fn send(&self, wallet: &str, frame: Vec<u8>) -> bool {
        let mut listeners = self.listeners.lock().expect("mining liveness listeners");
        let Some((_, tx)) = listeners.get(wallet) else {
            return false;
        };
        match tx.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                listeners.remove(wallet);
                false
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(
                    wallet,
                    "mining liveness listener is behind; dropping stale frame"
                );
                true
            }
        }
    }
}

pub async fn run_publisher(ctx: Arc<NodeCtx>) {
    if !ctx.mining_liveness_enabled {
        debug!("mining liveness publisher disabled: --mining-liveness not enabled");
        return;
    }
    if ctx.mining_node_ip.is_none() {
        debug!("mining liveness publisher disabled: --node-ip-address not configured");
        return;
    }
    let Some(rpc) = ctx.epoch_rpc.clone() else {
        debug!("mining liveness publisher disabled: CoNET RPC unavailable");
        return;
    };
    let mut last_head = None;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        match publish_tick(&ctx, &rpc, &mut last_head).await {
            Ok(()) => {}
            Err(error) => warn!(%error, "mining liveness data unavailable; no heartbeat emitted"),
        }
    }
}

async fn publish_tick(ctx: &NodeCtx, rpc: &Rpc, last_head: &mut Option<u64>) -> Result<(), String> {
    let node_ip_addr = ctx
        .mining_node_ip
        .ok_or_else(|| "configured nodeIpAddr unavailable".to_string())?
        .to_string();
    match rpc.chain_id().await.map_err(|e| e.to_string())? {
        crate::chain::CONET_CHAIN_ID => {}
        other => return Err(format!("unexpected CoNET chain id {other}")),
    }
    let head = rpc.block_number().await.map_err(|e| e.to_string())?;
    if !epoch::checks_this_block(head) || *last_head == Some(head) {
        return Ok(());
    }
    let info = epoch::read_current_info(rpc)
        .await
        .map_err(|e| e.to_string())?;
    let Some(rate) = epoch::current_rate(&info) else {
        return Err("currentInfo has no active rate".into());
    };
    let total_miners = u64::try_from(rate.total_miners)
        .map_err(|_| "currentInfo totalMiners exceeds response range")?;
    let total_users = u64::try_from(rate.total_usrs)
        .map_err(|_| "currentInfo totalUsrs exceeds response range")?;
    let (node_wallets, user_wallets) = ctx.validator_pools.snapshot(Instant::now());
    let listeners = ctx.mining_liveness.wallets();
    let miner_rate = alloy_primitives::utils::format_ether(rate.miner_rate)
        .parse::<f64>()
        .map_err(|_| "currentInfo minerRate is not numeric")?;
    if !miner_rate.is_finite() {
        return Err("currentInfo minerRate is not finite".into());
    }
    let node_wallet = ctx.wallet.address().to_ascii_lowercase();

    for wallet in listeners {
        let notices = ctx.notices.clone();
        let sign_wallet = wallet.clone();
        let signature = tokio::task::spawn_blocking(move || {
            notices.sign_validator_heartbeat(head, &sign_wallet)
        })
        .await
        .map_err(|e| format!("heartbeat signer task: {e}"))?
        .map_err(|e| format!("heartbeat signing unavailable: {e}"))?;
        let payload = json!({
            "status": 200,
            "epoch": head.to_string(),
            "rate": miner_rate,
            "hash": signature,
            "nodeWallet": node_wallet.clone(),
            "online": total_miners,
            "nodeDomain": ctx.key_id.clone(),
            "nodeIpAddr": node_ip_addr,
            "nodeWallets": node_wallets.clone(),
            "minerResponseHash": "",
            "userWallets": user_wallets.clone(),
            "totalUsers": total_users,
        });
        let frame = format!("data: {payload}\r\n\r\n").into_bytes();
        ctx.mining_liveness.send(&wallet, frame);
    }
    *last_head = Some(head);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::RouteTable;
    use crate::store::MemoryStore;
    use si_core::{RouteDecryptor, WalletSigner};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct UnusedDecryptor;
    impl RouteDecryptor for UnusedDecryptor {
        fn decrypt(&self, _: &str) -> si_crypto::Result<Vec<u8>> {
            unreachable!()
        }
    }

    fn ctx() -> NodeCtx {
        let wallet = Arc::new(
            si_crypto::eth::EthKey::from_hex(&format!("0x{}", "00".repeat(31) + "01")).unwrap(),
        );
        NodeCtx::new(
            "NODEKEY".into(),
            Arc::new(UnusedDecryptor),
            wallet.clone() as Arc<dyn WalletSigner>,
            wallet,
            Arc::new(RouteTable::new("NODEKEY", Duration::from_secs(60))),
            Arc::new(MemoryStore::default()),
        )
    }

    #[tokio::test]
    async fn missing_advertised_ip_is_unavailable_and_emits_no_partial_frame() {
        let ctx = ctx();
        let target = "0x0000000000000000000000000000000000000002".to_string();
        let (_id, mut receiver) = ctx.mining_liveness.register(target).unwrap();
        let rpc = Rpc::new("http://127.0.0.1:1").unwrap();
        let mut last_head = None;
        let error = publish_tick(&ctx, &rpc, &mut last_head).await.unwrap_err();
        assert!(error.contains("configured nodeIpAddr unavailable"));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(last_head, None);
    }

    #[tokio::test]
    async fn publisher_is_disabled_by_default_and_emits_nothing() {
        let ctx = Arc::new(ctx());
        let (_id, mut receiver) = ctx
            .mining_liveness
            .register("0x0000000000000000000000000000000000000002".into())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), run_publisher(ctx.clone()))
            .await
            .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    async fn rpc_url(responses: Vec<(String, String)>) -> String {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let responses: HashMap<String, String> = responses.into_iter().collect();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut scratch = [0u8; 2048];
                let body = loop {
                    let n = stream.read(&mut scratch).await.unwrap();
                    if n == 0 {
                        break Vec::new();
                    }
                    bytes.extend_from_slice(&scratch[..n]);
                    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break bytes[end + 4..end + 4 + length].to_vec();
                    }
                };
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let method = request["method"].as_str().unwrap_or("");
                let response = responses.get(method).cloned().unwrap_or_else(|| {
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unexpected method"}}"#.into()
                });
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn emits_signed_loopback_heartbeat_with_verified_pool_snapshots() {
        let mut ctx = ctx();
        ctx.mining_node_ip = Some("203.0.113.7".parse().unwrap());
        let miner = "0x0000000000000000000000000000000000000002";
        let user = "0x0000000000000000000000000000000000000003";
        assert!(ctx.validator_pools.record(
            &crate::validator_mining::Accept::Miner {
                wallet: miner.into(),
                data: serde_json::Value::Null,
            },
            Instant::now(),
        ));
        assert!(ctx.validator_pools.record(
            &crate::validator_mining::Accept::User {
                wallet: user.into(),
                data: serde_json::Value::Null,
            },
            Instant::now(),
        ));
        let (_id, mut receiver) = ctx.mining_liveness.register(user.into()).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/epoch_readonly.json")).unwrap();
        let current_info = fixture["currentInfo"][0]["returndata"].as_str().unwrap();
        let url = rpc_url(vec![
            (
                "eth_chainId".into(),
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":"0x{:x}"}}"#,
                    crate::chain::CONET_CHAIN_ID
                ),
            ),
            (
                "eth_blockNumber".into(),
                r#"{"jsonrpc":"2.0","id":1,"result":"0xa"}"#.into(),
            ),
            (
                "eth_call".into(),
                format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{current_info}"}}"#),
            ),
        ])
        .await;
        let rpc = Rpc::new(&url).unwrap();
        let mut last_head = None;
        publish_tick(&ctx, &rpc, &mut last_head).await.unwrap();
        assert_eq!(last_head, Some(10));
        let frame = receiver.try_recv().unwrap();
        let frame = String::from_utf8(frame).unwrap();
        let payload: serde_json::Value = serde_json::from_str(
            frame
                .strip_prefix("data: ")
                .unwrap()
                .trim_end_matches("\r\n\r\n"),
        )
        .unwrap();
        assert_eq!(payload["epoch"], "10");
        assert_eq!(payload["rate"], 2.5);
        assert_eq!(payload["online"], 17);
        assert_eq!(payload["totalUsers"], 9876);
        assert_eq!(payload["nodeIpAddr"], "203.0.113.7");
        assert_eq!(payload["nodeWallets"][0], miner);
        assert_eq!(payload["userWallets"][0], user);
        assert!(payload.get("connetingNodes").is_none());
        assert!(payload.get("transfer").is_none());
        let text = si_proto::validator_heartbeat_text(10, user).unwrap();
        assert_eq!(
            si_crypto::eth::recover_message(&text, payload["hash"].as_str().unwrap()).unwrap(),
            ctx.wallet.address()
        );
    }
}

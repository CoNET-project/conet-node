//! Optional, HTTP-only runtime observers for the Treasury V3 and Epoch readers.
//!
//! These loops are opt-in and read-only. They keep the library scanners/decoders connected to the
//! Linux process lifecycle, persist the Treasury scan cursor, retry RPC failures without advancing
//! state, and report explicit inactive/no-contract states. They do not sign or submit transactions
//! and do not execute the TypeScript restart command.
use crate::chain::{ChainError, Rpc};
use crate::epoch::{self, CurrentRate};
use crate::treasury_v3::{ReadOnlyCursorStore, ReadOnlyScanner};
use crate::treasury_v3_miner;
use alloy_primitives::Address;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochTick {
    OddBlock { head: u64 },
    RepeatedBlock { head: u64 },
    Inactive { head: u64 },
    Active { head: u64, rate: CurrentRate },
}

/// One observable Epoch tick. A valid zero epoch is reported as `Inactive`; RPC/decode failure is
/// an error and never becomes a zero/default rate. Repeated/odd heads do not read contract state.
pub async fn epoch_tick(rpc: &Rpc, last_head: Option<u64>) -> Result<EpochTick, ChainError> {
    let head = rpc.block_number().await?;
    if last_head == Some(head) {
        return Ok(EpochTick::RepeatedBlock { head });
    }
    if !epoch::checks_this_block(head) {
        return Ok(EpochTick::OddBlock { head });
    }
    let info = epoch::read_current_info(rpc).await?;
    match epoch::current_rate(&info) {
        Some(rate) => Ok(EpochTick::Active { head, rate }),
        None => Ok(EpochTick::Inactive { head }),
    }
}

pub async fn run_epoch_watch(rpc: Rpc, interval: Duration) {
    let mut last_head = None;
    loop {
        match epoch_tick(&rpc, last_head).await {
            Ok(EpochTick::OddBlock { head }) => tracing::debug!(head, "epoch watch: odd block"),
            Ok(EpochTick::RepeatedBlock { head }) => {
                tracing::debug!(head, "epoch watch: unchanged")
            }
            Ok(EpochTick::Inactive { head }) => {
                last_head = Some(head);
                tracing::info!(head, "epoch watch: valid currentInfo with epoch zero");
                log_restart_state(&rpc).await;
            }
            Ok(EpochTick::Active { head, rate }) => {
                last_head = Some(head);
                tracing::info!(
                    head,
                    epoch = %rate.epoch,
                    total_miners = %rate.total_miners,
                    miner_rate_wei = %rate.miner_rate,
                    total_users = %rate.total_usrs,
                    "epoch watch: currentInfo"
                );
                log_restart_state(&rpc).await;
            }
            Err(error) => tracing::warn!(%error, "epoch watch: RPC/decode unavailable; retrying"),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn log_restart_state(rpc: &Rpc) {
    match epoch::read_restart_block(rpc).await {
        Ok(None) => tracing::info!("epoch watch: restart contract has no code"),
        Ok(Some(block)) => {
            tracing::info!(restart_block = %block, "epoch watch: restart advice input")
        }
        Err(error) => tracing::warn!(%error, "epoch watch: restart read unavailable"),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run_treasury_v3_scan(
    rpc: Rpc,
    address: Address,
    expected_chain_id: u64,
    miner_wallet: Address,
    state_dir: PathBuf,
    chain: &str,
    deploy_block: u64,
    interval: Duration,
) {
    match treasury_v3_eligible(&rpc, address, expected_chain_id, miner_wallet).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(chain, wallet = %format!("{miner_wallet:#x}"), "Treasury V3 scan: configured signer is not an eligible miner");
            return;
        }
        Err(error) => {
            tracing::error!(%error, chain, "Treasury V3 scan: miner eligibility unavailable; refusing to scan");
            return;
        }
    }
    let store = match ReadOnlyCursorStore::for_chain(&state_dir, chain) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, chain, "Treasury V3 scan: invalid cursor store");
            return;
        }
    };
    let mut scanner = ReadOnlyScanner::new(rpc.clone(), address, store, deploy_block, 400, 4);
    let mut started = false;
    loop {
        match rpc.block_number().await {
            Ok(head) => {
                if !started {
                    match scanner.start(head, now_unix()) {
                        Ok(cursor) => {
                            started = true;
                            tracing::info!(
                                chain,
                                head,
                                last_processed = cursor.last_processed,
                                scan_target = cursor.scan_target,
                                deploy_block,
                                "Treasury V3 read-only scanner started"
                            );
                        }
                        Err(error) => {
                            tracing::error!(%error, chain, "Treasury V3 scan: cursor start failed")
                        }
                    }
                } else {
                    match scanner.tick(head, now_unix()).await {
                        Ok(Some(tick)) if tick.failures > 0 => tracing::warn!(
                            chain,
                            from = tick.window.from,
                            to = tick.window.to,
                            failures = tick.failures,
                            "Treasury V3 scan: malformed/unmatched log; cursor held for retry"
                        ),
                        Ok(Some(tick)) => {
                            for operation in tick.ops {
                                tracing::info!(
                                    chain,
                                    operation_id = %format!("{:#x}", operation.operation_id),
                                    source_block = operation.source_block_number,
                                    "Treasury V3 BridgeOperation observed (read-only)"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(%error, chain, "Treasury V3 scan: retrying same cursor")
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, chain, "Treasury V3 scan: head unavailable; retrying")
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// Validate the configured endpoint before using a chain-specific Treasury address. Wrong-chain
/// RPC, chainId failure, and isMiner failure stay errors; an explicit `false` is the sole
/// ineligible result.
pub async fn treasury_v3_eligible(
    rpc: &Rpc,
    address: Address,
    expected_chain_id: u64,
    miner_wallet: Address,
) -> Result<bool, ChainError> {
    let actual = rpc.chain_id().await?;
    if actual != expected_chain_id {
        return Err(ChainError(format!(
            "Treasury V3 expected chainId {expected_chain_id}, got {actual}"
        )));
    }
    treasury_v3_miner::is_miner(rpc, &format!("{address:#x}"), miner_wallet).await
}

pub fn treasury_address(raw: &str) -> Result<Address, String> {
    Address::from_str(raw.trim())
        .map_err(|_| "--treasury-v3-address must be an Ethereum address".into())
}

pub const DEFAULT_TREASURY_V3_ADDRESS: &str = "0xa208982212978550594A7FEEB70a61665d129003";

/// Mirror the TypeScript `TREASURY_V3_ADDRESS` source: explicit CLI override, then environment,
/// then the reviewed source default. A present but blank override is an error rather than a
/// fallback to another address.
pub fn treasury_address_from(cli: Option<&str>, env: Option<&str>) -> Result<Address, String> {
    match cli.or(env) {
        Some(raw) => treasury_address(raw),
        None => treasury_address(DEFAULT_TREASURY_V3_ADDRESS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        loop {
            let n = stream.read(&mut tmp).await.unwrap();
            assert_ne!(n, 0);
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|x| x == b"\r\n\r\n") {
                let head_end = i + 4;
                let head = String::from_utf8_lossy(&buf[..head_end]);
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|s| s.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + content_length {
                    let n = stream.read(&mut tmp).await.unwrap();
                    assert_ne!(n, 0);
                    buf.extend_from_slice(&tmp[..n]);
                }
                return buf;
            }
        }
    }

    async fn rpc_http(responses: Vec<(u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = read_http_request(&mut stream).await;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn treasury_address_requires_a_valid_address() {
        assert!(treasury_address("0xa208982212978550594A7FEEB70a61665d129003").is_ok());
        assert!(treasury_address("not-an-address").is_err());
        assert!(treasury_address_from(None, None).is_ok());
        assert!(treasury_address_from(None, Some(" ")).is_err());
        assert!(
            treasury_address_from(Some("0x0000000000000000000000000000000000000001"), None).is_ok()
        );
    }

    #[tokio::test]
    async fn epoch_tick_keeps_explicit_zero_and_rpc_failure_distinct() {
        let zero_info = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}\"}}",
            "00".repeat(128)
        );
        let url = rpc_http(vec![
            (200, r#"{"jsonrpc":"2.0","id":1,"result":"0x2"}"#.into()),
            (200, zero_info),
        ])
        .await;
        let rpc = Rpc::new(&url).unwrap();
        assert!(matches!(
            epoch_tick(&rpc, None).await,
            Ok(EpochTick::Inactive { head: 2 })
        ));

        let url = rpc_http(vec![(503, r#"{"error":"unavailable"}"#.into())]).await;
        let rpc = Rpc::new(&url).unwrap();
        assert!(epoch_tick(&rpc, None).await.is_err());
    }

    #[tokio::test]
    async fn treasury_startup_gate_distinguishes_chain_miner_and_rpc_failure() {
        let true_word = format!("0x{}01", "00".repeat(31));
        let url = rpc_http(vec![
            (200, r#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#.into()),
            (
                200,
                format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{true_word}"}}"#),
            ),
        ])
        .await;
        let rpc = Rpc::new(&url).unwrap();
        let address = Address::repeat_byte(0x11);
        let wallet = Address::repeat_byte(0x22);
        assert!(treasury_v3_eligible(&rpc, address, 8_453, wallet)
            .await
            .unwrap());

        let url = rpc_http(vec![(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x36d0e"}"#.into(),
        )])
        .await;
        let rpc = Rpc::new(&url).unwrap();
        assert!(treasury_v3_eligible(&rpc, address, 8_453, wallet)
            .await
            .is_err());

        let url = rpc_http(vec![
            (200, r#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#.into()),
            (
                200,
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
                    "00".repeat(32)
                ),
            ),
        ])
        .await;
        let rpc = Rpc::new(&url).unwrap();
        assert!(!treasury_v3_eligible(&rpc, address, 8_453, wallet)
            .await
            .unwrap());

        let url = rpc_http(vec![(503, r#"{"error":"unavailable"}"#.into())]).await;
        let rpc = Rpc::new(&url).unwrap();
        assert!(treasury_v3_eligible(&rpc, address, 8_453, wallet)
            .await
            .is_err());
    }
}

//! Treasury V3 scan tick against an in-process JSON-RPC node (loopback, ephemeral port). The node
//! filters `eth_getLogs` by address, topic and block range, like a real node. The logs are the TS
//! fixture logs placed at real block numbers, and the expected operations are the TS outputs with
//! those block numbers filled in. No network.
use alloy_primitives::Address;
use alloy_sol_types::SolEvent;
use conet_node::chain::Rpc;
use conet_node::treasury_v3::{
    check_backfill_env, load_cursor, save_cursor, scan_tick, start_cursor, ReadOnlyCursorStore,
    ReadOnlyScanner, ScanError, Window,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TREASURY: &str = "0xa208982212978550594A7FEEB70a61665d129003";
const DEPLOY: u64 = 100;

fn fixture() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/treasury_v3_bridge_operation.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn hexn(n: u64) -> String {
    format!("0x{n:x}")
}

struct Node {
    url: String,
    /// Every eth_getLogs filter the node received, in order.
    requests: Arc<Mutex<Vec<Value>>>,
    logs: Arc<Mutex<Vec<Value>>>,
    fail_get_logs: Arc<AtomicBool>,
    /// When set, the node ignores the address in the filter (a misbehaving node).
    loose_address: Arc<AtomicBool>,
}

fn filter_matches(f: &Value, log: &Value, loose: bool) -> bool {
    let addr_ok = loose
        || f["address"].as_str().is_some_and(|a| {
            log["address"]
                .as_str()
                .is_some_and(|b| a.eq_ignore_ascii_case(b))
        });
    let topic_ok = f["topics"][0]
        .as_str()
        .is_some_and(|t| log["topics"][0].as_str() == Some(t));
    let block =
        |v: &Value| u64::from_str_radix(v.as_str().unwrap_or("").trim_start_matches("0x"), 16).ok();
    let (Some(from), Some(to), Some(b)) = (
        block(&f["fromBlock"]),
        block(&f["toBlock"]),
        block(&log["blockNumber"]),
    ) else {
        return false;
    };
    addr_ok && topic_ok && b >= from && b <= to
}

async fn node(logs: Vec<Value>) -> Node {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let n = Node {
        url,
        requests: Arc::new(Mutex::new(Vec::new())),
        logs: Arc::new(Mutex::new(logs)),
        fail_get_logs: Arc::new(AtomicBool::new(false)),
        loose_address: Arc::new(AtomicBool::new(false)),
    };
    let (requests, logs, fail, loose) = (
        n.requests.clone(),
        n.logs.clone(),
        n.fail_get_logs.clone(),
        n.loose_address.clone(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (requests, logs, fail, loose) =
                (requests.clone(), logs.clone(), fail.clone(), loose.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let body = loop {
                    let k = match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => k,
                    };
                    buf.extend_from_slice(&tmp[..k]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(p) = text.find("\r\n\r\n") {
                        let len: usize = text[..p]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= p + 4 + len {
                            break buf[p + 4..p + 4 + len].to_vec();
                        }
                    }
                };
                let req: Value = serde_json::from_slice(&body).unwrap();
                let reply = match req["method"].as_str().unwrap_or("") {
                    "eth_getLogs" => {
                        let f = req["params"][0].clone();
                        requests.lock().unwrap().push(f.clone());
                        if fail.load(Ordering::SeqCst) {
                            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"node busy"}})
                        } else {
                            let hits: Vec<Value> = logs
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|l| filter_matches(&f, l, loose.load(Ordering::SeqCst)))
                                .cloned()
                                .collect();
                            json!({"jsonrpc":"2.0","id":1,"result":hits})
                        }
                    }
                    _ => {
                        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unexpected"}})
                    }
                };
                let out = reply.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    n
}

/// The fixture logs at real block numbers, in order. Case `i` sits at `1000 + 300 * i`.
fn logs_from_fixture(include_bad: bool) -> (Vec<Value>, Vec<(u64, Value)>) {
    let f = fixture();
    let mut logs = Vec::new();
    let mut expected = Vec::new();
    for (i, case) in f["cases"].as_array().unwrap().iter().enumerate() {
        let block = 1000 + 300 * i as u64;
        if case["name"] == "foreign_topic_is_skipped" {
            continue; // the node's topic filter never returns it
        }
        if case["name"] == "truncated_data_throws" && !include_bad {
            continue;
        }
        let mut log = case["log"].clone();
        log["blockNumber"] = json!(hexn(block));
        if case["expect"].get("ok").is_some() {
            let mut op = case["expect"]["ok"].clone();
            op["sourceBlockNumber"] = json!(block);
            expected.push((block, op));
        }
        logs.push(log);
    }
    (logs, expected)
}

fn treasury() -> Address {
    TREASURY.parse().unwrap()
}

#[tokio::test]
async fn a_full_scan_returns_every_initiated_operation_once_in_block_order() {
    let (logs, expected) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let mut c = start_cursor(None, DEPLOY, head);
    let mut got = Vec::new();
    while let Some(t) = scan_tick(&rpc, treasury(), &mut c, head, 400, 4)
        .await
        .unwrap()
    {
        assert_eq!(t.failures, 0);
        got.extend(t.ops.iter().map(|o| o.to_json()));
    }
    let want: Vec<Value> = expected.into_iter().map(|(_, v)| v).collect();
    assert_eq!(got.len(), want.len(), "operation count");
    for (g, w) in got.iter().zip(&want) {
        assert_eq!(g, w);
    }
    assert_eq!(c.last_processed, head, "the scan reaches the head");
}

#[tokio::test]
async fn every_filter_is_the_treasury_address_the_topic_and_the_chunk_windows() {
    let (logs, _) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let mut c = start_cursor(None, DEPLOY, head);
    while scan_tick(&rpc, treasury(), &mut c, head, 400, 4)
        .await
        .unwrap()
        .is_some()
    {}
    let reqs = n.requests.lock().unwrap().clone();
    let topic0 = format!(
        "{:#x}",
        conet_node::treasury_v3::BridgeOperation::SIGNATURE_HASH
    );
    let mut windows = Vec::new();
    for r in &reqs {
        assert_eq!(
            r["address"], TREASURY,
            "address is the checksummed Treasury V3 address"
        );
        assert_eq!(r["topics"], json!([topic0]), "topic0 is BridgeOperation");
        let from = u64::from_str_radix(
            r["fromBlock"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let to = u64::from_str_radix(r["toBlock"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap();
        windows.push(Window { from, to });
    }
    // Requests cover the scanned range contiguously from DEPLOY, in chunks of at most 400 blocks.
    assert!(
        windows.iter().all(|w| w.to - w.from < 400),
        "a chunk exceeds 400 blocks"
    );
    assert_eq!(windows.first().unwrap().from, DEPLOY);
    for pair in windows.windows(2) {
        assert_eq!(
            pair[1].from,
            pair[0].to + 1,
            "gap or overlap between chunks"
        );
    }
    assert_eq!(windows.last().unwrap().to, head);
}

#[tokio::test]
async fn a_bad_log_holds_the_cursor_and_the_same_window_is_fetched_again() {
    let (logs, _) = logs_from_fixture(true);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let mut c = start_cursor(None, DEPLOY, head);
    let mut stuck_at = None;
    // Tick until the window that holds the bad log (block 1000 + 300 * 8 = 3400) fails.
    for _ in 0..40 {
        let before = c;
        let t = scan_tick(&rpc, treasury(), &mut c, head, 400, 4)
            .await
            .unwrap()
            .unwrap();
        if t.failures > 0 {
            assert!(t.ops.is_empty(), "a failed window delivers nothing");
            assert_eq!(
                c.last_processed, before.last_processed,
                "cursor must not move"
            );
            stuck_at = Some(t.window);
            break;
        }
    }
    let stuck = stuck_at.expect("the bad log was never reached");
    assert!(
        stuck.from <= 3400 && 3400 <= stuck.to,
        "bad log at 3400 not in {stuck:?}"
    );
    // Retrying keeps failing on the same window: a permanently bad log blocks progress, as in TS.
    for _ in 0..2 {
        let t = scan_tick(&rpc, treasury(), &mut c, head, 400, 4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(t.window, stuck);
        assert!(t.failures > 0);
    }
}

#[tokio::test]
async fn an_rpc_error_leaves_the_cursor_unchanged_and_the_retry_delivers_everything() {
    let (logs, expected) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let start = start_cursor(None, DEPLOY, head);
    // The caller keeps a copy: a failed tick never moves the real cursor.
    let mut copy = start;
    n.fail_get_logs.store(true, Ordering::SeqCst);
    let err = scan_tick(&rpc, treasury(), &mut copy, head, 400, 4)
        .await
        .unwrap_err();
    assert!(matches!(err, ScanError::Rpc(_)));
    assert_eq!(
        start.last_processed,
        DEPLOY - 1,
        "the saved cursor is untouched"
    );
    n.fail_get_logs.store(false, Ordering::SeqCst);
    let mut c = start;
    let mut got = Vec::new();
    while let Some(t) = scan_tick(&rpc, treasury(), &mut c, head, 400, 4)
        .await
        .unwrap()
    {
        got.extend(t.ops.iter().map(|o| o.to_json()));
    }
    assert_eq!(
        got.len(),
        expected.len(),
        "the retry delivers every operation"
    );
}

#[tokio::test]
async fn a_log_from_another_address_is_a_failure() {
    let (mut logs, _) = logs_from_fixture(false);
    // Same topic and block range, but another contract: the node should not return it, and if it
    // did, the tick must refuse to advance.
    logs[0]["address"] = json!("0x0000000000000000000000000000000000000001");
    let n = node(logs).await;
    n.loose_address.store(true, Ordering::SeqCst);
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let mut c = start_cursor(None, DEPLOY, head);
    let t = scan_tick(&rpc, treasury(), &mut c, head, 400, 4)
        .await
        .unwrap()
        .unwrap();
    assert!(t.failures > 0);
    assert!(t.ops.is_empty());
    assert_eq!(c.last_processed, DEPLOY - 1);
}

#[tokio::test]
async fn a_restart_between_ticks_neither_skips_nor_repeats_an_operation() {
    let (logs, expected) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let dir = std::env::temp_dir().join(format!("conet-treasury-v3-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("cursor.json");
    let mut got = Vec::new();
    let mut tick_no = 0usize;
    let mut c = start_cursor(None, DEPLOY, head);
    loop {
        // Restart before every third tick: save, drop the in-memory cursor, load it back.
        if tick_no % 3 == 2 {
            save_cursor(&file, &c, 1).unwrap();
            c = start_cursor(load_cursor(&file).unwrap(), DEPLOY, head);
        }
        let mut copy = c;
        match scan_tick(&rpc, treasury(), &mut copy, head, 400, 4)
            .await
            .unwrap()
        {
            None => break,
            Some(t) => {
                got.extend(t.ops.iter().map(|o| o.to_json()));
                c = copy;
                save_cursor(&file, &c, 1).unwrap();
            }
        }
        tick_no += 1;
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        got.len(),
        expected.len(),
        "restarts changed the operation count"
    );
    for (g, (_, w)) in got.iter().zip(&expected) {
        assert_eq!(g, w);
    }
    assert!(tick_no > 3, "the run must cross several restarts");
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "conet-treasury-v3-ro-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn the_backfill_variable_refuses_a_non_zero_or_unreadable_value() {
    assert!(check_backfill_env(None).is_ok());
    assert!(check_backfill_env(Some("0")).is_ok());
    assert!(check_backfill_env(Some(" 0 ")).is_ok());
    let e = check_backfill_env(Some("400")).unwrap_err();
    assert!(
        e.contains("TREASURY_V3_BACKFILL_BLOCKS") && e.contains("non-zero"),
        "{e}"
    );
    for bad in ["", "  ", "abc", "-1"] {
        let e = check_backfill_env(Some(bad)).unwrap_err();
        assert!(e.contains("whole number"), "{bad:?}: {e}");
    }
}

#[test]
fn the_read_only_store_refuses_the_vote_state_name() {
    let dir = scratch("store-name");
    assert!(ReadOnlyCursorStore::at(dir.join("treasury-v3-vote-conet.json")).is_err());
    assert!(ReadOnlyCursorStore::at(dir.join("treasury-v3-vote-base.json")).is_err());
    let s = ReadOnlyCursorStore::for_chain(&dir, "conet").unwrap();
    assert_eq!(
        s.path().file_name().unwrap(),
        "treasury-v3-readonly-conet.json"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_read_only_run_never_writes_the_vote_process_state() {
    let (logs, _) = logs_from_fixture(false);
    let head = 1000 + 300 * 20;
    // With a vote state file present: its bytes must not change, and no other file is created.
    let dir = scratch("vote-present");
    let vote = dir.join("treasury-v3-vote-conet.json");
    let sentinel = r#"{"version":1,"lastProcessedBlock":"777","scanTargetBlock":"999","updatedAt":"sentinel"}"#;
    std::fs::write(&vote, sentinel).unwrap();
    let n = node(logs.clone()).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let store = ReadOnlyCursorStore::for_chain(&dir, "conet").unwrap();
    let mut s = ReadOnlyScanner::new(rpc, treasury(), store, DEPLOY, 400, 4);
    s.start(head, 1).unwrap();
    while s.tick(head, 2).await.unwrap().is_some() {}
    assert_eq!(
        std::fs::read_to_string(&vote).unwrap(),
        sentinel,
        "the vote state changed"
    );
    assert_eq!(
        names(&dir),
        vec![
            "treasury-v3-readonly-conet.json",
            "treasury-v3-vote-conet.json"
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
    // Without a vote state file: none is created.
    let dir = scratch("vote-absent");
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let store = ReadOnlyCursorStore::for_chain(&dir, "conet").unwrap();
    let mut s = ReadOnlyScanner::new(rpc, treasury(), store, DEPLOY, 400, 4);
    s.start(head, 1).unwrap();
    while s.tick(head, 2).await.unwrap().is_some() {}
    assert_eq!(names(&dir), vec!["treasury-v3-readonly-conet.json"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_corrupt_state_file_refuses_the_start_with_a_reason_and_no_content() {
    let dir = scratch("corrupt-start");
    let store = ReadOnlyCursorStore::for_chain(&dir, "conet").unwrap();
    std::fs::write(
        store.path(),
        r#"{"version":1,"lastProcessedBlock":"SECRET-MARKER-123","scanTargetBlock":"5"}"#,
    )
    .unwrap();
    let (logs, _) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let mut s = ReadOnlyScanner::new(rpc, treasury(), store.clone(), DEPLOY, 400, 4);
    let err = s.start(2000, 1).unwrap_err().to_string();
    assert!(
        err.contains(store.path().to_str().unwrap()),
        "does not name the file: {err}"
    );
    assert!(
        err.contains("lastProcessedBlock is not a block number"),
        "{err}"
    );
    assert!(
        err.contains("delete the file to rescan from the deploy block"),
        "{err}"
    );
    assert!(
        !err.contains("SECRET-MARKER-123"),
        "echoes the file content: {err}"
    );
    assert!(s.cursor().is_none(), "a refused start must not scan");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn deleting_the_state_file_rescans_from_the_deploy_block() {
    let (logs, expected) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let dir = scratch("rescan");
    let store = ReadOnlyCursorStore::for_chain(&dir, "conet").unwrap();
    let mut s = ReadOnlyScanner::new(rpc.clone(), treasury(), store.clone(), DEPLOY, 400, 4);
    s.start(head, 1).unwrap();
    let mut first = 0;
    while let Some(t) = s.tick(head, 2).await.unwrap() {
        first += t.ops.len();
    }
    assert_eq!(first, expected.len());
    std::fs::remove_file(store.path()).unwrap();
    let mut again = ReadOnlyScanner::new(rpc, treasury(), store, DEPLOY, 400, 4);
    let c = again.start(head, 3).unwrap();
    assert_eq!(
        c.last_processed,
        DEPLOY - 1,
        "a missing file starts from the deploy block"
    );
    let mut second = 0;
    while let Some(t) = again.tick(head, 4).await.unwrap() {
        second += t.ops.len();
    }
    assert_eq!(
        second,
        expected.len(),
        "the rescan delivers every operation again"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_scanner_restart_resumes_from_the_saved_cursor() {
    let (logs, expected) = logs_from_fixture(false);
    let n = node(logs).await;
    let rpc = Rpc::new(&n.url).unwrap();
    let head = 1000 + 300 * 20;
    let dir = scratch("restart-scanner");
    let store = ReadOnlyCursorStore::for_chain(&dir, "conet").unwrap();
    let mut s = ReadOnlyScanner::new(rpc.clone(), treasury(), store.clone(), DEPLOY, 400, 4);
    s.start(head, 1).unwrap();
    let mut got = 0;
    // One tick, then the process "stops".
    if let Some(t) = s.tick(head, 2).await.unwrap() {
        got += t.ops.len();
    }
    drop(s);
    let mut s = ReadOnlyScanner::new(rpc, treasury(), store, DEPLOY, 400, 4);
    let resumed = s.start(head, 3).unwrap();
    assert!(
        resumed.last_processed > DEPLOY - 1,
        "the restart must not start over"
    );
    while let Some(t) = s.tick(head, 4).await.unwrap() {
        got += t.ops.len();
    }
    assert_eq!(
        got,
        expected.len(),
        "a restart neither skips nor repeats an operation"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

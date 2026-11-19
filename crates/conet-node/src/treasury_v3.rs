//! Treasury V3 `BridgeOperation` read path, read-only. Mirrors CoNET-SI 215afb1
//! `src/vote/treasuryV3Listen.ts`: the event decode (`parseBridgeOperation`), the scan window
//! planning (`runChain` / `tick` / `getLogsChunked`) and the cursor state file (`loadState` /
//! `saveState`). No RPC calls and no votes here: the vote is a separate, later step.
use crate::chain::{checked_u64, parse_rpc_data, parse_rpc_quantity, Rpc};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolEvent};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};

sol! {
    /// The on-chain event, exactly as the TS ABI in 215afb1 declares it.
    event BridgeOperation(
        bytes32 indexed operationId,
        uint256 indexed sourceChainId,
        uint256 indexed destinationChainId,
        uint8 phase,
        uint8 mode,
        address sourceTreasury,
        address sourceAsset,
        address destinationAsset,
        address sender,
        address[] beneficiaries,
        uint256[] amounts,
        uint256 grossAmount,
        uint256 feeAmount,
        uint256 netAmount,
        bytes32 sourceTxHash,
        uint256 nonce,
        address callbackTarget
    );
}

/// The phase of an Initiated operation (TS: `Number(parsed.args.phase) !== 0` skips the log).
pub const PHASE_INITIATED: u8 = 0;

/// A raw log as the RPC returns it (the TS side reads `topics`, `data`, `transactionHash`,
/// `blockNumber`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawLog {
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
    pub transaction_hash: B256,
    pub block_number: u64,
}

/// The fields TS returns from `parseBridgeOperation`, in the same meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeOp {
    pub operation_id: B256,
    pub source_chain_id: U256,
    pub destination_chain_id: U256,
    pub mode: u8,
    pub source_treasury: Address,
    pub source_asset: Address,
    pub destination_asset: Address,
    pub beneficiaries: Vec<Address>,
    pub amounts: Vec<U256>,
    pub gross_amount: U256,
    pub fee_amount: U256,
    pub source_tx_hash: B256,
    pub nonce: U256,
    pub callback_target: Address,
    pub source_transaction_hash: B256,
    pub source_block_number: u64,
}

impl BridgeOp {
    /// The TS object as JSON: the same keys, decimal strings for `bigint`s and checksummed
    /// addresses (ethers returns checksummed addresses). Used to compare against the TS output.
    pub fn to_json(&self) -> Value {
        json!({
            "operationId": format!("{:#x}", self.operation_id),
            "sourceChainId": self.source_chain_id.to_string(),
            "destinationChainId": self.destination_chain_id.to_string(),
            "mode": self.mode,
            "sourceTreasury": self.source_treasury.to_checksum(None),
            "sourceAsset": self.source_asset.to_checksum(None),
            "destinationAsset": self.destination_asset.to_checksum(None),
            "beneficiaries": self.beneficiaries.iter().map(|a| a.to_checksum(None)).collect::<Vec<_>>(),
            "amounts": self.amounts.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            "grossAmount": self.gross_amount.to_string(),
            "feeAmount": self.fee_amount.to_string(),
            "sourceTxHash": format!("{:#x}", self.source_tx_hash),
            "nonce": self.nonce.to_string(),
            "callbackTarget": self.callback_target.to_checksum(None),
            "sourceTransactionHash": format!("{:#x}", self.source_transaction_hash),
            "sourceBlockNumber": self.source_block_number,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The topic is BridgeOperation but the data does not decode. TS throws here, and the caller
    /// must treat it as a retryable failure, never as "no event".
    Abi(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Abi(e) => write!(f, "BridgeOperation does not decode: {e}"),
        }
    }
}

/// `parseBridgeOperation`: `Ok(None)` for another topic (TS returns null) and for a phase other
/// than Initiated (TS returns null); `Err` when the topic matches but the payload is malformed.
pub fn decode(log: &RawLog) -> Result<Option<BridgeOp>, DecodeError> {
    if log.topics.first() != Some(&BridgeOperation::SIGNATURE_HASH) {
        return Ok(None);
    }
    let ev = BridgeOperation::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
        .map_err(|e| DecodeError::Abi(e.to_string()))?;
    if ev.phase != PHASE_INITIATED {
        return Ok(None);
    }
    Ok(Some(BridgeOp {
        operation_id: ev.operationId,
        source_chain_id: ev.sourceChainId,
        destination_chain_id: ev.destinationChainId,
        mode: ev.mode,
        source_treasury: ev.sourceTreasury,
        source_asset: ev.sourceAsset,
        destination_asset: ev.destinationAsset,
        beneficiaries: ev.beneficiaries,
        amounts: ev.amounts,
        gross_amount: ev.grossAmount,
        fee_amount: ev.feeAmount,
        source_tx_hash: ev.sourceTxHash,
        nonce: ev.nonce,
        callback_target: ev.callbackTarget,
        source_transaction_hash: log.transaction_hash,
        source_block_number: log.block_number,
    }))
}

/// The scan cursor: the last block fully processed and the head it scans towards. Same meaning as
/// the TS `lastProcessedBlock` and `scanTargetBlock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub last_processed: u64,
    pub scan_target: u64,
}

/// An inclusive block window `[from, to]` to fetch logs for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub from: u64,
    pub to: u64,
}

/// The start-of-run cursor, as TS computes it in `runChain`. `deploy_block` 0 means "from the
/// head". A saved cursor is clamped: it never goes below `deploy_block - 1`, and the scan target
/// is never below the last processed block. (TS also has a backfill env var that defaults to 0;
/// it is not ported.)
pub fn start_cursor(saved: Option<Cursor>, deploy_block: u64, head: u64) -> Cursor {
    let initial_last = if deploy_block > 0 {
        deploy_block - 1
    } else {
        head
    };
    let mut last = saved.map_or(initial_last, |c| c.last_processed);
    let mut scan = saved.map_or(head, |c| c.scan_target);
    if last < initial_last {
        last = initial_last;
    }
    if scan < last {
        scan = last;
    }
    Cursor {
        last_processed: last,
        scan_target: scan,
    }
}

/// One `tick` of the TS loop: refresh the scan target when caught up, then the window
/// `(last, min(last + chunk * chunks_per_tick, scan)]`. `None` when there is nothing to fetch.
pub fn next_window(c: &mut Cursor, head: u64, chunk: u64, chunks_per_tick: u64) -> Option<Window> {
    let (chunk, chunks_per_tick) = (chunk.max(1), chunks_per_tick.max(1));
    if c.last_processed >= c.scan_target {
        c.scan_target = head;
    }
    let max = chunk.saturating_mul(chunks_per_tick);
    let to = c.last_processed.saturating_add(max).min(c.scan_target);
    if c.last_processed < to {
        Some(Window {
            from: c.last_processed + 1,
            to,
        })
    } else {
        None
    }
}

/// `getLogsChunked`: split a window into `chunk`-block ranges, each inclusive, in order.
pub fn chunk_ranges(w: Window, chunk: u64) -> Vec<Window> {
    let chunk = chunk.max(1);
    let mut out = Vec::new();
    let mut start = w.from;
    while start <= w.to {
        let end = start.saturating_add(chunk - 1).min(w.to);
        out.push(Window {
            from: start,
            to: end,
        });
        if end == u64::MAX {
            break;
        }
        start = end + 1;
    }
    out
}

/// The TS rule: move the cursor to the window end only when every log in the window was handled
/// (`failures == 0`). Otherwise it stays, and the same window is fetched again.
pub fn advance(c: &mut Cursor, to: u64, failures: usize) {
    if failures == 0 {
        c.last_processed = to;
    }
}

#[derive(Debug)]
pub enum CursorError {
    /// Reading or writing the state file failed. The path is kept so the message can name it.
    Io(PathBuf, std::io::Error),
    /// The file exists but cannot be used: not JSON, not version 1, or a field is not a block
    /// number. The message names the file and the reason, never the file's content.
    Format(String),
}

/// What an operator does about a refused state file, and what it costs.
const RECOVERY: &str =
    "delete the file to rescan from the deploy block (no operation is lost, but a \
    rescan reads every block since the deploy block, so delivery waits until it catches up)";

impl std::fmt::Display for CursorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CursorError::Io(p, e) => write!(
                f,
                "state file {} unusable: {e}; fix it or {RECOVERY}",
                p.display()
            ),
            CursorError::Format(m) => write!(f, "{m}; {RECOVERY}"),
        }
    }
}

/// Load the state file. A missing file is a first start (`Ok(None)`). A file that exists but cannot
/// be read or is not version 1 is an error: TS would quietly start over, Rust refuses instead.
pub fn load_cursor(path: &Path) -> Result<Option<Cursor>, CursorError> {
    let refuse = |reason: &str| {
        CursorError::Format(format!("state file {} refused: {reason}", path.display()))
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CursorError::Io(path.to_path_buf(), e)),
    };
    let v: Value = serde_json::from_str(&text).map_err(|_| refuse("not valid JSON"))?;
    if v.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(refuse("version is not 1"));
    }
    let parse = |key: &str| -> Result<u64, CursorError> {
        v.get(key)
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| refuse(&format!("{key} is not a block number")))
    };
    Ok(Some(Cursor {
        last_processed: parse("lastProcessedBlock")?,
        scan_target: parse("scanTargetBlock")?,
    }))
}

/// Save the state file atomically: write a temporary file next to it, then rename. The JSON keys
/// match the TS state file (`version`, `lastProcessedBlock`, `scanTargetBlock`, `updatedAt`).
/// `updatedAt` holds Unix seconds here, not an ISO string; the TS loader does not read it.
pub fn save_cursor(path: &Path, c: &Cursor, updated_at_unix: u64) -> Result<(), CursorError> {
    let body = json!({
        "version": 1,
        "lastProcessedBlock": c.last_processed.to_string(),
        "scanTargetBlock": c.scan_target.to_string(),
        "updatedAt": updated_at_unix.to_string(),
    });
    let text = serde_json::to_string_pretty(&body)
        .map_err(|_| CursorError::Format("cursor encode failed".into()))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let io = |e| CursorError::Io(path.to_path_buf(), e);
    {
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        f.write_all(text.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

/// A log as `eth_getLogs` returns it. An error names the field, never the value.
pub fn raw_log_from_rpc(v: &Value) -> Result<RawLog, &'static str> {
    let topics = v["topics"]
        .as_array()
        .ok_or("topics")?
        .iter()
        .map(|t| {
            let bytes = parse_rpc_data(t, "eth_getLogs topic").map_err(|_| "topics")?;
            if bytes.len() != 32 {
                return Err("topics");
            }
            Ok(B256::from_slice(&bytes))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if topics.first() != Some(&BridgeOperation::SIGNATURE_HASH) {
        return Err("topics");
    }
    let data = parse_rpc_data(&v["data"], "eth_getLogs data").map_err(|_| "data")?;
    let hash = parse_rpc_data(&v["transactionHash"], "eth_getLogs transactionHash")
        .map_err(|_| "transactionHash")?;
    if hash.len() != 32 {
        return Err("transactionHash");
    }
    let transaction_hash = B256::from_slice(&hash);
    let block_number = checked_u64(
        parse_rpc_quantity(&v["blockNumber"], "eth_getLogs blockNumber")
            .map_err(|_| "blockNumber")?,
        "eth_getLogs blockNumber",
    )
    .map_err(|_| "blockNumber")?;
    Ok(RawLog {
        topics,
        data,
        transaction_hash,
        block_number,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// The RPC call failed or answered with something that is not a log list. The cursor must
    /// not move: the caller keeps its copy and retries the same window later.
    Rpc(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Rpc(e) => write!(f, "treasury v3 scan: {e}"),
        }
    }
}

/// One tick that fetched a window. `ops` holds the decoded Initiated operations in node order.
/// When any log failed (a malformed log, a foreign address, a decode error), `ops` is empty and
/// the window is fetched again whole, so no operation is delivered twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tick {
    pub window: Window,
    pub ops: Vec<BridgeOp>,
    pub failures: usize,
}

/// One TS tick, read-only. Fetches the window's logs chunk by chunk with `eth_getLogs`, filtered
/// by the Treasury address and the BridgeOperation topic, decodes each log, and advances the
/// cursor only when every log decoded. `Ok(None)` when there is nothing to fetch. On `Err` the
/// caller discards its cursor copy. The caller persists the cursor only after `Ok`.
pub async fn scan_tick(
    rpc: &Rpc,
    address: alloy_primitives::Address,
    cursor: &mut Cursor,
    head: u64,
    chunk: u64,
    chunks_per_tick: u64,
) -> Result<Option<Tick>, ScanError> {
    let Some(window) = next_window(cursor, head, chunk, chunks_per_tick) else {
        return Ok(None);
    };
    let addr = address.to_checksum(None);
    let topic0 = format!("{:#x}", BridgeOperation::SIGNATURE_HASH);
    let mut ops = Vec::new();
    let mut failures = 0usize;
    for r in chunk_ranges(window, chunk) {
        let logs = rpc
            .call(
                "eth_getLogs",
                json!([{
                    "address": addr,
                    "topics": [topic0],
                    "fromBlock": format!("0x{:x}", r.from),
                    "toBlock": format!("0x{:x}", r.to),
                }]),
            )
            .await
            .map_err(|e| ScanError::Rpc(e.0))?;
        let list = logs
            .as_array()
            .ok_or_else(|| ScanError::Rpc("eth_getLogs did not return a list".into()))?;
        for l in list {
            let from_treasury = l["address"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case(&addr));
            if !from_treasury {
                failures += 1;
                continue;
            }
            match raw_log_from_rpc(l)
                .map_err(|_| ())
                .and_then(|raw| decode(&raw).map_err(|_| ()))
            {
                Ok(Some(op)) => ops.push(op),
                Ok(None) => {}
                Err(()) => failures += 1,
            }
        }
    }
    advance(cursor, window.to, failures);
    if failures > 0 {
        ops.clear();
    }
    Ok(Some(Tick {
        window,
        ops,
        failures,
    }))
}

/// `TREASURY_V3_BACKFILL_BLOCKS`: TS backfills from `head - N` on a first start. The Rust scanner
/// does not implement backfill, so a non-zero value refuses the start. Ignoring it would start the
/// scan somewhere the operator did not ask for. Unset and `0` are accepted. An empty or non-numeric
/// value is refused too, because its meaning cannot be told.
pub fn check_backfill_env(value: Option<&str>) -> Result<(), String> {
    const NAME: &str = "TREASURY_V3_BACKFILL_BLOCKS";
    match value {
        None => Ok(()),
        Some(v) => match v.trim().parse::<u64>() {
            Ok(0) => Ok(()),
            Ok(_) => Err(format!(
                "{NAME} is set to a non-zero value; the Rust scanner does not implement backfill and refuses to start. Unset it or set it to 0."
            )),
            Err(_) => Err(format!("{NAME} is not a whole number; refusing to start. Unset it or set it to 0.")),
        },
    }
}

/// The vote process's state file name prefix (the TS name is `treasury-v3-vote-<chain>.json`). The
/// read-only scanner never opens a file with this prefix, and this module never writes one.
pub const VOTE_STATE_PREFIX: &str = "treasury-v3-vote-";

/// The read-only scanner's own cursor file, `treasury-v3-readonly-<chain>.json`. It is separate from
/// the vote process's cursor, so a read-only run cannot move the cursor a voting process reads.
#[derive(Clone, Debug)]
pub struct ReadOnlyCursorStore {
    path: PathBuf,
}

impl ReadOnlyCursorStore {
    pub fn for_chain(dir: &Path, chain: &str) -> Result<Self, CursorError> {
        Self::at(dir.join(format!("treasury-v3-readonly-{chain}.json")))
    }

    pub fn at(path: PathBuf) -> Result<Self, CursorError> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.is_empty() || name.starts_with(VOTE_STATE_PREFIX) {
            return Err(CursorError::Format(format!(
                "state file {} refused: the read-only scanner must not use the vote state name",
                path.display()
            )));
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<Cursor>, CursorError> {
        load_cursor(&self.path)
    }

    pub fn save(&self, c: &Cursor, now_unix: u64) -> Result<(), CursorError> {
        save_cursor(&self.path, c, now_unix)
    }
}

#[derive(Debug)]
pub enum ScanRunError {
    Cursor(CursorError),
    Scan(ScanError),
}

impl std::fmt::Display for ScanRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanRunError::Cursor(e) => write!(f, "{e}"),
            ScanRunError::Scan(e) => write!(f, "{e}"),
        }
    }
}

/// The read-only scan loop: one cursor, kept in the read-only store, advanced one tick at a time.
/// Nothing here votes or sends a transaction.
pub struct ReadOnlyScanner {
    rpc: Rpc,
    address: Address,
    store: ReadOnlyCursorStore,
    deploy_block: u64,
    chunk: u64,
    chunks_per_tick: u64,
    cursor: Option<Cursor>,
}

impl ReadOnlyScanner {
    pub fn new(
        rpc: Rpc,
        address: Address,
        store: ReadOnlyCursorStore,
        deploy_block: u64,
        chunk: u64,
        chunks_per_tick: u64,
    ) -> Self {
        Self {
            rpc,
            address,
            store,
            deploy_block,
            chunk,
            chunks_per_tick,
            cursor: None,
        }
    }

    /// Load the saved cursor (a refused file is an error, see `CursorError`), clamp it to the deploy
    /// block, and save it at once, as TS does.
    pub fn start(&mut self, head: u64, now_unix: u64) -> Result<Cursor, CursorError> {
        let c = start_cursor(self.store.load()?, self.deploy_block, head);
        self.store.save(&c, now_unix)?;
        self.cursor = Some(c);
        Ok(c)
    }

    /// One tick. The in-memory cursor and its file move only when the tick succeeds.
    pub async fn tick(&mut self, head: u64, now_unix: u64) -> Result<Option<Tick>, ScanRunError> {
        let Some(mut c) = self.cursor else {
            return Err(ScanRunError::Cursor(CursorError::Format(
                "the read-only scanner was not started".into(),
            )));
        };
        let t = scan_tick(
            &self.rpc,
            self.address,
            &mut c,
            head,
            self.chunk,
            self.chunks_per_tick,
        )
        .await
        .map_err(ScanRunError::Scan)?;
        self.store
            .save(&c, now_unix)
            .map_err(ScanRunError::Cursor)?;
        self.cursor = Some(c);
        Ok(t)
    }

    pub fn cursor(&self) -> Option<Cursor> {
        self.cursor
    }
}

//! Offline mailbox store, mirroring SI `saveLocal` / `tryGetLocal` / `removeLocalByArmorHash`:
//! every delivery is stored first, flushed on each listen, and deleted only by the client's
//! `gossip_delivery_ack` (keccak256 of the armor). Like SI, the disk store has NO limit on the number of
//! messages per key and NO age limit (project decision, relayed: 「沿用 TS，不设条数或天数上限，实际存储失败时明确拒收」):
//! an accepted message stays until the mailbox owner acknowledges it. The only refusal is a real storage failure
//! (`SaveResult::Failed`), which the post reply reports as `ok:false` so the sender keeps the message and retries.
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stored {
    pub armor: String,
    pub no_push: bool,
    /// Verified prior-hop bytes (GB metering input).
    pub hop_bytes: u64,
    pub hops: usize,
}

/// SI `hashPgpArmor`: keccak256 of the UTF-8 armor, 0x lowercase hex.
pub fn armor_hash(armor: &str) -> String {
    si_crypto::eth::keccak_hex(armor)
}

/// What one save did. `Failed` means the armor is NOT durably stored (a storage error), which `save`'s bool cannot tell from a duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveResult {
    Stored,
    /// The same armor was already stored (SI dedups byte for byte).
    Duplicate,
    Failed,
}

pub trait MailboxStore: Send + Sync {
    /// Store ciphertext for a user key. Returns false when it was already stored (SI dedups) or when the store failed; use `save_result` to tell them apart.
    fn save(&self, user_key: &str, item: Stored) -> bool;
    /// Same as `save`, but a storage error is `Failed`, not "already stored". Stores that cannot fail keep this default.
    fn save_result(&self, user_key: &str, item: Stored) -> SaveResult {
        if self.save(user_key, item) {
            SaveResult::Stored
        } else {
            SaveResult::Duplicate
        }
    }
    /// Everything not yet acknowledged, oldest first.
    fn pending(&self, user_key: &str) -> Vec<Stored>;
    /// Delete by armor hash (client ACK). True when something was removed.
    fn remove_by_hash(&self, user_key: &str, hash: &str) -> bool;
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, Vec<Stored>>>,
}

impl MailboxStore for MemoryStore {
    fn save(&self, user_key: &str, item: Stored) -> bool {
        let mut m = self.inner.lock().expect("store lock");
        let list = m.entry(user_key.to_uppercase()).or_default();
        if list.iter().any(|s| s.armor == item.armor) {
            return false;
        }
        list.push(item);
        true
    }
    fn pending(&self, user_key: &str) -> Vec<Stored> {
        self.inner
            .lock()
            .expect("store lock")
            .get(&user_key.to_uppercase())
            .cloned()
            .unwrap_or_default()
    }
    fn remove_by_hash(&self, user_key: &str, hash: &str) -> bool {
        let mut m = self.inner.lock().expect("store lock");
        let Some(list) = m.get_mut(&user_key.to_uppercase()) else {
            return false;
        };
        let before = list.len();
        list.retain(|s| !armor_hash(&s.armor).eq_ignore_ascii_case(hash));
        before != list.len()
    }
}

/// (user key, sequence) → JSON row.
const MSGS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("msgs");
/// user key → next sequence.
const SEQ: TableDefinition<&str, u64> = TableDefinition::new("seq");
/// (user key, armor hash) of every TS offline message the import has taken over (also the ones the owner acknowledged since): an import run never brings one back,
/// and an export at a rollback knows which TS messages Rust has already served.
const TS_IMPORTED: TableDefinition<(&str, &str), u8> = TableDefinition::new("ts_imported");

/// What importing one TS message did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Stored now (and recorded as taken over).
    Imported,
    /// The same armor was already stored (delivered live to this node); recorded as taken over, nothing added.
    AlreadyPresent,
    /// Taken over by an earlier run (it may have been acknowledged since): nothing done.
    AlreadyImported,
}

#[derive(Serialize, Deserialize)]
struct Row {
    item: Stored,
    hash: String,
    /// Kept for diagnostics and for compatibility with databases written by earlier builds; never used to drop a message.
    #[serde(default)]
    saved_at: u64,
}

/// The mailbox database. After a real I/O error redb refuses every later write on the same handle (`PreviousIo`) until the file is opened again; the store
/// therefore keeps the handle behind a lock and, on such an error, reopens the EXISTING file itself: one writer at a time (the reopen holds the exclusive lock),
/// at most `reopen_limit` attempts within `reopen_window`, and the failed operation is retried once on the new handle (its duplicate check runs again, so a write that
/// did commit is never stored twice). While the storage stays unhealthy the operation keeps failing and is refused. The reopen never creates a database: a missing,
/// emptied or corrupted file is opened with an integrity check, fails, and is left exactly as it is.
pub struct DiskStore {
    path: PathBuf,
    db: RwLock<Option<Database>>,
    generation: AtomicU64,
    reopens: Mutex<VecDeque<Instant>>,
    reopen_total: AtomicU64,
    pub reopen_limit: usize,
    pub reopen_window: Duration,
}

/// The errors after which reopening the file can help: redb's own write failed (`Io`) or an earlier one did (`PreviousIo`).
fn heals_by_reopening(e: &redb::Error) -> bool {
    matches!(e, redb::Error::Io(_) | redb::Error::PreviousIo)
}

/// Opens an existing database; never creates one. The integrity check turns a damaged file into an error instead of a panic.
fn open_existing(path: &Path) -> Result<Database, redb::Error> {
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Database::builder()
            .set_check_integrity_on_open(true)
            .open(path)
    }));
    match opened {
        Ok(Ok(db)) => Ok(db),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(redb::Error::Corrupted(
            "the database file could not be opened".into(),
        )),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl DiskStore {
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        let w = db.begin_write()?;
        w.open_table(MSGS)?;
        w.open_table(SEQ)?;
        w.open_table(OFFERS)?;
        w.open_table(TS_IMPORTED)?;
        w.commit()?;
        Ok(Self {
            path: path.to_path_buf(),
            db: RwLock::new(Some(db)),
            generation: AtomicU64::new(0),
            reopens: Mutex::new(VecDeque::new()),
            reopen_total: AtomicU64::new(0),
            reopen_limit: 3,
            reopen_window: Duration::from_secs(60),
        })
    }

    /// How many times the store has reopened its file after an I/O error (diagnostics and tests).
    pub fn reopen_attempts(&self) -> u64 {
        self.reopen_total.load(Ordering::Relaxed)
    }

    /// Runs `f` on the database. On an I/O error the file is reopened (single writer, bounded) and `f` runs once more on the new handle.
    fn with_db<R>(
        &self,
        mut f: impl FnMut(&Database) -> Result<R, redb::Error>,
    ) -> Result<R, redb::Error> {
        let seen;
        {
            let g = self
                .db
                .read()
                .map_err(|_| redb::Error::from(redb::StorageError::DatabaseClosed))?;
            seen = self.generation.load(Ordering::Acquire);
            if let Some(db) = g.as_ref() {
                match f(db) {
                    Err(e) if heals_by_reopening(&e) => {
                        tracing::warn!(%e, "mailbox database I/O error; reopening")
                    }
                    other => return other,
                }
            }
        }
        // The handle is gone or refused a write: one writer reopens it.
        let mut g = self
            .db
            .write()
            .map_err(|_| redb::Error::from(redb::StorageError::DatabaseClosed))?;
        if self.generation.load(Ordering::Acquire) == seen {
            let now = Instant::now();
            {
                let mut q = self.reopens.lock().expect("reopen budget");
                while q
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > self.reopen_window)
                {
                    q.pop_front();
                }
                if q.len() >= self.reopen_limit {
                    tracing::error!(
                        limit = self.reopen_limit,
                        "mailbox database reopen budget used up; refusing until the window passes"
                    );
                    return Err(redb::Error::PreviousIo);
                }
                q.push_back(now);
            }
            self.reopen_total.fetch_add(1, Ordering::Relaxed);
            *g = None; // closes the old handle (its file lock) before the file is opened again
            match open_existing(&self.path) {
                Ok(db) => {
                    *g = Some(db);
                    self.generation.fetch_add(1, Ordering::Release);
                }
                Err(e) => {
                    tracing::error!(%e, "mailbox database could not be reopened; refusing");
                    return Err(e);
                }
            }
        }
        match g.as_ref() {
            Some(db) => f(db),
            None => Err(redb::Error::from(redb::StorageError::DatabaseClosed)),
        }
    }

    fn rows(&self, key: &str) -> Result<Vec<(u64, Row)>, redb::Error> {
        self.with_db(|db| Self::rows_in(db, key))
    }

    fn rows_in(db: &Database, key: &str) -> Result<Vec<(u64, Row)>, redb::Error> {
        let r = db.begin_read()?;
        let t = r.open_table(MSGS)?;
        let mut out = vec![];
        for e in t.range((key, 0u64)..=(key, u64::MAX))? {
            let (k, v) = e?;
            if let Ok(row) = serde_json::from_slice::<Row>(v.value()) {
                out.push((k.value().1, row));
            }
        }
        Ok(out)
    }

    fn save_inner(&self, key: &str, item: Stored) -> Result<bool, redb::Error> {
        let hash = armor_hash(&item.armor);
        self.with_db(|db| {
            // The duplicate check runs INSIDE the write transaction: redb allows one writer at a time, so two concurrent posts of the same armor cannot both pass the check.
            let w = db.begin_write()?;
            {
                let mut msgs = w.open_table(MSGS)?;
                let mut seq = w.open_table(SEQ)?;
                let mut duplicate = false;
                for e in msgs.range((key, 0u64)..=(key, u64::MAX))? {
                    let (_, v) = e?;
                    if serde_json::from_slice::<Row>(v.value()).is_ok_and(|r| r.hash == hash) {
                        duplicate = true;
                        break;
                    }
                }
                if duplicate {
                    return Ok(false); // the transaction is dropped without a commit
                }
                // Nothing is removed here: no count cap, no age purge. A failure anywhere in this block or in `commit` is an error, not a store.
                let next = seq.get(key)?.map(|v| v.value()).unwrap_or(0);
                let row = serde_json::to_vec(&Row {
                    item: item.clone(),
                    hash: hash.clone(),
                    saved_at: now(),
                })
                .expect("row json");
                msgs.insert((key, next), row.as_slice())?;
                seq.insert(key, next + 1)?;
            }
            w.commit()?;
            Ok(true)
        })
    }

    /// Takes over one TS offline message in ONE write transaction: the ledger entry and the row commit together, so a crash leaves either both or neither.
    pub fn import_message(&self, key: &str, item: Stored) -> Result<ImportOutcome, redb::Error> {
        let key = key.to_uppercase();
        let hash = armor_hash(&item.armor);
        self.with_db(|db| {
            let w = db.begin_write()?;
            let outcome;
            {
                let mut ledger = w.open_table(TS_IMPORTED)?;
                if ledger.get((key.as_str(), hash.as_str()))?.is_some() {
                    return Ok(ImportOutcome::AlreadyImported);
                }
                let mut msgs = w.open_table(MSGS)?;
                let mut seq = w.open_table(SEQ)?;
                let mut present = false;
                for e in msgs.range((key.as_str(), 0u64)..=(key.as_str(), u64::MAX))? {
                    let (_, v) = e?;
                    if serde_json::from_slice::<Row>(v.value()).is_ok_and(|r| r.hash == hash) {
                        present = true;
                        break;
                    }
                }
                ledger.insert((key.as_str(), hash.as_str()), 1u8)?;
                if present {
                    outcome = ImportOutcome::AlreadyPresent;
                } else {
                    let next = seq.get(key.as_str())?.map(|v| v.value()).unwrap_or(0);
                    let row = serde_json::to_vec(&Row {
                        item: item.clone(),
                        hash: hash.clone(),
                        saved_at: now(),
                    })
                    .expect("row json");
                    msgs.insert((key.as_str(), next), row.as_slice())?;
                    seq.insert(key.as_str(), next + 1)?;
                    outcome = ImportOutcome::Imported;
                }
            }
            w.commit()?;
            Ok(outcome)
        })
    }

    /// The armor hashes of the TS messages taken over for one key (acknowledged ones included).
    pub fn ts_imported_hashes(
        &self,
        key: &str,
    ) -> Result<std::collections::HashSet<String>, redb::Error> {
        let key = key.to_uppercase();
        self.with_db(|db| {
            let r = db.begin_read()?;
            let t = r.open_table(TS_IMPORTED)?;
            let mut out = std::collections::HashSet::new();
            for e in t.range((key.as_str(), "")..)? {
                let (k, _) = e?;
                let (kk, h) = k.value();
                if kk != key {
                    break;
                }
                out.insert(h.to_string());
            }
            Ok(out)
        })
    }

    /// Every user key that has a stored message or a TS ledger entry.
    pub fn mailbox_keys(&self) -> Result<std::collections::BTreeSet<String>, redb::Error> {
        self.with_db(|db| {
            let r = db.begin_read()?;
            let mut out = std::collections::BTreeSet::new();
            for e in r.open_table(MSGS)?.iter()? {
                let (k, _) = e?;
                out.insert(k.value().0.to_string());
            }
            for e in r.open_table(TS_IMPORTED)?.iter()? {
                let (k, _) = e?;
                out.insert(k.value().0.to_string());
            }
            Ok(out)
        })
    }

    fn remove_inner(&self, key: &str, hash: &str) -> Result<bool, redb::Error> {
        let hit: Vec<u64> = self
            .rows(key)?
            .into_iter()
            .filter(|(_, r)| r.hash.eq_ignore_ascii_case(hash))
            .map(|(s, _)| s)
            .collect();
        if hit.is_empty() {
            return Ok(false);
        }
        self.with_db(|db| {
            let w = db.begin_write()?;
            {
                let mut msgs = w.open_table(MSGS)?;
                for s in &hit {
                    msgs.remove((key, *s))?;
                }
            }
            w.commit()?;
            Ok(true)
        })
    }
}

impl MailboxStore for DiskStore {
    fn save(&self, user_key: &str, item: Stored) -> bool {
        self.save_result(user_key, item) == SaveResult::Stored
    }
    fn save_result(&self, user_key: &str, item: Stored) -> SaveResult {
        match self.save_inner(&user_key.to_uppercase(), item) {
            Ok(true) => SaveResult::Stored,
            Ok(false) => SaveResult::Duplicate,
            Err(e) => {
                tracing::error!(%e, "mailbox save failed");
                SaveResult::Failed
            }
        }
    }
    fn pending(&self, user_key: &str) -> Vec<Stored> {
        self.rows(&user_key.to_uppercase())
            .map(|v| v.into_iter().map(|(_, r)| r.item).collect())
            .unwrap_or_default()
    }
    fn remove_by_hash(&self, user_key: &str, hash: &str) -> bool {
        self.remove_inner(&user_key.to_uppercase(), hash)
            .unwrap_or(false)
    }
}

/// Voice offer index (SI `voiceOfferIndex.ts`): callee user-PGP ciphertext by (callId, sessionId),
/// fetched by a native shell woken by push. Never decrypted here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    pub call_id: String,
    pub session_id: String,
    pub offer_armor: String,
    pub expires_at: i64,
}

pub trait OfferStore: Send + Sync {
    fn put(&self, call_id: &str, session_id: &str, armor: &str, expires_at: i64, now: i64) -> bool;
    fn get(&self, call_id: &str, session_id: &str, now: i64) -> Option<Offer>;
}

fn offer_key(call_id: &str, session_id: &str) -> String {
    format!("{}|{}", call_id.to_lowercase(), session_id.to_lowercase())
}

/// In memory, at most 256 entries (SI `MAX_ENTRIES`), oldest dropped first.
#[derive(Default)]
pub struct MemoryOffers {
    inner: Mutex<(HashMap<String, Offer>, std::collections::VecDeque<String>)>,
}

impl OfferStore for MemoryOffers {
    fn put(&self, call_id: &str, session_id: &str, armor: &str, expires_at: i64, now: i64) -> bool {
        let mut g = self.inner.lock().expect("offers");
        let (map, order) = &mut *g;
        map.retain(|_, o| o.expires_at > now);
        order.retain(|k| map.contains_key(k));
        let k = offer_key(call_id, session_id);
        if map
            .insert(
                k.clone(),
                Offer {
                    call_id: call_id.into(),
                    session_id: session_id.into(),
                    offer_armor: armor.into(),
                    expires_at,
                },
            )
            .is_none()
        {
            order.push_back(k);
        }
        while map.len() > si_proto::voice::OFFER_MEMORY_MAX {
            let Some(old) = order.pop_front() else { break };
            map.remove(&old);
        }
        true
    }
    fn get(&self, call_id: &str, session_id: &str, now: i64) -> Option<Offer> {
        if call_id.is_empty() || session_id.is_empty() {
            return None;
        }
        let mut g = self.inner.lock().expect("offers");
        let k = offer_key(call_id, session_id);
        match g.0.get(&k) {
            Some(o) if o.expires_at > now => Some(o.clone()),
            Some(_) => {
                g.0.remove(&k);
                None
            }
            None => None,
        }
    }
}

const OFFERS: TableDefinition<&str, &[u8]> = TableDefinition::new("voice_offers");

impl OfferStore for DiskStore {
    fn put(&self, call_id: &str, session_id: &str, armor: &str, expires_at: i64, now: i64) -> bool {
        let run = || -> Result<(), redb::Error> {
            self.with_db(|db| {
                let w = db.begin_write()?;
                {
                    let mut t = w.open_table(OFFERS)?;
                    let expired: Vec<String> = t
                        .iter()?
                        .filter_map(|e| e.ok())
                        .filter(|(_, v)| {
                            serde_json::from_slice::<Offer>(v.value())
                                .map(|o| o.expires_at <= now)
                                .unwrap_or(true)
                        })
                        .map(|(k, _)| k.value().to_string())
                        .collect();
                    for k in expired {
                        t.remove(k.as_str())?;
                    }
                    let o = Offer {
                        call_id: call_id.into(),
                        session_id: session_id.into(),
                        offer_armor: armor.into(),
                        expires_at,
                    };
                    t.insert(
                        offer_key(call_id, session_id).as_str(),
                        serde_json::to_vec(&o).expect("offer json").as_slice(),
                    )?;
                }
                w.commit()?;
                Ok(())
            })
        };
        run().is_ok()
    }
    fn get(&self, call_id: &str, session_id: &str, now: i64) -> Option<Offer> {
        if call_id.is_empty() || session_id.is_empty() {
            return None;
        }
        self.with_db(|db| {
            let r = db.begin_read()?;
            let t = r.open_table(OFFERS)?;
            Ok(t.get(offer_key(call_id, session_id).as_str())?
                .and_then(|v| serde_json::from_slice::<Offer>(v.value()).ok()))
        })
        .ok()
        .flatten()
        .filter(|o| o.expires_at > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(a: &str) -> Stored {
        Stored {
            armor: a.into(),
            no_push: false,
            hop_bytes: 0,
            hops: 0,
        }
    }

    #[test]
    fn disk_store_saves_dedups_acks_and_never_evicts() {
        let dir = tempfile::tempdir().unwrap();
        let s = DiskStore::open(&dir.path().join("m.redb")).unwrap();
        assert!(s.save("k1", item("a")));
        assert!(!s.save("K1", item("a")), "dedup, key case-insensitive");
        assert!(s.save("k1", item("b")));
        assert!(s.save("k2", item("x")));
        assert_eq!(
            s.pending("k1")
                .iter()
                .map(|i| i.armor.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(s.remove_by_hash("k1", &armor_hash("a")));
        assert!(!s.remove_by_hash("k1", &armor_hash("a")));
        for a in ["c", "d", "e", "f", "g"] {
            assert!(s.save("k1", item(a)));
        }
        assert_eq!(
            s.pending("k1")
                .iter()
                .map(|i| i.armor.as_str())
                .collect::<Vec<_>>(),
            ["b", "c", "d", "e", "f", "g"],
            "nothing is evicted to make room"
        );
        assert_eq!(s.pending("k2").len(), 1);
        drop(s);
        let s = DiskStore::open(&dir.path().join("m.redb")).unwrap();
        assert_eq!(s.pending("k1").len(), 6, "survives reopen");
    }

    #[test]
    fn offers_expire_and_are_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskStore::open(&dir.path().join("o.redb")).unwrap();
        let mem = MemoryOffers::default();
        for s in [&disk as &dyn OfferStore, &mem] {
            assert!(s.put("CallId01", "SESSION-0123456789", "armor", 1000, 0));
            assert_eq!(
                s.get("callid01", "session-0123456789", 500)
                    .unwrap()
                    .offer_armor,
                "armor"
            );
            assert!(
                s.get("callid01", "session-0123456789", 1000).is_none(),
                "expired"
            );
            assert!(s.get("", "x", 0).is_none());
        }
        for i in 0..300 {
            mem.put(&format!("call{i:08}"), "s-0123456789abcdef", "a", 10_000, 0);
        }
        assert!(
            mem.get("call00000000", "s-0123456789abcdef", 1).is_none(),
            "oldest evicted at 256"
        );
        assert!(mem.get("call00000299", "s-0123456789abcdef", 1).is_some());
    }
}

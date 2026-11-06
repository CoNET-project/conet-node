//! Offline mailbox store, mirroring SI `saveLocal` / `tryGetLocal` / `removeLocalByArmorHash`:
//! every delivery is stored first, flushed on each listen, and deleted only by the client's
//! `gossip_delivery_ack` (keccak256 of the armor). Unlike SI, the disk store bounds each
//! mailbox by count and age, so one key cannot fill the disk.
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub trait MailboxStore: Send + Sync {
    /// Store ciphertext for a user key. Returns false when it was already stored (SI dedups).
    fn save(&self, user_key: &str, item: Stored) -> bool;
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

#[derive(Serialize, Deserialize)]
struct Row {
    item: Stored,
    hash: String,
    saved_at: u64,
}

pub struct DiskStore {
    db: Database,
    pub max_per_key: usize,
    pub max_age_secs: u64,
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
        w.commit()?;
        Ok(Self {
            db,
            max_per_key: 2000,
            max_age_secs: 30 * 24 * 3600,
        })
    }

    fn rows(&self, key: &str) -> Result<Vec<(u64, Row)>, redb::Error> {
        let r = self.db.begin_read()?;
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
        let existing = self.rows(key)?;
        if existing.iter().any(|(_, r)| r.hash == hash) {
            return Ok(false);
        }
        let cutoff = now().saturating_sub(self.max_age_secs);
        let w = self.db.begin_write()?;
        {
            let mut msgs = w.open_table(MSGS)?;
            let mut seq = w.open_table(SEQ)?;
            // Drop expired rows, then the oldest beyond the cap (keeping room for the new one).
            let mut live: Vec<u64> = vec![];
            for (s, r) in &existing {
                if r.saved_at < cutoff {
                    msgs.remove((key, *s))?;
                } else {
                    live.push(*s);
                }
            }
            while live.len() >= self.max_per_key {
                let s = live.remove(0);
                msgs.remove((key, s))?;
            }
            let next = seq.get(key)?.map(|v| v.value()).unwrap_or(0);
            let row = serde_json::to_vec(&Row {
                item,
                hash,
                saved_at: now(),
            })
            .expect("row json");
            msgs.insert((key, next), row.as_slice())?;
            seq.insert(key, next + 1)?;
        }
        w.commit()?;
        Ok(true)
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
        let w = self.db.begin_write()?;
        {
            let mut msgs = w.open_table(MSGS)?;
            for s in hit {
                msgs.remove((key, s))?;
            }
        }
        w.commit()?;
        Ok(true)
    }
}

impl MailboxStore for DiskStore {
    fn save(&self, user_key: &str, item: Stored) -> bool {
        self.save_inner(&user_key.to_uppercase(), item)
            .unwrap_or_else(|e| {
                tracing::error!(%e, "mailbox save failed");
                false
            })
    }
    fn pending(&self, user_key: &str) -> Vec<Stored> {
        let cutoff = now().saturating_sub(self.max_age_secs);
        self.rows(&user_key.to_uppercase())
            .map(|v| {
                v.into_iter()
                    .filter(|(_, r)| r.saved_at >= cutoff)
                    .map(|(_, r)| r.item)
                    .collect()
            })
            .unwrap_or_default()
    }
    fn remove_by_hash(&self, user_key: &str, hash: &str) -> bool {
        self.remove_inner(&user_key.to_uppercase(), hash)
            .unwrap_or(false)
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
    fn disk_store_saves_dedups_acks_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = DiskStore::open(&dir.path().join("m.redb")).unwrap();
        s.max_per_key = 3;
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
        for a in ["c", "d", "e"] {
            s.save("k1", item(a));
        }
        assert_eq!(
            s.pending("k1")
                .iter()
                .map(|i| i.armor.as_str())
                .collect::<Vec<_>>(),
            ["c", "d", "e"]
        );
        assert_eq!(s.pending("k2").len(), 1);
        drop(s);
        let s = DiskStore::open(&dir.path().join("m.redb")).unwrap();
        assert_eq!(s.pending("k1").len(), 3, "survives reopen");
    }
}

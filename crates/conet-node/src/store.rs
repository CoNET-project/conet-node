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
        w.open_table(OFFERS)?;
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
            let w = self.db.begin_write()?;
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
        };
        run().is_ok()
    }
    fn get(&self, call_id: &str, session_id: &str, now: i64) -> Option<Offer> {
        if call_id.is_empty() || session_id.is_empty() {
            return None;
        }
        let r = self.db.begin_read().ok()?;
        let t = r.open_table(OFFERS).ok()?;
        let v = t.get(offer_key(call_id, session_id).as_str()).ok()??;
        let o: Offer = serde_json::from_slice(v.value()).ok()?;
        (o.expires_at > now).then_some(o)
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

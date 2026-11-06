//! Offline mailbox store. A1 has the trait and an in-memory implementation; A2 adds the
//! durable store (redb) with ACK-based deletion, mirroring SI `saveLocal` / ACK.
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub armor: String,
    pub no_push: bool,
    /// Verified prior-hop bytes (GB metering input).
    pub hop_bytes: u64,
    pub hops: usize,
}

pub trait MailboxStore: Send + Sync {
    /// Store ciphertext for a user key. Returns false when it was already stored (SI dedups).
    fn save(&self, user_key: &str, item: Stored) -> bool;
    fn pending(&self, user_key: &str) -> Vec<Stored>;
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
}

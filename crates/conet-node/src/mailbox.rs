//! Mailbox B: durable store plus live listen sessions (SI `mailbox_listen`).
//!
//! Every frame on a listen is sealed with that listen's `streamKey`, so the entry relaying the
//! stream sees no key ID, wallet or frame type. A wallet may hold several listens (phone,
//! desktop, browser), each a separate delivery target.
use crate::push::Push;
use crate::store::{MailboxStore, SaveResult, Stored};
use rand_core::{OsRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

/// Frames queued per listen before it is treated as stuck and dropped.
pub const LISTEN_QUEUE: usize = 256;

pub struct Listener {
    pub id: u64,
    pub wallet: String,
    pub user_key: Option<String>,
    pub stream_key: [u8; 32],
    pub tx: mpsc::Sender<Vec<u8>>,
    pub connected_at: Instant,
    /// Legacy `mining` + `listenKind:"chat"` listen: presence only, no deliveries, one per wallet.
    pub legacy: bool,
}

/// What one delivery did: stored newly, push queued, live listens written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverReport {
    /// What the store did with this armor; `fresh` is `outcome == Stored`.
    pub outcome: SaveResult,
    pub fresh: bool,
    pub push_enqueued: bool,
    pub live_sessions: u32,
}

impl DeliverReport {
    /// The reply body a mailbox gives the sender for a post: `h` is the keccak256 of the armor exactly as stored (the `gossip_delivery_ack` hash).
    /// Old senders only look for `ok:false`, so a stored or duplicate armor is `ok:true` and a storage failure is `ok:false`.
    pub fn ack_body(&self, h: &str) -> String {
        match self.outcome {
            SaveResult::Stored => {
                serde_json::json!({ "ok": true, "stored": true, "h": h }).to_string()
            }
            SaveResult::Duplicate => {
                serde_json::json!({ "ok": true, "duplicate": true, "h": h }).to_string()
            }
            SaveResult::Failed => {
                serde_json::json!({ "ok": false, "error": STORE_FAILED }).to_string()
            }
        }
    }
}

/// The reply error when the armor could not be stored; the sender may retry the same armor.
pub const STORE_FAILED: &str = "store_failed";

pub struct Mailbox {
    pub store: Arc<dyn MailboxStore>,
    pub push: Arc<dyn Push>,
    listeners: Mutex<Vec<Listener>>,
    next_id: AtomicU64,
}

/// `data: base64(iv ‖ AES-GCM(json padded to 256)) \r\n\r\n` (SI `mailboxSseFrame`).
pub fn sealed_frame(json: &str, key: &[u8; 32]) -> Vec<u8> {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let sealed = si_core::seal_mailbox(json, key, &iv).expect("aes-gcm with a 32-byte key");
    format!("data: {sealed}\r\n\r\n").into_bytes()
}

impl Mailbox {
    pub fn new(store: Arc<dyn MailboxStore>, push: Arc<dyn Push>) -> Self {
        Self {
            store,
            push,
            listeners: Mutex::new(vec![]),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Store first, push unless NoPush, then write to every live listen of that key.
    /// Returns true when the armor was newly stored.
    pub fn deliver(&self, user_key: &str, item: Stored) -> bool {
        self.deliver_report(user_key, item).fresh
    }

    /// Same as [`deliver`], with what happened (for the evidence log).
    pub fn deliver_report(&self, user_key: &str, item: Stored) -> DeliverReport {
        let armor = item.armor.clone();
        let no_push = item.no_push;
        let outcome = self.store.save_result(user_key, item);
        let fresh = outcome == SaveResult::Stored;
        let push_enqueued = fresh && !no_push;
        if outcome == SaveResult::Failed {
            // A real storage failure is a clear refusal (the post reply is ok:false and the sender keeps the message and retries):
            // nothing is pushed and nothing is written to a live listen, so a refused message is never half delivered.
            return DeliverReport {
                outcome,
                fresh: false,
                push_enqueued: false,
                live_sessions: 0,
            };
        }
        if push_enqueued {
            self.push.offline_chat(user_key.to_uppercase());
        }
        let frame_json = serde_json::json!({ "data": armor }).to_string();
        let mut live_sessions = 0u32;
        let mut ls = self.listeners.lock().expect("listeners");
        ls.retain(|l| {
            if l.legacy
                || l.user_key
                    .as_deref()
                    .map(|k| k.eq_ignore_ascii_case(user_key))
                    != Some(true)
            {
                return true;
            }
            // A full or closed queue means a stuck listen: drop it (the message stays stored).
            let sent =
                l.tx.try_send(sealed_frame(&frame_json, &l.stream_key))
                    .is_ok();
            if sent {
                live_sessions += 1;
            }
            sent
        });
        DeliverReport {
            outcome,
            fresh,
            push_enqueued,
            live_sessions,
        }
    }

    pub fn register(&self, l: Listener) {
        let mut ls = self.listeners.lock().expect("listeners");
        if l.legacy {
            // SI keeps one legacy listen per wallet and ends the older one; dropping its sender
            // ends that session's loop.
            ls.retain(|o| !(o.legacy && o.wallet.eq_ignore_ascii_case(&l.wallet)));
        }
        ls.push(l);
    }

    pub fn remove(&self, id: u64) {
        self.listeners
            .lock()
            .expect("listeners")
            .retain(|l| l.id != id);
    }

    /// Oldest live listen of a wallet (SI `wallet_online_query`).
    pub fn online_since(&self, wallet: &str) -> Option<Instant> {
        let ls = self.listeners.lock().expect("listeners");
        ls.iter()
            .filter(|l| l.wallet.eq_ignore_ascii_case(wallet) && !l.tx.is_closed())
            .map(|l| l.connected_at)
            .min()
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.lock().expect("listeners").len()
    }
}

pub fn random_instance_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

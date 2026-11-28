//! Mailbox capacity boundaries, written as the EXPECTED semantics (project decision, relayed: 「沿用 TS，不设条数或天数上限，实际存储失败时明确拒收」):
//! an accepted but unacknowledged message is kept until the mailbox owner acknowledges it, across restarts, past 2000 messages per key and past 30 days;
//! nothing is silently dropped. Synthetic data only; no node, no network.
use conet_node::mailbox::Mailbox;
use conet_node::chain::BoxFut;
use conet_node::push::{Push, VoiceCall};
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

struct NoPush;
impl Push for NoPush {
    fn voice_call(&self, _c: VoiceCall) {}
    fn offline_chat(&self, _user_key: String) {}
    fn native_wakeable<'a>(&'a self, _eoa: &'a str) -> BoxFut<'a, Option<bool>> {
        Box::pin(async { Some(true) })
    }
    fn register_device(&self, _p: serde_json::Value) {}
}

fn item(armor: &str) -> Stored {
    Stored {
        armor: armor.to_string(),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

fn armors(s: &DiskStore, key: &str) -> Vec<String> {
    s.pending(key).into_iter().map(|i| i.armor).collect()
}

/// 1. An accepted, unacknowledged message is retrievable after the process restarts (the redb file is closed and opened again).
#[test]
fn unacknowledged_messages_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.redb");
    {
        let s = DiskStore::open(&p).unwrap();
        for a in ["old-1", "old-2", "old-3"] {
            assert_eq!(s.save_result("KEY1", item(a)), SaveResult::Stored);
        }
        // one of them is acknowledged: it must not come back
        assert!(s.remove_by_hash("KEY1", &armor_hash("old-2")));
    }
    let s = DiskStore::open(&p).unwrap();
    assert_eq!(armors(&s, "KEY1"), ["old-1", "old-3"], "unacknowledged survive, acknowledged stays gone");
    // a retry of an already stored armor is a duplicate (no second copy), after the restart too
    assert_eq!(s.save_result("KEY1", item("old-1")), SaveResult::Duplicate);
    assert_eq!(armors(&s, "KEY1").len(), 2);
}

/// 2. The 2001st message for one key (and every later one) is accepted, and the oldest message is still there:
/// no message is silently dropped to make room, and the report of each delivery says Stored.
#[test]
fn the_2001st_message_is_accepted_and_the_oldest_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.redb");
    let s = Arc::new(DiskStore::open(&p).unwrap());
    let mb = Mailbox::new(s.clone(), Arc::new(NoPush));
    let total = 2003usize;
    let mut outcomes = vec![];
    for i in 0..total {
        let r = mb.deliver_report("KEY1", item(&format!("msg-{i:05}")));
        outcomes.push((r.outcome, r.fresh));
    }
    println!(
        "MEASURE report of delivery 2000/2001/2002/2003: {:?} {:?} {:?} {:?}",
        outcomes[1999], outcomes[2000], outcomes[2001], outcomes[2002]
    );
    assert!(
        outcomes.iter().all(|(o, fresh)| *o == SaveResult::Stored && *fresh),
        "every delivery, including the 2001st and later, is reported as newly stored"
    );
    let got = armors(&s, "KEY1");
    println!("MEASURE rows after {total} deliveries: {} first={:?} last={:?}", got.len(), got.first(), got.last());
    assert_eq!(got.len(), total, "no message was removed to make room");
    assert_eq!(got.first().map(String::as_str), Some("msg-00000"), "the oldest message is still stored");
    assert_eq!(got.last().map(String::as_str), Some("msg-02002"));
    // restart: still all there
    drop(mb);
    drop(s);
    let s = DiskStore::open(&p).unwrap();
    assert_eq!(armors(&s, "KEY1").len(), total, "all of them survive a restart");
}

const MSGS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("msgs");

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Rewrites the stored timestamp of one armor in the database file (the store has no injectable clock): the process is "closed" while this runs.
fn age_row(path: &Path, key: &str, armor: &str, saved_at: u64) {
    let db = Database::open(path).unwrap();
    let h = armor_hash(armor);
    let w = db.begin_write().unwrap();
    {
        let mut t = w.open_table(MSGS).unwrap();
        let rows: Vec<(u64, Vec<u8>)> = t
            .range((key, 0u64)..=(key, u64::MAX))
            .unwrap()
            .map(|e| {
                let (k, v) = e.unwrap();
                (k.value().1, v.value().to_vec())
            })
            .collect();
        let mut hit = 0;
        for (seq, raw) in rows {
            let mut row: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            if row["hash"].as_str() == Some(h.as_str()) {
                row["saved_at"] = serde_json::json!(saved_at);
                t.insert((key, seq), serde_json::to_vec(&row).unwrap().as_slice()).unwrap();
                hit += 1;
            }
        }
        assert_eq!(hit, 1, "exactly one row was aged");
    }
    w.commit().unwrap();
}

/// 3. An accepted, unacknowledged message is still retrievable 31 days after it was stored, also after a restart, and a later save does not purge it.
#[test]
fn an_accepted_message_is_retrievable_after_31_days_and_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.redb");
    {
        let s = DiskStore::open(&p).unwrap();
        assert_eq!(s.save_result("KEY1", item("aged")), SaveResult::Stored);
        assert_eq!(s.save_result("KEY1", item("recent")), SaveResult::Stored);
    }
    age_row(&p, "KEY1", "aged", now_secs() - 31 * 24 * 3600);
    let s = DiskStore::open(&p).unwrap();
    let got = armors(&s, "KEY1");
    println!("MEASURE pending after aging one row to 31 days and reopening: {got:?}");
    assert_eq!(got, ["aged", "recent"], "the 31-day-old accepted message is still retrievable after the restart");
    // a new save (which used to purge expired rows) must not remove it either
    assert_eq!(s.save_result("KEY1", item("newest")), SaveResult::Stored);
    assert_eq!(armors(&s, "KEY1"), ["aged", "recent", "newest"], "a later save does not purge the old message");
    // and the owner's acknowledgement still removes it
    assert!(s.remove_by_hash("KEY1", &armor_hash("aged")));
    assert_eq!(armors(&s, "KEY1"), ["recent", "newest"]);
}

/// A store whose writes always fail (a refusal the sender must see), used with a live listener.
struct FailingStore;
impl MailboxStore for FailingStore {
    fn save(&self, _k: &str, _i: Stored) -> bool {
        false
    }
    fn save_result(&self, _k: &str, _i: Stored) -> SaveResult {
        SaveResult::Failed
    }
    fn pending(&self, _k: &str) -> Vec<Stored> {
        vec![]
    }
    fn remove_by_hash(&self, _k: &str, _h: &str) -> bool {
        false
    }
}

/// 4. A message the store REFUSED (a real storage failure) is refused as a whole: it is not written to a live listen and not pushed, so the sender's retry
/// is the only delivery and the receiver never sees a message that the sender was told failed.
#[test]
fn a_refused_message_is_not_delivered_live_or_pushed() {
    use conet_node::mailbox::Listener;
    let mb = Mailbox::new(Arc::new(FailingStore), Arc::new(NoPush));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    mb.register(Listener {
        id: mb.next_id(),
        wallet: "0xw".into(),
        user_key: Some("KEY1".into()),
        stream_key: [7; 32],
        tx,
        connected_at: std::time::Instant::now(),
        legacy: false,
    });
    let r = mb.deliver_report("KEY1", Stored { armor: "refused".into(), no_push: false, hop_bytes: 0, hops: 0 });
    println!("MEASURE refused delivery: outcome={:?} fresh={} push_enqueued={} live_sessions={} reply={}", r.outcome, r.fresh, r.push_enqueued, r.live_sessions, r.ack_body(&armor_hash("refused")));
    assert_eq!(r.outcome, SaveResult::Failed);
    assert_eq!(r.ack_body(&armor_hash("refused")), r#"{"ok":false,"error":"store_failed"}"#);
    assert_eq!(r.live_sessions, 0, "no live listen was written");
    assert!(rx.try_recv().is_err(), "nothing arrived on the live listen");
}

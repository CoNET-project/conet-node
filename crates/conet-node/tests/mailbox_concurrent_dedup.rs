//! Concurrent posts of the SAME armor (a sender that retried through another entry after a slow answer, or two entries forwarding at once) must leave exactly one copy
//! and exactly one `Stored` answer per message: the duplicate check and the insert are one atomic step. Healthy storage; synthetic data.
use conet_node::store::{DiskStore, MailboxStore, SaveResult, Stored};
use std::sync::Arc;

fn item(armor: &str) -> Stored {
    Stored {
        armor: armor.to_string(),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

#[test]
fn concurrent_saves_of_the_same_message_store_it_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(DiskStore::open(&dir.path().join("m.redb")).unwrap());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let s = store.clone();
            std::thread::spawn(move || {
                (0..30)
                    .map(|k| s.save_result("KEY1", item(&format!("msg-{k:03}"))))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let outcomes: Vec<SaveResult> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let stored = outcomes
        .iter()
        .filter(|r| **r == SaveResult::Stored)
        .count();
    let dup = outcomes
        .iter()
        .filter(|r| **r == SaveResult::Duplicate)
        .count();
    println!(
        "MEASURE 8 threads x 30 same messages: Stored={stored} Duplicate={dup} rows={}",
        store.pending("KEY1").len()
    );
    assert_eq!(stored, 30, "each message is answered Stored exactly once");
    assert_eq!(dup, 8 * 30 - 30);
    assert_eq!(store.pending("KEY1").len(), 30, "one row per message");
}

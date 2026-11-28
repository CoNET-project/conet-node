//! A REAL write failure of the mailbox database (not a mocked return value): the process file-size limit (RLIMIT_FSIZE) is set to the current size of the
//! redb file, so the first commit that needs the file to grow fails in the operating system (EFBIG) inside redb. Expected semantics (project decision, relayed:
//! 「沿用 TS，不设条数或天数上限，实际存储失败时明确拒收」): the delivery is refused (`ok:false`, never Stored), nothing half-stored, and after the failure is gone
//! the SAME armor is stored exactly once. This binary has exactly one test, so the limit applies to this process only. Synthetic data; no node, no network.
use conet_node::chain::BoxFut;
use conet_node::mailbox::Mailbox;
use conet_node::push::{Push, VoiceCall};
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use std::sync::Arc;

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}
extern "C" {
    fn getrlimit(resource: i32, rlp: *mut Rlimit) -> i32;
    fn setrlimit(resource: i32, rlp: *const Rlimit) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
}
const RLIMIT_FSIZE: i32 = 1;
const SIGXFSZ: i32 = 25;
const SIG_IGN: usize = 1;

fn set_file_size_limit(limit: Option<u64>) {
    unsafe {
        let mut cur = Rlimit { cur: 0, max: 0 };
        assert_eq!(getrlimit(RLIMIT_FSIZE, &mut cur), 0);
        let new = Rlimit {
            cur: limit.unwrap_or(cur.max),
            max: cur.max,
        };
        assert_eq!(setrlimit(RLIMIT_FSIZE, &new), 0);
    }
}

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

/// An armor-sized payload (about 3 KB) so the file fills in a few hundred messages.
fn armor(i: usize) -> String {
    format!("-----BEGIN PGP MESSAGE-----\n{i:08}{}\n-----END PGP MESSAGE-----", "A".repeat(3000))
}

#[test]
fn a_real_write_failure_refuses_the_message_and_a_retry_after_recovery_stores_it_once() {
    unsafe {
        signal(SIGXFSZ, SIG_IGN);
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.redb");
    let uk = "KEY1";
    // 1. a first message is stored; the size limit is then set to the current file size
    let s = Arc::new(DiskStore::open(&p).unwrap());
    let mb = Mailbox::new(s.clone(), Arc::new(NoPush));
    let first = mb.deliver_report(uk, item(&armor(0)));
    assert_eq!(first.outcome, SaveResult::Stored);
    let len = std::fs::metadata(&p).unwrap().len();
    set_file_size_limit(Some(len));
    // 2. distinct messages until the first real write failure
    let mut stored = 1usize;
    let mut failed: Option<(usize, String)> = None;
    for i in 1..20_000usize {
        let a = armor(i);
        let r = mb.deliver_report(uk, item(&a));
        match r.outcome {
            SaveResult::Stored => stored += 1,
            SaveResult::Failed => {
                failed = Some((i, a));
                let body = r.ack_body(&armor_hash(&failed.as_ref().unwrap().1));
                println!("MEASURE first failure at message {i}: outcome={:?} fresh={} live_sessions={} push_enqueued={} reply={body}", r.outcome, r.fresh, r.live_sessions, r.push_enqueued);
                assert!(!r.fresh && !r.push_enqueued && r.live_sessions == 0);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v, serde_json::json!({ "ok": false, "error": "store_failed" }), "the post reply is an explicit failure");
                break;
            }
            SaveResult::Duplicate => panic!("distinct armor reported as duplicate at {i}"),
        }
    }
    let (fi, fa) = failed.expect("a real write failure was provoked (file size limit)");
    println!("MEASURE file size limit {len} bytes; {stored} messages stored before the failure");
    // 3. node result: nothing half-stored, everything accepted before is still there, and the failed one is NOT there
    let pend = s.pending(uk);
    assert_eq!(pend.len(), stored, "rows equal the accepted messages");
    assert!(pend.iter().all(|i| i.armor != fa), "the refused message is not stored");
    // a second try on the same handle while the failure persists: still an explicit refusal (never Stored)
    let again = mb.deliver_report(uk, item(&fa));
    assert_eq!(again.outcome, SaveResult::Failed);
    // 4. the failure goes away
    set_file_size_limit(None);
    let same_handle = mb.deliver_report(uk, item(&fa));
    println!("MEASURE after the limit is lifted, SAME database handle, retry of the same armor: outcome={:?}", same_handle.outcome);
    drop(mb);
    drop(s);
    // 5. restart (the file is opened again): the same armor is stored exactly once and a second retry is a duplicate
    let s = Arc::new(DiskStore::open(&p).unwrap());
    let rows_before = s.pending(uk).len();
    let mb = Mailbox::new(s.clone(), Arc::new(NoPush));
    let r1 = mb.deliver_report(uk, item(&fa));
    let r2 = mb.deliver_report(uk, item(&fa));
    println!("MEASURE after restart: rows_before={rows_before} retry={:?} second retry={:?}", r1.outcome, r2.outcome);
    let want_first = if same_handle.outcome == SaveResult::Stored { SaveResult::Duplicate } else { SaveResult::Stored };
    assert_eq!(r1.outcome, want_first, "the retry is stored once (or already stored by the same-handle retry)");
    assert_eq!(r2.outcome, SaveResult::Duplicate, "a second retry is a duplicate, never a second copy");
    let pend = s.pending(uk);
    assert_eq!(pend.len(), stored + 1, "exactly one copy of the retried armor (message {fi}); no other change");
    assert_eq!(pend.iter().filter(|i| i.armor == fa).count(), 1);
}

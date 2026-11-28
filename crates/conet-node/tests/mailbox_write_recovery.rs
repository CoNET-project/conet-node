//! Recovery of the mailbox database after a REAL write failure, written as the EXPECTED semantics. The failure is provoked as in `mailbox_write_failure.rs`
//! (the process file-size limit is set to the redb file's size, so redb's own write fails with EFBIG). redb then refuses every later write on the same handle
//! (`PreviousIo`) until the database is opened again. Two ways back are compared on synthetic databases: A) the controlled restart (the process drops the store and
//! opens the file again; this is what an operator or systemd does today) and B) a single-writer, bounded reopen inside the store. Three properties are checked for both:
//! nothing accepted is lost, nothing is stored twice, and while the storage is still unhealthy every write keeps being refused. A database that cannot be opened is never
//! replaced by a new empty one. All tests share one process-wide limit, so they take a lock and reset the limit. Synthetic data only; no node, no network.
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use std::collections::BTreeSet;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

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

fn item(armor: &str) -> Stored {
    Stored {
        armor: armor.to_string(),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

fn armor(i: usize) -> String {
    format!(
        "-----BEGIN PGP MESSAGE-----\n{i:08}{}\n-----END PGP MESSAGE-----",
        "A".repeat(3000)
    )
}

fn set_of(s: &DiskStore, uk: &str) -> BTreeSet<String> {
    s.pending(uk)
        .into_iter()
        .map(|i| armor_hash(&i.armor))
        .collect()
}

struct Episode {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    store: DiskStore,
    accepted: BTreeSet<String>,
    refused: String,
}

const UK: &str = "KEY1";

/// A database with messages in it, then a real write failure: returns the store (limit still in force), the set of accepted hashes and the armor that was refused.
fn provoke() -> Episode {
    unsafe {
        signal(SIGXFSZ, SIG_IGN);
    }
    set_file_size_limit(None);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.redb");
    let store = DiskStore::open(&path).unwrap();
    assert_eq!(store.save_result(UK, item(&armor(0))), SaveResult::Stored);
    set_file_size_limit(Some(std::fs::metadata(&path).unwrap().len()));
    let mut i = 1;
    loop {
        let a = armor(i);
        match store.save_result(UK, item(&a)) {
            SaveResult::Stored => {}
            SaveResult::Failed => {
                let accepted = set_of(&store, UK);
                println!(
                    "MEASURE failure provoked at message {i}; {} accepted before it",
                    accepted.len()
                );
                return Episode {
                    dir,
                    path,
                    store,
                    accepted,
                    refused: a,
                };
            }
            SaveResult::Duplicate => panic!("duplicate at {i}"),
        }
        i += 1;
        assert!(i < 20_000, "no failure was provoked");
    }
}

/// B, recovery: when the failure is gone, the SAME store accepts the refused message again without a restart; once; nothing accepted before is lost.
#[test]
fn after_the_failure_is_gone_the_same_store_accepts_writes_without_a_restart() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = provoke();
    set_file_size_limit(None);
    let first = e.store.save_result(UK, item(&e.refused));
    println!("MEASURE same handle after the limit is lifted: first retry = {first:?}");
    assert_eq!(first, SaveResult::Stored, "the store recovered by itself");
    assert_eq!(
        e.store.save_result(UK, item(&e.refused)),
        SaveResult::Duplicate,
        "a second retry is a duplicate"
    );
    let now = set_of(&e.store, UK);
    assert!(
        e.accepted.is_subset(&now),
        "nothing accepted before the failure is lost"
    );
    assert_eq!(
        now.len(),
        e.accepted.len() + 1,
        "exactly one copy of the retried message"
    );
    assert!(now.contains(&armor_hash(&e.refused)));
    drop(e.dir);
}

/// B, unhealthy storage: while the failure persists every write keeps being refused, however often it is tried, and nothing changes.
#[test]
fn while_the_failure_persists_every_save_is_refused_and_nothing_changes() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = provoke();
    for k in 0..25 {
        let r = e.store.save_result(UK, item(&armor(100_000 + k)));
        assert_eq!(
            r,
            SaveResult::Failed,
            "save {k} while the storage is unhealthy"
        );
    }
    assert_eq!(
        set_of(&e.store, UK),
        e.accepted,
        "the stored set did not change"
    );
    assert_eq!(
        e.store.save_result(UK, item(&e.refused)),
        SaveResult::Failed
    );
    set_file_size_limit(None);
    drop(e.dir);
}

/// Never a new empty database: if the file is emptied while the store runs, a write is refused, never Stored, and the file is not rebuilt.
#[test]
fn an_emptied_database_file_is_never_rebuilt() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = provoke();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&e.path)
        .unwrap()
        .set_len(0)
        .unwrap();
    set_file_size_limit(None);
    for k in 0..5 {
        let r = e.store.save_result(UK, item(&armor(200_000 + k)));
        println!("MEASURE save {k} after the file was emptied and the limit lifted: {r:?}");
        assert_ne!(
            r,
            SaveResult::Stored,
            "a message must not be stored into a rebuilt empty database"
        );
    }
    assert_eq!(
        std::fs::metadata(&e.path).unwrap().len(),
        0,
        "the file was not rebuilt"
    );
    drop(e.dir);
}

/// A, the controlled restart: the store is dropped and the file opened again; everything accepted is there, the refused message is stored once.
#[test]
fn a_controlled_restart_recovers_without_loss_or_duplicate() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = provoke();
    let Episode {
        dir,
        path,
        store,
        accepted,
        refused,
    } = e;
    // the restart while the storage is still unhealthy: opening must not pretend to work
    drop(store);
    let reopened_unhealthy = DiskStore::open(&path);
    println!(
        "MEASURE restart while the limit is still in force: open = {}",
        if reopened_unhealthy.is_ok() {
            "ok"
        } else {
            "refused"
        }
    );
    drop(reopened_unhealthy);
    set_file_size_limit(None);
    let s = DiskStore::open(&path).unwrap();
    assert_eq!(
        set_of(&s, UK),
        accepted,
        "everything accepted is there after the restart"
    );
    assert_eq!(s.save_result(UK, item(&refused)), SaveResult::Stored);
    assert_eq!(s.save_result(UK, item(&refused)), SaveResult::Duplicate);
    assert_eq!(set_of(&s, UK).len(), accepted.len() + 1);
    drop(dir);
}

/// B, single writer: after the failure is gone, many threads write the SAME new messages at once. Each message is stored exactly once, nothing accepted before is lost,
/// and the store reopened its file once (one writer reopens; the others find the new handle), not once per thread.
#[test]
fn concurrent_writers_during_the_recovery_store_each_message_once() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = provoke();
    set_file_size_limit(None);
    let store = std::sync::Arc::new(e.store);
    let before = store.reopen_attempts();
    let outcomes: Vec<Vec<SaveResult>> = (0..8)
        .map(|_| {
            let s = store.clone();
            std::thread::spawn(move || {
                (0..30)
                    .map(|k| s.save_result(UK, item(&armor(300_000 + k))))
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    let stored = outcomes
        .iter()
        .flatten()
        .filter(|r| **r == SaveResult::Stored)
        .count();
    let failed = outcomes
        .iter()
        .flatten()
        .filter(|r| **r == SaveResult::Failed)
        .count();
    println!(
        "MEASURE 8 threads x 30 messages: stored={stored} failed={failed} reopens={}",
        store.reopen_attempts() - before
    );
    let now = set_of(&store, UK);
    assert!(
        e.accepted.is_subset(&now),
        "nothing accepted before the failure is lost"
    );
    assert_eq!(
        stored,
        now.len() - e.accepted.len(),
        "each stored result is one new row: no message is stored twice"
    );
    // whatever was refused during the race is stored by a plain retry, once
    for k in 0..30 {
        let r = store.save_result(UK, item(&armor(300_000 + k)));
        assert!(
            matches!(r, SaveResult::Stored | SaveResult::Duplicate),
            "message {k}: {r:?}"
        );
    }
    assert_eq!(
        set_of(&store, UK).len(),
        e.accepted.len() + 30,
        "exactly the 30 new messages, one copy each"
    );
    assert!(
        store.reopen_attempts() - before <= 1,
        "one writer reopened the file once"
    );
    drop(e.dir);
}

//! MEASUREMENT (ignored; needs about 1.2 GB of free disk): how long the store's reopen takes on a database of at least 1 GB. The reopen holds the exclusive lock and opens the
//! file with the integrity check (checksums of every page of the committed trees, allocator rebuilt, and a commit), so every other caller waits for that time.
//! Run: `cargo test -p conet-node --test mailbox_reopen_large_db -- --ignored --nocapture`. The database is built with redb directly (rows in the store's own format) because
//! filling 1 GB through `save` would scan every earlier row for the duplicate check on each of the saves; synthetic bytes only.
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use redb::{Database, TableDefinition};
use std::time::Instant;

const MSGS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("msgs");
const SEQ: TableDefinition<&str, u64> = TableDefinition::new("seq");

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
fn set_limit(limit: Option<u64>) {
    unsafe {
        let mut cur = Rlimit { cur: 0, max: 0 };
        assert_eq!(getrlimit(1, &mut cur), 0);
        let new = Rlimit {
            cur: limit.unwrap_or(cur.max),
            max: cur.max,
        };
        assert_eq!(setrlimit(1, &new), 0);
    }
}

fn item(armor: String) -> Stored {
    Stored {
        armor,
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

#[test]
#[ignore = "measurement: builds a database of about 1.1 GB"]
fn reopen_time_on_a_database_of_at_least_one_gigabyte() {
    unsafe {
        signal(25, 1);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.redb");
    let uk = "KEY1";
    // build: DiskStore creates the tables, then rows of ~100 MB are written with redb directly
    drop(DiskStore::open(&path).unwrap());
    let t = Instant::now();
    {
        let db = Database::open(&path).unwrap();
        for i in 0..11u64 {
            let armor = format!("{i:04}{}", "B".repeat(100 * 1024 * 1024));
            let row = serde_json::to_vec(&serde_json::json!({
                "item": { "armor": armor, "no_push": true, "hop_bytes": 0, "hops": 0 },
                "hash": armor_hash(&armor),
                "saved_at": 1u64,
            }))
            .unwrap();
            let w = db.begin_write().unwrap();
            {
                w.open_table(MSGS)
                    .unwrap()
                    .insert((uk, i), row.as_slice())
                    .unwrap();
                w.open_table(SEQ).unwrap().insert(uk, i + 1).unwrap();
            }
            w.commit().unwrap();
        }
    }
    let len = std::fs::metadata(&path).unwrap().len();
    println!(
        "MEASURE database built in {:.1} s: {} bytes ({:.2} GB)",
        t.elapsed().as_secs_f64(),
        len,
        len as f64 / 1e9
    );
    assert!(len >= 1_000_000_000, "the database is at least 1 GB");

    // 1. the cost of the reopen's own call, three times (file closed in between)
    for n in 1..=3 {
        let t = Instant::now();
        let db = Database::builder()
            .set_check_integrity_on_open(true)
            .open(&path)
            .unwrap();
        println!(
            "MEASURE integrity-checked open #{n}: {:.2} s",
            t.elapsed().as_secs_f64()
        );
        drop(db);
    }
    let t = Instant::now();
    let store = std::sync::Arc::new(DiskStore::open(&path).unwrap());
    println!(
        "MEASURE plain DiskStore::open (create path, no integrity check): {:.2} s",
        t.elapsed().as_secs_f64()
    );

    // 2. the lock: the store's own reopen with another caller waiting. The reopen holds the exclusive lock for the open only, so a cheap read started a little after it began
    //    is blocked for about the time of the open.
    let reader = {
        let s = store.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let t = Instant::now();
            let _ = s.ts_imported_hashes(uk);
            t.elapsed()
        })
    };
    let reopen = store.reopen_now().unwrap();
    let blocked = reader.join().unwrap();
    println!("MEASURE the store's own reopen (exclusive lock, integrity check): {:.2} s; a cheap read started 0.5 s into it waited {:.2} s", reopen.as_secs_f64(), blocked.as_secs_f64());
    assert!(
        blocked.as_secs_f64() > reopen.as_secs_f64() - 1.5,
        "the reader waited for the reopen"
    );

    // 3. end to end: a real write failure (file-size limit = the file's size; the file has free space inside it, so writes of 200 MB are made until one needs the file to grow),
    //    then the failure goes away and the next save recovers by itself. The time of that save includes the duplicate scan of every row (about 1.2 GB of JSON in a debug build).
    set_limit(Some(len));
    let mut refused = None;
    for i in 0..8 {
        let t = Instant::now();
        let r = store.save_result(
            uk,
            item(format!("grow-{i}-{}", "C".repeat(200 * 1024 * 1024))),
        );
        println!(
            "MEASURE write #{i} under the size limit: {r:?} in {:.1} s",
            t.elapsed().as_secs_f64()
        );
        if r == SaveResult::Failed {
            refused = Some(i);
            break;
        }
    }
    assert!(refused.is_some(), "the failure was provoked");
    set_limit(None);
    let t = Instant::now();
    let again = store.save_result(
        uk,
        item(format!("grow-retry-{}", "C".repeat(200 * 1024 * 1024))),
    );
    println!("MEASURE first save after the failure went away (reopen + the retry with its duplicate scan): {again:?} in {:.2} s; reopen attempts in total {}", t.elapsed().as_secs_f64(), store.reopen_attempts());
    assert_eq!(again, SaveResult::Stored);
}

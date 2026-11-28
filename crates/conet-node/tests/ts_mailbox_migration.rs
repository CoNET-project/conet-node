//! Migration of the TS node's offline mailbox files into the Rust store at the cutover, and back at a rollback. Expected semantics (project decision, relayed:
//! 「沿用 TS，不设条数或天数上限，实际存储失败时明确拒收」; already accepted and not yet acknowledged messages must stay available until the mailbox owner acknowledges them):
//! the TS files `<KEYID>.json` (not yet sent) and `<KEYID>.inflight.json` (sent, not acknowledged), arrays of PGP armor strings written with `JSON.stringify(list, null, 2)`
//! (CoNET-SI 215afb18 util.ts saveLocal, tryGetLocal, removeLocalByArmorHash), are taken over by the Rust store; the owner's ACK deletes by armor hash; at a rollback
//! the Rust node's pending messages are exported back in the TS format so the TS node serves them. Synthetic files and a synthetic redb only; no node, no network.
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use conet_node::ts_mailbox::{
    export_ts_dir, export_ts_dir_with, import_ts_dir, import_ts_dir_with,
};
use std::path::Path;

fn item(armor: &str) -> Stored {
    Stored {
        armor: armor.to_string(),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

/// A TS file as TS writes it.
fn write_ts(dir: &Path, name: &str, list: &[&str]) {
    let v: Vec<&str> = list.to_vec();
    std::fs::write(dir.join(name), serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// TS `tryGetLocal`: the inflight file first, then the new file, merged without duplicates; missing or unreadable files count as empty.
fn ts_reads(dir: &Path, key: &str) -> Vec<String> {
    let read = |n: String| -> Vec<String> {
        std::fs::read_to_string(dir.join(n))
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok())
            .unwrap_or_default()
    };
    let mut out: Vec<String> = vec![];
    for a in read(format!("{key}.inflight.json"))
        .into_iter()
        .chain(read(format!("{key}.json")))
    {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

fn armors(s: &DiskStore, key: &str) -> Vec<String> {
    s.pending(key).into_iter().map(|i| i.armor).collect()
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(ts.join("voice-offers")).unwrap();
    write_ts(&ts, "0123456789ABCDEF.inflight.json", &["i1", "i2"]);
    write_ts(&ts, "0123456789ABCDEF.json", &["j1", "j2", "j3"]);
    write_ts(&ts, "FEDCBA9876543210.json", &["k1"]);
    std::fs::write(ts.join("nodeSetup-like.json"), "{}").unwrap(); // not a mailbox file
    std::fs::write(ts.join("0123456789abcdef.json"), "[\"lower\"]").unwrap(); // lower-case name: TS writes upper case only
    (d, ts)
}

const K1: &str = "0123456789ABCDEF";
const K2: &str = "FEDCBA9876543210";

/// RED TODAY, with the code as it is: a Rust node started on the TS data directory knows nothing of the TS messages (no code reads those files).
#[test]
fn today_a_rust_store_started_next_to_the_ts_files_has_none_of_the_ts_messages() {
    let (d, _ts) = fixture();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    assert_eq!(
        armors(&s, K1),
        ["i1", "i2", "j1", "j2", "j3"],
        "the TS messages are available to the Rust node"
    );
}

/// Import: inflight first, then the new file (the TS merge order), the other key too; non-mailbox files, sub-directories and lower-case names are not touched; the source is not modified.
#[test]
fn import_takes_over_the_ts_messages_in_ts_order_and_leaves_the_source_alone() {
    let (d, ts) = fixture();
    let before: Vec<_> = std::fs::read_dir(&ts)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.clone(),
                if p.is_file() {
                    std::fs::read(&p).unwrap()
                } else {
                    vec![]
                },
            )
        })
        .collect();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    let r = import_ts_dir(&s, &ts).unwrap();
    println!("MEASURE import report: {r:?}");
    assert_eq!(armors(&s, K1), ["i1", "i2", "j1", "j2", "j3"]);
    assert_eq!(armors(&s, K2), ["k1"]);
    assert!(s.pending("0123456789abcdef-lower").is_empty());
    assert_eq!(
        (
            r.files,
            r.keys,
            r.imported,
            r.already_present,
            r.already_imported,
            r.failed_files
        ),
        (3, 2, 6, 0, 0, 0)
    );
    for (p, bytes) in before {
        if p.is_file() {
            assert_eq!(std::fs::read(&p).unwrap(), bytes, "{p:?} unchanged");
        }
    }
}

/// Idempotent: the same files imported twice give the same store; the second run reports everything as already imported.
#[test]
fn importing_the_same_files_twice_changes_nothing() {
    let (d, ts) = fixture();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    let (a1, a2) = (armors(&s, K1), armors(&s, K2));
    let r = import_ts_dir(&s, &ts).unwrap();
    assert_eq!((r.imported, r.already_imported), (0, 6));
    assert_eq!((armors(&s, K1), armors(&s, K2)), (a1, a2));
}

/// Duplicate keys: the same armor in the inflight and the new file, twice in one file, and already delivered live to the Rust node before the import: one row, never two.
#[test]
fn the_same_armor_in_several_places_is_one_message() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    write_ts(
        &ts,
        &format!("{K1}.inflight.json"),
        &["dup", "only-inflight", "dup"],
    );
    write_ts(&ts, &format!("{K1}.json"), &["dup", "live", "only-json"]);
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    assert_eq!(
        s.save_result(K1, item("live")),
        SaveResult::Stored,
        "delivered live to Rust before the import"
    );
    let r = import_ts_dir(&s, &ts).unwrap();
    println!("MEASURE duplicate case report: {r:?}");
    assert_eq!(
        armors(&s, K1),
        ["live", "dup", "only-inflight", "only-json"],
        "one row per armor"
    );
    assert_eq!(r.imported, 3);
    assert_eq!(r.already_present, 1, "the live one was already there");
}

/// Owner ACK: the delete by armor hash works on an imported message, and a later import run does NOT bring it back (the TS file still holds it).
#[test]
fn an_acknowledged_message_stays_gone_even_if_the_import_runs_again() {
    let (d, ts) = fixture();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    assert!(
        s.remove_by_hash(K1, &armor_hash("i2")),
        "the ACK of an imported message removes it"
    );
    assert!(!s.remove_by_hash(K1, &armor_hash("i2")));
    let r = import_ts_dir(&s, &ts).unwrap();
    assert_eq!(
        armors(&s, K1),
        ["i1", "j1", "j2", "j3"],
        "i2 is not resurrected"
    );
    assert_eq!((r.imported, r.already_imported), (0, 6));
    // after a restart too
    drop(s);
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    assert_eq!(armors(&s, K1), ["i1", "j1", "j2", "j3"]);
}

/// A message that was delivered live to Rust before the import, and acknowledged there, is not resurrected from the TS file either.
#[test]
fn a_message_acknowledged_in_rust_before_the_import_is_not_resurrected() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    write_ts(&ts, &format!("{K1}.json"), &["m1", "m2"]);
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    assert!(s.remove_by_hash(K1, &armor_hash("m1")));
    // a TS file that gains the same message again (a second TS run before the cutover) must not bring it back either
    import_ts_dir(&s, &ts).unwrap();
    assert_eq!(armors(&s, K1), ["m2"]);
}

const FIXTURE_N: usize = 400;
const CRASH_AFTER: usize = 137;

/// Child of the crash test: imports a big fixture and kills ITSELF (abort: no destructors, no flush) after CRASH_AFTER messages.
#[test]
#[ignore = "child process of import_crash_midway_then_rerun; needs TSMIG_DIR"]
fn crash_child() {
    let Ok(dir) = std::env::var("TSMIG_DIR") else {
        return;
    };
    let s = DiskStore::open(&Path::new(&dir).join("m.redb")).unwrap();
    let mut n = 0usize;
    let _ = import_ts_dir_with(&s, &Path::new(&dir).join(".data"), &mut |_| {
        n += 1;
        if n == CRASH_AFTER {
            std::process::abort();
        }
    });
}

/// Crash resume: the process is killed in the middle of the import; the second run completes it: nothing lost, nothing twice, and the first CRASH_AFTER messages were already durable.
#[test]
fn import_crash_midway_then_rerun_loses_nothing_and_duplicates_nothing() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    let all: Vec<String> = (0..FIXTURE_N).map(|i| format!("m-{i:04}")).collect();
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    write_ts(&ts, &format!("{K1}.json"), &refs);
    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(exe)
        .args([
            "--ignored",
            "--exact",
            "crash_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("TSMIG_DIR", d.path())
        .status()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    println!(
        "MEASURE child status: {status:?} signal={:?}",
        status.signal()
    );
    assert!(
        status.signal().is_some(),
        "the child was killed (abort), it did not finish: {status:?}"
    );
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    let durable = armors(&s, K1).len();
    println!("MEASURE messages durable after the kill: {durable} of {FIXTURE_N}");
    assert!(
        durable >= CRASH_AFTER - 1 && durable < FIXTURE_N,
        "a durable prefix survived: {durable}"
    );
    assert_eq!(armors(&s, K1), all[..durable], "a clean prefix, in order");
    let r = import_ts_dir(&s, &ts).unwrap();
    println!("MEASURE rerun report: {r:?}");
    assert_eq!(armors(&s, K1), all, "everything, once, in order");
    assert_eq!(r.imported, FIXTURE_N - durable);
    assert_eq!(r.already_imported, durable);
}

/// A file that does not parse is reported and left alone (TS would silently drop it): the other files are imported; nothing of the bad file is imported.
#[test]
fn a_corrupt_file_is_reported_not_skipped_silently() {
    let (d, ts) = fixture();
    std::fs::write(ts.join("AAAAAAAAAAAAAAAA.json"), "[\"cut\",").unwrap();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    let r = import_ts_dir(&s, &ts).unwrap();
    println!("MEASURE corrupt case report: {r:?}");
    assert_eq!(r.failed_files, 1);
    assert_eq!(r.imported, 6);
    assert!(s.pending("AAAAAAAAAAAAAAAA").is_empty());
}

/// ROLLBACK. Rust period: new messages arrive (also for a new key), some imported messages are acknowledged. The export writes the TS files so that the TS node
/// (tryGetLocal) serves exactly the Rust node's pending messages: acknowledged ones gone, new ones present; a key with nothing pending has no file; originals are backed up.
#[test]
fn rollback_exports_what_rust_accepted_in_the_ts_format() {
    let (d, ts) = fixture();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    // the Rust period
    assert_eq!(s.save_result(K1, item("n1")), SaveResult::Stored);
    assert_eq!(s.save_result(K1, item("n2")), SaveResult::Stored);
    assert_eq!(
        s.save_result("1111111111111111", item("n3")),
        SaveResult::Stored
    );
    assert!(
        s.remove_by_hash(K1, &armor_hash("i2")),
        "acknowledged by the owner under Rust"
    );
    assert!(
        s.remove_by_hash(K2, &armor_hash("k1")),
        "the only message of K2 acknowledged"
    );
    // a message that only TS knows (written to the TS file after the import) must survive the rollback
    write_ts(&ts, "2222222222222222.json", &["ts-only"]);
    let orig_json = std::fs::read(ts.join(format!("{K1}.json"))).unwrap();
    let r = export_ts_dir(&s, &ts).unwrap();
    println!("MEASURE export report: {r:?}");
    assert_eq!(ts_reads(&ts, K1), ["i1", "j1", "j2", "j3", "n1", "n2"]);
    assert_eq!(
        ts_reads(&ts, K2),
        Vec::<String>::new(),
        "nothing pending: TS finds no messages"
    );
    assert!(
        !ts.join(format!("{K2}.json")).exists() && !ts.join(format!("{K2}.inflight.json")).exists()
    );
    assert_eq!(
        ts_reads(&ts, "1111111111111111"),
        ["n3"],
        "a key that is new in the Rust period"
    );
    assert_eq!(
        ts_reads(&ts, "2222222222222222"),
        ["ts-only"],
        "a TS-only message is kept"
    );
    assert!(
        !ts.join(format!("{K1}.inflight.json")).exists(),
        "everything pending is in the one TS file"
    );
    assert_eq!(
        std::fs::read(ts.join(format!("{K1}.json.rollback-bak"))).unwrap(),
        orig_json,
        "the original TS file is backed up"
    );
    assert!(ts.join(format!("{K1}.inflight.json.rollback-bak")).exists());
    let leftovers: Vec<_> = std::fs::read_dir(&ts)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "no temporary file is left behind");
    // idempotent
    let again = export_ts_dir(&s, &ts).unwrap();
    assert_eq!(again.written, 0, "a second export has nothing to change");
    assert_eq!(ts_reads(&ts, K1), ["i1", "j1", "j2", "j3", "n1", "n2"]);
}

/// The rollback and the cutover again: TS runs after the rollback and acknowledges one message in its file (removing it there); the import of the NEXT cutover must not
/// bring back what TS acknowledged ... only messages the Rust store has never seen are taken. (Known limit, recorded: a message that TS acknowledged after the rollback
/// but that is still in the Rust store is delivered again by Rust; clients drop it by armor hash and sendId.)
#[test]
fn a_second_cutover_after_a_rollback_takes_only_what_is_new() {
    let (d, ts) = fixture();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    s.save_result(K1, item("n1"));
    export_ts_dir(&s, &ts).unwrap();
    // TS runs and receives a new message
    let mut list = ts_reads(&ts, K1);
    list.push("t-new".to_string());
    let refs: Vec<&str> = list.iter().map(String::as_str).collect();
    write_ts(&ts, &format!("{K1}.json"), &refs);
    let r = import_ts_dir(&s, &ts).unwrap();
    println!("MEASURE second cutover report: {r:?}");
    assert_eq!(r.imported, 1, "only the new TS message");
    assert_eq!(
        armors(&s, K1),
        ["i1", "i2", "j1", "j2", "j3", "n1", "t-new"]
    );
}

/// Child of the export crash test.
#[test]
#[ignore = "child process of export_crash_midway_then_rerun; needs TSMIG_DIR"]
fn export_crash_child() {
    let Ok(dir) = std::env::var("TSMIG_DIR") else {
        return;
    };
    let s = DiskStore::open(&Path::new(&dir).join("m.redb")).unwrap();
    let mut keys = 0usize;
    let _ = export_ts_dir_with(&s, &Path::new(&dir).join(".data"), &mut |_| {
        keys += 1;
        if keys == 2 {
            std::process::abort();
        }
    });
}

/// The export killed in the middle (after two keys): a rerun finishes with the same result as an uninterrupted run, no temporary file, no lost message.
#[test]
fn export_crash_midway_then_rerun_gives_the_same_result() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    let keys = [
        "AAAAAAAAAAAAAAA1",
        "AAAAAAAAAAAAAAA2",
        "AAAAAAAAAAAAAAA3",
        "AAAAAAAAAAAAAAA4",
    ];
    {
        let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
        for k in keys {
            assert_eq!(
                s.save_result(k, item(&format!("{k}-n1"))),
                SaveResult::Stored
            );
            assert_eq!(
                s.save_result(k, item(&format!("{k}-n2"))),
                SaveResult::Stored
            );
        }
    }
    let exe = std::env::current_exe().unwrap();
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(exe)
        .args([
            "--ignored",
            "--exact",
            "export_crash_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("TSMIG_DIR", d.path())
        .status()
        .unwrap();
    assert!(
        status.signal().is_some(),
        "the child was killed: {status:?}"
    );
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    export_ts_dir(&s, &ts).unwrap();
    for k in keys {
        assert_eq!(
            ts_reads(&ts, k),
            [format!("{k}-n1"), format!("{k}-n2")],
            "{k}"
        );
    }
    let leftovers: Vec<_> = std::fs::read_dir(&ts)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temporary file is left behind: {leftovers:?}"
    );
}

/// A key whose TS file does not parse is not rewritten by the export (the rollback must not destroy what it cannot read); it is reported.
#[test]
fn export_refuses_to_overwrite_a_ts_file_it_cannot_read() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    std::fs::write(ts.join(format!("{K1}.json")), "[\"half").unwrap();
    let s = DiskStore::open(&d.path().join("m.redb")).unwrap();
    s.save_result(K1, item("n1"));
    let r = export_ts_dir(&s, &ts).unwrap();
    println!("MEASURE export over a corrupt file: {r:?}");
    assert_eq!(r.failed_keys, 1);
    assert_eq!(
        std::fs::read_to_string(ts.join(format!("{K1}.json"))).unwrap(),
        "[\"half",
        "the unreadable file is untouched"
    );
}

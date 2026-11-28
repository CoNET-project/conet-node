//! Export back to the TS files and the reconciliation digest, over a store in which some rows cannot be read. Expected behaviour: the step fails with an error, every TS file
//! stays byte for byte, the database keeps every row, the record of the last export is unchanged, and the step can be run again; after the cause is removed it succeeds.
//! Synthetic files and a synthetic redb only; no node, no network.
use conet_node::store::{armor_hash, DiskStore, MailboxStore, SaveResult, Stored};
use conet_node::ts_mailbox::{
    export_ts_dir, import_ts_dir, store_digest, store_digest_at, ExportReport, MigrateError,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MSGS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("msgs");
const K1: &str = "0123456789ABCDEF";
const K2: &str = "FEDCBA9876543210";

fn item(armor: &str) -> Stored {
    Stored {
        armor: armor.to_string(),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

fn write_ts(dir: &Path, name: &str, list: &[&str]) {
    std::fs::write(dir.join(name), serde_json::to_string_pretty(&list).unwrap()).unwrap();
}

struct Fix {
    _d: tempfile::TempDir,
    ts: PathBuf,
    db: PathBuf,
}

/// The cutover state followed by a Rust period: five TS messages for K1 and one for K2 are imported, then Rust accepts one more message (n1) for K1.
fn fixture() -> Fix {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    write_ts(&ts, &format!("{K1}.inflight.json"), &["i1", "i2"]);
    write_ts(&ts, &format!("{K1}.json"), &["j1", "j2", "j3"]);
    write_ts(&ts, &format!("{K2}.json"), &["k1"]);
    let db = d.path().join("m.redb");
    let s = DiskStore::open(&db).unwrap();
    import_ts_dir(&s, &ts).unwrap();
    assert_eq!(s.save_result(K1, item("n1")), SaveResult::Stored);
    drop(s);
    Fix { _d: d, ts, db }
}

/// Every file of the TS directory with its bytes.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

/// The messages the live TS files hold (backups are not read by TS).
fn ts_messages(dir: &Path) -> BTreeSet<String> {
    tree(dir)
        .into_iter()
        .filter(|(n, _)| n.ends_with(".json"))
        .flat_map(|(_, b)| serde_json::from_slice::<Vec<String>>(&b).unwrap_or_default())
        .collect()
}

fn raw_rows(db: &Path) -> Vec<(String, u64, Vec<u8>)> {
    let db = Database::open(db).unwrap();
    let r = db.begin_read().unwrap();
    let t = r.open_table(MSGS).unwrap();
    t.iter()
        .unwrap()
        .map(|e| {
            let (k, v) = e.unwrap();
            (k.value().0.to_string(), k.value().1, v.value().to_vec())
        })
        .collect()
}

fn put_raw(db: &Path, key: &str, seq: u64, bytes: &[u8]) {
    let db = Database::open(db).unwrap();
    let w = db.begin_write().unwrap();
    w.open_table(MSGS)
        .unwrap()
        .insert((key, seq), bytes)
        .unwrap();
    w.commit().unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    NotJson,
    WrongShape,
    TextDoesNotMatchHash,
}
const ALL_DAMAGE: [Damage; 3] = [
    Damage::NotJson,
    Damage::WrongShape,
    Damage::TextDoesNotMatchHash,
];

/// Damages the row of `armor` under `key`; returns what is needed to repair it.
fn damage(db: &Path, key: &str, armor: &str, how: Damage) -> (String, u64, Vec<u8>) {
    let (k, seq, original) = raw_rows(db)
        .into_iter()
        .find(|(k, _, v)| {
            k == key
                && serde_json::from_slice::<serde_json::Value>(v)
                    .is_ok_and(|j| j["item"]["armor"] == armor)
        })
        .expect("row");
    let bytes = match how {
        Damage::NotJson => original[..original.len() / 2].to_vec(),
        Damage::WrongShape => br#"{"item":{"armor":"x"}}"#.to_vec(),
        Damage::TextDoesNotMatchHash => {
            let mut j: serde_json::Value = serde_json::from_slice(&original).unwrap();
            j["item"]["armor"] = serde_json::json!(format!("{armor}-altered"));
            serde_json::to_vec(&j).unwrap()
        }
    };
    put_raw(db, &k, seq, &bytes);
    (k, seq, original)
}

fn exported(s: &DiskStore) -> BTreeSet<(String, String)> {
    s.exported_pairs().unwrap().into_iter().collect()
}

/// The TS files (live and backup) of one key.
fn files_of(t: &BTreeMap<String, Vec<u8>>, key: &str) -> BTreeMap<String, Vec<u8>> {
    t.iter()
        .filter(|(n, _)| n.starts_with(key))
        .map(|(n, b)| (n.clone(), b.clone()))
        .collect()
}

fn record_of(s: &DiskStore, key: &str) -> BTreeSet<(String, String)> {
    exported(s).into_iter().filter(|(k, _)| k == key).collect()
}

/// A failure the caller cannot miss: an error, or a report that counts a failed key (the command exits non-zero on it, see the binary test).
fn failed(r: &Result<ExportReport, MigrateError>) -> bool {
    r.as_ref().map(|r| r.failed_keys > 0).unwrap_or(true)
}

/// Runs the export twice over a store in which `bad` cannot be read completely. `unacked` are the TS originals the owners have not acknowledged; `healthy_live` are
/// messages of the readable key that must be in its TS files afterwards.
#[must_use]
fn refused_and_preserved(
    f: &Fix,
    what: &str,
    bad: &str,
    unacked: &[&str],
    healthy_live: &[&str],
) -> Vec<String> {
    let before = tree(&f.ts);
    let rows_before = raw_rows(&f.db);
    let mut problems = vec![];
    for run in 1..=2 {
        let s = DiskStore::open(&f.db).unwrap();
        let record_before = record_of(&s, bad);
        let result = export_ts_dir(&s, &f.ts);
        let live = ts_messages(&f.ts);
        let missing: Vec<&&str> = unacked.iter().filter(|m| !live.contains(**m)).collect();
        println!("MEASURE [{what}] run {run}: result={:?} unacknowledged TS originals missing from the live files={missing:?} live={live:?}", result.as_ref().map_err(|e| e.to_string()));
        if !failed(&result) {
            problems.push(format!("run {run}: the export reported success"));
        }
        if !missing.is_empty() {
            problems.push(format!(
                "run {run}: unacknowledged originals missing {missing:?}"
            ));
        }
        if files_of(&tree(&f.ts), bad) != files_of(&before, bad) {
            problems.push(format!(
                "run {run}: the TS files of the unreadable key changed"
            ));
        }
        if record_of(&s, bad) != record_before {
            problems.push(format!(
                "run {run}: the export record of the unreadable key changed"
            ));
        }
        for m in healthy_live {
            if !live.contains(*m) {
                problems.push(format!(
                    "run {run}: {m} of the readable key is not in the TS files"
                ));
            }
        }
    }
    assert!(f.db.is_file(), "the database must stay");
    assert_eq!(
        raw_rows(&f.db),
        rows_before,
        "the database rows must be unchanged"
    );
    problems
        .into_iter()
        .map(|p| format!("[{what}] {p}"))
        .collect()
}

#[test]
fn one_unreadable_row_among_imported_messages() {
    let mut problems = vec![];
    for how in ALL_DAMAGE {
        let f = fixture();
        damage(&f.db, K1, "j2", how);
        problems.extend(refused_and_preserved(
            &f,
            &format!("{how:?} on j2"),
            K1,
            &["i1", "i2", "j1", "j2", "j3", "k1"],
            &["k1"],
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("; "));
}

#[test]
fn every_row_of_one_key_unreadable() {
    let mut problems = vec![];
    for how in ALL_DAMAGE {
        let f = fixture();
        damage(&f.db, K2, "k1", how);
        problems.extend(refused_and_preserved(
            &f,
            &format!("{how:?} on the only row of a key"),
            K2,
            &["i1", "i2", "j1", "j2", "j3", "k1"],
            &["n1"],
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("; "));
}

#[test]
fn an_unreadable_row_in_one_key_does_not_stop_the_other_key() {
    let f = fixture();
    {
        // the readable key has a change of its own to write: i1 was acknowledged during the Rust period
        let s = DiskStore::open(&f.db).unwrap();
        assert!(s.remove_by_hash(K1, &armor_hash("i1")));
    }
    damage(&f.db, K2, "k1", Damage::NotJson);
    let problems = refused_and_preserved(
        &f,
        "bad row in the second key",
        K2,
        &["i2", "j1", "j2", "j3", "k1"],
        &["i2", "j1", "j2", "j3", "n1"],
    );
    assert!(problems.is_empty(), "{}", problems.join("; "));
    assert!(
        !ts_messages(&f.ts).contains("i1"),
        "the acknowledged message came back"
    );
}

#[test]
fn an_unreadable_row_of_a_message_accepted_during_the_rust_period() {
    let mut problems = vec![];
    for how in ALL_DAMAGE {
        let f = fixture();
        damage(&f.db, K1, "n1", how);
        problems.extend(refused_and_preserved(
            &f,
            &format!("{how:?} on a message only Rust holds"),
            K1,
            &["i1", "i2", "j1", "j2", "j3", "k1"],
            &["k1"],
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("; "));
}

#[test]
fn after_the_row_is_repaired_the_same_export_succeeds_with_every_message() {
    let f = fixture();
    let (k, seq, original) = damage(&f.db, K1, "j2", Damage::NotJson);
    let _ = {
        let s = DiskStore::open(&f.db).unwrap();
        export_ts_dir(&s, &f.ts)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    put_raw(&f.db, &k, seq, &original);
    let s = DiskStore::open(&f.db).unwrap();
    export_ts_dir(&s, &f.ts).expect("export after the repair");
    let live = ts_messages(&f.ts);
    println!("MEASURE after repair: live TS messages={live:?}");
    for m in ["i1", "i2", "j1", "j2", "j3", "n1", "k1"] {
        assert!(live.contains(m), "{m} is missing after the repaired export");
    }
}

#[test]
fn the_store_digests_refuse_an_unreadable_row() {
    let mut problems = vec![];
    for how in ALL_DAMAGE {
        let f = fixture();
        damage(&f.db, K1, "j2", how);
        let readonly = store_digest_at(&f.db).map_err(|e| e.to_string());
        let s = DiskStore::open(&f.db).unwrap();
        let live = store_digest(&s).map_err(|e| e.to_string());
        println!(
            "MEASURE [{how:?}] store_digest_at={:?} store_digest={:?}",
            readonly.as_ref().map(|d| d.messages),
            live.as_ref().map(|d| d.messages)
        );
        if readonly.is_ok() {
            problems.push(format!("{how:?}: the read-only digest reported a result"));
        }
        if live.is_ok() {
            problems.push(format!("{how:?}: the store digest reported a result"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("; "));
}

#[test]
fn the_binary_fails_the_export_and_the_digest_and_changes_nothing() {
    let f = fixture();
    damage(&f.db, K1, "j2", Damage::NotJson);
    let before = tree(&f.ts);
    let bin = env!("CARGO_BIN_EXE_conet-node");
    let run = |args: &[&str]| {
        let o = std::process::Command::new(bin).args(args).output().unwrap();
        println!(
            "MEASURE {:?} -> code {:?} stdout {:?}",
            args[0],
            o.status.code(),
            String::from_utf8_lossy(&o.stdout).trim()
        );
        o.status.success()
    };
    let export_ok = run(&[
        "--export-ts-mailbox",
        f.ts.to_str().unwrap(),
        "--mailbox-db",
        f.db.to_str().unwrap(),
    ]);
    let digest_ok = run(&["--mailbox-digest", "--mailbox-db", f.db.to_str().unwrap()]);
    assert!(!export_ok, "the export command exited with success");
    assert!(!digest_ok, "the digest command exited with success");
    assert_eq!(tree(&f.ts), before, "the TS directory changed");
}

#[test]
fn rows_written_by_earlier_builds_are_still_exported_and_counted() {
    let f = fixture();
    // the same row as earlier builds wrote it, and one without the saved_at field
    let (k, seq, original) = raw_rows(&f.db)
        .into_iter()
        .find(|(k, _, _)| k == K2)
        .unwrap();
    let mut j: serde_json::Value = serde_json::from_slice(&original).unwrap();
    j.as_object_mut().unwrap().remove("saved_at");
    put_raw(&f.db, &k, seq, &serde_json::to_vec(&j).unwrap());
    assert_eq!(store_digest_at(&f.db).unwrap().messages, 7);
    let s = DiskStore::open(&f.db).unwrap();
    assert_eq!(store_digest(&s).unwrap().messages, 7);
    export_ts_dir(&s, &f.ts).unwrap();
    assert!(ts_messages(&f.ts).contains("k1"));
}

#[cfg(feature = "test-fault")]
mod read_errors {
    use super::*;

    /// One failed read of one key, then the storage works again.
    #[test]
    fn a_single_read_error_fails_the_export_and_the_rerun_succeeds() {
        let mut problems = vec![];
        for (bad, other) in [(K1, "k1"), (K2, "n1")] {
            let f = fixture();
            let before = tree(&f.ts);
            let s = DiskStore::open(&f.db).unwrap();
            let record_before = record_of(&s, bad);
            s.fail_reads_for(bad, 0, 1);
            let r = export_ts_dir(&s, &f.ts);
            let live = ts_messages(&f.ts);
            let missing: Vec<&str> = ["i1", "i2", "j1", "j2", "j3", "k1"]
                .into_iter()
                .filter(|m| !live.contains(*m))
                .collect();
            println!("MEASURE one read error on {bad}: result={:?} unacknowledged TS originals missing={missing:?} live={live:?}", r.as_ref().map_err(|e| e.to_string()));
            if !failed(&r) {
                problems.push(format!("{bad}: the export reported success"));
            }
            if !missing.is_empty() {
                problems.push(format!(
                    "{bad}: unacknowledged originals missing {missing:?}"
                ));
            }
            if files_of(&tree(&f.ts), bad) != files_of(&before, bad) {
                problems.push(format!("{bad}: the TS files of the failing key changed"));
            }
            if record_of(&s, bad) != record_before {
                problems.push(format!(
                    "{bad}: the export record of the failing key changed"
                ));
            }
            if !live.contains(other) {
                problems.push(format!("{bad}: the readable key was not exported"));
            }
            let again = export_ts_dir(&s, &f.ts);
            if failed(&again) {
                problems.push(format!("{bad}: the rerun failed"));
            }
            let live = ts_messages(&f.ts);
            if !["i1", "i2", "j1", "j2", "j3", "n1", "k1"]
                .iter()
                .all(|m| live.contains(*m))
            {
                problems.push(format!("{bad}: a message is missing after the rerun"));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("; "));
    }

    #[test]
    fn a_lasting_read_error_keeps_that_key_and_fails_the_digest() {
        let f = fixture();
        let before = tree(&f.ts);
        let s = DiskStore::open(&f.db).unwrap();
        s.fail_reads_for(K2, 0, u32::MAX);
        let r = export_ts_dir(&s, &f.ts);
        let digest = store_digest(&s)
            .map(|d| d.messages)
            .map_err(|e| e.to_string());
        println!("MEASURE lasting read error on the second key: result={:?} live={:?} store_digest={digest:?}", r.as_ref().map_err(|e| e.to_string()), ts_messages(&f.ts));
        let mut problems = vec![];
        if !failed(&r) {
            problems.push("the export reported success");
        }
        if files_of(&tree(&f.ts), K2) != files_of(&before, K2) {
            problems.push("the TS files of the failing key changed");
        }
        if digest.is_ok() {
            problems.push("the digest reported a result under a read error");
        }
        assert!(problems.is_empty(), "{}", problems.join("; "));
    }
}

#[test]
fn rev_a_prior_export_record_survives_a_failed_export() {
    let f = fixture();
    {
        let s = DiskStore::open(&f.db).unwrap();
        export_ts_dir(&s, &f.ts).expect("first export");
    }
    damage(&f.db, K1, "j2", Damage::NotJson);
    let before = tree(&f.ts);
    let s = DiskStore::open(&f.db).unwrap();
    let record_before = record_of(&s, K1);
    assert!(
        record_before.len() >= 6,
        "the fixture must hold a non-empty record: {}",
        record_before.len()
    );
    let r = export_ts_dir(&s, &f.ts);
    println!(
        "REV-A record before={} after={} result={:?}",
        record_before.len(),
        record_of(&s, K1).len(),
        r.as_ref().map_err(|e| e.to_string())
    );
    assert!(failed(&r), "export reported success");
    assert_eq!(
        record_of(&s, K1),
        record_before,
        "REV-A the export record of the unreadable key changed"
    );
    assert_eq!(
        files_of(&tree(&f.ts), K1),
        files_of(&before, K1),
        "REV-A files changed"
    );
}

#[test]
fn rev_b_a_bad_first_key_does_not_stop_the_later_key() {
    let f = fixture();
    {
        let s = DiskStore::open(&f.db).unwrap();
        assert_eq!(s.save_result(K2, item("n2")), SaveResult::Stored);
    }
    damage(&f.db, K1, "j2", Damage::NotJson);
    let s = DiskStore::open(&f.db).unwrap();
    let r = export_ts_dir(&s, &f.ts);
    let live = ts_messages(&f.ts);
    println!(
        "REV-B result={:?} live={live:?}",
        r.as_ref().map_err(|e| e.to_string())
    );
    assert!(failed(&r), "export reported success");
    assert!(
        live.contains("n2") && live.contains("k1"),
        "REV-B the later readable key was not exported"
    );
    assert!(
        record_of(&s, K2).contains(&(K2.to_string(), armor_hash("n2"))),
        "REV-B record of the readable key"
    );
}

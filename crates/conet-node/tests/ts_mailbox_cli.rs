//! The real binary's one-shot migration steps (`--import-ts-mailbox`, `--export-ts-mailbox`): exit codes, counts only on stdout, a second run changes nothing, a corrupt file
//! stops the exit code (non-zero) without importing it, and the database lock keeps the steps from running next to a running node. Synthetic files.
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_conet-node");

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn the_binary_imports_twice_and_exports_with_counts_only() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    std::fs::write(
        ts.join("0123456789ABCDEF.json"),
        serde_json::to_string_pretty(&["SECRET-ARMOR-ONE", "SECRET-ARMOR-TWO"]).unwrap(),
    )
    .unwrap();
    let db = d.path().join("m.redb");
    let (dbs, tss) = (db.to_str().unwrap(), ts.to_str().unwrap());
    let a = run(&["--import-ts-mailbox", tss, "--mailbox-db", dbs]);
    println!("MEASURE first import: {}", text(&a).trim());
    assert!(a.status.success(), "{}", text(&a));
    assert!(
        text(&a).contains("imported=2") && text(&a).contains("failed_files=0"),
        "{}",
        text(&a)
    );
    let b = run(&["--import-ts-mailbox", tss, "--mailbox-db", dbs]);
    println!("MEASURE second import: {}", text(&b).trim());
    assert!(
        text(&b).contains("imported=0") && text(&b).contains("already_imported=2"),
        "{}",
        text(&b)
    );
    let c = run(&["--export-ts-mailbox", tss, "--mailbox-db", dbs]);
    println!("MEASURE export: {}", text(&c).trim());
    assert!(c.status.success(), "{}", text(&c));
    for o in [&a, &b, &c] {
        assert!(
            !text(o).contains("SECRET-ARMOR"),
            "no message text in the output"
        );
    }
    // the TS file still serves both messages
    let back: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(ts.join("0123456789ABCDEF.json")).unwrap())
            .unwrap();
    assert_eq!(back, ["SECRET-ARMOR-ONE", "SECRET-ARMOR-TWO"]);
}

#[test]
fn a_corrupt_file_makes_the_step_fail_and_nothing_of_it_is_imported() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    std::fs::write(ts.join("0123456789ABCDEF.json"), "[\"half").unwrap();
    let db = d.path().join("m.redb");
    let o = run(&[
        "--import-ts-mailbox",
        ts.to_str().unwrap(),
        "--mailbox-db",
        db.to_str().unwrap(),
    ]);
    println!(
        "MEASURE corrupt: status={:?} {}",
        o.status.code(),
        text(&o).trim()
    );
    assert!(!o.status.success());
    assert!(
        text(&o).contains("failed_files=1") && text(&o).contains("imported=0"),
        "{}",
        text(&o)
    );
}

#[test]
fn the_steps_need_the_database_and_are_one_at_a_time() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    let tss = ts.to_str().unwrap();
    let o = run(&["--import-ts-mailbox", tss]);
    assert!(
        !o.status.success() && text(&o).contains("--mailbox-db is required"),
        "{}",
        text(&o)
    );
    let db = d.path().join("m.redb");
    let o = run(&[
        "--import-ts-mailbox",
        tss,
        "--export-ts-mailbox",
        tss,
        "--mailbox-db",
        db.to_str().unwrap(),
    ]);
    assert!(
        !o.status.success() && text(&o).contains("separate steps"),
        "{}",
        text(&o)
    );
    let o = run(&["--import-ts-mailbox"]);
    assert!(
        !o.status.success() && text(&o).contains("without a value"),
        "{}",
        text(&o)
    );
}

/// A running node (or any process) holds the redb lock: the step refuses instead of racing it.
#[test]
fn the_step_refuses_while_the_database_is_open_elsewhere() {
    let d = tempfile::tempdir().unwrap();
    let ts = d.path().join(".data");
    std::fs::create_dir_all(&ts).unwrap();
    let db = d.path().join("m.redb");
    let _held = conet_node::store::DiskStore::open(&db).unwrap();
    let o = run(&[
        "--import-ts-mailbox",
        ts.to_str().unwrap(),
        "--mailbox-db",
        db.to_str().unwrap(),
    ]);
    println!(
        "MEASURE database open elsewhere: status={:?} {}",
        o.status.code(),
        text(&o).trim()
    );
    assert!(!o.status.success(), "{}", text(&o));
}

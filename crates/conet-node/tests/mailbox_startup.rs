//! Where the mailbox database comes from, on the real binary. A start of the node and an export never create one: a missing, empty or mistyped path is refused with a
//! non-zero exit, nothing is created or changed and nothing listens. Synthetic data and throw-away keys made by the test; local ports only.
use conet_node::store::{DiskStore, MailboxStore, SaveResult, Stored};
use rand_core::{OsRng, RngCore};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut sk = [0u8; 32];
        let (wallet_hex, wallet) = loop {
            OsRng.fill_bytes(&mut sk);
            let h = format!("0x{}", hex::encode(sk));
            if let Ok(k) = si_crypto::eth::EthKey::from_hex(&h) {
                break (h, k.address());
            }
        };
        let (armor, _public, key_id) = si_crypto::opgp::generate_route_key(OsRng, &wallet).unwrap();
        std::fs::write(dir.path().join("route.asc"), armor).unwrap();
        std::fs::write(dir.path().join("wallet.hex"), wallet_hex).unwrap();
        std::fs::write(
            dir.path().join("routes.json"),
            format!(r#"{{"nodes":[{{"keyId":"{key_id}","addr":"127.0.0.1:9"}}]}}"#),
        )
        .unwrap();
        Node { dir }
    }
    fn p(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }
    fn command(&self, extra: &[&str], health: u16) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_conet-node"));
        c.args(["--insecure-dev-keys", "--dev-route-key"])
            .arg(self.p("route.asc"))
            .arg("--routes")
            .arg(self.p("routes.json"))
            .args(["--health-listen", &format!("127.0.0.1:{health}")])
            .args(extra)
            .env(
                "CONET_DEV_WALLET_KEY",
                std::fs::read_to_string(self.p("wallet.hex")).unwrap(),
            )
            .env_remove("CONET_RPC")
            .env_remove("BEAMIO_API_BASE")
            .env_remove("CONET_PUBLIC_IP")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }
}

fn reachable(port: u16) -> bool {
    ["127.0.0.1", "::1"].iter().any(|h| {
        let addr = format!("[{h}]:{port}").replace("[127.0.0.1]", "127.0.0.1");
        addr.parse::<std::net::SocketAddr>()
            .ok()
            .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_millis(200)).is_ok())
    })
}

fn wait_reachable(child: &mut Child, port: u16) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        if reachable(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn stop(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Starts the node with `--mailbox-db db`. Returns (it listened, it exited by itself with success, log).
fn start_node(n: &Node, db: &Path) -> (bool, Option<bool>, String) {
    let (http, health) = (free_port(), free_port());
    let mut child = n
        .command(
            &[
                "--listen",
                &format!("127.0.0.1:{http}"),
                "--mailbox-db",
                db.to_str().unwrap(),
            ],
            health,
        )
        .spawn()
        .unwrap();
    let up = wait_reachable(&mut child, http);
    let exited = child.try_wait().unwrap().map(|s| s.success());
    let log = stop(child);
    (up, exited, log)
}

fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.path().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

fn item(n: usize) -> Stored {
    Stored {
        armor: format!("synthetic-{n}"),
        no_push: true,
        hop_bytes: 0,
        hops: 0,
    }
}

fn mail_db(path: &Path) {
    let s = DiskStore::open(path).unwrap();
    for i in 0..3 {
        assert_eq!(
            s.save_result("0123456789ABCDEF", item(i)),
            SaveResult::Stored
        );
    }
}

#[test]
fn a_node_whose_database_is_missing_does_not_start_and_creates_nothing() {
    let n = Node::new();
    let state = n.p("state");
    std::fs::create_dir_all(&state).unwrap();
    mail_db(&state.join("mailbox.redb"));
    let before = tree(&state);
    // a mistyped path next to the real database
    let (up, exit, log) = start_node(&n, &state.join("mailbx.redb"));
    println!(
        "MEASURE wrong path: listened={up} exit_success={exit:?} files={:?}",
        tree(&state).iter().map(|f| &f.0).collect::<Vec<_>>()
    );
    assert!(
        !up,
        "the node listened with a database path that does not exist"
    );
    assert_eq!(exit, Some(false), "{log}");
    assert_eq!(tree(&state), before, "something was created or changed");
    // the database removed
    std::fs::remove_file(state.join("mailbox.redb")).unwrap();
    let (up, exit, log) = start_node(&n, &state.join("mailbox.redb"));
    println!(
        "MEASURE removed database: listened={up} exit_success={exit:?} exists_after={}",
        state.join("mailbox.redb").exists()
    );
    assert!(!up && exit == Some(false), "{log}");
    assert!(
        !state.join("mailbox.redb").exists(),
        "a new database was created"
    );
}

#[test]
fn a_node_whose_database_is_empty_or_cut_does_not_start_and_leaves_the_file() {
    let n = Node::new();
    let db = n.p("mailbox.redb");
    mail_db(&db);
    let whole = std::fs::read(&db).unwrap();
    for (what, bytes) in [
        ("zero length", Vec::new()),
        ("cut", whole[..100].to_vec()),
        ("not a database", vec![7u8; 8192]),
    ] {
        std::fs::write(&db, &bytes).unwrap();
        let (up, exit, log) = start_node(&n, &db);
        let after = std::fs::read(&db).unwrap();
        println!(
            "MEASURE {what}: listened={up} exit_success={exit:?} bytes {} -> {}",
            bytes.len(),
            after.len()
        );
        assert!(!up && exit == Some(false), "{what}: {log}");
        assert_eq!(after, bytes, "{what}: the file changed");
    }
}

#[test]
fn a_node_with_its_database_starts_as_before() {
    let n = Node::new();
    let db = n.p("mailbox.redb");
    mail_db(&db);
    let (up, _, log) = start_node(&n, &db);
    assert!(up, "{log}");
    assert_eq!(
        DiskStore::open(&db)
            .unwrap()
            .pending("0123456789ABCDEF")
            .len(),
        3
    );
}

#[test]
fn an_export_from_a_database_that_is_not_there_fails_and_creates_nothing() {
    let n = Node::new();
    let ts = n.p("ts");
    std::fs::create_dir_all(&ts).unwrap();
    std::fs::write(ts.join("0123456789ABCDEF.json"), r#"["a"]"#).unwrap();
    let db = n.p("absent.redb");
    let o = Command::new(env!("CARGO_BIN_EXE_conet-node"))
        .arg("--export-ts-mailbox")
        .arg(&ts)
        .arg("--mailbox-db")
        .arg(&db)
        .output()
        .unwrap();
    println!(
        "MEASURE export from a missing database: success={} stdout={:?} created={}",
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).trim(),
        db.exists()
    );
    assert!(!o.status.success(), "the export reported success");
    assert!(!db.exists(), "the export created a database");
}

// ---- the preparation step (new with the fix) ------------------------------------------

fn prepare_cmd(db: &Path, marker: &Path, record: &Path) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_conet-node"))
        .arg("--prepare-mailbox-db")
        .arg("--mailbox-db")
        .arg(db)
        .arg("--mailbox-marker")
        .arg(marker)
        .arg("--mailbox-upgrade-record")
        .arg(record)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.success(), text.trim().to_string())
}

fn pending_count(db: &Path) -> usize {
    DiskStore::open(db)
        .unwrap()
        .pending("0123456789ABCDEF")
        .len()
}

#[test]
fn a_new_installation_gets_a_database_once_and_never_a_second_one() {
    let n = Node::new();
    let (db, marker, record) = (
        n.p("mailbox.redb"),
        n.p("mailbox.installed"),
        n.p("upgraded"),
    );
    let (ok, out) = prepare_cmd(&db, &marker, &record);
    assert!(ok && out.contains("Created"), "{out}");
    let (up, _, log) = start_node(&n, &db);
    assert!(up, "{log}");
    let (ok, out) = prepare_cmd(&db, &marker, &record);
    assert!(ok && out.contains("Present"), "{out}");
    for bytes in [None, Some(Vec::<u8>::new())] {
        let _ = std::fs::remove_file(&db);
        if let Some(b) = &bytes {
            std::fs::write(&db, b).unwrap();
        }
        let before = tree(n.dir.path());
        let (ok, out) = prepare_cmd(&db, &marker, &record);
        println!(
            "MEASURE installed, database {:?}: prepare success={ok} {out}",
            bytes
        );
        assert!(!ok, "{out}");
        assert_eq!(tree(n.dir.path()), before);
    }
}

#[test]
fn an_upgrade_keeps_the_database_of_the_earlier_version() {
    let n = Node::new();
    let (db, marker, record) = (
        n.p("mailbox.redb"),
        n.p("mailbox.installed"),
        n.p("upgraded"),
    );
    mail_db(&db);
    std::fs::write(&record, "0.0.0\n").unwrap();
    let (ok, out) = prepare_cmd(&db, &marker, &record);
    assert!(ok && out.contains("Adopted"), "{out}");
    assert_eq!(pending_count(&db), 3);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim_end(),
        db.to_str().unwrap()
    );
}

#[test]
fn an_upgrade_whose_database_is_gone_is_refused_even_without_a_marker() {
    let n = Node::new();
    let (db, marker, record) = (
        n.p("mailbox.redb"),
        n.p("mailbox.installed"),
        n.p("upgraded"),
    );
    std::fs::write(&record, "0.0.0\n").unwrap();
    let before = tree(n.dir.path());
    let (ok, out) = prepare_cmd(&db, &marker, &record);
    println!("MEASURE upgrade record, no database: success={ok} {out}");
    assert!(!ok, "{out}");
    assert_eq!(tree(n.dir.path()), before);
}

#[test]
fn a_marker_for_another_path_is_refused() {
    let n = Node::new();
    let (db, marker, record) = (
        n.p("mailbox.redb"),
        n.p("mailbox.installed"),
        n.p("upgraded"),
    );
    assert!(prepare_cmd(&db, &marker, &record).0);
    let before = tree(n.dir.path());
    let (ok, out) = prepare_cmd(&n.p("other.redb"), &marker, &record);
    println!("MEASURE marker for another path: success={ok} {out}");
    assert!(!ok, "{out}");
    assert_eq!(tree(n.dir.path()), before);
}

#[test]
fn the_shipped_units_prepare_the_database_they_then_open_and_the_package_leaves_the_upgrade_record()
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let unit = std::fs::read_to_string(root.join("deploy/apt/systemd/conet-node.service")).unwrap();
    let joined = unit.replace("\\\n", " ");
    let line = |p: &str| {
        joined
            .lines()
            .find(|l| l.starts_with(p))
            .unwrap_or_else(|| panic!("{p} line"))
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let (pre, exec) = (line("ExecStartPre="), line("ExecStart="));
    let value = |l: &[String], f: &str| l[l.iter().position(|t| t == f).unwrap() + 1].clone();
    assert!(pre.contains(&"--prepare-mailbox-db".to_string()));
    assert_eq!(value(&pre, "--mailbox-db"), value(&exec, "--mailbox-db"));
    assert!(value(&pre, "--mailbox-marker").starts_with("/var/lib/conet-node/"));
    let record = value(&pre, "--mailbox-upgrade-record");
    assert!(
        !record.starts_with("/var/lib/conet-node/"),
        "the record must not live in the service's own directory"
    );
    let post = std::fs::read_to_string(root.join("deploy/apt/debian/postinst")).unwrap();
    assert!(post.contains(&record), "{post}");

    // the maintainer script itself, with its paths redirected into a scratch directory
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("install");
    let script = post
        .replace("/var/lib/conet-node-install", dir.to_str().unwrap())
        .replace("/usr/bin/systemd-", "/nonexistent/systemd-");
    let run = |args: &[&str]| {
        assert!(Command::new("sh")
            .arg("-c")
            .arg(&script)
            .arg("postinst")
            .args(args)
            .status()
            .unwrap()
            .success())
    };
    run(&["configure"]);
    run(&["configure", ""]);
    assert!(
        !dir.join("upgraded").exists(),
        "a first installation leaves no record"
    );
    run(&["configure", "0.0.1-1"]);
    assert_eq!(
        std::fs::read_to_string(dir.join("upgraded")).unwrap(),
        "0.0.1-1\n"
    );
    run(&["configure", "0.0.2-1"]);
    assert_eq!(
        std::fs::read_to_string(dir.join("upgraded")).unwrap(),
        "0.0.1-1\n",
        "the first record is kept"
    );
}

/// A node killed while it was writing must start again (the strict open must not refuse an ordinary unclean shutdown).
#[test]
fn a_database_left_by_a_killed_writer_still_opens() {
    if let Ok(path) = std::env::var("STARTUP_WRITER_DB") {
        let s = DiskStore::open(Path::new(&path)).unwrap();
        for i in 0.. {
            assert_eq!(
                s.save_result("0123456789ABCDEF", item(i)),
                SaveResult::Stored
            );
            println!("stored {i}");
        }
    }
    for round in 0..5u64 {
        let n = Node::new();
        let db = n.p("mailbox.redb");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "a_database_left_by_a_killed_writer_still_opens",
                "--exact",
                "--nocapture",
            ])
            .env("STARTUP_WRITER_DB", &db)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines =
            std::io::BufRead::lines(std::io::BufReader::new(child.stdout.take().unwrap()));
        let mut seen = 0;
        while seen < 20 + 7 * round {
            if lines.next().unwrap().unwrap().starts_with("stored ") {
                seen += 1;
            }
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let s = DiskStore::open_installed(&db).expect("open after a killed writer");
        let got = s.pending("0123456789ABCDEF").len() as u64;
        println!("MEASURE round {round}: at least {seen} acknowledged before the kill, {got} after reopening");
        assert!(got >= seen, "an accepted message is gone");
    }
}

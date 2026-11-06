//! Update agent tests, mapped to the TypeScript random-update cases in the security line's
//! `si-s1-s6-eval.md` §3.9 (random time, backoff, version order, missing keys, up to date,
//! fetch failure, build/selftest failure with retry cap, crash-loop rollback by an offline guard,
//! signature checks).
use conet_updater::agent::{
    backoff, boot_guard, decide, random_delay, Agent, Decision, GuardOutcome, Hook, State,
    BACKOFF_BASE, CHECK_WINDOW,
};
use conet_updater::manifest::{self, Artifact, Manifest, SigFile, VerifyError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const NODE: &str = "0x1111111111111111111111111111111111111111";

fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i; 32])
}
fn vk(i: u8) -> VerifyingKey {
    key(i).verifying_key()
}

fn man(version: &str, rollout: u8, revoked: &[&str], art: Option<Artifact>) -> Manifest {
    Manifest {
        product: "conet-node".into(),
        version: version.into(),
        released_at: 1,
        rollout_percent: rollout,
        min_version: None,
        revoked: revoked.iter().map(|s| s.to_string()).collect(),
        artifacts: art.into_iter().collect(),
        urgent: false,
    }
}

fn signed(m: &Manifest, keys: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let b = serde_json::to_vec(m).unwrap();
    let sigs = SigFile {
        sigs: keys.iter().map(|k| manifest::sign(&b, &key(*k))).collect(),
    };
    (b, serde_json::to_vec(&sigs).unwrap())
}

#[test]
fn manifest_needs_k_of_n_trusted_signatures() {
    let trusted = [vk(1), vk(2), vk(3)];
    let m = man("1.2.3", 100, &[], None);
    let (b, s) = signed(&m, &[1, 2]);
    assert_eq!(manifest::verify(&b, &s, &trusted, 2).unwrap(), m);
    let (b1, s1) = signed(&m, &[1, 1]);
    assert_eq!(
        manifest::verify(&b1, &s1, &trusted, 2),
        Err(VerifyError::NotEnoughSignatures { valid: 1, need: 2 }),
        "same key twice counts once"
    );
    let (b2, s2) = signed(&m, &[1, 9]);
    assert!(
        matches!(
            manifest::verify(&b2, &s2, &trusted, 2),
            Err(VerifyError::NotEnoughSignatures { valid: 1, .. })
        ),
        "untrusted key ignored"
    );
    let (b3, _) = signed(&m, &[]);
    assert!(
        manifest::verify(&b3, br#"{"sigs":[]}"#, &trusted, 1).is_err(),
        "unsigned refused"
    );
    let mut tampered = b.clone();
    tampered[10] ^= 1;
    assert!(manifest::verify(&tampered, &s, &trusted, 1).is_err());
    let mut other = m.clone();
    other.product = "other".into();
    let (b4, s4) = signed(&other, &[1]);
    assert_eq!(
        manifest::verify(&b4, &s4, &trusted, 1),
        Err(VerifyError::WrongProduct)
    );
    assert!(
        manifest::verify(&b, &s, &trusted, 0).is_err(),
        "threshold 0 never passes"
    );
}

#[test]
fn missing_release_keys_disable_updates() {
    let dir = tempfile::tempdir().unwrap();
    assert!(Agent::new(
        dir.path().into(),
        vec![],
        vec![],
        1,
        NODE.into(),
        TARGET.into()
    )
    .is_err());
    assert!(Agent::new(
        dir.path().into(),
        vec![],
        vec![vk(1)],
        0,
        NODE.into(),
        TARGET.into()
    )
    .is_err());
}

#[test]
fn decision_rules() {
    let art = Artifact {
        target: TARGET.into(),
        urls: vec![],
        sha256: String::new(),
        size: 0,
    };
    let st = State::default();
    let none: Vec<String> = vec![];
    let d = |m: &Manifest, cur: &str, st: &State, blocked: &[String]| {
        decide(m, cur, NODE, TARGET, st, blocked)
    };
    assert_eq!(
        d(
            &man("1.0.0", 100, &[], Some(art.clone())),
            "1.0.0",
            &st,
            &none
        ),
        Decision::UpToDate
    );
    assert_eq!(
        d(
            &man("1.10.0", 100, &[], Some(art.clone())),
            "1.9.0",
            &st,
            &none
        )
        .label(),
        "update",
        "numeric, not string order"
    );
    assert_eq!(
        d(
            &man("1.1.0", 0, &[], Some(art.clone())),
            "1.0.0",
            &st,
            &none
        ),
        Decision::NotInCohort
    );
    assert_eq!(
        d(
            &man("1.1.0", 100, &["1.0.0"], Some(art.clone())),
            "1.0.0",
            &st,
            &none
        ),
        Decision::Rollback
    );
    assert_eq!(
        d(&man("1.1.0", 100, &[], None), "1.0.0", &st, &none),
        Decision::Skip("no_artifact_for_target")
    );
    let mut below = man("1.1.0", 100, &[], Some(art.clone()));
    below.min_version = Some("1.2.0".into());
    assert_eq!(
        d(&below, "1.0.0", &st, &none),
        Decision::Skip("below_min_version")
    );
    let seen = State {
        highest_seen: Some("2.0.0".into()),
        ..Default::default()
    };
    assert_eq!(
        d(
            &man("1.1.0", 100, &[], Some(art.clone())),
            "1.0.0",
            &seen,
            &none
        ),
        Decision::Stale,
        "replayed older manifest"
    );
    let bad = State {
        bad: vec!["1.5.0".into()],
        ..Default::default()
    };
    assert_eq!(
        d(
            &man("1.5.0", 100, &[], Some(art.clone())),
            "1.0.0",
            &bad,
            &none
        ),
        Decision::Skip("version_blocked")
    );
    assert_eq!(
        d(
            &man("1.5.0", 100, &[], Some(art.clone())),
            "1.0.0",
            &st,
            &["1.5.0".to_string()]
        ),
        Decision::Skip("version_blocked"),
        "boot-guard blacklist"
    );
    let tried = State {
        attempts: [("1.5.0".to_string(), 3)].into(),
        ..Default::default()
    };
    assert_eq!(
        d(
            &man("1.5.0", 100, &[], Some(art.clone())),
            "1.0.0",
            &tried,
            &none
        ),
        Decision::Skip("attempts_exhausted")
    );
    assert_eq!(
        d(&man("1.6.0", 100, &[], Some(art)), "1.0.0", &tried, &none).label(),
        "update",
        "a newer version is tried again"
    );
}

#[test]
fn random_times_backoff_and_cohorts() {
    for _ in 0..1000 {
        assert!(random_delay(CHECK_WINDOW) < CHECK_WINDOW);
    }
    for (n, lo, hi) in [
        (1, BACKOFF_BASE / 2, BACKOFF_BASE),
        (3, BACKOFF_BASE * 2, BACKOFF_BASE * 4),
        (30, CHECK_WINDOW / 2, CHECK_WINDOW),
    ] {
        for _ in 0..200 {
            let b = backoff(n, CHECK_WINDOW);
            assert!(b >= lo && b <= hi + Duration::from_millis(1), "n={n} {b:?}");
        }
    }
    assert_eq!(
        manifest::cohort("0xAbC", "1.0.0"),
        manifest::cohort("0xabc", "1.0.0")
    );
    let half = (0..1000)
        .filter(|i| manifest::cohort(&format!("0x{i:040x}"), "1.0.0") < 50)
        .count();
    assert!((400..=600).contains(&half), "{half}");
}

/// Tiny HTTP server for manifests and artifacts.
async fn serve(files: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let files = files.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = files.lock().unwrap().get(&path).cloned();
                let resp = match body {
                    Some(b) => [
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            b.len()
                        )
                        .into_bytes(),
                        b,
                    ]
                    .concat(),
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = s.write_all(&resp).await;
            });
        }
    });
    base
}

struct Count(AtomicUsize);
impl Hook for Count {
    fn call(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { true })
    }
}
struct Fixed(bool);
impl Hook for Fixed {
    fn call(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        let v = self.0;
        Box::pin(async move { v })
    }
}

fn link(root: &Path, name: &str) -> String {
    std::fs::read_link(root.join(name))
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// A stand-in node binary: a shell script whose `--selftest` passes or fails.
fn script(version: &str, selftest_ok: bool) -> Vec<u8> {
    format!(
        "#!/bin/sh\n# {version}\nif [ \"$1\" = \"--selftest\" ]; then exit {}; fi\nexit 0\n",
        if selftest_ok { 0 } else { 1 }
    )
    .into_bytes()
}

struct Env {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    base: String,
    agent: Agent,
}

impl Env {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("releases/0.1.0")).unwrap();
        std::fs::write(
            root.join("releases/0.1.0/conet-node"),
            script("0.1.0", true),
        )
        .unwrap();
        std::os::unix::fs::symlink("releases/0.1.0", root.join("current")).unwrap();
        let files = Arc::new(Mutex::new(HashMap::new()));
        let base = serve(files.clone()).await;
        let agent = Agent::new(
            root.clone(),
            vec![format!("{base}/manifest.json")],
            vec![vk(1), vk(2), vk(3)],
            2,
            NODE.into(),
            TARGET.into(),
        )
        .unwrap();
        Self {
            _dir: dir,
            root,
            files,
            base,
            agent,
        }
    }
    fn publish(&self, m: &Manifest, bin: Option<(&str, &[u8])>) {
        let mut f = self.files.lock().unwrap();
        if let Some((name, b)) = bin {
            f.insert(format!("/{name}"), b.to_vec());
        }
        let (b, s) = signed(m, &[1, 2]);
        f.insert("/manifest.json".into(), b);
        f.insert("/manifest.json.sig".into(), s);
    }
    fn art(&self, name: &str, b: &[u8]) -> Artifact {
        Artifact {
            target: TARGET.into(),
            urls: vec![format!("{}/{name}", self.base)],
            sha256: manifest::sha256_hex(b),
            size: b.len() as u64,
        }
    }
    fn release(&self, v: &str, selftest_ok: bool) -> Manifest {
        let b = script(v, selftest_ok);
        let m = man(v, 100, &[], Some(self.art(v, &b)));
        self.publish(&m, Some((v, &b)));
        m
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_health_rollback_revoke_and_replay() {
    let e = Env::new().await;
    let restarts = Count(AtomicUsize::new(0));

    // newer version: stage, verify hash, selftest, switch, restart once, mark healthy
    e.release("0.2.0", true);
    assert_eq!(
        e.agent
            .check_once(&restarts, &Fixed(true))
            .await
            .unwrap()
            .label(),
        "update"
    );
    assert_eq!(
        (link(&e.root, "current"), link(&e.root, "previous")),
        ("0.2.0".into(), "0.1.0".into())
    );
    assert_eq!(restarts.0.load(Ordering::SeqCst), 1);
    assert!(e.agent.load_boot().healthy);
    assert_eq!(
        e.agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::UpToDate
    );

    // next version fails its health check: roll back, never retry it
    e.release("0.3.0", true);
    e.agent.check_once(&restarts, &Fixed(false)).await.unwrap();
    assert_eq!(
        (link(&e.root, "current"), link(&e.root, "previous")),
        ("0.2.0".into(), "0.1.0".into())
    );
    assert_eq!(
        restarts.0.load(Ordering::SeqCst),
        3,
        "restart into 0.3.0, then back"
    );
    assert_eq!(e.agent.load_state().bad, ["0.3.0"]);
    assert_eq!(
        e.agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Skip("version_blocked")
    );

    // replayed older manifest is ignored
    e.publish(&man("0.2.0", 100, &[], None), None);
    assert_eq!(
        e.agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Stale
    );

    // wrong hash: nothing changes, no restart
    let mut bad = e.art("0.4.0", &script("0.4.0", true));
    bad.sha256 = manifest::sha256_hex(b"something else");
    e.publish(
        &man("0.4.0", 100, &[], Some(bad)),
        Some(("0.4.0", &script("0.4.0", true))),
    );
    let before = restarts.0.load(Ordering::SeqCst);
    assert!(e.agent.check_once(&restarts, &Fixed(true)).await.is_err());
    assert_eq!(
        (link(&e.root, "current"), restarts.0.load(Ordering::SeqCst)),
        ("0.2.0".into(), before)
    );

    // the running version gets revoked: back to previous
    e.publish(&man("0.4.1", 0, &["0.2.0"], None), None);
    assert_eq!(
        e.agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Rollback
    );
    assert_eq!(link(&e.root, "current"), "0.1.0");
    let c = e.agent.load_state().counters;
    assert!(
        c["installed"] >= 1 && c["rolled_back"] >= 2 && c["failed"] >= 1 && c["stale"] >= 1,
        "{c:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_and_selftest_failures_never_restart_and_give_up_after_three() {
    let e = Env::new().await;
    let restarts = Count(AtomicUsize::new(0));
    // manifest unavailable
    assert!(e.agent.check_once(&restarts, &Fixed(true)).await.is_err());
    // selftest fails three times, then the version is given up
    e.release("0.2.0", false);
    for _ in 0..3 {
        assert!(e.agent.check_once(&restarts, &Fixed(true)).await.is_err());
        assert_eq!(link(&e.root, "current"), "0.1.0");
    }
    assert_eq!(
        restarts.0.load(Ordering::SeqCst),
        0,
        "no restart on any failure"
    );
    assert_eq!(e.agent.load_state().attempts["0.2.0"], 3);
    assert_eq!(
        e.agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Skip("attempts_exhausted")
    );
    // a newer version is tried
    e.release("0.2.1", true);
    assert_eq!(
        e.agent
            .check_once(&restarts, &Fixed(true))
            .await
            .unwrap()
            .label(),
        "update"
    );
    assert_eq!(link(&e.root, "current"), "0.2.1");
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_loop_is_rolled_back_by_the_offline_boot_guard() {
    let e = Env::new().await;
    // first start, nothing recorded: trusted
    assert_eq!(boot_guard(&e.root).unwrap(), GuardOutcome::Healthy);
    // install 0.2.0 but the node never stays up long enough (health hook still running when it dies)
    e.release("0.2.0", true);
    let restarts = Count(AtomicUsize::new(0));
    // emulate: switch happened, boot.json says unhealthy (updater killed before marking healthy)
    e.agent.switch_to("0.2.0").unwrap();
    std::fs::create_dir_all(e.root.join("releases/0.2.0")).unwrap();
    std::fs::write(
        e.root.join("boot.json"),
        r#"{"version":"0.2.0","boots":0,"healthy":false,"blacklist":[]}"#,
    )
    .unwrap();
    for i in 1..=3 {
        assert_eq!(boot_guard(&e.root).unwrap(), GuardOutcome::Counted(i));
    }
    assert_eq!(
        boot_guard(&e.root).unwrap(),
        GuardOutcome::RolledBack {
            from: "0.2.0".into(),
            to: "0.1.0".into()
        }
    );
    assert_eq!(link(&e.root, "current"), "0.1.0");
    assert_eq!(
        boot_guard(&e.root).unwrap(),
        GuardOutcome::Healthy,
        "previous release starts normally"
    );
    // the updater never installs the blacklisted version again
    assert_eq!(
        e.agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Skip("version_blocked")
    );
}

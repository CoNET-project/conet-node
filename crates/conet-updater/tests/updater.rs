use conet_updater::agent::{decide, random_delay, Agent, Decision, Hook, State, CHECK_WINDOW};
use conet_updater::manifest::{self, Artifact, Manifest, SigFile, VerifyError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TARGET: &str = "x86_64-unknown-linux-gnu";

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
    let mut tampered = b.clone();
    tampered[10] ^= 1;
    assert!(manifest::verify(&tampered, &s, &trusted, 1).is_err());
    let mut other = m.clone();
    other.product = "other".into();
    let (b3, s3) = signed(&other, &[1]);
    assert_eq!(
        manifest::verify(&b3, &s3, &trusted, 1),
        Err(VerifyError::WrongProduct)
    );
    assert!(
        manifest::verify(&b, &s, &trusted, 0).is_err(),
        "threshold 0 never passes"
    );
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
    let node = "0x1111111111111111111111111111111111111111";
    assert_eq!(
        decide(
            &man("1.0.0", 100, &[], Some(art.clone())),
            "1.0.0",
            node,
            TARGET,
            &st
        ),
        Decision::UpToDate
    );
    assert!(matches!(
        decide(
            &man("1.1.0", 100, &[], Some(art.clone())),
            "1.0.0",
            node,
            TARGET,
            &st
        ),
        Decision::Update { .. }
    ));
    assert_eq!(
        decide(
            &man("1.1.0", 0, &[], Some(art.clone())),
            "1.0.0",
            node,
            TARGET,
            &st
        ),
        Decision::NotInCohort
    );
    assert_eq!(
        decide(
            &man("1.1.0", 100, &["1.0.0"], Some(art.clone())),
            "1.0.0",
            node,
            TARGET,
            &st
        ),
        Decision::Rollback
    );
    assert_eq!(
        decide(&man("1.1.0", 100, &[], None), "1.0.0", node, TARGET, &st),
        Decision::Skip("no_artifact_for_target")
    );
    let seen = State {
        highest_seen: Some("2.0.0".into()),
        bad: vec!["1.5.0".into()],
    };
    assert_eq!(
        decide(
            &man("1.1.0", 100, &[], Some(art.clone())),
            "1.0.0",
            node,
            TARGET,
            &seen
        ),
        Decision::Stale,
        "replayed older manifest"
    );
    let seen = State {
        highest_seen: None,
        bad: vec!["1.5.0".into()],
    };
    assert_eq!(
        decide(
            &man("1.5.0", 100, &[], Some(art)),
            "1.0.0",
            node,
            TARGET,
            &seen
        ),
        Decision::Skip("version_blocked")
    );
}

#[test]
fn cohorts_are_stable_and_spread() {
    assert_eq!(
        manifest::cohort("0xAbC", "1.0.0"),
        manifest::cohort("0xabc", "1.0.0")
    );
    let half = (0..1000)
        .filter(|i| manifest::cohort(&format!("0x{i:040x}"), "1.0.0") < 50)
        .count();
    assert!((400..=600).contains(&half), "{half}");
    for _ in 0..1000 {
        assert!(random_delay(CHECK_WINDOW) < CHECK_WINDOW);
    }
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

#[tokio::test(flavor = "multi_thread")]
async fn update_health_rollback_revoke_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(root.join("releases/0.1.0")).unwrap();
    std::fs::write(root.join("releases/0.1.0/conet-node"), b"v0.1.0").unwrap();
    std::os::unix::fs::symlink("releases/0.1.0", root.join("current")).unwrap();

    let files = Arc::new(Mutex::new(HashMap::new()));
    let base = serve(files.clone()).await;
    let publish = |m: &Manifest, bin: Option<(&str, &[u8])>| {
        let mut f = files.lock().unwrap();
        if let Some((name, b)) = bin {
            f.insert(format!("/{name}"), b.to_vec());
        }
        let (b, s) = signed(m, &[1, 2]);
        f.insert("/manifest.json".into(), b);
        f.insert("/manifest.json.sig".into(), s);
    };
    let art = |name: &str, b: &[u8]| Artifact {
        target: TARGET.into(),
        urls: vec![format!("{base}/{name}")],
        sha256: manifest::sha256_hex(b),
        size: b.len() as u64,
    };
    let agent = Agent::new(
        root.clone(),
        vec![format!("{base}/manifest.json")],
        vec![vk(1), vk(2), vk(3)],
        2,
        "0x1111111111111111111111111111111111111111".into(),
        TARGET.into(),
    )
    .unwrap();
    let restarts = Count(AtomicUsize::new(0));

    // 1. newer version: stage, verify hash, switch, restart once
    publish(
        &man("0.2.0", 100, &[], Some(art("b020", b"v0.2.0"))),
        Some(("b020", b"v0.2.0")),
    );
    assert!(matches!(
        agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Update { .. }
    ));
    assert_eq!(
        (link(&root, "current"), link(&root, "previous")),
        ("0.2.0".into(), "0.1.0".into())
    );
    assert_eq!(
        std::fs::read(root.join("current/conet-node")).unwrap(),
        b"v0.2.0"
    );
    assert_eq!(restarts.0.load(Ordering::SeqCst), 1);
    assert!(agent.check_once(&restarts, &Fixed(true)).await.unwrap() == Decision::UpToDate);

    // 2. next version fails its health check: roll back, never retry it
    publish(
        &man("0.3.0", 100, &[], Some(art("b030", b"v0.3.0"))),
        Some(("b030", b"v0.3.0")),
    );
    agent.check_once(&restarts, &Fixed(false)).await.unwrap();
    assert_eq!(link(&root, "current"), "0.2.0");
    assert_eq!(
        restarts.0.load(Ordering::SeqCst),
        3,
        "restart into 0.3.0, then back"
    );
    assert_eq!(agent.load_state().bad, ["0.3.0"]);
    assert_eq!(
        agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Skip("version_blocked")
    );

    // 3. a replayed older manifest is ignored
    publish(&man("0.2.0", 100, &[], Some(art("b020", b"v0.2.0"))), None);
    assert_eq!(
        agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Stale
    );

    // 4. a wrong hash leaves everything as it is
    let mut bad = art("b040", b"v0.4.0");
    bad.sha256 = manifest::sha256_hex(b"something else");
    publish(
        &man("0.4.0", 100, &[], Some(bad)),
        Some(("b040", b"v0.4.0")),
    );
    assert!(agent.check_once(&restarts, &Fixed(true)).await.is_err());
    assert_eq!(link(&root, "current"), "0.2.0");

    // 5. the running version gets revoked: back to previous
    publish(
        &man("0.4.1", 0, &["0.2.0"], Some(art("b041", b"v0.4.1"))),
        Some(("b041", b"v0.4.1")),
    );
    assert_eq!(
        agent.check_once(&restarts, &Fixed(true)).await.unwrap(),
        Decision::Rollback
    );
    assert_eq!(link(&root, "current"), "0.1.0");
}

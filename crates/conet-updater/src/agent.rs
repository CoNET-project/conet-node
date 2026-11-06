//! Update agent (M0 report §9; security line `si-s1-s6-eval.md` §3; user decision 2026-11-06:
//! no restart contract; after each start, check at a random moment within 12 hours, restart
//! only when there is an update).
//!
//! Layout under `root`:
//!   releases/<version>/conet-node   binaries, never modified once written
//!   current  -> releases/<version>  what systemd runs
//!   previous -> releases/<version>  rollback target
//!   state.json                      updater: highest version seen, attempts, counters
//!   boot.json                       boot guard: boots of the current version, healthy flag, blacklist
use crate::manifest::{self, Manifest};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

pub const CHECK_WINDOW: Duration = Duration::from_secs(12 * 3600);
pub const BINARY: &str = "conet-node";
/// Same version is tried at most this many times (download, verify, selftest, health).
pub const MAX_ATTEMPTS: u32 = 3;
/// Starts without reaching "healthy" before the boot guard rolls back.
pub const MAX_UNHEALTHY_BOOTS: u32 = 3;
pub const BACKOFF_BASE: Duration = Duration::from_secs(15 * 60);

/// Uniform random delay in [0, window): each node draws its own (OS CSPRNG, no block number,
/// time or wallet as seed), so the fleet spreads out.
pub fn random_delay(window: Duration) -> Duration {
    Duration::from_millis(OsRng.next_u64() % (window.as_millis() as u64).max(1))
}

/// Delay after `failures` consecutive failed checks: base·2^(n−1) capped at the window,
/// drawn uniformly in [half, full].
pub fn backoff(failures: u32, window: Duration) -> Duration {
    let full = BACKOFF_BASE
        .saturating_mul(1u32 << failures.saturating_sub(1).min(16))
        .min(window);
    let half = full / 2;
    half + random_delay(full - half + Duration::from_millis(1))
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    /// Highest manifest version accepted (anti-rollback / anti-replay).
    pub highest_seen: Option<String>,
    /// Versions that failed their health check here; never retried.
    pub bad: Vec<String>,
    /// Failed attempts per version.
    #[serde(default)]
    pub attempts: BTreeMap<String, u32>,
    /// Check outcomes, for fleet statistics without logging in.
    #[serde(default)]
    pub counters: BTreeMap<String, u64>,
}

impl State {
    fn count(&mut self, what: &str) {
        *self.counters.entry(what.to_string()).or_default() += 1;
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct Boot {
    pub version: String,
    pub boots: u32,
    pub healthy: bool,
    /// Versions the guard rolled back from; the updater never installs them again.
    #[serde(default)]
    pub blacklist: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    UpToDate,
    NotInCohort,
    /// Older than a manifest already seen: a replay. Ignore.
    Stale,
    Update {
        version: String,
        artifact: manifest::Artifact,
    },
    /// The running version is revoked: go back to `previous`.
    Rollback,
    Skip(&'static str),
}

impl Decision {
    pub fn label(&self) -> &'static str {
        match self {
            Decision::UpToDate => "up_to_date",
            Decision::NotInCohort => "not_in_cohort",
            Decision::Stale => "stale",
            Decision::Update { .. } => "update",
            Decision::Rollback => "rollback",
            Decision::Skip(_) => "skipped",
        }
    }
}

fn ver(s: &str) -> Option<semver::Version> {
    semver::Version::parse(s).ok()
}

/// Pure decision from a verified manifest. `blocked` = versions that failed here (health or boot).
pub fn decide(
    m: &Manifest,
    current: &str,
    node_id: &str,
    target: &str,
    st: &State,
    blocked: &[String],
) -> Decision {
    let (Some(cur), Some(new)) = (ver(current), ver(&m.version)) else {
        return Decision::Skip("version_parse");
    };
    if let Some(h) = st.highest_seen.as_deref().and_then(ver) {
        if new < h {
            return Decision::Stale;
        }
    }
    if m.revoked.iter().any(|r| r == current) {
        return Decision::Rollback;
    }
    if new <= cur {
        return Decision::UpToDate;
    }
    if let Some(min) = m.min_version.as_deref().and_then(ver) {
        if new < min {
            return Decision::Skip("below_min_version");
        }
    }
    if m.revoked.contains(&m.version) || st.bad.contains(&m.version) || blocked.contains(&m.version)
    {
        return Decision::Skip("version_blocked");
    }
    if st.attempts.get(&m.version).copied().unwrap_or(0) >= MAX_ATTEMPTS {
        return Decision::Skip("attempts_exhausted");
    }
    if manifest::cohort(node_id, &m.version) >= m.rollout_percent {
        return Decision::NotInCohort;
    }
    match m.artifacts.iter().find(|a| a.target == target) {
        Some(a) => Decision::Update {
            version: m.version.clone(),
            artifact: a.clone(),
        },
        None => Decision::Skip("no_artifact_for_target"),
    }
}

/// Async hook for restart and health check (keeps tests free of systemd). Returns success.
pub trait Hook: Sync {
    fn call(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;
}

pub struct Agent {
    pub root: PathBuf,
    pub manifest_urls: Vec<String>,
    pub trusted: Vec<VerifyingKey>,
    pub threshold: usize,
    pub node_id: String,
    pub target: String,
    pub max_artifact: u64,
    pub selftest_timeout: Duration,
    http: reqwest::Client,
}

#[derive(Debug)]
pub struct AgentError(pub String);

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AgentError {}

fn ae<E: std::fmt::Display>(e: E) -> AgentError {
    AgentError(e.to_string())
}

impl Agent {
    pub fn new(
        root: PathBuf,
        manifest_urls: Vec<String>,
        trusted: Vec<VerifyingKey>,
        threshold: usize,
        node_id: String,
        target: String,
    ) -> Result<Self, AgentError> {
        if trusted.is_empty() || threshold == 0 {
            // No release keys compiled in: never update (security §3.9 "missing keys").
            return Err(AgentError("no release keys: updates disabled".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(ae)?;
        Ok(Self {
            root,
            manifest_urls,
            trusted,
            threshold,
            node_id,
            target,
            max_artifact: 256 * 1024 * 1024,
            selftest_timeout: Duration::from_secs(60),
            http,
        })
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn load_state(&self) -> State {
        read_json(&self.state_path()).unwrap_or_default()
    }
    pub fn save_state(&self, st: &State) -> Result<(), AgentError> {
        atomic_write(
            &self.state_path(),
            &serde_json::to_vec_pretty(st).map_err(ae)?,
        )
        .map_err(ae)
    }
    pub fn load_boot(&self) -> Boot {
        read_json(&self.root.join("boot.json")).unwrap_or_default()
    }

    /// Version `current` points at (directory name under releases/).
    pub fn current_version(&self) -> Option<String> {
        link_version(&self.root.join("current"))
    }

    async fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, AgentError> {
        let r = self.http.get(url).send().await.map_err(ae)?;
        if !r.status().is_success() {
            return Err(AgentError(format!("http {}", r.status())));
        }
        if r.content_length().map(|l| l > max).unwrap_or(false) {
            return Err(AgentError("too large".into()));
        }
        let b = r.bytes().await.map_err(ae)?;
        if b.len() as u64 > max {
            return Err(AgentError("too large".into()));
        }
        Ok(b.to_vec())
    }

    /// Fetch manifest + signatures from the first mirror that verifies.
    pub async fn fetch_manifest(&self) -> Result<Manifest, AgentError> {
        let mut last = AgentError("no manifest url".into());
        for u in &self.manifest_urls {
            let (m, s) = (
                self.get(u, 1 << 20).await,
                self.get(&format!("{u}.sig"), 1 << 16).await,
            );
            match (m, s) {
                (Ok(m), Ok(s)) => match manifest::verify(&m, &s, &self.trusted, self.threshold) {
                    Ok(v) => return Ok(v),
                    Err(e) => last = AgentError(format!("{e:?}")),
                },
                (Err(e), _) | (_, Err(e)) => last = e,
            }
        }
        Err(last)
    }

    /// Download, check size and hash, write `releases/<version>/conet-node` (0755).
    pub async fn stage(
        &self,
        version: &str,
        a: &manifest::Artifact,
    ) -> Result<PathBuf, AgentError> {
        if a.size > self.max_artifact {
            return Err(AgentError("artifact too large".into()));
        }
        let mut last = AgentError("no artifact url".into());
        for u in &a.urls {
            match self.get(u, a.size).await {
                Ok(b)
                    if b.len() as u64 == a.size
                        && manifest::sha256_hex(&b).eq_ignore_ascii_case(&a.sha256) =>
                {
                    let dir = self.root.join("releases").join(version);
                    std::fs::create_dir_all(&dir).map_err(ae)?;
                    let bin = dir.join(BINARY);
                    atomic_write(&bin, &b).map_err(ae)?;
                    set_exec(&bin).map_err(ae)?;
                    return Ok(dir);
                }
                Ok(_) => last = AgentError("hash or size mismatch".into()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Run the staged binary's `--selftest` before switching to it.
    pub async fn selftest(&self, dir: &Path) -> Result<(), AgentError> {
        let run = tokio::process::Command::new(dir.join(BINARY))
            .arg("--selftest")
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(self.selftest_timeout, run).await {
            Ok(Ok(o)) if o.status.success() => Ok(()),
            Ok(Ok(o)) => Err(AgentError(format!("selftest exit {:?}", o.status.code()))),
            Ok(Err(e)) => Err(AgentError(format!("selftest spawn: {e}"))),
            Err(_) => Err(AgentError("selftest timeout".into())),
        }
    }

    /// current → new version, previous → old current. Atomic per link (rename of a temp link).
    pub fn switch_to(&self, version: &str) -> Result<(), AgentError> {
        let cur = self.root.join("current");
        if let Ok(old) = std::fs::read_link(&cur) {
            replace_link(&self.root.join("previous"), &old).map_err(ae)?;
        }
        replace_link(&cur, &Path::new("releases").join(version)).map_err(ae)
    }

    /// current → previous (used on a failed health check or a revoked version).
    pub fn rollback(&self) -> Result<String, AgentError> {
        rollback_links(&self.root).map_err(ae)
    }

    fn failed(&self, st: &mut State, version: &str, why: AgentError) -> AgentError {
        *st.attempts.entry(version.to_string()).or_default() += 1;
        st.count("failed");
        let _ = self.save_state(st);
        why
    }

    /// One check. `restart` restarts the node; `healthy` waits until it has run healthily long
    /// enough. Any failure before the switch leaves the running node alone (no restart).
    pub async fn check_once(
        &self,
        restart: &dyn Hook,
        healthy: &dyn Hook,
    ) -> Result<Decision, AgentError> {
        let current = self
            .current_version()
            .ok_or_else(|| AgentError("no current release".into()))?;
        let mut st = self.load_state();
        let m = match self.fetch_manifest().await {
            Ok(m) => m,
            Err(e) => {
                st.count("failed");
                let _ = self.save_state(&st);
                return Err(e);
            }
        };
        let boot = self.load_boot();
        let d = decide(
            &m,
            &current,
            &self.node_id,
            &self.target,
            &st,
            &boot.blacklist,
        );
        if d != Decision::Stale {
            st.highest_seen = Some(m.version.clone());
        }
        st.count(d.label());
        self.save_state(&st)?;
        match &d {
            Decision::Update { version, artifact } => {
                let dir = match self.stage(version, artifact).await {
                    Ok(d) => d,
                    Err(e) => return Err(self.failed(&mut st, version, e)),
                };
                if let Err(e) = self.selftest(&dir).await {
                    return Err(self.failed(&mut st, version, e));
                }
                let old_previous = std::fs::read_link(self.root.join("previous")).ok();
                self.switch_to(version)?;
                write_boot(
                    &self.root,
                    &Boot {
                        version: version.clone(),
                        boots: 0,
                        healthy: false,
                        blacklist: boot.blacklist.clone(),
                    },
                )
                .map_err(ae)?;
                info!(%version, "switched; restarting");
                restart.call().await;
                if healthy.call().await {
                    let mut b = self.load_boot();
                    b.healthy = true;
                    write_boot(&self.root, &b).map_err(ae)?;
                    st.count("installed");
                    st.attempts.remove(version);
                } else {
                    warn!(%version, "health check failed; rolling back");
                    st.bad.push(version.clone());
                    st.count("rolled_back");
                    self.rollback()?;
                    // Keep the older release as the rollback target, not the one we just left.
                    if let Some(p) = old_previous {
                        replace_link(&self.root.join("previous"), &p).map_err(ae)?;
                    }
                    let mut b = self.load_boot();
                    b.version = self.current_version().unwrap_or_default();
                    b.boots = 0;
                    b.healthy = true;
                    write_boot(&self.root, &b).map_err(ae)?;
                    restart.call().await;
                }
                self.save_state(&st)?;
            }
            Decision::Rollback => {
                let prev = link_version(&self.root.join("previous"))
                    .ok_or_else(|| AgentError("no previous release".into()))?;
                if let (Some(min), Some(p)) = (m.min_version.as_deref().and_then(ver), ver(&prev)) {
                    if p < min {
                        warn!(%prev, "running version revoked, but previous is below min_version; staying");
                        return Ok(Decision::Skip("rollback_below_min_version"));
                    }
                }
                let v = self.rollback()?;
                warn!(to = %v, "running version revoked; rolled back");
                st.count("rolled_back");
                self.save_state(&st)?;
                restart.call().await;
            }
            _ => {}
        }
        Ok(d)
    }
}

/// What the boot guard did on this start.
#[derive(Debug, PartialEq)]
pub enum GuardOutcome {
    Healthy,
    Counted(u32),
    RolledBack { from: String, to: String },
    NoPrevious,
}

/// Boot guard, run before every start of conet-node (systemd `ExecStartPre=`). Separate from the
/// binary being updated and needs no network: if the current version has started more than
/// `MAX_UNHEALTHY_BOOTS` times without being marked healthy, switch back to `previous` and
/// blacklist it. Never blocks the start.
pub fn boot_guard(root: &Path) -> std::io::Result<GuardOutcome> {
    let current = link_version(&root.join("current")).unwrap_or_default();
    let mut b: Boot = read_json(&root.join("boot.json")).unwrap_or_else(|| Boot {
        version: current.clone(),
        boots: 0,
        healthy: true,
        blacklist: vec![],
    });
    if b.version != current {
        // Installed by hand (or first start): trust it.
        b = Boot {
            version: current.clone(),
            boots: 0,
            healthy: true,
            blacklist: b.blacklist,
        };
    }
    if b.healthy {
        write_boot(root, &b)?;
        return Ok(GuardOutcome::Healthy);
    }
    b.boots += 1;
    if b.boots <= MAX_UNHEALTHY_BOOTS {
        write_boot(root, &b)?;
        return Ok(GuardOutcome::Counted(b.boots));
    }
    if std::fs::read_link(root.join("previous")).is_err() {
        write_boot(root, &b)?;
        return Ok(GuardOutcome::NoPrevious);
    }
    let to = rollback_links(root)?;
    if !b.blacklist.contains(&current) {
        b.blacklist.push(current.clone());
    }
    b.version = to.clone();
    b.boots = 0;
    b.healthy = true;
    write_boot(root, &b)?;
    Ok(GuardOutcome::RolledBack { from: current, to })
}

fn rollback_links(root: &Path) -> std::io::Result<String> {
    let prev = std::fs::read_link(root.join("previous"))?;
    replace_link(&root.join("current"), &prev)?;
    link_version(&root.join("current")).ok_or_else(|| std::io::Error::other("bad link"))
}

fn write_boot(root: &Path, b: &Boot) -> std::io::Result<()> {
    atomic_write(
        &root.join("boot.json"),
        &serde_json::to_vec_pretty(b).map_err(std::io::Error::other)?,
    )
}

fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Option<T> {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn link_version(link: &Path) -> Option<String> {
    std::fs::read_link(link)
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_string)
}

fn replace_link(link: &Path, target: &Path) -> std::io::Result<()> {
    let tmp = link.with_extension("tmp-link");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)?;
    std::fs::rename(&tmp, link)
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn set_exec(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

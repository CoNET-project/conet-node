//! Update agent (M0 report §9, user decision 2026-11-06: no restart contract; after each start,
//! check at a random moment within 12 hours, restart only when there is an update).
//!
//! Layout under `root`:
//!   releases/<version>/conet-node   binaries, never modified once written
//!   current  -> releases/<version>  what systemd runs
//!   previous -> releases/<version>  rollback target
//!   state.json                      highest version seen, versions that failed health checks
use crate::manifest::{self, Manifest};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

pub const CHECK_WINDOW: Duration = Duration::from_secs(12 * 3600);
pub const BINARY: &str = "conet-node";

/// Uniform random delay in [0, window): each node draws its own, so the fleet spreads out.
pub fn random_delay(window: Duration) -> Duration {
    Duration::from_millis(OsRng.next_u64() % (window.as_millis() as u64).max(1))
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    /// Highest manifest version accepted (anti-rollback / anti-replay).
    pub highest_seen: Option<String>,
    /// Versions that failed their health check here; never retried.
    pub bad: Vec<String>,
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

/// Pure decision from a verified manifest.
pub fn decide(m: &Manifest, current: &str, node_id: &str, target: &str, st: &State) -> Decision {
    let (Ok(cur), Ok(new)) = (
        semver::Version::parse(current),
        semver::Version::parse(&m.version),
    ) else {
        return Decision::Skip("version_parse");
    };
    if let Some(h) = st
        .highest_seen
        .as_deref()
        .and_then(|h| semver::Version::parse(h).ok())
    {
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
    if m.revoked.contains(&m.version) || st.bad.contains(&m.version) {
        return Decision::Skip("version_blocked");
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

pub struct Agent {
    pub root: PathBuf,
    pub manifest_urls: Vec<String>,
    pub trusted: Vec<VerifyingKey>,
    pub threshold: usize,
    pub node_id: String,
    pub target: String,
    pub max_artifact: u64,
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
            http,
        })
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn load_state(&self) -> State {
        std::fs::read(self.state_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    pub fn save_state(&self, st: &State) -> Result<(), AgentError> {
        atomic_write(
            &self.state_path(),
            &serde_json::to_vec_pretty(st).map_err(ae)?,
        )
        .map_err(ae)
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
        let prev = std::fs::read_link(self.root.join("previous"))
            .map_err(|_| AgentError("no previous release".into()))?;
        replace_link(&self.root.join("current"), &prev).map_err(ae)?;
        link_version(&self.root.join("current")).ok_or_else(|| AgentError("bad link".into()))
    }

    /// One check. `restart` restarts the node; `healthy` waits for it to come up.
    pub async fn check_once(
        &self,
        restart: &dyn Hook,
        healthy: &dyn Hook,
    ) -> Result<Decision, AgentError> {
        let current = self
            .current_version()
            .ok_or_else(|| AgentError("no current release".into()))?;
        let m = self.fetch_manifest().await?;
        let mut st = self.load_state();
        let d = decide(&m, &current, &self.node_id, &self.target, &st);
        if d != Decision::Stale {
            st.highest_seen = Some(m.version.clone());
            self.save_state(&st)?;
        }
        match &d {
            Decision::Update { version, artifact } => {
                self.stage(version, artifact).await?;
                let old_previous = std::fs::read_link(self.root.join("previous")).ok();
                self.switch_to(version)?;
                info!(%version, "switched; restarting");
                restart.call().await;
                if !healthy.call().await {
                    warn!(%version, "health check failed; rolling back");
                    st.bad.push(version.clone());
                    self.save_state(&st)?;
                    self.rollback()?;
                    // Keep the older release as the rollback target, not the one we just left.
                    if let Some(p) = old_previous {
                        replace_link(&self.root.join("previous"), &p).map_err(ae)?;
                    }
                    restart.call().await;
                }
            }
            Decision::Rollback => {
                let v = self.rollback()?;
                warn!(to = %v, "running version revoked; rolled back");
                restart.call().await;
            }
            _ => {}
        }
        Ok(d)
    }
}

/// Async hook for restart and health check (keeps tests free of systemd). Returns success.
pub trait Hook: Sync {
    fn call(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;
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

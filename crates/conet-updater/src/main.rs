//! `conet-updater run | release keygen | release sign | release verify`.
//!
//! run: after start, wait a random time within 12 hours, check the signed manifest, update and
//!      restart only when there is a newer version for this node's cohort; repeat. No restart
//!      contract and no fixed schedule (user decision 2026-11-06).
//! release: offline tooling for the release keys (custody is decision N6).
use conet_updater::agent::{random_delay, Agent, Hook, CHECK_WINDOW};
use conet_updater::manifest::{self, SigFile};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::PathBuf;
use std::time::Duration;

fn args(name: &str) -> Vec<String> {
    let a: Vec<String> = std::env::args().collect();
    a.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}
fn arg(name: &str) -> Option<String> {
    args(name).into_iter().next()
}

fn trusted() -> Result<Vec<VerifyingKey>, Box<dyn std::error::Error>> {
    let mut out = vec![];
    for k in args("--trusted-key") {
        let b: [u8; 32] = hex::decode(k)?
            .try_into()
            .map_err(|_| "trusted key must be 32 bytes hex")?;
        out.push(VerifyingKey::from_bytes(&b)?);
    }
    if out.is_empty() {
        return Err("at least one --trusted-key".into());
    }
    Ok(out)
}

struct Restart(Vec<String>);
impl Hook for Restart {
    fn call(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let Some((cmd, rest)) = self.0.split_first() else {
                return false;
            };
            tokio::process::Command::new(cmd)
                .args(rest)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
        })
    }
}

struct Health(String);
impl Hook for Health {
    fn call(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let c = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .ok();
            for _ in 0..60 {
                if let Some(c) = &c {
                    if c.get(&self.0)
                        .send()
                        .await
                        .map(|r| r.status().is_success())
                        .unwrap_or(false)
                    {
                        return true;
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            false
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let a: Vec<String> = std::env::args().collect();
    match (a.get(1).map(String::as_str), a.get(2).map(String::as_str)) {
        (Some("run"), _) => {
            let agent = Agent::new(
                PathBuf::from(arg("--root").ok_or("--root <dir>")?),
                args("--manifest-url"),
                trusted()?,
                arg("--threshold").and_then(|t| t.parse().ok()).unwrap_or(1),
                arg("--node-id").ok_or("--node-id <node wallet>")?,
                arg("--target").unwrap_or_else(|| "x86_64-unknown-linux-gnu".into()),
            )?;
            let restart = Restart(
                arg("--restart-cmd")
                    .ok_or("--restart-cmd \"systemctl restart conet-node\"")?
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
            );
            let health = Health(
                arg("--health-url").unwrap_or_else(|| "http://127.0.0.1:80/nodeWallet".into()),
            );
            loop {
                let wait = random_delay(CHECK_WINDOW);
                tracing::info!(minutes = wait.as_secs() / 60, "next update check");
                tokio::time::sleep(wait).await;
                match agent.check_once(&restart, &health).await {
                    Ok(d) => tracing::info!(?d, "update check"),
                    Err(e) => tracing::warn!(err = %e.0, "update check failed"),
                }
            }
        }
        (Some("release"), Some("keygen")) => {
            let out = PathBuf::from(arg("--out").ok_or("--out <secret key file>")?);
            let mut seed = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
            let sk = SigningKey::from_bytes(&seed);
            write_private(&out, hex::encode(seed).as_bytes())?;
            println!("public key: {}", hex::encode(sk.verifying_key().to_bytes()));
        }
        (Some("release"), Some("sign")) => {
            let mpath = PathBuf::from(arg("--manifest").ok_or("--manifest <manifest.json>")?);
            let seed: [u8; 32] = hex::decode(
                std::fs::read_to_string(arg("--key").ok_or("--key <secret key file>")?)?.trim(),
            )?
            .try_into()
            .map_err(|_| "bad key")?;
            let m = std::fs::read(&mpath)?;
            let sig_path = mpath.with_extension("json.sig");
            let mut sf: SigFile = std::fs::read(&sig_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(SigFile { sigs: vec![] });
            let e = manifest::sign(&m, &SigningKey::from_bytes(&seed));
            sf.sigs.retain(|s| s.key != e.key);
            sf.sigs.push(e);
            std::fs::write(&sig_path, serde_json::to_vec_pretty(&sf)?)?;
            println!("signatures: {}", sf.sigs.len());
        }
        (Some("release"), Some("verify")) => {
            let mpath = PathBuf::from(arg("--manifest").ok_or("--manifest <manifest.json>")?);
            let m = std::fs::read(&mpath)?;
            let s = std::fs::read(mpath.with_extension("json.sig"))?;
            let threshold = arg("--threshold").and_then(|t| t.parse().ok()).unwrap_or(1);
            match manifest::verify(&m, &s, &trusted()?, threshold) {
                Ok(v) => println!("ok: {} {}", v.product, v.version),
                Err(e) => return Err(format!("{e:?}").into()),
            }
        }
        _ => eprintln!("usage: conet-updater run ... | release keygen|sign|verify ..."),
    }
    Ok(())
}

fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

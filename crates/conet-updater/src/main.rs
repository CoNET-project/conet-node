//! `conet-updater run | release keygen | release sign | release verify`.
//!
//! run: after start, wait a random time within 12 hours, check the signed manifest, update and
//!      restart only when there is a newer version for this node's cohort; repeat. No restart
//!      contract and no fixed schedule (user decision 2026-11-06).
//! release: offline tooling for the release keys (custody is decision N6).
use conet_updater::agent::{backoff, random_delay, Agent, Hook, CHECK_WINDOW};
use conet_updater::manifest::{self, SigFile};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::PathBuf;
use std::time::Duration;

/// Values of flag `name`: the token after each occurrence. A flag with no value never takes the
/// next flag (`--…`) as its value; that is what an empty `${VAR}` expanded by systemd looks like.
fn args(name: &str) -> Vec<String> {
    let a: Vec<String> = std::env::args().collect();
    values_in(&a, name)
}
fn values_in(a: &[String], name: &str) -> Vec<String> {
    a.windows(2)
        .filter(|w| w[0] == name && !w[1].starts_with("--"))
        .map(|w| w[1].clone())
        .collect()
}
fn arg(name: &str) -> Option<String> {
    args(name).into_iter().next()
}

/// The value flags of this binary, including the repeated ones read through `args()`.
const VALUE_FLAGS: [&str; 11] = [
    "--health-url",
    "--key",
    "--manifest",
    "--manifest-url",
    "--node-id",
    "--out",
    "--restart-cmd",
    "--root",
    "--target",
    "--threshold",
    "--trusted-key",
];

/// True when a value is present and usable: not missing, not another flag, not blank.
fn has_value(v: Option<&String>) -> bool {
    v.is_some_and(|v| !v.starts_with("--") && !v.trim().is_empty())
}

/// The first value flag that appears without a usable value. Returns the flag name only.
fn valueless_flag(args: &[String]) -> Option<&'static str> {
    VALUE_FLAGS.iter().copied().find(|f| {
        args.iter()
            .enumerate()
            .any(|(i, a)| a == f && !has_value(args.get(i + 1)))
    })
}

/// Release public keys and threshold are compiled into this binary (security §3.2): a candidate
/// release cannot bring its own keys, and changing keys takes a release signed by the old ones.
/// Build with CONET_RELEASE_KEYS="hex,hex,..." CONET_RELEASE_THRESHOLD=k. Without them, `run`
/// never updates.
const RELEASE_KEYS: Option<&str> = option_env!("CONET_RELEASE_KEYS");
const RELEASE_THRESHOLD: Option<&str> = option_env!("CONET_RELEASE_THRESHOLD");

fn compiled_keys() -> (Vec<VerifyingKey>, usize) {
    let keys = RELEASE_KEYS
        .unwrap_or("")
        .split(',')
        .filter(|k| !k.trim().is_empty())
        .filter_map(|k| hex::decode(k.trim()).ok()?.try_into().ok())
        .filter_map(|b: [u8; 32]| VerifyingKey::from_bytes(&b).ok())
        .collect();
    (
        keys,
        RELEASE_THRESHOLD.and_then(|t| t.parse().ok()).unwrap_or(0),
    )
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
    // Fail closed: a value flag given without a usable value stops the start. Nothing falls back
    // to a default. Only the flag name is printed, never a value.
    if let Some(flag) = valueless_flag(&a) {
        return Err(format!("{flag} is given without a value; refusing to start").into());
    }
    match (a.get(1).map(String::as_str), a.get(2).map(String::as_str)) {
        (Some("run"), _) => {
            let (keys, threshold) = compiled_keys();
            let agent = Agent::new(
                PathBuf::from(arg("--root").ok_or("--root <dir>")?),
                args("--manifest-url"),
                keys,
                threshold,
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
                arg("--health-url").unwrap_or_else(|| "http://127.0.0.1:9180/healthz".into()),
            );
            let mut failures = 0u32;
            let mut wait = random_delay(CHECK_WINDOW);
            loop {
                tracing::info!(minutes = wait.as_secs() / 60, "next update check");
                tokio::time::sleep(wait).await;
                match agent.check_once(&restart, &health).await {
                    Ok(d) => {
                        tracing::info!(result = d.label(), "update check");
                        failures = 0;
                        wait = random_delay(CHECK_WINDOW);
                    }
                    Err(e) => {
                        failures += 1;
                        wait = backoff(failures, CHECK_WINDOW);
                        tracing::warn!(err = %e.0, failures, "update check failed; backing off");
                    }
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

#[cfg(test)]
mod arg_tests {
    use super::values_in;

    /// Every flag `main` reads through `arg()` or `args()`.
    const FLAGS: [&str; 11] = [
        "--health-url",
        "--key",
        "--manifest",
        "--manifest-url",
        "--node-id",
        "--out",
        "--restart-cmd",
        "--root",
        "--target",
        "--threshold",
        "--trusted-key",
    ];

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn first(a: &[String], name: &str) -> Option<String> {
        values_in(a, name).into_iter().next()
    }

    #[test]
    fn every_flag_takes_a_normal_value() {
        for f in FLAGS {
            assert_eq!(first(&argv(&["bin", f, "v1"]), f), Some("v1".into()), "{f}");
        }
    }

    #[test]
    fn every_flag_missing_from_argv_is_none() {
        for f in FLAGS {
            assert_eq!(first(&argv(&["bin", "--other", "x"]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_at_the_end_has_no_value() {
        for f in FLAGS {
            assert_eq!(first(&argv(&["bin", "--other", "x", f]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_followed_by_a_flag_takes_no_value_and_the_next_flag_still_parses() {
        for f in FLAGS {
            let next = if f == "--root" { "--target" } else { "--root" };
            let a = argv(&["bin", f, next, "/opt/x"]);
            assert_eq!(first(&a, f), None, "{f} took the next flag");
            assert_eq!(first(&a, next), Some("/opt/x".into()), "{next} after {f}");
        }
    }

    #[test]
    fn a_single_dash_value_is_kept() {
        assert_eq!(
            first(&argv(&["bin", "--threshold", "-1"]), "--threshold"),
            Some("-1".into())
        );
    }

    #[test]
    fn an_empty_value_is_kept_for_the_caller_to_judge() {
        assert_eq!(
            first(&argv(&["bin", "--restart-cmd", ""]), "--restart-cmd"),
            Some(String::new())
        );
    }

    #[test]
    fn repeated_flags_yield_every_valid_value_in_order() {
        let a = argv(&[
            "bin",
            "--trusted-key",
            "k1",
            "--trusted-key",
            "--root",
            "--trusted-key",
            "k2",
        ]);
        assert_eq!(
            values_in(&a, "--trusted-key"),
            vec!["k1".to_string(), "k2".to_string()]
        );
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::{valueless_flag, VALUE_FLAGS};

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_value_flag_without_a_value_refuses_to_start() {
        for f in VALUE_FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "run", f])),
                Some(f),
                "{f} at end"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "run", f, "--root", "/opt/x"])),
                Some(f),
                "{f} then flag"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "run", f, ""])),
                Some(f),
                "{f} empty"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "run", f, "  \t"])),
                Some(f),
                "{f} blank"
            );
        }
    }

    #[test]
    fn every_value_flag_with_a_usable_value_starts() {
        for f in VALUE_FLAGS {
            assert_eq!(valueless_flag(&argv(&["bin", "run", f, "v1"])), None, "{f}");
            assert_eq!(
                valueless_flag(&argv(&["bin", "run", f, "-1"])),
                None,
                "{f} -1"
            );
        }
    }

    #[test]
    fn an_absent_flag_still_starts() {
        for f in VALUE_FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "run", "--other", "x"])),
                None,
                "{f}"
            );
        }
    }

    #[test]
    fn the_refusal_names_the_flag_and_no_value() {
        let secret = "https://secret.example/manifest.json";
        let got = valueless_flag(&argv(&["bin", "run", "--manifest-url", secret, "--target"]));
        assert_eq!(got, Some("--target"));
        assert!(!got.unwrap().contains(secret));
    }
}

//! `conet-signer init|serve`.
//!
//! init:  seal a wallet key and route PGP key into a keystore file.
//!        Secrets come from environment variables, never argv:
//!        CONET_INIT_WALLET_KEY (0x hex), CONET_INIT_PGP_PASS (may be empty); the armored
//!        key from `--pgp-key <file>`.
//! serve: open the keystore and answer the network process on a Unix socket.
//! The KEK comes from systemd-creds (`$CREDENTIALS_DIRECTORY/conet-node-kek`); `--insecure-kek-file`
//! exists for tests and local networks only.
use si_signer::{kek, keystore, server};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}
fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let kek_path = arg("--insecure-kek-file").map(PathBuf::from);
    if kek_path.is_some() {
        eprintln!("WARNING: --insecure-kek-file is for tests only; production uses systemd-creds");
    }
    let kek = kek::load(kek_path.as_deref()).map_err(|e| e.to_string())?;
    match std::env::args().nth(1).as_deref() {
        Some("init") => {
            let out = PathBuf::from(arg("--keystore").ok_or("--keystore <path>")?);
            let state = PathBuf::from(arg("--state").ok_or("--state <path>")?);
            if out.exists() {
                return Err("keystore exists; refusing to overwrite".into());
            }
            let secrets = keystore::Secrets {
                wallet_hex: std::env::var("CONET_INIT_WALLET_KEY")
                    .map_err(|_| "CONET_INIT_WALLET_KEY")?,
                pgp_armored: std::fs::read_to_string(arg("--pgp-key").ok_or("--pgp-key <file>")?)?,
                pgp_pass: std::env::var("CONET_INIT_PGP_PASS").unwrap_or_default(),
            };
            let sealed = Zeroizing::new(keystore::seal(&kek, &secrets).map_err(|e| e.to_string())?);
            write_private(&out, sealed.as_bytes())?;
            server::Signer::init_state(&state, &kek)?;
            println!("keystore written; state initialised");
        }
        Some("serve") => {
            let socket = PathBuf::from(arg("--socket").ok_or("--socket <path>")?);
            let cfg = server::SignerConfig {
                keystore_file: std::fs::read_to_string(
                    arg("--keystore").ok_or("--keystore <path>")?,
                )?,
                kek,
                state_path: PathBuf::from(arg("--state").ok_or("--state <path>")?),
                verifying_contract: arg("--verifying-contract")
                    .ok_or("--verifying-contract <NodeRegistryV2 address>")?,
                reset_floor: arg("--reset-statement-floor").and_then(|s| s.parse().ok()),
                allow_bind: flag("--allow-bind"),
                allow_uid: arg("--allow-uid").and_then(|s| s.parse().ok()),
            };
            let signer = Arc::new(server::Signer::start(cfg).map_err(|e| e.0)?);
            let _ = std::fs::remove_file(&socket);
            let listener = tokio::net::UnixListener::bind(&socket)?;
            set_mode(&socket, 0o660)?;
            server::serve(listener, signer).await?;
        }
        _ => eprintln!("usage: conet-signer init|serve ..."),
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

fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

//! `conet-signer init|serve`.
//!
//! keygen: generate a new wallet and route key inside the signer and seal them (no shell, no
//!        passphrase); prints only the public values for registration.
//! init:  seal an existing wallet key and route PGP key into a keystore file.
//!        Secrets come from environment variables, never argv:
//!        CONET_INIT_WALLET_KEY (0x hex), CONET_INIT_PGP_PASS (may be empty); the armored
//!        key from `--pgp-key <file>`.
//! import-ts-setup: seal the node identity a CoNET-SI (TS) node already has, read from its
//!        `nodeSetup.json` (`--setup <path>`, may be `/dev/fd/3`), checked against the PUBLIC wallet and
//!        route encryption sub-key ID the caller expects (`--expect-wallet`, `--expect-key-id`, both
//!        required). Keys never touch argv, environment or output; only public values are printed.
//! serve: open the keystore and answer the network process on a Unix socket.
//!        `--quota-state <file>` (required with `--anchor-node-id`) keeps the daily quota ledger;
//!        `--quota-config <json>` overrides the defaults (see quota.example.json).
//!        `--topup-config <json>` with `--topup-state <file>` enables the approved main-wallet
//!        topUp entry for AUTO-TOPUP (see topup.example.json); both or neither.
//! The KEK comes from systemd-creds (`$CREDENTIALS_DIRECTORY/conet-node-kek`); `--insecure-kek-file`
//! exists for tests and local networks only.
use si_signer::{kek, keystore, server, ts_setup};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The value of flag `name`: the token after it. A flag with no value never takes the next flag
/// (`--…`) as its value; that is what an empty `${VAR}` expanded by systemd looks like.
fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    arg_in(&a, name)
}
fn arg_in(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|x| x == name)?;
    let v = args.get(i + 1)?;
    (!v.starts_with("--")).then(|| v.clone())
}
/// The value flags this binary reads through `arg()`. `--allow-bind` is a switch (`flag()`).
const VALUE_FLAGS: [&str; 14] = [
    "--allow-uid",
    "--anchor-node-id",
    "--expect-key-id",
    "--expect-wallet",
    "--insecure-kek-file",
    "--keystore",
    "--pgp-key",
    "--quota-config",
    "--quota-state",
    "--setup",
    "--socket",
    "--topup-config",
    "--topup-state",
    "--verifying-contract",
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

/// `--allow-uid`: the only peer uid the signer accepts. Required for `serve`. Missing, empty,
/// non-numeric, negative or above u32 refuses to start; the check is never skipped.
fn allow_uid_from(value: Option<&str>) -> Result<u32, String> {
    let v = value.ok_or_else(|| "--allow-uid <uid> is required".to_string())?;
    v.trim()
        .parse::<u32>()
        .map_err(|_| "--allow-uid must be a uid (0 to 4294967295)".to_string())
}

/// `--quota-state` and `--quota-config` go together. There is no built-in config. Neither flag:
/// no quota ledger, so quota-gated requests are refused.
fn quota_flags<'a>(
    state: Option<&'a str>,
    config: Option<&'a str>,
) -> Result<Option<(&'a str, &'a str)>, String> {
    match (state, config) {
        (None, None) => Ok(None),
        (Some(s), Some(c)) => Ok(Some((s, c))),
        (Some(_), None) => {
            Err("--quota-state needs --quota-config (no default quota is used)".into())
        }
        (None, Some(_)) => Err("--quota-config needs --quota-state".into()),
    }
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // Fail closed: a value flag given without a usable value stops the start. Nothing falls back
    // to a default or to "not configured". Only the flag name is printed, never a value.
    let argv: Vec<String> = std::env::args().collect();
    if let Some(flag) = valueless_flag(&argv) {
        return Err(format!("{flag} is given without a value; refusing to start").into());
    }
    let kek_path = arg("--insecure-kek-file").map(PathBuf::from);
    if kek_path.is_some() {
        eprintln!("WARNING: --insecure-kek-file is for tests only; production uses systemd-creds");
    }
    let kek = kek::load(kek_path.as_deref()).map_err(|e| e.to_string())?;
    match std::env::args().nth(1).as_deref() {
        Some("init") => {
            let out = PathBuf::from(arg("--keystore").ok_or("--keystore <path>")?);
            if out.exists() {
                return Err("keystore exists; refusing to overwrite".into());
            }
            let secrets = keystore::Secrets {
                wallet_hex: std::env::var("CONET_INIT_WALLET_KEY")
                    .map_err(|_| "CONET_INIT_WALLET_KEY")?,
                pgp_armored: std::fs::read_to_string(arg("--pgp-key").ok_or("--pgp-key <file>")?)?,
                pgp_pass: std::env::var("CONET_INIT_PGP_PASS").unwrap_or_default(),
                previous_pgp_armored: String::new(),
                previous_pgp_pass: String::new(),
            };
            let sealed = Zeroizing::new(keystore::seal(&kek, &secrets).map_err(|e| e.to_string())?);
            write_private(&out, sealed.as_bytes())?;
            println!("keystore written");
        }
        Some("import-ts-setup") => {
            let out = PathBuf::from(arg("--keystore").ok_or("--keystore <path>")?);
            if out.exists() {
                return Err("keystore exists; refusing to overwrite".into());
            }
            let setup = arg("--setup").ok_or("--setup <path to nodeSetup.json>")?;
            let want_wallet = arg("--expect-wallet").ok_or("--expect-wallet <0x address>")?;
            let want_key_id = arg("--expect-key-id").ok_or("--expect-key-id <16 hex>")?;
            let bytes = read_setup(std::path::Path::new(&setup))?;
            let imported = ts_setup::import(&bytes, &want_wallet, &want_key_id)?;
            let sealed =
                Zeroizing::new(keystore::seal(&kek, &imported.secrets).map_err(|e| e.to_string())?);
            write_private(&out, sealed.as_bytes())?;
            // Public values only, for the receipt: they match the expected values or we never get here.
            println!(
                "keystore written\nwallet: {}\nkeyId: {}",
                imported.wallet, imported.key_id
            );
        }
        Some("keygen") => {
            let out = PathBuf::from(arg("--keystore").ok_or("--keystore <path>")?);
            if out.exists() {
                return Err("keystore exists; refusing to overwrite".into());
            }
            let (secrets, public) = keystore::generate().map_err(|e| e.to_string())?;
            let sealed = Zeroizing::new(keystore::seal(&kek, &secrets).map_err(|e| e.to_string())?);
            write_private(&out, sealed.as_bytes())?;
            // Public values only: wallet address and route key, for node registration.
            let wallet = si_crypto::eth::EthKey::from_hex(&secrets.wallet_hex)
                .map_err(|e| e.to_string())?
                .address();
            let cert =
                si_crypto::opgp::PublicCert::from_armor(&public).map_err(|e| e.to_string())?;
            println!(
                "wallet: {wallet}\nkeyId: {}\n{public}",
                cert.enc_key_id().unwrap_or_default()
            );
        }
        Some(cmd @ ("rotate-route" | "retire-route")) => {
            // R11: new route key with a transition (old key still decrypts), then retire the old one.
            let path = PathBuf::from(arg("--keystore").ok_or("--keystore <path>")?);
            let mut secrets = keystore::open(&kek, &std::fs::read_to_string(&path)?)
                .map_err(|e| e.to_string())?;
            let public = if cmd == "rotate-route" {
                Some(keystore::rotate_route(&mut secrets).map_err(|e| e.to_string())?)
            } else {
                keystore::retire_previous(&mut secrets);
                None
            };
            let sealed = Zeroizing::new(keystore::seal(&kek, &secrets).map_err(|e| e.to_string())?);
            let tmp = path.with_extension("tmp");
            let _ = std::fs::remove_file(&tmp);
            write_private(&tmp, sealed.as_bytes())?;
            std::fs::rename(&tmp, &path)?;
            match public {
                Some(p) => {
                    let id = si_crypto::opgp::PublicCert::from_armor(&p)
                        .map_err(|e| e.to_string())?
                        .enc_key_id()
                        .unwrap_or_default();
                    println!("new route keyId: {id}\n{p}\nrestart conet-signer and conet-node; register the new key; retire the old one after clients moved");
                }
                None => println!("previous route key removed; restart conet-signer and conet-node"),
            }
        }
        Some("topup-ledger-init") => {
            // The operator creates the AUTO-TOPUP ledger once (mode 0600), never over an existing one.
            let state = PathBuf::from(arg("--topup-state").ok_or("--topup-state <file>")?);
            si_signer::topup_policy::TopUpLedger::create(&state)?;
            println!("topup ledger created");
        }
        Some("serve") => {
            // Required: the peer-uid check is the only gate on who may connect. It is never off.
            let allow_uid = allow_uid_from(arg("--allow-uid").as_deref())?;
            let socket = PathBuf::from(arg("--socket").ok_or("--socket <path>")?);
            let cfg = server::SignerConfig {
                keystore_file: std::fs::read_to_string(
                    arg("--keystore").ok_or("--keystore <path>")?,
                )?,
                kek,
                verifying_contract: arg("--verifying-contract")
                    .ok_or("--verifying-contract <NodeRegistryV2 address>")?,
                allow_bind: flag("--allow-bind"),
                anchor_node_id: arg("--anchor-node-id"),
                allow_uid: Some(allow_uid),
                // The built-in quota defaults are N6 proposals, pending approval, so they are never
                // used: a quota ledger needs an explicit config file.
                quota: match quota_flags(
                    arg("--quota-state").as_deref(),
                    arg("--quota-config").as_deref(),
                )? {
                    None => None,
                    Some((state, config)) => {
                        let qc = serde_json::from_str(&std::fs::read_to_string(config)?)?;
                        Some((qc, PathBuf::from(state)))
                    }
                },
                // AUTO-TOPUP entry (approved 2026-11-09): both flags or neither.
                topup: match (arg("--topup-config"), arg("--topup-state")) {
                    (None, None) => None,
                    (Some(c), Some(st)) => Some((
                        serde_json::from_str(&std::fs::read_to_string(c)?)?,
                        PathBuf::from(st),
                    )),
                    _ => return Err("--topup-config and --topup-state go together".into()),
                },
            };
            let signer = Arc::new(server::Signer::start(cfg).map_err(|e| e.0)?);
            let _ = std::fs::remove_file(&socket);
            let listener = tokio::net::UnixListener::bind(&socket)?;
            set_mode(&socket, 0o660)?;
            server::serve(listener, signer).await?;
        }
        _ => eprintln!(
            "usage: conet-signer keygen|init|rotate-route|retire-route|topup-ledger-init|serve ..."
        ),
    }
    Ok(())
}

/// The setup file, read-only, at most `MAX_SETUP_BYTES`. A `/dev/fd/N` path works (the caller opens
/// the file and passes the descriptor); nothing is written, moved or locked.
fn read_setup(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    use std::io::Read;
    // Allocated once at the largest size read, so no grown-and-freed copy is left behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(ts_setup::MAX_SETUP_BYTES + 1));
    std::fs::File::open(path)?
        .take(ts_setup::MAX_SETUP_BYTES as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > ts_setup::MAX_SETUP_BYTES {
        return Err("setup file too large".into());
    }
    Ok(buf)
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

#[cfg(test)]
mod arg_tests {
    use super::{allow_uid_from, arg_in, quota_flags, valueless_flag, VALUE_FLAGS};

    extern "C" {
        fn getuid() -> u32;
    }

    /// The uid of the test process itself.
    fn current_uid() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { getuid() }
    }

    #[test]
    fn allow_uid_accepts_the_current_process_uid() {
        let uid = current_uid();
        assert_eq!(allow_uid_from(Some(&uid.to_string())), Ok(uid));
        assert_eq!(allow_uid_from(Some(&format!(" {uid} "))), Ok(uid));
    }

    #[test]
    fn allow_uid_refuses_missing_empty_invalid_and_out_of_range_values() {
        for bad in [
            None,
            Some(""),
            Some("   "),
            Some("abc"),
            Some("-1"),
            Some("4294967296"),
            Some("1.5"),
        ] {
            assert!(allow_uid_from(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn quota_flags_go_together_and_have_no_default() {
        assert_eq!(quota_flags(None, None), Ok(None));
        assert_eq!(quota_flags(Some("/s"), Some("/c")), Ok(Some(("/s", "/c"))));
        assert!(quota_flags(Some("/s"), None).is_err());
        assert!(quota_flags(None, Some("/c")).is_err());
    }

    #[test]
    fn the_uid_and_quota_refusals_name_no_value() {
        let secret = "/secret/path";
        let msg = quota_flags(Some(secret), None).unwrap_err();
        assert!(!msg.contains(secret));
    }

    /// Every value flag this binary reads through `arg()`. `--allow-bind` is a switch (`flag()`).
    const FLAGS: [&str; 14] = [
        "--allow-uid",
        "--anchor-node-id",
        "--expect-key-id",
        "--expect-wallet",
        "--insecure-kek-file",
        "--keystore",
        "--pgp-key",
        "--quota-config",
        "--quota-state",
        "--setup",
        "--socket",
        "--topup-config",
        "--topup-state",
        "--verifying-contract",
    ];

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_flag_takes_a_normal_value() {
        for f in FLAGS {
            assert_eq!(
                arg_in(&argv(&["bin", f, "v1"]), f),
                Some("v1".into()),
                "{f}"
            );
        }
    }

    #[test]
    fn every_flag_missing_from_argv_is_none() {
        for f in FLAGS {
            assert_eq!(arg_in(&argv(&["bin", "--other", "x"]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_at_the_end_has_no_value() {
        for f in FLAGS {
            assert_eq!(arg_in(&argv(&["bin", "--other", "x", f]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_followed_by_a_flag_takes_no_value_and_the_next_flag_still_parses() {
        for f in FLAGS {
            let next = if f == "--socket" {
                "--keystore"
            } else {
                "--socket"
            };
            let a = argv(&["bin", f, next, "/run/conet-signer/signer.sock"]);
            assert_eq!(arg_in(&a, f), None, "{f} took the next flag");
            assert_eq!(
                arg_in(&a, next),
                Some("/run/conet-signer/signer.sock".into()),
                "{next} after {f}"
            );
        }
    }

    #[test]
    fn a_single_dash_value_is_kept() {
        assert_eq!(
            arg_in(&argv(&["bin", "--allow-uid", "-1"]), "--allow-uid"),
            Some("-1".into())
        );
    }

    #[test]
    fn an_empty_value_is_kept_for_the_caller_to_judge() {
        assert_eq!(
            arg_in(&argv(&["bin", "--quota-state", ""]), "--quota-state"),
            Some(String::new())
        );
    }

    #[test]
    fn the_value_list_is_the_one_arg_reads() {
        assert_eq!(VALUE_FLAGS, FLAGS);
    }

    #[test]
    fn every_value_flag_without_a_value_refuses_to_start() {
        // (argv tail after the flag, why) -- each must return that flag's name.
        for f in FLAGS {
            // last in argv
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f])),
                Some(f),
                "{f} at end"
            );
            // followed by another flag
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f, "--socket", "/run/s.sock"])),
                Some(f),
                "{f} then flag"
            );
            // empty string
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f, ""])),
                Some(f),
                "{f} empty"
            );
            // whitespace only
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f, "   "])),
                Some(f),
                "{f} blank"
            );
            // a tab/newline-only value is blank too
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f, "\t\n"])),
                Some(f),
                "{f} tab"
            );
        }
    }

    #[test]
    fn every_value_flag_with_a_usable_value_starts() {
        for f in FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f, "v1"])),
                None,
                "{f}"
            );
            // a single-dash value is a value
            assert_eq!(
                valueless_flag(&argv(&["bin", "serve", f, "-1"])),
                None,
                "{f} -1"
            );
        }
    }

    #[test]
    fn an_absent_value_flag_is_unchanged_and_starts() {
        // The flag not appearing at all: no valueless refusal, and arg() reports it as absent.
        // --allow-uid is the exception: it is required, so its absence is refused by
        // allow_uid_from (see allow_uid_refuses_missing_empty_invalid_and_out_of_range_values).
        for f in FLAGS.into_iter().filter(|f| *f != "--allow-uid") {
            let a = argv(&["bin", "serve", "--other", "x"]);
            assert_eq!(valueless_flag(&a), None, "{f} absent");
            assert_eq!(arg_in(&a, f), None, "{f} absent");
        }
        let a = argv(&["bin", "serve", "--other", "x"]);
        assert_eq!(valueless_flag(&a), None);
        assert!(allow_uid_from(arg_in(&a, "--allow-uid").as_deref()).is_err());
    }

    #[test]
    fn a_switch_without_a_value_is_not_refused() {
        // --allow-bind is a switch read through flag(); it takes no value.
        assert_eq!(
            valueless_flag(&argv(&["bin", "serve", "--allow-bind"])),
            None
        );
    }

    #[test]
    fn the_refusal_names_the_flag_and_nothing_else() {
        // Only the static flag name comes back, so no configured value can appear in the message.
        let secret = "SECRET-PATH-XYZ";
        let got = valueless_flag(&argv(&[
            "bin",
            "serve",
            "--keystore",
            secret,
            "--quota-state",
        ]));
        assert_eq!(got, Some("--quota-state"));
        assert!(!got.unwrap().contains(secret));
    }
}

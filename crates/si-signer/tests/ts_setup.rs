//! `import-ts-setup`: the TS `nodeSetup.json` loader. Fixtures are TEST-ONLY files made with the
//! libraries CoNET-SI uses (`tests/fixtures/ts-setup/gen.cjs`: ethers 6 + openpgp.js 6).
use serde_json::{json, Value};
use si_signer::{keystore, ts_setup};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ts-setup")
        .join(name);
    std::fs::read(p).unwrap()
}

fn expected() -> Value {
    serde_json::from_slice(&fixture("expected.json")).unwrap()
}

fn small() -> (Vec<u8>, String, String, String) {
    let e = expected();
    (
        fixture("setup-small.json"),
        e["small"]["wallet"].as_str().unwrap().into(),
        e["small"]["keyId"].as_str().unwrap().into(),
        e["small"]["privateKeyHex"].as_str().unwrap().into(),
    )
}

fn edit(f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&fixture("setup-small.json")).unwrap();
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

fn keychain(v: &Value) -> Value {
    serde_json::from_str(v["keychain"].as_str().unwrap()).unwrap()
}

#[test]
fn a_ts_made_setup_imports_and_seals() {
    let (file, wallet, key_id, key_hex) = small();
    let got = ts_setup::import(&file, &wallet, &key_id).unwrap();
    assert!(got.wallet.eq_ignore_ascii_case(&wallet));
    assert_eq!(got.key_id, key_id);
    assert_eq!(
        got.secrets.wallet_hex.to_lowercase(),
        key_hex.to_lowercase()
    );
    // The sealed keystore opens again and carries the same public identity.
    let kek = [7u8; 32];
    let sealed = keystore::seal(&kek, &got.secrets).unwrap();
    assert!(sealed.contains(&key_id));
    let opened = keystore::open(&kek, &sealed).unwrap();
    assert_eq!(opened.wallet_hex, got.secrets.wallet_hex);
    assert_eq!(opened.pgp_pass, got.secrets.pgp_pass);
}

#[test]
fn the_default_ethers_cost_n_131072_imports() {
    // `Wallet.encrypt(password)` as CoNET-SI's cli.ts calls it: scrypt N=131072, r=8, p=1 (128 MiB).
    let e = expected();
    let file = fixture("setup-default.json");
    let got = ts_setup::import(
        &file,
        e["default"]["wallet"].as_str().unwrap(),
        e["default"]["keyId"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        got.secrets.wallet_hex.to_lowercase(),
        e["default"]["privateKeyHex"]
            .as_str()
            .unwrap()
            .to_lowercase()
    );
}

#[test]
fn keychain_may_be_an_object_or_a_string_and_crypto_may_be_capitalised() {
    let (_, wallet, key_id, _) = small();
    let as_object = edit(|v| {
        let k = keychain(v);
        v["keychain"] = k;
    });
    assert!(ts_setup::import(&as_object, &wallet, &key_id).is_ok());
    let lower = edit(|v| {
        let mut k = keychain(v);
        let c = k["Crypto"].take();
        k.as_object_mut().unwrap().remove("Crypto");
        k["crypto"] = c;
        v["keychain"] = Value::String(k.to_string());
    });
    assert!(ts_setup::import(&lower, &wallet, &key_id).is_ok());
}

#[test]
fn expected_values_are_checked_before_anything_is_sealed() {
    let (file, wallet, key_id, _) = small();
    let other_wallet = "0x0000000000000000000000000000000000000001";
    let e = ts_setup::import(&file, other_wallet, &key_id)
        .err()
        .unwrap();
    assert_eq!(e.0, "wallet_mismatch");
    let e = ts_setup::import(&file, &wallet, "0123456789ABCDEF")
        .err()
        .unwrap();
    assert_eq!(e.0, "key_id_mismatch");
    assert_eq!(
        ts_setup::import(&file, "0x12", &key_id).err().unwrap().0,
        "expect_wallet_format"
    );
    assert_eq!(
        ts_setup::import(&file, &wallet, "ABC").err().unwrap().0,
        "expect_key_id_format"
    );
    // The comparison ignores case, as the chain value may be checksummed or upper case.
    assert!(ts_setup::import(&file, &wallet.to_lowercase(), &key_id.to_lowercase()).is_ok());
}

#[test]
fn wrong_password_damaged_file_and_unsupported_keystores_are_refused() {
    let (_, wallet, key_id, _) = small();
    let code = |file: Vec<u8>| ts_setup::import(&file, &wallet, &key_id).err().unwrap().0;
    assert_eq!(
        code(edit(|v| v["passwd"] = json!("not the password"))),
        "keystore_password_or_mac"
    );
    assert_eq!(
        code(edit(|v| {
            let mut k = keychain(v);
            let ct = k["Crypto"]["ciphertext"].as_str().unwrap().to_string();
            let flipped = format!(
                "{}{}",
                if ct.starts_with('0') { "1" } else { "0" },
                &ct[1..]
            );
            k["Crypto"]["ciphertext"] = json!(flipped);
            v["keychain"] = Value::String(k.to_string());
        })),
        "keystore_password_or_mac"
    );
    let mutate = |f: fn(&mut Value)| {
        edit(|v| {
            let mut k = keychain(v);
            f(&mut k);
            v["keychain"] = Value::String(k.to_string());
        })
    };
    assert_eq!(
        code(mutate(|k| k["Crypto"]["kdf"] = json!("pbkdf2"))),
        "keystore_kdf"
    );
    assert_eq!(
        code(mutate(|k| k["Crypto"]["cipher"] = json!("aes-256-cbc"))),
        "keystore_cipher"
    );
    assert_eq!(
        code(mutate(|k| k["version"] = json!(1))),
        "keystore_version"
    );
    assert_eq!(
        code(mutate(|k| k["Crypto"]["kdfparams"]["n"] = json!(1u64 << 40))),
        "keystore_params"
    );
    assert_eq!(
        code(mutate(|k| k["Crypto"]["kdfparams"]["n"] = json!(1000))),
        "keystore_params"
    );
    assert_eq!(
        code(mutate(|k| k["Crypto"]["kdfparams"]["dklen"] = json!(64))),
        "keystore_params"
    );
    assert_eq!(
        code(mutate(|k| k["Crypto"]["cipherparams"]["iv"] = json!("00"))),
        "keystore_shape"
    );
    assert_eq!(
        code(mutate(
            |k| k["address"] = json!("0000000000000000000000000000000000000001")
        )),
        "keystore_address_mismatch"
    );
}

#[test]
fn pgp_problems_and_missing_fields_are_refused() {
    let (_, wallet, key_id, _) = small();
    let code = |file: Vec<u8>| ts_setup::import(&file, &wallet, &key_id).err().unwrap().0;
    assert_eq!(
        code(edit(|v| v["pgpKey"]["privateKey"] = json!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nnope\n-----END PGP PRIVATE KEY BLOCK-----"
        ))),
        "pgp_unlock"
    );
    assert_eq!(
        code(edit(|v| v["pgpKey"]["keyID"] = json!("0123456789ABCDEF"))),
        "declared_key_id_mismatch"
    );
    assert_eq!(
        code(edit(|v| {
            v.as_object_mut().unwrap().remove("passwd");
        })),
        "missing_passwd"
    );
    assert_eq!(
        code(edit(|v| {
            v.as_object_mut().unwrap().remove("keychain");
        })),
        "missing_keychain"
    );
    assert_eq!(
        code(edit(|v| {
            v.as_object_mut().unwrap().remove("pgpKey");
        })),
        "missing_pgpkey"
    );
    assert_eq!(code(edit(|v| v["keychain"] = json!(5))), "keychain_type");
    assert_eq!(
        code(edit(|v| v["keychain"] = json!("{not json"))),
        "keychain_not_json"
    );
    assert_eq!(code(b"not json".to_vec()), "not_json");
    assert_eq!(
        code(vec![b' '; ts_setup::MAX_SETUP_BYTES + 1]),
        "file_too_large"
    );
}

#[test]
fn no_refusal_text_contains_a_secret() {
    let (_, wallet, key_id, key_hex) = small();
    let e = expected();
    let password = e["password"].as_str().unwrap();
    let setup: Value = serde_json::from_slice(&fixture("setup-small.json")).unwrap();
    let armored = setup["pgpKey"]["privateKey"].as_str().unwrap().to_string();
    let mut texts = vec![];
    for f in [
        edit(|v| v["passwd"] = json!("wrong")),
        edit(|v| v["pgpKey"]["privateKey"] = json!("junk")),
        edit(|v| {
            v["keychain"] = json!("{broken");
        }),
    ] {
        texts.push(
            ts_setup::import(&f, &wallet, &key_id)
                .err()
                .unwrap()
                .to_string(),
        );
    }
    texts.push(
        ts_setup::import(
            &fixture("setup-small.json"),
            "0x0000000000000000000000000000000000000001",
            &key_id,
        )
        .err()
        .unwrap()
        .to_string(),
    );
    for t in texts {
        for secret in [password, key_hex.as_str(), &armored[40..80]] {
            assert!(!t.contains(secret), "{t}");
        }
        assert!(t.starts_with("ts-setup import refused: "), "{t}");
    }
}

// ---- the binary ----

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conet-signer"))
}

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], stdin_file: Option<&std::path::Path>) -> Run {
    let mut c = bin();
    c.args(args)
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = stdin_file {
        c.stdin(std::fs::File::open(p).unwrap());
    }
    let out = c.output().unwrap();
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into(),
        stderr: String::from_utf8_lossy(&out.stderr).into(),
    }
}

#[test]
fn the_binary_imports_prints_only_public_values_and_leaves_the_source_alone() {
    use std::os::unix::fs::PermissionsExt;
    let (file, wallet, key_id, key_hex) = small();
    let e = expected();
    let password = e["password"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let setup = dir.path().join("nodeSetup.json");
    std::fs::write(&setup, &file).unwrap();
    let before = (
        std::fs::metadata(&setup).unwrap().modified().unwrap(),
        std::fs::read(&setup).unwrap(),
    );
    let kek = dir.path().join("kek");
    std::fs::write(&kek, "11".repeat(32)).unwrap();
    let out = dir.path().join("keystore.json");
    let args = |extra: &[&'static str]| -> Vec<String> {
        let mut v: Vec<String> = [
            "import-ts-setup",
            "--insecure-kek-file",
            kek.to_str().unwrap(),
            "--keystore",
            out.to_str().unwrap(),
            "--setup",
            setup.to_str().unwrap(),
            "--expect-wallet",
            &wallet,
            "--expect-key-id",
            &key_id,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };
    let a = args(&[]);
    let r = run(&a.iter().map(String::as_str).collect::<Vec<_>>(), None);
    assert!(r.ok, "{}", r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{}", r.stdout);
    assert_eq!(lines[0], "keystore written");
    assert!(
        lines[1].starts_with("wallet: 0x")
            && lines[1]
                .to_lowercase()
                .ends_with(&wallet.to_lowercase()[2..])
    );
    assert_eq!(lines[2], format!("keyId: {key_id}"));
    for text in [&r.stdout, &r.stderr] {
        assert!(
            !text.contains(password)
                && !text.to_lowercase().contains(&key_hex.to_lowercase()[2..])
                && !text.contains("PRIVATE KEY")
        );
    }
    // The keystore is 0600, carries the public identity, and does not contain the password in clear.
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let ks = std::fs::read_to_string(&out).unwrap();
    assert!(ks.contains(&key_id) && !ks.contains(password));
    // The source file is untouched (content and mtime).
    assert_eq!(
        before,
        (
            std::fs::metadata(&setup).unwrap().modified().unwrap(),
            std::fs::read(&setup).unwrap()
        )
    );
    // A second run refuses to overwrite.
    let r = run(&a.iter().map(String::as_str).collect::<Vec<_>>(), None);
    assert!(
        !r.ok && r.stderr.contains("refusing to overwrite"),
        "{}",
        r.stderr
    );
}

#[test]
fn the_binary_reads_the_file_from_a_descriptor_and_refuses_a_wrong_identity() {
    let (file, wallet, key_id, _) = small();
    let dir = tempfile::tempdir().unwrap();
    let setup = dir.path().join("s.json");
    std::fs::write(&setup, &file).unwrap();
    let kek = dir.path().join("kek");
    std::fs::write(&kek, "22".repeat(32)).unwrap();
    // `--setup /dev/fd/0` with the file on stdin: no path to the file is needed.
    let out = dir.path().join("ks.json");
    let r = run(
        &[
            "import-ts-setup",
            "--insecure-kek-file",
            kek.to_str().unwrap(),
            "--keystore",
            out.to_str().unwrap(),
            "--setup",
            "/dev/fd/0",
            "--expect-wallet",
            &wallet,
            "--expect-key-id",
            &key_id,
        ],
        Some(&setup),
    );
    assert!(r.ok, "{}", r.stderr);
    // Wrong expected wallet: nothing is written and the error names no value.
    let out2 = dir.path().join("ks2.json");
    let r = run(
        &[
            "import-ts-setup",
            "--insecure-kek-file",
            kek.to_str().unwrap(),
            "--keystore",
            out2.to_str().unwrap(),
            "--setup",
            setup.to_str().unwrap(),
            "--expect-wallet",
            "0x0000000000000000000000000000000000000001",
            "--expect-key-id",
            &key_id,
        ],
        None,
    );
    assert!(
        !r.ok && r.stderr.contains("wallet_mismatch") && !out2.exists(),
        "{}",
        r.stderr
    );
    // Missing required flags fail closed.
    let r = run(
        &[
            "import-ts-setup",
            "--insecure-kek-file",
            kek.to_str().unwrap(),
            "--keystore",
            out2.to_str().unwrap(),
            "--setup",
            setup.to_str().unwrap(),
            "--expect-key-id",
            &key_id,
        ],
        None,
    );
    assert!(!r.ok && !out2.exists());
}

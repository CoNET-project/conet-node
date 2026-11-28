//! First start of a node: bring up the node identity exactly once, never replace one that exists.
//!
//! Two stages, both non-interactive (systemd runs them; nothing reads a terminal):
//!
//! - **Stage B, [`seal_stage`]** (`conet-signer first-start-seal`, runs as the signer account with
//!   the KEK credential): looks at the keystore path and then does exactly one of
//!   reuse the existing keystore, generate a new identity, or import a TS node's identity.
//!   Publication is atomic and never overwrites (see [`crate::atomic`]).
//! - **Stage A, [`stage_a`]** (`conet-signer first-start`, runs as root): validates the node's
//!   `init.json`, makes sure the KEK credential exists (`systemd-creds`), refuses when a TS node
//!   is present but the operator did not choose how to proceed, finds the TS `nodeSetup.json`
//!   through the original service account, and starts stage B through `systemd-run` in the same
//!   sandbox the README documents for the manual import.
//!
//! Rules that hold in both stages:
//! - A keystore that exists is never replaced: not when it is corrupt, truncated, unreadable, has
//!   the wrong mode, or the KEK does not open it. Those refuse with a fixed code.
//! - A missing KEK is never recreated while a keystore (or any entry at its path) exists.
//! - Nothing here prints a secret. Output is the public wallet address and the route encryption
//!   sub-key ID, the source, and fixed codes.
//! - Registration on chain is not part of this; the report says so.
//!
//! Fixed refusal codes (log and exit status carry the code and a field name only):
//! `KEYSTORE_PRESENT_KEK_MISSING` (70), `KEYSTORE_UNREADABLE` (71), `KEYSTORE_RESIDUE` (72),
//! `KEK_UNDECRYPTABLE` (73); every other refusal exits 74.
//! Operator exits are in `deploy/apt/README.md`; the program never does them by itself.
use crate::atomic::{self, Published};
use crate::init_config::{self, Identity, InitConfig, Mode, TsSource};
use crate::{kek, keystore, ts_setup};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// Name of the systemd credential that carries the TS `nodeSetup.json` into stage B.
pub const SETUP_CREDENTIAL: &str = "nodesetup";
/// Largest keystore file read.
const MAX_KEYSTORE_BYTES: u64 = 1 << 20;
/// A temporary file older than this belongs to no live writer.
pub const STALE_TEMP_AGE: Duration = Duration::from_secs(600);

#[derive(Debug, PartialEq, Eq)]
pub struct FirstStartError(pub String);

impl std::fmt::Display for FirstStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "first start refused: {}", self.0)
    }
}
impl std::error::Error for FirstStartError {}

impl FirstStartError {
    /// Process exit status for this refusal (see the module comment).
    pub fn exit_code(&self) -> i32 {
        let c = self.0.as_str();
        if c.starts_with("KEYSTORE_PRESENT_KEK_MISSING") {
            70
        } else if c.starts_with("KEYSTORE_UNREADABLE") {
            71
        } else if c.starts_with("KEYSTORE_RESIDUE") {
            72
        } else if c.starts_with("KEK_UNDECRYPTABLE") {
            73
        } else {
            74
        }
    }
}

fn refuse<T>(code: impl Into<String>) -> Result<T, FirstStartError> {
    Err(FirstStartError(code.into()))
}

fn unreadable(detail: &str) -> FirstStartError {
    FirstStartError(format!("KEYSTORE_UNREADABLE:{detail}"))
}
fn residue(detail: &str) -> FirstStartError {
    FirstStartError(format!("KEYSTORE_RESIDUE:{detail}"))
}
fn kek_bad(detail: &str) -> FirstStartError {
    FirstStartError(format!("KEK_UNDECRYPTABLE:{detail}"))
}

// ---------------------------------------------------------------------------------------------
// Stage B
// ---------------------------------------------------------------------------------------------

pub enum Create {
    /// Reuse only: no keystore means refuse (stage A saw one, so its absence is a surprise).
    Refuse,
    Generate,
    TsImport {
        setup: Zeroizing<Vec<u8>>,
        expect_wallet: String,
        expect_key_id: String,
    },
}

pub struct SealRequest<'a> {
    pub keystore: &'a Path,
    pub kek: &'a [u8; 32],
    pub create: Create,
    /// Public identity an existing keystore must carry (wallet, route key ID), when known.
    pub expect_existing: Option<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Existing,
    Generated,
    TsImport,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Existing => "existing",
            Source::Generated => "generated",
            Source::TsImport => "ts-import",
        }
    }
}

#[derive(Debug)]
pub struct Outcome {
    pub source: Source,
    pub wallet: String,
    pub key_id: String,
    /// Another first start published first; this run reused its keystore.
    pub lost_race: bool,
    pub stale_temps_removed: usize,
    /// A 0-byte keystore (residue of an interrupted older write; it cannot hold an identity) was
    /// renamed to this name, in the same directory, before the new identity was created.
    pub zero_byte_moved_to: Option<String>,
}

fn norm(a: &str) -> String {
    a.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}

fn dir_private(dir: &Path) -> Result<(), FirstStartError> {
    let md = std::fs::metadata(dir).map_err(|_| unreadable("state_dir_missing"))?;
    if !md.is_dir() {
        return Err(unreadable("state_dir_not_a_directory"));
    }
    if md.permissions().mode() & 0o077 != 0 {
        return Err(unreadable("state_dir_mode"));
    }
    Ok(())
}

/// The keystore at `path` must be a plain private file that the KEK opens and whose clear-text
/// label matches its content. Returns (wallet, route key ID).
pub fn verify_existing(
    path: &Path,
    kek: &[u8; 32],
    expect: Option<&(String, String)>,
) -> Result<(String, String), FirstStartError> {
    let md = std::fs::symlink_metadata(path).map_err(|_| unreadable("stat"))?;
    if !md.is_file() {
        return Err(unreadable("not_regular"));
    }
    if md.permissions().mode() & 0o077 != 0 {
        return Err(unreadable("mode"));
    }
    if md.len() > MAX_KEYSTORE_BYTES {
        return Err(residue("too_large"));
    }
    let bytes = std::fs::read(path).map_err(|_| unreadable("read"))?;
    let text = String::from_utf8(bytes).map_err(|_| residue("not_utf8"))?;
    // A truncated or garbled file (a non-empty residue) lands here: never treated as "no keystore".
    let (label_wallet, label_key_id) =
        keystore::public_identity(&text).map_err(|_| residue("not_a_keystore"))?;
    let secrets = keystore::open(kek, &text).map_err(|_| kek_bad("keystore_not_opened_by_kek"))?;
    let wallet = si_crypto::eth::EthKey::from_hex(&secrets.wallet_hex)
        .map_err(|_| residue("wallet_key_invalid"))?
        .address();
    let (_, key_id) = si_core::node::load_route(&secrets.pgp_armored, &secrets.pgp_pass)
        .map_err(|_| residue("route_key_invalid"))?;
    if norm(&wallet) != norm(&label_wallet) || !key_id.eq_ignore_ascii_case(&label_key_id) {
        return Err(residue("public_label_mismatch"));
    }
    if let Some((w, k)) = expect {
        if norm(&wallet) != norm(w) || !key_id.eq_ignore_ascii_case(k) {
            return refuse("existing_identity_differs_from_expected");
        }
    }
    Ok((wallet, key_id))
}

/// Exclusive lock on `<dir>/.<name>.lock` (flock: released by the kernel when the process ends,
/// so a crash never leaves a stale lock). Serializes first starts on one keystore path; the
/// no-overwrite link below stays as the second line of defense.
fn lock_for(path: &Path) -> Result<std::fs::File, FirstStartError> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| unreadable("path"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(format!(".{name}.lock")))
        .map_err(|_| unreadable("lock_open"))?;
    f.lock().map_err(|_| unreadable("lock"))?;
    Ok(f)
}

pub fn seal_stage(req: SealRequest<'_>) -> Result<Outcome, FirstStartError> {
    let SealRequest {
        keystore: path,
        kek,
        create,
        expect_existing,
    } = req;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    dir_private(dir)?;
    let _lock = lock_for(path)?;
    let dir_uid = std::fs::metadata(dir)
        .map_err(|_| unreadable("state_dir"))?
        .uid();
    let existing = |lost_race: bool,
                    stale: usize,
                    moved: Option<String>|
     -> Result<Outcome, FirstStartError> {
        let (wallet, key_id) = verify_existing(path, kek, expect_existing.as_ref())?;
        Ok(Outcome {
            source: Source::Existing,
            wallet,
            key_id,
            lost_race,
            stale_temps_removed: stale,
            zero_byte_moved_to: moved,
        })
    };
    let mut moved = None;
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_file() && md.len() == 0 && md.uid() == dir_uid => {
            // A 0-byte file cannot hold an identity, and the older writer printed nothing before
            // the write completed, so nothing was ever announced. It is renamed, not deleted, and
            // the new identity is created below. Non-empty residue is refused by `verify_existing`.
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("keystore");
            let aside = format!(
                "{name}.zero-byte.{}.{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                std::process::id()
            );
            std::fs::rename(path, dir.join(&aside)).map_err(|_| unreadable("zero_byte_move"))?;
            moved = Some(aside);
        }
        Ok(_) => {
            let stale = atomic::remove_stale_temps(path, STALE_TEMP_AGE);
            return existing(false, stale, None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unreadable("stat")),
    }
    // Nothing usable at the final path. Old temporary files are leftovers of attempts that never
    // published anything; they are cleared, never promoted.
    let stale = atomic::remove_stale_temps(path, STALE_TEMP_AGE);
    let (secrets, wallet, key_id, source) = match create {
        Create::Refuse => return refuse("keystore_missing"),
        Create::Generate => {
            let (secrets, public) =
                keystore::generate().map_err(|_| FirstStartError("generate_failed".into()))?;
            let wallet = si_crypto::eth::EthKey::from_hex(&secrets.wallet_hex)
                .map_err(|_| FirstStartError("generate_failed".into()))?
                .address();
            let key_id = si_crypto::opgp::PublicCert::from_armor(&public)
                .ok()
                .and_then(|c| c.enc_key_id())
                .ok_or_else(|| FirstStartError("generate_failed".into()))?;
            (secrets, wallet, key_id, Source::Generated)
        }
        Create::TsImport {
            setup,
            expect_wallet,
            expect_key_id,
        } => {
            let imported = ts_setup::import(&setup, &expect_wallet, &expect_key_id)
                .map_err(|e| FirstStartError(format!("ts_import_refused:{}", e.0)))?;
            // Before publishing: the public identity must be exactly the one the operator expects.
            if norm(&imported.wallet) != norm(&expect_wallet)
                || !imported.key_id.eq_ignore_ascii_case(&expect_key_id)
            {
                return refuse("ts_import_refused:expected_public_values");
            }
            (
                imported.secrets,
                imported.wallet,
                imported.key_id,
                Source::TsImport,
            )
        }
    };
    let sealed = Zeroizing::new(
        keystore::seal(kek, &secrets).map_err(|_| FirstStartError("seal_failed".into()))?,
    );
    match atomic::publish_new(path, sealed.as_bytes()) {
        Ok(Published::Created) => {
            // Read back what was published and compare, before anything is announced.
            let want = (wallet.clone(), key_id.clone());
            verify_existing(path, kek, Some(&want))
                .map_err(|_| residue("published_readback_mismatch"))?;
            Ok(Outcome {
                source,
                wallet,
                key_id,
                lost_race: false,
                stale_temps_removed: stale,
                zero_byte_moved_to: moved,
            })
        }
        // Another first start published first. Our new keys were never visible and are dropped;
        // the winner's keystore is the node identity.
        Ok(Published::Exists) => existing(true, stale, moved),
        Err(_) => refuse("keystore_write_failed"),
    }
}

// ---------------------------------------------------------------------------------------------
// Stage A
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Absent,
    /// A regular file with content (or any regular file, for the KEK).
    Present,
    /// A regular 0-byte keystore: stage B renames it aside; planning treats the node as fresh.
    ZeroByte,
}

fn keystore_state(path: &Path) -> Result<PathState, FirstStartError> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_file() && md.len() == 0 => Ok(PathState::ZeroByte),
        Ok(md) if md.is_file() => Ok(PathState::Present),
        Ok(_) => Err(unreadable("not_regular")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PathState::Absent),
        Err(_) => Err(unreadable("stat")),
    }
}

fn kek_state(path: &Path) -> Result<PathState, FirstStartError> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_file() => {
            // The credential is encrypted to this host; only write access by others is refused.
            if md.permissions().mode() & 0o022 != 0 {
                return Err(kek_bad("credential_mode"));
            }
            if md.len() == 0 {
                return Err(kek_bad("credential_empty"));
            }
            Ok(PathState::Present)
        }
        Ok(_) => Err(kek_bad("credential_not_regular")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PathState::Absent),
        Err(_) => Err(kek_bad("credential_unreadable")),
    }
}

/// Turns the 32 plaintext KEK bytes into the credential blob that gets stored.
pub type EncryptFn<'a> = &'a dyn Fn(&[u8; 32]) -> Result<Vec<u8>, FirstStartError>;

/// `systemd-creds encrypt --name=conet-node-kek - -` fed with `plain` on stdin; the credential
/// comes back on stdout. No plaintext touches the disk or argv, and no terminal is read.
pub fn encrypt_with_systemd_creds(
    creds_bin: &str,
    plain: &[u8; 32],
) -> Result<Vec<u8>, FirstStartError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(creds_bin)
        .args([
            "encrypt",
            &format!("--name={}", kek::CREDENTIAL_NAME),
            "-",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FirstStartError("kek_encrypt_unavailable".into()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| FirstStartError("kek_encrypt_failed".into()))?;
    let wrote = stdin.write_all(plain);
    drop(stdin);
    let out = child
        .wait_with_output()
        .map_err(|_| FirstStartError("kek_encrypt_failed".into()))?;
    if wrote.is_err() || !out.status.success() || out.stdout.is_empty() {
        return refuse("kek_encrypt_failed");
    }
    Ok(out.stdout)
}

/// Create the KEK credential if it is absent. Never while the keystore side is not absent too:
/// a new KEK next to an existing keystore would lock the node out of its own identity.
/// Returns whether this call created it. Two first starts racing: one credential is published, the
/// other is dropped, and both then use the published one (the caller re-reads the path).
pub fn ensure_kek(
    cred: &Path,
    ks: PathState,
    encrypt: EncryptFn<'_>,
) -> Result<bool, FirstStartError> {
    use rand_core::{OsRng, RngCore};
    match (kek_state(cred)?, ks) {
        (PathState::Present, _) => Ok(false),
        (PathState::Absent, PathState::Present) => {
            refuse("KEYSTORE_PRESENT_KEK_MISSING:credential_absent")
        }
        (PathState::Absent, _) => {
            if let Some(dir) = cred.parent() {
                use std::os::unix::fs::DirBuilderExt;
                match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                    Ok(()) => {}
                    // Another first start made it a moment ago.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
                    Err(_) => return refuse("kek_dir_create_failed"),
                }
            }
            let mut plain = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut plain[..]);
            let blob = encrypt(&plain)?;
            match atomic::publish_new(cred, &blob) {
                Ok(Published::Created) => Ok(true),
                // Lost the race: ours is dropped unused; the published one stands.
                Ok(Published::Exists) => {
                    kek_state(cred)?;
                    Ok(false)
                }
                Err(_) => refuse("kek_write_failed"),
            }
        }
        (PathState::ZeroByte, _) => unreachable!("kek_state never returns ZeroByte"),
    }
}

/// Where TS traces are looked for. Production values are the defaults; tests point elsewhere.
pub struct TsProbe<'a> {
    pub home_base: &'a Path,
    pub root_home: &'a Path,
    pub unit_dirs: &'a [PathBuf],
    pub proc_dir: &'a Path,
}

/// TS traces on this host. Any one of them means "a CoNET-SI (TS) node may live here":
/// a `.CoNET-SI` or `CoNET-SI` directory in any account's home (or root's), a `conet.service`
/// unit (or its enablement link), or a running process of the TS program.
/// Returns short descriptions (paths and pids only).
pub fn detect_ts(p: &TsProbe<'_>) -> Vec<String> {
    let mut found = Vec::new();
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(p.home_base) {
        homes.extend(rd.flatten().map(|e| e.path()));
    }
    homes.push(p.root_home.to_path_buf());
    for h in homes {
        for d in [".CoNET-SI", "CoNET-SI"] {
            let path = h.join(d);
            if std::fs::symlink_metadata(&path).is_ok() {
                found.push(format!("home_dir:{}", path.display()));
            }
        }
    }
    for u in p.unit_dirs {
        for rel in ["conet.service", "multi-user.target.wants/conet.service"] {
            let path = u.join(rel);
            if std::fs::symlink_metadata(&path).is_ok() {
                found.push(format!("unit:{}", path.display()));
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(p.proc_dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(pid) = name
                .to_str()
                .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
            else {
                continue;
            };
            let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else {
                continue;
            };
            let has = |needle: &[u8]| cmd.windows(needle.len()).any(|w| w == needle);
            if has(b"conet-mvp-si") || has(b"/CoNET-SI/") {
                found.push(format!("process:{pid}"));
            }
        }
    }
    found.sort();
    found
}

/// (uid, home) of `name` from a passwd-format file.
pub fn lookup_account(passwd: &Path, name: &str) -> Result<(u32, PathBuf), FirstStartError> {
    let text =
        std::fs::read_to_string(passwd).map_err(|_| FirstStartError("passwd_unreadable".into()))?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 6 && f[0] == name {
            let uid = f[2]
                .parse::<u32>()
                .map_err(|_| FirstStartError("ts_account_bad_entry".into()))?;
            if !f[5].starts_with('/') {
                return refuse("ts_account_bad_entry");
            }
            return Ok((uid, PathBuf::from(f[5])));
        }
    }
    refuse("ts_account_unknown")
}

/// The TS setup file must be a plain file, not writable by group or others, small, and (when the
/// service account is known) owned by it. Only read here; the caller never moves or edits it.
pub fn check_setup_file(path: &Path, owner_uid: Option<u32>) -> Result<(), FirstStartError> {
    let md = std::fs::symlink_metadata(path).map_err(|e| {
        FirstStartError(if e.kind() == std::io::ErrorKind::NotFound {
            "ts_setup_missing".into()
        } else {
            "ts_setup_unreadable".into()
        })
    })?;
    if !md.is_file() {
        return refuse("ts_setup_not_regular");
    }
    if md.permissions().mode() & 0o022 != 0 {
        return refuse("ts_setup_writable_by_others");
    }
    if md.len() > ts_setup::MAX_SETUP_BYTES as u64 {
        return refuse("ts_setup_too_large");
    }
    if let Some(uid) = owner_uid {
        if md.uid() != uid {
            return refuse("ts_setup_wrong_owner");
        }
    }
    Ok(())
}

pub struct StageA<'a> {
    pub init_config: &'a Path,
    pub keystore: &'a Path,
    pub kek_credential: &'a Path,
    /// This binary, run again as stage B.
    pub exe: &'a Path,
    pub systemd_run: &'a str,
    pub systemd_creds: &'a str,
    pub ts_home_base: &'a Path,
    pub ts_root_home: &'a Path,
    pub ts_unit_dirs: &'a [PathBuf],
    pub proc_dir: &'a Path,
    pub passwd: &'a Path,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// A keystore exists: light check passed; the signer opens it when it starts.
    Light { wallet: String, key_id: String },
    /// Run stage B. `create` is `refuse`, `generate` or `ts-import`.
    Seal {
        create: &'static str,
        setup_path: Option<PathBuf>,
    },
}

/// What stage A decided; stage B (when needed) is started from this.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub action: Action,
    pub expect: Option<(String, String)>,
    pub kek_created: bool,
    pub legacy_ignored: Vec<&'static str>,
    /// New identity on a host with TS traces, confirmed by the operator: report loudly.
    pub new_identity_on_ts_host: Vec<String>,
}

fn expect_of(id: &Identity) -> Option<(String, String)> {
    match (&id.expect_wallet, &id.expect_key_id) {
        (Some(w), Some(k)) => Some((w.clone(), k.clone())),
        _ => None,
    }
}

/// The light check for a keystore that exists: type, owner (the signer account when the passwd
/// file knows it), mode, size, and the clear-text public label. It never opens the keystore.
fn light_check(
    a: &StageA<'_>,
    expect: Option<&(String, String)>,
) -> Result<(String, String), FirstStartError> {
    let md = std::fs::symlink_metadata(a.keystore).map_err(|_| unreadable("stat"))?;
    if !md.is_file() {
        return Err(unreadable("not_regular"));
    }
    if md.permissions().mode() & 0o077 != 0 {
        return Err(unreadable("mode"));
    }
    if let Ok((uid, _)) = lookup_account(a.passwd, "conet-signer") {
        if md.uid() != uid {
            return Err(unreadable("owner"));
        }
    }
    if md.len() > MAX_KEYSTORE_BYTES {
        return Err(residue("too_large"));
    }
    let bytes = std::fs::read(a.keystore).map_err(|_| unreadable("read"))?;
    let text = String::from_utf8(bytes).map_err(|_| residue("not_utf8"))?;
    let (wallet, key_id) =
        keystore::public_identity(&text).map_err(|_| residue("not_a_keystore"))?;
    if let Some((w, k)) = expect {
        if norm(&wallet) != norm(w) || !key_id.eq_ignore_ascii_case(k) {
            return refuse("existing_identity_differs_from_expected");
        }
    }
    Ok((wallet, key_id))
}

/// All checks and the KEK step of stage A, without starting stage B.
pub fn plan(a: &StageA<'_>, encrypt: EncryptFn<'_>) -> Result<Plan, FirstStartError> {
    let cfg: InitConfig = init_config::load(a.init_config)
        .map_err(|e| FirstStartError(format!("init_config:{}", e.0)))?
        .unwrap_or_default();
    let ks = keystore_state(a.keystore)?;
    let expect = expect_of(&cfg.identity);
    if ks == PathState::Present {
        // Light path: nothing is generated, imported or started. Same checks on every boot.
        let (wallet, key_id) = light_check(a, expect.as_ref())?;
        let kek_created = ensure_kek(a.kek_credential, ks, encrypt)?;
        return Ok(Plan {
            action: Action::Light { wallet, key_id },
            expect,
            kek_created,
            legacy_ignored: cfg.legacy_ignored,
            new_identity_on_ts_host: vec![],
        });
    }
    let traces = detect_ts(&TsProbe {
        home_base: a.ts_home_base,
        root_home: a.ts_root_home,
        unit_dirs: a.ts_unit_dirs,
        proc_dir: a.proc_dir,
    });
    let mut new_on_ts = vec![];
    let (create, setup_path) = match cfg.identity.mode {
        Mode::Auto => {
            if !traces.is_empty() {
                return refuse(format!("ts_node_detected:{}", summarize(&traces)));
            }
            ("generate", None)
        }
        Mode::Generate => {
            if !traces.is_empty() {
                if !cfg.identity.confirm_generate_on_ts_host {
                    return refuse(format!(
                        "ts_traces_need_confirm_generate_on_ts_host:{}",
                        summarize(&traces)
                    ));
                }
                new_on_ts = traces;
            }
            ("generate", None)
        }
        Mode::TsImport => {
            let (path, uid) = match &cfg.identity.source {
                Some(TsSource::Account(name)) => {
                    let (uid, home) = lookup_account(a.passwd, name)?;
                    (home.join(".CoNET-SI").join("nodeSetup.json"), Some(uid))
                }
                Some(TsSource::Path(p)) => (p.clone(), None),
                None => return refuse("ts_source_missing"),
            };
            check_setup_file(&path, uid)?;
            ("ts-import", Some(path))
        }
    };
    // The KEK last, so a refusal above never leaves a new KEK behind.
    let kek_created = ensure_kek(a.kek_credential, ks, encrypt)?;
    Ok(Plan {
        action: Action::Seal { create, setup_path },
        expect,
        kek_created,
        legacy_ignored: cfg.legacy_ignored,
        new_identity_on_ts_host: new_on_ts,
    })
}

fn summarize(traces: &[String]) -> String {
    let mut v: Vec<&str> = traces.iter().take(6).map(String::as_str).collect();
    if traces.len() > 6 {
        v.push("...");
    }
    v.join(",")
}

/// The `systemd-run` argument vector for stage B (no shell; every value is its own element).
pub fn systemd_run_args(
    a: &StageA<'_>,
    create: &str,
    setup: Option<&Path>,
    expect: Option<&(String, String)>,
) -> Vec<String> {
    let s = |x: &str| x.to_string();
    let mut v = vec![
        s("--wait"),
        s("--pipe"),
        s("--collect"),
        s("--quiet"),
        s("--unit=conet-node-first-start-seal"),
    ];
    for p in [
        "User=conet-signer",
        "ProtectSystem=strict",
        "StateDirectory=conet-signer",
        "StateDirectoryMode=0700",
        "PrivateNetwork=yes",
        "LimitCORE=0",
        "NoNewPrivileges=yes",
        "RuntimeMaxSec=120",
    ] {
        v.push(s("-p"));
        v.push(s(p));
    }
    v.push(s("-p"));
    v.push(format!(
        "LoadCredentialEncrypted={}:{}",
        kek::CREDENTIAL_NAME,
        a.kek_credential.display()
    ));
    if let Some(p) = setup {
        v.push(s("-p"));
        v.push(format!("LoadCredential={SETUP_CREDENTIAL}:{}", p.display()));
    }
    v.push(a.exe.display().to_string());
    v.push(s("first-start-seal"));
    v.push(s("--keystore"));
    v.push(a.keystore.display().to_string());
    v.push(s("--create"));
    v.push(s(create));
    if let Some((w, k)) = expect {
        v.push(s("--expect-wallet"));
        v.push(w.clone());
        v.push(s("--expect-key-id"));
        v.push(k.clone());
    }
    v
}

/// Stage A end to end. Prints the report lines stage B does not know about.
pub fn stage_a(a: &StageA<'_>) -> Result<(), FirstStartError> {
    let creds = a.systemd_creds.to_string();
    let p = plan(a, &|plain| encrypt_with_systemd_creds(&creds, plain))?;
    if p.kek_created {
        println!("kek: created");
        println!(
            "kek note: back up /etc/credstore.encrypted/{} together with this host's systemd credential key (or TPM state); the credential alone cannot be opened on another host",
            kek::CREDENTIAL_NAME
        );
    } else {
        println!("kek: present");
    }
    if !p.new_identity_on_ts_host.is_empty() {
        println!(
            "WARNING: NEW IDENTITY CREATED ON A HOST WITH CoNET-SI (TS) TRACES ({}); the TS node identity is NOT reused",
            summarize(&p.new_identity_on_ts_host)
        );
    }
    match &p.action {
        Action::Light { wallet, key_id } => {
            println!("source: existing\nwallet: {wallet}\nkeyId: {key_id}");
            println!(
                "check: light (type, owner, mode, label); the signer opens the keystore at start"
            );
        }
        Action::Seal { create, setup_path } => {
            let status = std::process::Command::new(a.systemd_run)
                .args(systemd_run_args(
                    a,
                    create,
                    setup_path.as_deref(),
                    p.expect.as_ref(),
                ))
                .stdin(std::process::Stdio::null())
                .status()
                .map_err(|_| FirstStartError("systemd_run_unavailable".into()))?;
            if !status.success() {
                // The stage's own refusal code is on stderr; its status becomes ours.
                let name = match status.code() {
                    Some(70) => "KEYSTORE_PRESENT_KEK_MISSING",
                    Some(71) => "KEYSTORE_UNREADABLE",
                    Some(72) => "KEYSTORE_RESIDUE",
                    Some(73) => "KEK_UNDECRYPTABLE",
                    _ => "seal_stage_failed",
                };
                return refuse(format!("{name}:from_seal_stage"));
            }
        }
    }
    for f in &p.legacy_ignored {
        println!("ignored: {f} (no Rust consumer)");
    }
    if let Ok(n) = std::thread::available_parallelism() {
        println!("cpus: {n}");
    }
    println!("registration: not performed");
    Ok(())
}

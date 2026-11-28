//! Migration of the TS node's offline mailbox files into the Rust store (cutover) and back (rollback).
//!
//! TS (CoNET-SI 215afb18, util.ts `saveLocal`, `tryGetLocal`, `removeLocalByArmorHash`) keeps, per user key, `~/.data/<KEYID>.json` (messages not yet sent) and
//! `<KEYID>.inflight.json` (sent, not yet acknowledged): arrays of PGP armor strings written with `JSON.stringify(list, null, 2)`; a listen merges inflight first, then the
//! new file, without duplicates; the owner's ACK deletes by `keccak256(armor)`. The Rust store is a redb file and knows nothing of those files, so without this module
//! every message still unacknowledged at the cutover would stay on the disk and be invisible to the mailbox owner, and every message Rust accepted would be invisible to TS
//! after a rollback.
//!
//! Import (TS stopped, Rust not started): each message is taken over in one write transaction together with a ledger entry; the run is idempotent, crash-safe (a rerun
//! continues), never brings back a message the owner acknowledged, never writes to the source, and counts but never prints message text.
//! Export (Rust stopped, TS not started): per key the TS files are rewritten so that TS serves the Rust node's pending messages (acknowledged ones are gone, new ones are
//! present) plus any TS message the Rust store has never seen; originals are kept as `*.rollback-bak`; an unreadable file is never overwritten.
use crate::store::{armor_hash, DiskStore, ImportOutcome, MailboxStore, Stored};
use serde::de::{SeqAccess, Visitor};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::fs;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum MigrateError {
    Dir(std::io::Error),
    Store(redb::Error),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Dir(e) => write!(f, "TS data directory: {e}"),
            MigrateError::Store(e) => write!(f, "mailbox store: {e}"),
        }
    }
}

impl std::error::Error for MigrateError {}

/// Counts only. Never a file name, key or message text.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportReport {
    /// Mailbox files that parsed.
    pub files: usize,
    /// Keys with at least one parsed file.
    pub keys: usize,
    /// Messages read from parsed files.
    pub read: usize,
    pub imported: usize,
    pub already_present: usize,
    pub already_imported: usize,
    /// Files that did not parse (nothing of them was imported).
    pub failed_files: usize,
    /// Array elements that were not strings (TS ignores them too).
    pub skipped_non_string: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub keys: usize,
    /// Keys whose TS files were rewritten or removed.
    pub written: usize,
    pub unchanged: usize,
    /// Keys left alone because a TS file of theirs did not parse.
    pub failed_keys: usize,
    /// Store keys that are not 16 upper-case hex characters (TS never names a file so): not exported.
    pub skipped_keys: usize,
}

/// `<16 upper-case hex>.json` or `<16 upper-case hex>.inflight.json`: what TS `saveLocal` writes (`clentKeyID` upper-cased).
fn parse_name(name: &str) -> Option<(String, bool)> {
    let (stem, inflight) = match name.strip_suffix(".inflight.json") {
        Some(s) => (s, true),
        None => (name.strip_suffix(".json")?, false),
    };
    (stem.len() == 16
        && stem
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)))
    .then(|| (stem.to_string(), inflight))
}

struct Each<'a> {
    f: &'a mut dyn FnMut(String),
    non_string: usize,
}

impl<'de> Visitor<'de> for Each<'_> {
    type Value = usize;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array")
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<usize, A::Error> {
        while let Some(v) = seq.next_element::<serde_json::Value>()? {
            match v {
                serde_json::Value::String(s) => (self.f)(s),
                _ => self.non_string += 1,
            }
        }
        Ok(self.non_string)
    }
}

/// Streams the strings of a TS array file to `f` (nothing is collected). Returns the number of non-string elements, or an error if the file is not a complete JSON array.
fn read_array(path: &Path, f: &mut dyn FnMut(String)) -> Result<usize, String> {
    use serde::Deserializer;
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
    let non_string = (&mut de)
        .deserialize_seq(Each { f, non_string: 0 })
        .map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(non_string)
}

/// The mailbox files of a TS data directory, grouped by key: (inflight path, new-file path).
fn ts_files(
    dir: &Path,
) -> Result<BTreeMap<String, (Option<PathBuf>, Option<PathBuf>)>, MigrateError> {
    let mut out: BTreeMap<String, (Option<PathBuf>, Option<PathBuf>)> = BTreeMap::new();
    for e in fs::read_dir(dir).map_err(MigrateError::Dir)? {
        let e = e.map_err(MigrateError::Dir)?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some((key, inflight)) = parse_name(&name) else {
            continue;
        };
        if !e.file_type().map_err(MigrateError::Dir)?.is_file() {
            continue;
        }
        let slot = out.entry(key).or_default();
        if inflight {
            slot.0 = Some(e.path());
        } else {
            slot.1 = Some(e.path());
        }
    }
    Ok(out)
}

pub fn import_ts_dir(store: &DiskStore, dir: &Path) -> Result<ImportReport, MigrateError> {
    import_ts_dir_with(store, dir, &mut |_| {})
}

/// Like [`import_ts_dir`], calling `after_each` after every message that was processed (used by the crash tests).
pub fn import_ts_dir_with(
    store: &DiskStore,
    dir: &Path,
    after_each: &mut dyn FnMut(ImportOutcome),
) -> Result<ImportReport, MigrateError> {
    let mut rep = ImportReport::default();
    for (key, (inflight, json)) in ts_files(dir)? {
        let mut key_has_file = false;
        // TS merge order: the inflight file first, then the new file.
        for path in [inflight, json].into_iter().flatten() {
            // pass 1: the whole file must be a valid array before anything of it is imported
            let mut count = 0usize;
            let non_string = match read_array(&path, &mut |_| count += 1) {
                Ok(n) => n,
                Err(_) => {
                    rep.failed_files += 1;
                    continue;
                }
            };
            rep.files += 1;
            rep.skipped_non_string += non_string;
            key_has_file = true;
            // pass 2: import in order
            let mut failure: Option<redb::Error> = None;
            let r = read_array(&path, &mut |armor| {
                if failure.is_some() {
                    return;
                }
                rep.read += 1;
                match store.import_message(
                    &key,
                    Stored {
                        armor,
                        no_push: true,
                        hop_bytes: 0,
                        hops: 0,
                    },
                ) {
                    Ok(o) => {
                        match o {
                            ImportOutcome::Imported => rep.imported += 1,
                            ImportOutcome::AlreadyPresent => rep.already_present += 1,
                            ImportOutcome::AlreadyImported => rep.already_imported += 1,
                        }
                        after_each(o);
                    }
                    Err(e) => failure = Some(e),
                }
            });
            if let Some(e) = failure {
                return Err(MigrateError::Store(e));
            }
            if r.is_err() {
                // the file changed between the two passes: counted, not imported further
                rep.failed_files += 1;
            }
        }
        if key_has_file {
            rep.keys += 1;
        }
    }
    Ok(rep)
}

pub fn export_ts_dir(store: &DiskStore, dir: &Path) -> Result<ExportReport, MigrateError> {
    export_ts_dir_with(store, dir, &mut |_| {})
}

/// The TS files of one key read the way TS `tryGetLocal` merges them (inflight first, no duplicates). Err when a file exists and does not parse.
fn read_ts_merged(inflight: &Option<PathBuf>, json: &Option<PathBuf>) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    for path in [inflight, json].into_iter().flatten() {
        read_array(path, &mut |a| {
            if seen.insert(a.clone()) {
                out.push(a);
            }
        })
        .map_err(|_| ())?;
    }
    Ok(out)
}

fn backup_once(path: &Path) -> std::io::Result<()> {
    let mut bak = path.as_os_str().to_owned();
    bak.push(".rollback-bak");
    let bak = PathBuf::from(bak);
    if path.exists() && !bak.exists() {
        fs::copy(path, &bak)?;
    }
    Ok(())
}

/// Writes `list` as the TS file `final_path` atomically (temporary file in the same directory, fsync, rename, fsync of the directory), keeping the owner and mode of the
/// file it replaces (or of the directory).
fn write_atomic(final_path: &Path, list: &[String], dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let tmp = final_path.with_extension(format!("json.tmp-{}", std::process::id()));
    let text = serde_json::to_string_pretty(list).expect("json");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    let model = fs::metadata(final_path).or_else(|_| fs::metadata(dir))?;
    let _ = fs::set_permissions(&tmp, model.permissions());
    let _ = std::os::unix::fs::chown(&tmp, Some(model.uid()), Some(model.gid()));
    fs::rename(&tmp, final_path)?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Like [`export_ts_dir`], calling `after_each` with the key after each key was handled (used by the crash tests).
pub fn export_ts_dir_with(
    store: &DiskStore,
    dir: &Path,
    after_each: &mut dyn FnMut(&str),
) -> Result<ExportReport, MigrateError> {
    let mut rep = ExportReport::default();
    let files = ts_files(dir)?;
    let mut keys: BTreeSet<String> = files.keys().cloned().collect();
    for k in store.mailbox_keys().map_err(MigrateError::Store)? {
        if parse_name(&format!("{k}.json")).is_some() {
            keys.insert(k);
        } else {
            rep.skipped_keys += 1;
        }
    }
    for key in keys {
        rep.keys += 1;
        let (inflight, json) = files.get(&key).cloned().unwrap_or((None, None));
        let Ok(ts_items) = read_ts_merged(&inflight, &json) else {
            rep.failed_keys += 1;
            continue;
        };
        let rust: Vec<String> = store.pending(&key).into_iter().map(|i| i.armor).collect();
        let imported = store
            .ts_imported_hashes(&key)
            .map_err(MigrateError::Store)?;
        let in_rust: HashSet<&String> = rust.iter().collect();
        let extras: Vec<String> = ts_items
            .iter()
            .filter(|a| !in_rust.contains(a) && !imported.contains(&armor_hash(a)))
            .cloned()
            .collect();
        let result: Vec<String> = rust.iter().cloned().chain(extras).collect();
        let json_path = dir.join(format!("{key}.json"));
        let inflight_path = dir.join(format!("{key}.inflight.json"));
        let unchanged = if result.is_empty() {
            inflight.is_none() && json.is_none()
        } else {
            inflight.is_none() && json.is_some() && ts_items == result
        };
        if unchanged {
            rep.unchanged += 1;
        } else {
            let io = |e: std::io::Error| MigrateError::Dir(e);
            if let Some(p) = &json {
                backup_once(p).map_err(io)?;
            }
            if let Some(p) = &inflight {
                backup_once(p).map_err(io)?;
            }
            if result.is_empty() {
                if json.is_some() {
                    fs::remove_file(&json_path).map_err(io)?;
                }
            } else {
                write_atomic(&json_path, &result, dir).map_err(io)?;
            }
            if inflight.is_some() {
                fs::remove_file(&inflight_path).map_err(io)?;
            }
            rep.written += 1;
        }
        after_each(&key);
    }
    Ok(rep)
}

/// Aggregate view of a mailbox for the reconciliation of a cutover or a rollback. **The TS side and the store side are equal only right after the import has finished and before
/// the Rust node has received any new message** (afterwards the store holds more, or fewer after an acknowledgement, by design): how many keys and messages, and one SHA-256 over the sorted lines `KEY:armorhash`
/// (each distinct pair once). The seal compares two of these (the TS files and the Rust store); neither the keys nor the hashes leave the tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub keys: usize,
    pub messages: usize,
    pub sha256: String,
}

fn digest_of(pairs: BTreeSet<(String, String)>) -> Digest {
    use sha2::{Digest as _, Sha256};
    let keys = pairs.iter().map(|(k, _)| k).collect::<BTreeSet<_>>().len();
    let mut h = Sha256::new();
    for (k, a) in &pairs {
        h.update(format!("{k}:{a}\n").as_bytes());
    }
    Digest {
        keys,
        messages: pairs.len(),
        sha256: hex::encode(h.finalize()),
    }
}

/// The digest of the TS files: per key the inflight and the new file merged without duplicates (as TS merges them). A file that does not parse is an error, never a smaller digest.
pub fn ts_dir_digest(dir: &Path) -> Result<Digest, MigrateError> {
    let mut pairs = BTreeSet::new();
    for (key, (inflight, json)) in ts_files(dir)? {
        for path in [inflight, json].into_iter().flatten() {
            read_array(&path, &mut |a| {
                pairs.insert((key.clone(), armor_hash(&a)));
            })
            .map_err(|_| {
                MigrateError::Dir(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a TS mailbox file does not parse",
                ))
            })?;
        }
    }
    Ok(digest_of(pairs))
}

/// The digest of the Rust store file, read through a READ-ONLY open (the reconciliation tool uses this one: no write transaction, nothing created or changed).
pub fn store_digest_at(path: &Path) -> Result<Digest, MigrateError> {
    Ok(digest_of(
        DiskStore::read_pairs_readonly(path).map_err(MigrateError::Store)?,
    ))
}

/// The digest of the Rust store: every pending message of every key.
pub fn store_digest(store: &DiskStore) -> Result<Digest, MigrateError> {
    let mut pairs = BTreeSet::new();
    for key in store.mailbox_keys().map_err(MigrateError::Store)? {
        for m in store.pending(&key) {
            pairs.insert((key.clone(), armor_hash(&m.armor)));
        }
    }
    Ok(digest_of(pairs))
}

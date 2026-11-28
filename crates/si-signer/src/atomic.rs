//! Write a private file so that its final path is either absent or complete.
//!
//! The old `write_private` did `create_new(final)` and then `write_all` / `sync_all`: a process
//! that died in between left a 0-byte or truncated file at the final path, and the next run saw
//! "already exists". Here the bytes go to a unique temporary file in the same directory (mode 0600,
//! `create_new`), are synced, and are then published:
//!
//! - [`publish_new`] uses `link(2)`, which fails with `EEXIST` when the target exists: an atomic
//!   "never overwrite". Two writers racing for one path: at most one wins; the loser learns
//!   [`Published::Exists`] and must read the winner's file instead of replacing it.
//! - [`replace`] uses `rename(2)` (atomic replace) for files that are meant to be rewritten.
//!
//! An interruption can only leave a temporary file. It was never visible at the final path, so
//! nothing it holds was ever published. [`remove_stale_temps`] clears old ones.
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, PartialEq, Eq)]
pub enum Published {
    Created,
    /// The final path already existed; nothing was written there.
    Exists,
}

/// Prefix of the temporary files for `final_path`: `.<file name>.tmp.`.
fn temp_prefix(final_path: &Path) -> std::io::Result<String> {
    let name = final_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "path has no file name"))?;
    Ok(format!(".{name}.tmp."))
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn unique_temp(final_path: &Path) -> std::io::Result<PathBuf> {
    use rand_core::{OsRng, RngCore};
    let mut r = [0u8; 8];
    OsRng.fill_bytes(&mut r);
    Ok(parent_of(final_path).join(format!(
        "{}{}.{}",
        temp_prefix(final_path)?,
        std::process::id(),
        hex::encode(r)
    )))
}

/// Test-only fault points (feature `test-fault`, enabled for this crate's own tests through a
/// dev-dependency; absent from release builds). When `CONET_TEST_FAULT` names the point, the
/// process writes a marker file and then sleeps until the test kills it.
#[cfg(feature = "test-fault")]
fn fault(point: &str) {
    if std::env::var("CONET_TEST_FAULT").as_deref() == Ok(point) {
        if let Ok(m) = std::env::var("CONET_TEST_FAULT_MARKER") {
            let _ = std::fs::write(m, point);
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}
#[cfg(not(feature = "test-fault"))]
#[inline(always)]
fn fault(_point: &str) {}

type WriteFn<'a> = &'a dyn Fn(&mut std::fs::File, &[u8]) -> std::io::Result<()>;
type LinkFn<'a> = &'a dyn Fn(&Path, &Path) -> std::io::Result<()>;

fn real_write(f: &mut std::fs::File, data: &[u8]) -> std::io::Result<()> {
    f.write_all(data)
}

/// Create the temporary file (`create_new`, 0600, same directory as the target), write and sync
/// it. On any failure the file is removed.
fn write_temp(final_path: &Path, data: &[u8], write: WriteFn<'_>) -> std::io::Result<PathBuf> {
    let tmp = unique_temp(final_path)?;
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        write(&mut f, data)?;
        f.sync_all()
    })();
    match result {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Publish `data` at `path` only if nothing is there. Order: write temporary file, `sync_all`,
/// `link`, fsync the directory; only then does this return `Created`, so a caller that prints the
/// public identity afterwards never announces something a power cut could still take back.
/// A `link` failure other than `EEXIST` (no hard-link support, no space for the entry, ...) is an
/// error: there is no fallback to `rename` or copy, because those would overwrite.
pub fn publish_new(path: &Path, data: &[u8]) -> std::io::Result<Published> {
    publish_new_with(path, data, &real_write, &|a, b| std::fs::hard_link(a, b))
}

/// [`publish_new`] with the write and link steps injectable, for fault-injection tests.
pub fn publish_new_with(
    path: &Path,
    data: &[u8],
    write: WriteFn<'_>,
    link: LinkFn<'_>,
) -> std::io::Result<Published> {
    let tmp = write_temp(path, data, write)?;
    fault("before_link");
    let linked = link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            fault("after_link");
            sync_dir(parent_of(path))?;
            Ok(Published::Created)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(Published::Exists),
        Err(e) => Err(e),
    }
}

/// Atomically replace (or create) `path`: a reader sees the old or the new file, never a mix.
pub fn replace(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = write_temp(path, data, &real_write)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(parent_of(path))
}

/// True for `.<name>.tmp.<pid digits>.<16 lowercase hex>`, the exact names [`unique_temp`] makes.
fn is_temp_name(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some((pid, rnd)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && rnd.len() == 16
        && rnd.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Remove temporary files of `final_path` that are narrowly ours and old: exact temporary name
/// pattern, `lstat` says plain file (symlinks are never followed), owned by the owner of the state
/// directory (the signer account), at least `max_age` old (a live writer finishes in
/// milliseconds). An operator's `keystore.json.bak` or anything else is never touched. Returns how
/// many were removed.
pub fn remove_stale_temps(final_path: &Path, max_age: Duration) -> usize {
    use std::os::unix::fs::MetadataExt;
    let Ok(prefix) = temp_prefix(final_path) else {
        return 0;
    };
    let dir = parent_of(final_path);
    let Ok(dir_uid) = std::fs::metadata(dir).map(|m| m.uid()) else {
        return 0;
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_temp_name(name, &prefix) {
            continue;
        }
        let Ok(md) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !md.is_file() || md.uid() != dir_uid {
            continue;
        }
        let old = md
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= max_age);
        if old && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Number of temporary files of `final_path` present (any age). For reports and tests.
pub fn count_temps(final_path: &Path) -> usize {
    let Ok(prefix) = temp_prefix(final_path) else {
        return 0;
    };
    std::fs::read_dir(parent_of(final_path))
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with(&prefix))
                })
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn publish_new_creates_0600_and_leaves_no_temp() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        assert_eq!(publish_new(&p, b"one").unwrap(), Published::Created);
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(count_temps(&p), 0);
    }

    #[test]
    fn publish_new_never_overwrites_and_leaves_the_old_bytes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        publish_new(&p, b"first").unwrap();
        assert_eq!(publish_new(&p, b"second").unwrap(), Published::Exists);
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        assert_eq!(count_temps(&p), 0);
    }

    #[test]
    fn publish_new_keeps_a_zero_byte_or_partial_final_untouched() {
        // Residue of the old writer: the final path exists but is incomplete.
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        std::fs::write(&p, b"").unwrap();
        assert_eq!(publish_new(&p, b"x").unwrap(), Published::Exists);
        assert_eq!(std::fs::read(&p).unwrap(), b"");
    }

    #[test]
    fn replace_swaps_atomically() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        replace(&p, b"a").unwrap();
        replace(&p, b"b").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"b");
        assert_eq!(count_temps(&p), 0);
    }

    #[test]
    fn stale_temps_go_young_ones_and_foreign_files_stay() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        let old = d.path().join(".ks.json.tmp.1.00000000000000aa");
        let young = d.path().join(".ks.json.tmp.2.00000000000000bb");
        let other = d.path().join(".other.json.tmp.3.00000000000000cc");
        let bak = d.path().join("ks.json.bak");
        let odd = d.path().join(".ks.json.tmp.notapid.00000000000000dd");
        let link = d.path().join(".ks.json.tmp.4.00000000000000ee");
        std::os::unix::fs::symlink(&bak, &link).unwrap();
        for f in [&old, &young, &other, &bak, &odd] {
            std::fs::write(f, b"half").unwrap();
        }
        let f = std::fs::File::options().write(true).open(&old).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        assert_eq!(remove_stale_temps(&p, Duration::from_secs(600)), 1);
        assert!(!old.exists() && young.exists() && other.exists());
        // Narrow: an operator's backup, a name off the pattern and a symlink are never touched.
        assert!(bak.exists() && odd.exists());
        assert!(std::fs::symlink_metadata(&link).is_ok());
    }

    #[test]
    fn a_failed_write_leaves_no_temp() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("no-such-dir").join("ks.json");
        assert!(publish_new(&p, b"x").is_err());
        assert_eq!(count_temps(&p), 0);
    }

    #[test]
    fn a_full_volume_leaves_no_temp_and_no_final() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        let half = |f: &mut std::fs::File, data: &[u8]| -> std::io::Result<()> {
            f.write_all(&data[..data.len() / 2])?;
            Err(std::io::Error::from_raw_os_error(28)) // ENOSPC
        };
        let e = publish_new_with(&p, b"0123456789", &half, &|a, b| std::fs::hard_link(a, b))
            .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(28));
        assert!(!p.exists());
        assert_eq!(count_temps(&p), 0);
    }

    #[test]
    fn a_link_failure_other_than_eexist_fails_closed_without_fallback() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        for errno in [1, 95, 28, 18] {
            // EPERM, EOPNOTSUPP, ENOSPC, EXDEV
            let e = publish_new_with(&p, b"x", &real_write, &|_, _| {
                Err(std::io::Error::from_raw_os_error(errno))
            })
            .unwrap_err();
            assert_eq!(e.raw_os_error(), Some(errno));
            assert!(!p.exists(), "errno {errno} fell back to a copy or rename");
            assert_eq!(count_temps(&p), 0);
        }
    }

    #[test]
    fn a_link_failure_never_touches_an_existing_final() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ks.json");
        std::fs::write(&p, b"keep").unwrap();
        let _ = publish_new_with(&p, b"x", &real_write, &|_, _| {
            Err(std::io::Error::from_raw_os_error(1))
        });
        assert_eq!(std::fs::read(&p).unwrap(), b"keep");
    }
}

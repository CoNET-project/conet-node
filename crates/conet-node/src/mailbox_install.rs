//! Whether this host may create the mailbox database. The node never does. This step runs before it (unit `ExecStartPre`) and creates one only on a new installation.
//! "Already installed" is decided by two records that are not the database: the marker this step writes (it names the database path), and the record the package leaves
//! when it is configured over an earlier version. With either of them, a missing or empty database is refused and left for the operator.
use crate::store::DiskStore;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prepared {
    /// Marker and database are both there.
    Present,
    /// A database from before the marker existed; the marker is written, the database is kept.
    Adopted,
    /// A new installation: the database and the marker were created.
    Created,
}

pub fn prepare(
    db: &Path,
    marker: &Path,
    upgrade_record: Option<&Path>,
) -> Result<Prepared, String> {
    let open = || {
        DiskStore::open_installed(db)
            .map(drop)
            .map_err(|e| e.to_string())
    };
    let name = db
        .to_str()
        .ok_or("the mailbox database path is not UTF-8")?;
    match std::fs::read_to_string(marker) {
        Ok(recorded) => {
            if recorded.trim_end_matches('\n') != name {
                return Err("the installation marker names another mailbox database path; nothing was created or changed".into());
            }
            open()?;
            return Ok(Prepared::Present);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("the installation marker cannot be read: {e}")),
    }
    if exists(db)? {
        open()?;
        write_marker(marker, name)?;
        return Ok(Prepared::Adopted);
    }
    if let Some(record) = upgrade_record {
        if exists(record)? {
            return Err("an earlier version of the package was installed on this host and its mailbox database is missing; a new one is not created (see the package README)".into());
        }
    }
    DiskStore::open(db).map(drop).map_err(|e| e.to_string())?;
    write_marker(marker, name)?;
    Ok(Prepared::Created)
}

/// "Cannot tell" is an error, never "not there".
fn exists(p: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!(
            "a path of the installation check cannot be examined: {e}"
        )),
    }
}

fn write_marker(marker: &Path, db: &str) -> Result<(), String> {
    let io = |e: std::io::Error| format!("the installation marker cannot be written: {e}");
    let dir = marker
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("the marker path has no directory")?;
    let tmp = marker.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = std::fs::File::create(&tmp).map_err(io)?;
    writeln!(f, "{db}").map_err(io)?;
    f.sync_all().map_err(io)?;
    std::fs::rename(&tmp, marker).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io)
}

//! Durable record of signed NodeStatements, so a restart can never sign a second, different
//! statement for the same (epoch, kind). Written atomically (tmp + fsync + rename + dir fsync)
//! and authenticated with a KEK subkey, so a damaged or edited file is detected, not trusted.
use crate::subkey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use si_core::statement::StatementGuard;
use std::io::Write;
use std::path::Path;

const LABEL: &str = "conet-node statement state v1";

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Records {
    /// (kind, epoch, payloadHash hex)
    pub signed: Vec<(u8, u64, String)>,
    pub floor: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct File {
    records: Records,
    mac: String,
}

fn mac(kek: &[u8; 32], r: &Records) -> String {
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&subkey(kek, LABEL)).expect("hmac");
    m.update(serde_json::to_string(r).expect("records json").as_bytes());
    hex::encode(m.finalize().into_bytes())
}

#[derive(Debug, PartialEq)]
pub enum LoadError {
    /// No file: the operator must set a floor (`--reset-statement-floor`), never guess.
    Missing,
    Damaged,
}

pub fn load(path: &Path, kek: &[u8; 32]) -> Result<Records, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|_| LoadError::Missing)?;
    let f: File = serde_json::from_str(&text).map_err(|_| LoadError::Damaged)?;
    if f.mac != mac(kek, &f.records) {
        return Err(LoadError::Damaged);
    }
    Ok(f.records)
}

pub fn save(path: &Path, kek: &[u8; 32], r: &Records) -> std::io::Result<()> {
    let body = serde_json::to_string(&File {
        records: r.clone(),
        mac: mac(kek, r),
    })?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

pub fn guard_from(r: &Records) -> StatementGuard {
    let mut g = match r.floor {
        Some(f) => StatementGuard::after_state_loss(f.saturating_sub(1)),
        None => StatementGuard::default(),
    };
    for (k, e, p) in &r.signed {
        let mut w = [0u8; 32];
        if hex::decode_to_slice(p.trim_start_matches("0x"), &mut w).is_ok() {
            g.commit((*k, *e, w));
        }
    }
    g
}

impl Records {
    /// Keep only the newest record per kind (older ones can never be signed again anyway).
    pub fn push(&mut self, kind: u8, epoch: u64, payload: &[u8; 32]) {
        self.signed.retain(|(k, _, _)| *k != kind);
        self.signed.push((kind, epoch, hex::encode(payload)));
    }
}

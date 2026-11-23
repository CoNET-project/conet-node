//! Injectable authority lookup for signed `mining_validator` commands.
//!
//! This seam reads an already-built in-memory snapshot only; it has no RPC, HTTP, or API client.
//! A synchronous trait does not itself guarantee that an implementation avoids I/O, so future
//! implementations must preserve the snapshot-only contract. Snapshot publishers must update the
//! whole authority generation atomically and invalidate removed domains; otherwise a stale domain
//! could become trusted again.

use crate::route::NodeWalletLookup;
use std::collections::{hash_map::Entry, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorWalletSourceFailure;

/// Resolve a node domain against an authoritative in-memory snapshot.
///
/// This is synchronous but that alone does not prove implementations avoid I/O. This seam is
/// test-only and its implementations must read an in-memory snapshot. Any future production
/// integration must atomically publish authority generations and invalidate removed domains.
pub trait ValidatorWalletSource: Send + Sync {
    fn lookup(&self, domain: &str) -> Result<NodeWalletLookup, ValidatorWalletSourceFailure>;
}

/// Immutable synthetic snapshot for tests and explicit in-memory injection.
///
/// Present entries with `None` model a known domain whose wallet record is absent. A domain not
/// present in the snapshot is `UnknownDomain`; a source failure is represented by the trait's
/// `Err` and is never folded into either of those results.
#[derive(Debug, Clone, Default)]
pub struct InMemoryValidatorWalletSnapshot {
    entries: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotBuildError {
    EmptyDomain,
    DuplicateDomain,
}

impl InMemoryValidatorWalletSnapshot {
    pub fn try_new(
        entries: impl IntoIterator<Item = (String, Option<String>)>,
    ) -> Result<Self, SnapshotBuildError> {
        let mut snapshot = HashMap::new();
        for (domain, wallet) in entries {
            let domain = domain.trim().to_ascii_uppercase();
            if domain.is_empty() {
                return Err(SnapshotBuildError::EmptyDomain);
            }
            match snapshot.entry(domain) {
                Entry::Vacant(entry) => {
                    entry.insert(wallet);
                }
                Entry::Occupied(_) => return Err(SnapshotBuildError::DuplicateDomain),
            }
        }
        Ok(Self { entries: snapshot })
    }
}

impl ValidatorWalletSource for InMemoryValidatorWalletSnapshot {
    fn lookup(&self, domain: &str) -> Result<NodeWalletLookup, ValidatorWalletSourceFailure> {
        let domain = domain.trim().to_ascii_uppercase();
        Ok(match self.entries.get(&domain) {
            Some(Some(wallet)) => NodeWalletLookup::Known(wallet.clone()),
            Some(None) => NodeWalletLookup::NoRecord,
            None => NodeWalletLookup::UnknownDomain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_snapshot_distinguishes_known_no_record_and_unknown() {
        let snapshot = InMemoryValidatorWalletSnapshot::try_new([
            (
                " node-a ".into(),
                Some("0x0000000000000000000000000000000000000001".into()),
            ),
            ("node-b".into(), None),
        ])
        .unwrap();

        assert_eq!(
            snapshot.lookup("NODE-A").unwrap(),
            NodeWalletLookup::Known("0x0000000000000000000000000000000000000001".into())
        );
        assert_eq!(
            snapshot.lookup("node-b").unwrap(),
            NodeWalletLookup::NoRecord
        );
        assert_eq!(
            snapshot.lookup("node-c").unwrap(),
            NodeWalletLookup::UnknownDomain
        );
    }

    #[test]
    fn rejects_empty_and_duplicate_normalized_domains_in_both_orders() {
        assert_eq!(
            InMemoryValidatorWalletSnapshot::try_new([("  ".into(), None)]).unwrap_err(),
            SnapshotBuildError::EmptyDomain
        );
        let known = Some("0x0000000000000000000000000000000000000001".into());
        for entries in [
            vec![
                ("node-a".into(), known.clone()),
                (" NODE-A ".into(), known.clone()),
            ],
            vec![
                (" NODE-A ".into(), known.clone()),
                ("node-a".into(), known.clone()),
            ],
            vec![("node-a".into(), known.clone()), (" NODE-A ".into(), None)],
            vec![(" NODE-A ".into(), None), ("node-a".into(), known.clone())],
        ] {
            assert_eq!(
                InMemoryValidatorWalletSnapshot::try_new(entries).unwrap_err(),
                SnapshotBuildError::DuplicateDomain
            );
        }
    }
}

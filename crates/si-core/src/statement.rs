//! NodeRegistryV2 statements: typed builders plus the "one signature per (epoch, kind)" guard.
//!
//! The guard is sans-IO. The signer process asks it before signing, persists the returned
//! record durably, and only then releases the signature (design: si-signer, M1 line B).
use si_crypto::eip712::{self, Word};
use si_crypto::eth::keccak256;
use si_proto::node_registry as nr;
use std::collections::BTreeMap;

pub struct Domain {
    pub separator: Word,
}

impl Domain {
    pub fn new(verifying_contract: &str) -> si_crypto::Result<Self> {
        Ok(Self {
            separator: eip712::domain_separator(
                nr::DOMAIN_NAME,
                nr::DOMAIN_VERSION,
                nr::CHAIN_ID,
                verifying_contract,
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeStatement {
    pub node_id: Word,
    pub epoch: u64,
    pub kind: u8,
    pub payload_hash: Word,
}

impl NodeStatement {
    pub fn online(node_id: Word, epoch: u64) -> Self {
        Self {
            node_id,
            epoch,
            kind: nr::KIND_ONLINE,
            payload_hash: keccak256(nr::ONLINE_PAYLOAD_TEXT.as_bytes()),
        }
    }
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            nr::NODE_STATEMENT_TYPE,
            &[
                self.node_id,
                eip712::u64_word(self.epoch),
                eip712::u64_word(self.kind as u64),
                self.payload_hash,
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BindNode {
    pub operator: Word,
    pub node_id: Word,
    pub ip_hash: Word,
    pub key_id: Word,
    pub pgp_hash: Word,
    pub nonce: Word,
    pub deadline: Word,
}

impl BindNode {
    pub fn struct_hash(&self) -> Word {
        eip712::hash_words(
            nr::BIND_NODE_TYPE,
            &[
                self.operator,
                self.node_id,
                self.ip_hash,
                self.key_id,
                self.pgp_hash,
                self.nonce,
                self.deadline,
            ],
        )
    }
    pub fn digest(&self, d: &Domain) -> Word {
        eip712::digest(&d.separator, &self.struct_hash())
    }
}

/// What the signer may do with a NodeStatement request.
#[derive(Debug, PartialEq)]
pub enum GuardDecision {
    /// New (epoch, kind): persist `record` durably, then sign.
    PersistThenSign { record: (u8, u64, Word) },
    /// Same (epoch, kind, payload) as already signed: signing again yields the same bytes.
    SameAsBefore,
    /// Would be a double signature (or an epoch older than one already signed). Refuse.
    Refuse(&'static str),
}

/// Last signed statement per kind. Epochs only move forward per kind.
#[derive(Debug, Default)]
pub struct StatementGuard {
    last: BTreeMap<u8, (u64, Word)>,
    /// After lost state, nothing at or below this epoch may be signed.
    floor: Option<u64>,
}

impl StatementGuard {
    pub fn from_records(records: impl IntoIterator<Item = (u8, u64, Word)>) -> Self {
        let mut g = Self::default();
        for (k, e, p) in records {
            g.commit((k, e, p));
        }
        g
    }
    /// State was lost or corrupt: refuse every epoch up to `current_chain_epoch + 1`.
    pub fn after_state_loss(current_chain_epoch: u64) -> Self {
        Self {
            last: BTreeMap::new(),
            floor: Some(current_chain_epoch.saturating_add(1)),
        }
    }
    pub fn check(&self, s: &NodeStatement) -> GuardDecision {
        if !matches!(
            s.kind,
            nr::KIND_ONLINE | nr::KIND_SERVICE | nr::KIND_CAPABILITY
        ) {
            return GuardDecision::Refuse("unknown_kind");
        }
        if self.floor.map(|f| s.epoch <= f).unwrap_or(false) {
            return GuardDecision::Refuse("epoch_below_floor");
        }
        match self.last.get(&s.kind) {
            Some((e, p)) if *e == s.epoch && *p == s.payload_hash => GuardDecision::SameAsBefore,
            Some((e, _)) if *e == s.epoch => GuardDecision::Refuse("double_sign"),
            Some((e, _)) if *e > s.epoch => GuardDecision::Refuse("epoch_rewind"),
            _ => GuardDecision::PersistThenSign {
                record: (s.kind, s.epoch, s.payload_hash),
            },
        }
    }
    /// Call only after the record is durably persisted.
    pub fn commit(&mut self, (kind, epoch, payload): (u8, u64, Word)) {
        self.last.insert(kind, (epoch, payload));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(kind: u8, epoch: u64, p: u8) -> NodeStatement {
        NodeStatement {
            node_id: [0; 32],
            epoch,
            kind,
            payload_hash: [p; 32],
        }
    }

    #[test]
    fn one_signature_per_epoch_and_kind() {
        let mut g = StatementGuard::default();
        let GuardDecision::PersistThenSign { record } = g.check(&st(2, 10, 1)) else {
            panic!()
        };
        g.commit(record);
        assert_eq!(g.check(&st(2, 10, 1)), GuardDecision::SameAsBefore);
        assert_eq!(g.check(&st(2, 10, 2)), GuardDecision::Refuse("double_sign"));
        assert_eq!(g.check(&st(2, 9, 1)), GuardDecision::Refuse("epoch_rewind"));
        assert!(matches!(
            g.check(&st(1, 10, 9)),
            GuardDecision::PersistThenSign { .. }
        ));
        assert!(matches!(
            g.check(&st(2, 11, 3)),
            GuardDecision::PersistThenSign { .. }
        ));
        assert_eq!(
            g.check(&st(9, 11, 3)),
            GuardDecision::Refuse("unknown_kind")
        );
    }

    #[test]
    fn state_loss_sets_floor() {
        let g = StatementGuard::after_state_loss(100);
        assert_eq!(
            g.check(&st(1, 101, 0)),
            GuardDecision::Refuse("epoch_below_floor")
        );
        assert!(matches!(
            g.check(&st(1, 102, 0)),
            GuardDecision::PersistThenSign { .. }
        ));
    }

    #[test]
    fn typehashes_match_spec() {
        assert_eq!(
            eip712::to_hex(&eip712::type_hash(nr::NODE_STATEMENT_TYPE)),
            nr::NODE_STATEMENT_TYPEHASH
        );
        assert_eq!(
            eip712::to_hex(&eip712::type_hash(nr::BIND_NODE_TYPE)),
            nr::BIND_NODE_TYPEHASH
        );
    }
}

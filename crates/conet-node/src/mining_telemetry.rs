//! Pure transfer-byte aggregation for a future mining-liveness snapshot.
//!
//! This module has no runtime producer or listener. Callers must provide verified byte counts;
//! this candidate only tests aggregation and draining with synthetic input.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferUsage {
    pub wallet: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    EmptyWallet,
    ByteCountOverflow,
}

#[derive(Debug, Default)]
pub struct MiningTelemetry {
    bytes_by_wallet: BTreeMap<String, u64>,
}

impl MiningTelemetry {
    /// Add a verified byte count supplied by the caller. Zero-byte events are ignored.
    pub fn record_verified_bytes(
        &mut self,
        wallet: &str,
        bytes: u64,
    ) -> Result<(), TelemetryError> {
        let wallet = wallet.trim().to_ascii_lowercase();
        if wallet.is_empty() {
            return Err(TelemetryError::EmptyWallet);
        }
        if bytes == 0 {
            return Ok(());
        }
        let current = self.bytes_by_wallet.get(&wallet).copied().unwrap_or(0);
        let next = current
            .checked_add(bytes)
            .ok_or(TelemetryError::ByteCountOverflow)?;
        self.bytes_by_wallet.insert(wallet, next);
        Ok(())
    }

    /// Return a deterministic wallet-sorted snapshot and clear this aggregation window.
    pub fn snapshot_and_drain(&mut self) -> Vec<TransferUsage> {
        std::mem::take(&mut self.bytes_by_wallet)
            .into_iter()
            .map(|(wallet, bytes)| TransferUsage { wallet, bytes })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_by_normalized_wallet_and_drains_in_sorted_order() {
        let mut telemetry = MiningTelemetry::default();
        telemetry.record_verified_bytes("0xB", 4).unwrap();
        telemetry.record_verified_bytes("0xa", 2).unwrap();
        telemetry.record_verified_bytes(" 0xb ", 7).unwrap();
        telemetry.record_verified_bytes("0xc", 0).unwrap();

        assert_eq!(
            telemetry.snapshot_and_drain(),
            vec![
                TransferUsage {
                    wallet: "0xa".into(),
                    bytes: 2,
                },
                TransferUsage {
                    wallet: "0xb".into(),
                    bytes: 11,
                },
            ]
        );
        assert!(telemetry.snapshot_and_drain().is_empty());
    }

    #[test]
    fn rejects_empty_wallet_and_overflow_without_corrupting_snapshot() {
        let mut telemetry = MiningTelemetry::default();
        assert_eq!(
            telemetry.record_verified_bytes(" ", 1),
            Err(TelemetryError::EmptyWallet)
        );
        telemetry.record_verified_bytes("wallet", u64::MAX).unwrap();
        assert_eq!(
            telemetry.record_verified_bytes("WALLET", 1),
            Err(TelemetryError::ByteCountOverflow)
        );
        assert_eq!(
            telemetry.snapshot_and_drain(),
            vec![TransferUsage {
                wallet: "wallet".into(),
                bytes: u64::MAX,
            }]
        );
    }
}

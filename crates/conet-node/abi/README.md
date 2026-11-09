# NodeRegistryV2 ABIs (read-only copies)

Compiled from the node line's NodeRegistryV2 sources (not yet committed upstream; refreshed
2026-11-08 with the per-case vote lock, `settleReport` and the new `Report` fields), in a scratch
copy so the node line's tree is not touched: solc 0.8.35, via-IR, optimizer runs 2, cancun,
OpenZeppelin 5.4.0. Source set fingerprint (sha256 of the per-file sha256 list, mocks excluded):
`bee380fd2c26bd66…` (previous: `4e2a550b294401ee…`, v0.1.54).

Only the ABIs live here. `chain.rs` binds them with `sol!`, so a contract change shows up as a
compile error or a failing test once these files are refreshed. Refresh: compile the same way and
run `jq .abi out/<Name>.sol/<Name>.json`.

`NodeRegistryV2.json` also carries the events the contract emits from its linked libraries
(`NodeAdminLib`, `RegistrationLib`, `OfflineReportLib`); solc leaves those out of the contract's
own ABI, but log readers need them.

`getNodeRaw` is left out: its `Node` struct (36 members, 38 words) is past alloy's 24-element
tuple limit. `vote_gate.rs` reads the per-case lock (`voteLocked`) and the vote cooldown
(`voteEligibleAt`) from it by word position, because no other view exposes them; the layout is
checked by length and by the wallet word, and pinned to the fingerprint above. A dedicated view
(e.g. `voteCapacityOf(nodeId)`) would remove this dependency; requested from the node line.

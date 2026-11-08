# NodeRegistryV2 ABIs (read-only copies)

Compiled from the node line's NodeRegistryV2 v0.1.54 sources (not yet committed upstream), in a
scratch copy so the node line's tree is not touched: solc 0.8.35, via-IR, optimizer runs 2,
cancun, OpenZeppelin 5.4.0. Source set fingerprint (sha256 of the per-file sha256 list): `4e2a550b294401ee…`.

Only the ABIs live here. `chain.rs` binds them with `sol!`, so a contract change shows up as a
compile error or a failing test once these files are refreshed. Refresh: compile the same way and
run `jq .abi out/<Name>.sol/<Name>.json`.

`NodeRegistryV2.json` also carries the events the contract emits from its linked libraries
(`NodeAdminLib`, `RegistrationLib`, `OfflineReportLib`); solc leaves those out of the contract's
own ABI, but log readers need them.

`getNodeRaw` is left out: its 34-field `Node` struct is past alloy's 24-element tuple limit, and
`NodeRegistryLens.getNode` returns the same data.

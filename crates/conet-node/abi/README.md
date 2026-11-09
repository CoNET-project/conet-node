# NodeRegistryV2 ABIs (read-only copies)

Compiled from the node line's NodeRegistryV2 sources (not yet committed upstream), in a scratch
copy so the node line's tree is not touched, with its `hardhat.node-registry.config.ts` (solc
0.8.35, cancun). Refreshed 2026-11-09 to the node line's v0.4.2 snapshot (unified seal entries,
600 s / 7,200 s window, dueBreakdown, offlineSince). Source fingerprint with the node line's
algorithm (`shasum -a 256 *.sol | sort -k2 | shasum -a 256`, first 16 hex): `a1a13d465f4380fc`.
Earlier pins used another algorithm (sha256 of all `.sol` concatenated in sorted path order:
`a18191abf5c80d05`, `12123775fbd4e434`). Refresh: `tools/abi-refresh.py
<copy>/artifacts/node-registry/src/b-unit/node-registry-v2`.

`NodeRegistryV2.json` = the core ABI (minus `getNodeRaw`) + events and errors of the linked
libraries (`NodeAdminLib`, `RegistrationLib`, `OfflineReportLib`, `AdmissionLib`, `OnlineVoteLib`,
`RecoveryLib`) + the functions,
events and errors of `NodeRegistryV2Ext`, which the core reaches through its fallback (so calls
go to the registry address).

Only the ABIs live here. `chain.rs` binds them with `sol!`, so a contract change shows up as a
compile error or a failing test once these files are refreshed. Refresh: compile the same way and
run `jq .abi out/<Name>.sol/<Name>.json`.

`NodeRegistryV2.json` also carries the events the contract emits from its linked libraries
(`NodeAdminLib`, `RegistrationLib`, `OfflineReportLib`); solc leaves those out of the contract's
own ABI, but log readers need them.

`getNodeRaw` is left out: its `Node` struct (41 members, 43 words in v0.4.2) is past alloy's 24-element
tuple limit. `vote_gate.rs` reads the per-case lock (`voteLocked`) and the vote cooldown
(`voteEligibleAt`) from it by word position, because no other view exposes them; the layout is
checked by length and by the wallet word, and pinned to the fingerprint above. The lock math is
cross-checked against `lockCapacityOf(nodeId)` on every read.

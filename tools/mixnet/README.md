# Mixed-network regression (M3)

Live CoNET-SI and conet-node in one network, to check they interoperate before a canary.

- `run.sh [si-revision]` (Linux, sudo): fetches the public CoNET-SI repository at the pinned
  revision (default `74c6cfd`, the live fleet revision), applies `si_patch.py` to that scratch
  copy, builds both, and runs everything inside a network namespace with only loopback. Nothing
  can reach the internet or a live node. CI: `.github/workflows/mixnet.yml`.
- `setup.mjs`: local anvil (chain id 224422). GuardianNodesInfoV6, AddressPGP and a passport
  test double are placed at their mainnet addresses (`anvil_setCode`), so neither
  implementation needs an address patch. Registers S1, S2 (SI, golden nodeA/nodeB keys) and R1,
  R2 (conet-node, keys made per run) at 127.0.0.2–.5:80, and two users (user1 → mailbox R1,
  user2 → mailbox S2).
- `si_patch.py`: the only changes to SI, each asserted to apply once: RPC constants read
  `MIXNET_RPC`; the Treasury V3 vote listener is not started; the server binds its own IP.
- `contracts/`: creation bytecode of the two live contracts (compiled from the main
  repository's `src/b-unit/GuardianNodesInfoV6.sol` and `src/mainnet/AddressPGP.sol`) and the
  passport test double's source.
- Scenarios: `crates/conet-node/tests/mixnet.rs` (skipped unless `MIXNET_CONFIG` is set). Each
  one crosses implementations both ways: mailbox live delivery, offline store with flush and
  ACK, onion layers, voice v3 relay, SilentPass exit (paid and unpaid), legacy chat presence.

TEST keys only. Logs (artifact `mixnet-logs`) contain the SI test node key, because SI prints
its route key at start (reported to the security line).

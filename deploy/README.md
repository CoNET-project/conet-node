# Deployment templates

Three services, three users:

| Service | User | Holds |
| --- | --- | --- |
| `conet-signer` | `conet-signer` | keystore (sealed with the systemd-creds KEK), statement state |
| `conet-node` | `conet-node` | mailbox database; no keys |
| `conet-updater` | `conet-updater` | release directories; may only restart `conet-node.service` |

- Binaries live under `/opt/conet-node/releases/<version>/`; `current` and `previous` are symlinks
  switched by the updater. No `git pull`, no build on the node.
- Values in `/etc/conet-node/*.env`: RPC URL, Beamio API base, NodeRegistryV2 address, node
  wallet address, release public keys and threshold. No secrets go in these files.
- The KEK is created once per server with `systemd-creds encrypt` (see `conet-signer.service`).
- Release keys are offline; signing uses `conet-updater release sign` on the offline machine.

These are templates. Node addresses, accounts and key locations of real servers do not belong in
this repository.

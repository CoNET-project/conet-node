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
  wallet address, manifest mirror URLs. No secrets go in these files. Release public keys are
  compiled into `conet-updater`, not configured.
- `conet-boot-guard` runs before every start of `conet-node` and rolls back a release that fails
  to become healthy (10 minutes of `/healthz`) three times in a row.
- HTTPS on :443 with a certificate for `{routeKeyID}.conet.network`, obtained in-process through
  ACME TLS-ALPN-01 (no certbot, no sudo). `/var/lib/conet-node/acme` keeps the account and the
  certificate so restarts never re-issue. DNS for the name must point at the node.
- The KEK is created once per server with `systemd-creds encrypt` (see `conet-signer.service`).
- Release keys are offline; signing uses `conet-updater release sign` on the offline machine.

## Required checks before a node start

A value flag given without a usable value (last in argv, followed by another flag, empty, or
blank) stops the binary from starting. Nothing falls back to a default. The process prints the
flag name only, never the value.

### Variables that must be set

Each variable is passed as a flag value in a unit. When it is empty or blank, the process refuses to
start. This is intended (fail closed).

| Variable | Unit and flag | Empty or invalid |
| --- | --- | --- |
| `CONET_RPC` | `conet-node.service`, `--rpc` | node refuses to start |
| `CONET_PUBLIC_IP` | `conet-node.service`, `--public-ip` | node refuses to start (see `--public-ip` below) |
| `CONET_NODE_UID` | `conet-signer.service`, `--allow-uid` | signer refuses to start |
| `CONET_NODE_REGISTRY` | `conet-signer.service`, `--verifying-contract` | signer refuses to start |
| `CONET_MANIFEST_URL_1`, `CONET_MANIFEST_URL_2` | `conet-updater.service`, `--manifest-url` | updater refuses to start |
| `CONET_NODE_WALLET` | `conet-updater.service`, `--node-id` | updater refuses to start |

`--rpc` (`CONET_RPC`) must be the final URL. The JSON-RPC client does not follow redirects, so a URL
that answers with a 3xx makes every chain read fail. Before a start, confirm that the URL answers
without a redirect (expect `200 0`, meaning HTTP 200 and zero redirects):

```sh
curl -sS -o /dev/null -w '%{http_code} %{num_redirects}\n' -X POST \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
  "$CONET_RPC"
```

### Flags that are absent or invalid

- `conet-signer --allow-uid` (required for `serve`): missing, non-numeric, negative, or above
  4294967295 refuses to start. Without it the peer-uid check would be off.
- `conet-signer --quota-state` and `--quota-config` go together. Only one of them refuses to start.
  With neither, there is no quota ledger and quota-gated requests are refused
  (`quota_not_configured`). The built-in quota defaults are never used.
- `conet-node --public-ip` is a comma-separated list of IP addresses. Every entry must parse, and
  an empty, blank or invalid value refuses to start, with or without `--egress-policy`. When
  `--egress-policy` is given, the flag is required: if it is missing, the node refuses to start.
- `conet-node --max-body`: when absent, the default of 256 KiB applies. When given but empty or not
  a number, the node refuses to start.
- `conet-updater release verify --threshold`: required. Missing, non-numeric, or 0 is an error;
  there is no default of 1.

### Beamio API pushes

Pushes (offline-chat, voice-call, native-wake and device-registration calls to beamio.ca) run only
when both `--rpc` and `--api-base` are passed. Without one of them the node prints
`push disabled: --rpc not set` or `push disabled: --api-base not set` at start and sends no pushes.
An empty or blank `--api-base` counts as not set, and the same check decides whether pushes run. An
empty or blank `--rpc` stops the start instead (see the table above). `--api-base` is audited only;
the target is always https://beamio.ca.

### Removed from the unit templates

`conet-signer.service` no longer passes `--state`. The signer binary does not read that flag, so
the line only suggested a state file that was never used.

These are templates. Node addresses, accounts and key locations of real servers do not belong in
this repository.

## conet-register (operator tool, not a deployment unit)

`conet-register` prints NodeRegistryV2 registration data for operators. It is run by hand and never
sends a transaction, so no unit file starts it. Its required flags are `--ip`, `--tcp-port`,
`--udp-port` (request and reserved-bind) and `--node-type` (request). None of them defaults any
more. `--node-type` used to default to 1 (TCP), and the ports used to default to 0. Scripts that
omit these flags now fail on purpose. This is a deliberate strictness: a registration must state
its address, ports and node type. `--nonce` and `--deadline` keep bounded defaults (current time,
and now+3600).

## Node security rules (project AGENTS.md, 2026-11-08)

Every project node follows the repository root `AGENTS.md`. How the conet-node installation
lines up with it:

| Rule | conet-node installation |
| --- | --- |
| Only `peter` logs in interactively, ED25519 keys approved by the project only | The installer creates no login account. It never writes an `authorized_keys` file and never changes `peter`'s keys. |
| `root` never logs in; no public key for root (`/root/.ssh/` holds no login key, `sshd -T -C user=root` gives `pubkeyauthentication no`) | The installer never touches `/root/.ssh/` or the SSH server configuration. Checking it is part of the security receipt (below), not of the installer. |
| Services run under non-interactive accounts | `conet-signer`, `conet-node` and `conet-updater` are system accounts: `useradd --system --no-create-home --shell /usr/sbin/nologin <name>`, password locked (`usermod -L`). No SSH keys, no console login, no sudo rule, no group that grants a shell. |
| No reliance on a root shell or on sudo for an interactive shell | The services never call `sudo` or `su`. Ports below 1024 come from `AmbientCapabilities=CAP_NET_BIND_SERVICE` on `conet-node` only. The updater restarts `conet-node.service` through a polkit rule limited to that one unit, not through sudo. Installation and upgrades of the units are done by `peter` with `sudo`, which the rules record as the approved admin path. |
| Hardening | Each unit sets `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, an empty or minimal `CapabilityBoundingSet`; the signer also has no network (`PrivateNetwork`, `AF_UNIX` only) and no core dumps (`LimitCORE=0`). |

Polkit rule for the updater (template, `/etc/polkit-1/rules.d/50-conet-updater.rules`):

```js
polkit.addRule(function (action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" &&
      action.lookup("unit") == "conet-node.service" &&
      action.lookup("verb") == "restart" &&
      subject.user == "conet-updater") {
    return polkit.Result.YES;
  }
});
```

**Every node initialization is delivered with a read-only security receipt**: one per node, and a
separate one for the host and for each virtual machine, in the format of the project's receipt
template (kept outside this repository). It checks the effective SSH configuration
(including `Include` and `Match`), the root public-key rule in both places, account shells,
console autologin, other remote-login listeners and provider agents. A missing item or a failed
check is listed as blocking; the node is not "passed" until every applicable item has evidence.
Addresses, accounts and paths of real nodes go in the private operations folder, not here.

## Test fixture regeneration (release note, offline boundary)

The Treasury V3 and Epoch read-only fixtures are regenerated by the scripts under
`crates/conet-node/tests/fixtures/*_gen/`. They need ethers 6.17.0 from the pinned
`package-lock.json` in each directory.

- Regeneration needs npm registry access, or an npm cache already filled with the locked tarballs.
  Run `npm ci` in the generator directory before the script.
- On a fresh offline machine, either pre-fill the npm cache with the locked versions, or replace
  the dependency with a vendored copy of the locked ethers tree. Do not run the script against an
  arbitrary local `node_modules` and call the result reproduced.
- The committed fixtures are verified by the Rust tests (`treasury_v3`, `treasury_v3_scan`,
  `epoch_readonly`) without the generators, so the normal test gate works offline.
- The 444579d regeneration was checked with a local installed ethers 6.17.0 (version asserted by the
  script), not from a clean `npm ci`.

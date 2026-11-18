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

Beamio API pushes (offline-chat, voice-call, native-wake and device-registration calls to
beamio.ca) run only when both `--rpc` and `--api-base` are passed. Without one of them the node
prints `push disabled: --rpc not set` or `push disabled: --api-base not set` at start and sends no
pushes. An empty or blank value counts as not set, for both flags, and the same check decides
whether pushes run. Both are required items on every deployment:

- `--rpc ${CONET_RPC}` is set to a non-empty URL, so the node runs with user routes.
- `--api-base ${BEAMIO_API_BASE}` is set to a non-empty value. The value is audited only; the
  target is always https://beamio.ca.
- The start output has neither `push disabled:` line.

These are templates. Node addresses, accounts and key locations of real servers do not belong in
this repository.

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

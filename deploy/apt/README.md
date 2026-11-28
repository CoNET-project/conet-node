# conet-node APT package: layout, first start, upgrade

This is the layout of the signed APT package (`apt-get install conet-node`). The older templates in
`deploy/systemd/` describe the `/opt/conet-node` layout with an updater and a boot guard; the APT
package does not use them.

## What the package installs

| Path | What |
| --- | --- |
| `/usr/lib/conet-node/conet-node` | network process (mailbox, entry, forwarding); holds no keys |
| `/usr/lib/conet-node/conet-signer` | key-holding process, the first-start tool and the import tool |
| `/usr/lib/systemd/system/conet-node.service`, `conet-signer.service`, `conet-node-first-start.service` | units; installed disabled and not started |
| `/usr/lib/sysusers.d/conet-node.conf` | accounts `conet-signer` (uid 61050) and `conet-node` (uid 61051) |
| `/usr/lib/tmpfiles.d/conet-node.conf` | `/var/lib/conet-signer` (0700), `/etc/conet-node` (0755), `/etc/credstore.encrypted` (0700, empty) |
| `/usr/share/doc/conet-node/` | this file, `examples/node.env`, `examples/signer.env`, `examples/init.json`, `copyright` |

The maintainer script (`postinst`) only runs `systemd-sysusers` and `systemd-tmpfiles --create` for
the two files above. It never starts, stops, enables, restarts or reloads a service. The package
writes no file under `/etc` (it only creates the empty `/etc/credstore.encrypted` directory); the
operator creates `/etc/conet-node/node.env`, `/etc/conet-node/signer.env` and, optionally,
`/etc/conet-node/init.json`. A missing `node.env` or `signer.env` stops the unit (no `-` prefix);
`node.env` may be empty when `init.json` carries the values. Removing or purging the package keeps
`/var/lib/conet-signer` and `/var/lib/conet-node`.

## Install and first start (no prompts anywhere)

```sh
apt-get install conet-node
install -m 0644 /dev/null /etc/conet-node/node.env          # or fill it from examples/node.env
install -m 0644 /usr/share/doc/conet-node/examples/signer.env /etc/conet-node/signer.env
install -m 0644 /usr/share/doc/conet-node/examples/init.json /etc/conet-node/init.json   # edit it
systemctl daemon-reload
systemctl enable --now conet-node          # pulls in conet-signer and conet-node-first-start
journalctl -u conet-node-first-start -b    # the report: source, wallet, keyId (public values only)
```

Nothing in this path reads a terminal. `conet-node-first-start.service` is a one-shot unit with
`StandardInput=null`; the node identity and the key-encryption key (KEK) are made on the machine by
the program, never typed, never fetched from a remote, never printed.

What `conet-node-first-start.service` does, in order, every time it runs:

1. Reads `/etc/conet-node/init.json` (absent = none; damaged = refuse, see below).
2. **Keystore already there** (an existing Rust node, or an upgrade): light check only: regular
   file, owner, mode `0600`, public label readable; the KEK credential must exist. It prints the
   public wallet and route key ID and ends. It does not start the sealing stage, generate or import
   anything; the signer opens the keystore when it starts.
3. **No keystore**: looks for CoNET-SI (TS) traces: a `.CoNET-SI` or `CoNET-SI` directory in any home
   or in `/root`, a `conet.service` unit, a running TS process. With traces and `identity.mode`
   `auto` it refuses (`ts_node_detected`): choose `ts-import`, or `generate` with the explicit
   `confirm_generate_on_ts_host`. Without traces it makes the KEK if missing
   (`systemd-creds encrypt` fed from a pipe) and then runs the sealing stage as `conet-signer`
   (`systemd-run`, no network, `RuntimeMaxSec=120`, the KEK as an encrypted credential), which
   generates the wallet and route key, or imports the TS identity, and publishes the keystore
   atomically (temporary file, `fsync`, no-overwrite `link`, directory `fsync`, read-back; only then
   are the public values printed).
4. The identity is created **once**. Two first starts at the same moment end with one keystore and
   one public identity.

First start only makes the local identity. Registration on chain (NodeRegistryV2, GuardianNodesInfoV6)
is a separate step: the report ends with `registration: not performed`. Use `conet-register request`
with the printed wallet and route public key.

### init.json (node-provided settings)

`/etc/conet-node/init.json`, mode not writable by group or others. No secrets: `passwd`, `keychain`,
`pgpKey` and any other unknown key are refused (the message names the key, never a value).

```json
{ "version": 1,
  "http_port": 80, "https_port": 443,
  "public_ip": ["203.0.113.10"],
  "rpc": "https://rpc1.conet.network", "api_base": "https://beamio.ca",
  "identity": { "mode": "auto" } }
```

| Field | Meaning | Default |
| --- | --- | --- |
| `http_port` | HTTP listener `[::]:<port>` (TS `ipV4Port`) | 80 |
| `https_port` | HTTPS listener `[::]:<port>`; `0` = off. Other than 443, ACME uses DNS-01 | 443 |
| `public_ip` | list of addresses for `--public-ip`, or `"auto"` (global IPv4 of the local interfaces, same exclusions as the TS node). **Use explicit addresses on production nodes; `auto` can pick a different address than the TS node did on a multi-homed host** | unset |
| `rpc`, `api_base` | `--rpc`, `--api-base` (http or https URLs) | unset |
| `identity.mode` | `auto` (generate on a fresh host, refuse if TS traces), `generate`, `ts-import` | `auto` |
| `identity.confirm_generate_on_ts_host` | `true` allows `generate` on a host with TS traces (new identity; the report says so loudly) | false |
| `identity.ts_service_account` or `ts_setup_path` | where the TS `nodeSetup.json` is (`~<account>/.CoNET-SI/nodeSetup.json`, owner checked) | |
| `identity.expect_wallet`, `expect_key_id` | public values the imported identity must have; required for `ts-import`; also checked against an existing keystore | |

Priority per setting: command-line flag, then `init.json`, then the `node.env` variables
`CONET_RPC`, `BEAMIO_API_BASE`, `CONET_PUBLIC_IP`, then auto-detection, then the defaults. The unit
passes only `--init-config`, so an `init.json` port really is the listening port; without
`init.json`, a node with only `node.env` starts with exactly the flags the previous unit gave it.
A blank variable counts as unset.

TS `nodeSetup.json` field names are understood too, so nothing from a TS setup is dropped silently:
`ipV4Port` and `ipV4` are consumed (as `http_port`, `public_ip`); `ipV6`, `ipV6Port`, `cpus`,
`platform_verison`, `DL_registeredData`, `dl_publicKeyArmored`, `sslDate`, `restartBlockNumber`
and the two prices `storage_price` and `outbound_price` are validated and **ignored** (no Rust code
consumes them; no billing is added; the start log names each ignored field); `keychain`, `passwd`,
`pgpKey` are refused.

### Refusals and what the operator does

The first-start report and the unit log carry a fixed code and a field name, never a value. The exit
status is fixed too.

| Code (exit) | Meaning | Operator exit (the program never does these itself) |
| --- | --- | --- |
| `KEYSTORE_PRESENT_KEK_MISSING` (70) | a keystore exists but the KEK credential does not | Restore the KEK: put back `/etc/credstore.encrypted/conet-node-kek` from backup **together with this host's systemd credential key (`/var/lib/systemd/credential.secret`) or TPM state**; the credential file alone cannot be opened on another host. For a node whose identity came from a TS `nodeSetup.json`: rename (do not delete) the old keystore, set `identity.mode` `ts-import` with the original file, restart: the same public identity comes back. For a node whose identity was generated here there is no original to import: it is lost with the KEK; to make a new identity, rename the old keystore by hand, start again, and register the new identity on chain again. |
| `KEYSTORE_UNREADABLE` (71) | keystore (or state directory) is not a plain private file/directory, wrong mode or owner, or cannot be read | Fix type, mode `0600` (directory `0700`) and owner `conet-signer`. Nothing was changed. |
| `KEYSTORE_RESIDUE` (72) | a non-empty keystore that does not parse or does not match its label (possibly a damaged identity that was once announced) | Keep the file. Restore from backup, or, for a TS identity, rename it and use `ts-import`. A 0-byte keystore is different: it cannot hold an identity, so it is renamed to `keystore.json.zero-byte.<time>.<pid>` automatically and the start continues; the log names the new file. |
| `KEK_UNDECRYPTABLE` (73) | the KEK credential cannot be used, or does not open the keystore (clone, reinstall, wrong host key/TPM) | As for 70: recover the original host credential key or the original KEK; never delete the keystore to "fix" this. |
| other (74) | init.json refused, TS traces, TS setup file checks, `ts-import` refused, no space, no `link` support, ... | The message names the check. An interrupted start leaves at most a hidden temporary file (`.keystore.json.tmp.<pid>.<id>`), cleared after ten minutes; it is never taken for the keystore. |

A full or read-only volume, or a file system without hard links, fails closed with exit 74: no
keystore appears, no copy or rename fallback is tried.

## Upgrade

`apt-get install conet-node` (or `apt-get upgrade`) replaces the binaries and units; it does not
start, stop or restart anything. Restart the units yourself when it suits you. On the next start
`conet-node-first-start.service` finds the existing keystore, takes the light path and the node keeps
its identity. Nodes that only have `node.env` start with the same flags as before. Check:

```sh
journalctl -u conet-node-first-start -b | grep -E 'source:|wallet:|keyId:'   # same public values as before
systemctl cat conet-node.service conet-signer.service conet-node-first-start.service | grep -c -- '--insecure'   # 0
```

## Identity: keep the node identity a CoNET-SI (TS) node already has

The node keeps its wallet and route key. They come from the node's own `nodeSetup.json`, the file a
CoNET-SI (TS) node keeps in the `.CoNET-SI` directory of the account that runs the TS service. Set
`identity.mode` to `ts-import` with the account, and the node's public wallet and route encryption
sub-key ID (from the on-chain node table) as `expect_*`:

```json
{ "version": 1,
  "public_ip": ["<the TS node's address>"],
  "identity": { "mode": "ts-import", "ts_service_account": "<account>",
                "expect_wallet": "0x<node wallet>", "expect_key_id": "<16 hex>" } }
```

The first-start unit checks that the file is a plain file owned by that account and not writable
by others, hands it to the sealing stage as a systemd credential (so no key or password appears in
argv or environment), and the sealing stage opens it, compares the public values with `expect_*`
**before** publishing, publishes, and reads back and compares again. A mismatch, a wrong password,
a damaged file stops it with a fixed code, writes nothing and never falls back to making a new
identity. The file itself is only read: it is never moved or edited, and later boots do not need it.
(`systemd-run` with `LoadCredential=` holds an in-memory copy of it for as long as the transient unit
exists; the copy vanishes when the unit ends, and `LimitCORE=0` keeps a crash from writing it to disk.)

The manual way still works and uses the same code: as root, make the KEK
(`systemd-creds encrypt --name=conet-node-kek - /etc/credstore.encrypted/conet-node-kek` fed from 32
random bytes on stdin) and run `conet-signer import-ts-setup` under `systemd-run` with
`LoadCredential=nodesetup:<path>`; then `systemctl enable --now conet-signer conet-node`.

`signer.env` sets `CONET_NODE_REGISTRY=0x000…000`. This is a placeholder for the chat pilot (the
signer needs an address for its EIP-712 domain; NodeRegistryV2 is not deployed, the pilot requests
no statement, and `BindNode` stays refused; with the all-zero value the signer also refuses every EIP-712 statement request, `domain_placeholder`). It must be replaced with the real address when
NodeRegistryV2 is deployed. The signer was tested to start and serve chat with the all-zero value
(`the_all_zero_verifying_contract_placeholder_starts_and_serves_chat`).

## Evidence log

`conet-node.service` passes `--evidence-log /var/lib/conet-node/evidence/evidence.jsonl` (owner
`conet-node`, mode 0640, capped at 64 MiB). The binary has the log off unless the flag is given; this
unit turns it on for the pilot only, and the flag will be removed from the unit before the official
release. One JSON line per event with a closed field set:
UTC time, the node's public route key ID, role (`entry` or `mailbox`), event, and keccak256 hashes of
the armors handled. It holds no wallet, user key ID, client address, armor text or stream key.

Hashes are `0x` plus 64 lowercase hex, keccak256 over the UTF-8 text.

- `h_raw`: the `data` string of the `/post` exactly as received.
- `h_recv`: the same after SI normalisation (trimmed, cut after the `-----END PGP MESSAGE-----` line).
- `h_fwd`: the armor an entry passed on (equal to `h_raw` when passed on unchanged).
- `h_in`: the armor as the mailbox stored and delivered it (the `data` of the SSE frame); this is the
  hash in `gossip_delivery_ack` and in the sender's delivery receipt. For mailbox work it is the inner
  armor, trimmed and cut after its END line; for a bare armor post it is the posted string byte for byte.

`next_node` is the public route key ID (the domain label) of the next-hop node, taken from the node
table; rows contain no client address, no wallet and no IP address.

Rows: `post` (entry: `h_raw h_recv h_fwd next_node hops len_bucket forward`), `store` (mailbox:
`h_in stored live_sessions push_enqueued`, plus `h_raw h_recv` of the post that carried it),
`ack`, `listen_attach` (`instance` = first 8 hex of keccak256(instanceId), `sessions`),
`online_query`, `start`, `evidence_full`.

## Ports and addresses

By default the node listens on `[::]:80` and `[::]:443`, dual-stack while `net.ipv6.bindv6only=0`;
`http_port` and `https_port` in `init.json` change that. Check the sysctl before the first start.
HTTPS gets its certificate in-process (ACME TLS-ALPN-01 on 443) for `{routeKeyID}.conet.network`; the
first issuance happens at the first start, and a restart reuses the cache in `/var/lib/conet-node/acme`.

## Taking over from a CoNET-SI (TS) node

Stop and disable `conet.service` first (port 80 and 443 must be free). The TS program and
`nodeSetup.json` stay where they are as rollback material. Rollback: stop and disable
`conet-node.service`, `conet-signer.service` and `conet-node-first-start.service`, then enable and
start `conet.service`.

## Known gap (S7): `--insecure-*` flags are still in the binaries

`conet-node` still accepts `--insecure-dev-keys` (test keys from the environment) and `conet-signer`
still accepts `--insecure-kek-file`. Neither unit uses them; each prints a warning at start. They are
to be removed from release builds (a Cargo feature) before this package goes beyond the pilot. After
installing, check that both units are exactly the shipped ones:

```sh
systemctl cat conet-node.service conet-signer.service | grep -c -- '--insecure'   # must print 0
systemctl cat conet-node.service conet-signer.service | grep -E '^# /'            # only /usr/lib/... paths, no drop-in
```

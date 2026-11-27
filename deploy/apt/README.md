# conet-node APT package: layout and first start

This is the layout of the signed APT package (`apt install conet-node`). The older templates in
`deploy/systemd/` describe the `/opt/conet-node` layout with an updater and a boot guard; the APT
package does not use them.

## What the package installs

| Path | What |
| --- | --- |
| `/usr/lib/conet-node/conet-node` | network process (mailbox, entry, forwarding); holds no keys |
| `/usr/lib/conet-node/conet-signer` | key-holding process and the import tool |
| `/usr/lib/systemd/system/conet-node.service`, `conet-signer.service` | units; installed disabled and not started |
| `/usr/lib/sysusers.d/conet-node.conf` | accounts `conet-signer` (uid 61050) and `conet-node` (uid 61051) |
| `/usr/lib/tmpfiles.d/conet-node.conf` | `/var/lib/conet-signer` (0700) and `/etc/conet-node` (0755) |
| `/usr/share/doc/conet-node/` | this file, `examples/node.env`, `examples/signer.env`, `copyright` |

The maintainer script (`postinst`) only runs `systemd-sysusers` and `systemd-tmpfiles --create` for
the two files above. It never starts, stops, enables, restarts or reloads a service. Nothing is
written under `/etc` by the package; the operator creates `/etc/conet-node/node.env` and
`/etc/conet-node/signer.env` from the examples. A missing env file stops the unit (no `-` prefix).
Removing or purging the package keeps `/var/lib/conet-signer` and `/var/lib/conet-node`.

## Identity: keep the node identity a CoNET-SI (TS) node already has

The node keeps its wallet and route key. They come from the node's own `nodeSetup.json`
(`~/.CoNET-SI/nodeSetup.json` of the account that runs the TS service), read once, and sealed into
the signer's keystore under a KEK held by systemd-creds. The file is read only: never moved, edited
or copied, and the Rust side never reads it again.

1. One-time KEK (root): `systemd-creds encrypt --name=conet-node-kek - /etc/credstore.encrypted/conet-node-kek`
   fed from 32 random bytes on stdin (bound to the TPM when present, otherwise to the host key).
2. Import, as the signer account, with the setup file passed as a systemd credential so no key
   or password appears in argv or environment (the two `--expect-*` values are public: the node's
   wallet address and its route encryption sub-key ID from the on-chain node table):

   ```sh
   systemd-run --wait --pipe --collect \
     -p User=conet-signer -p ProtectSystem=strict -p StateDirectory=conet-signer -p PrivateNetwork=yes \
     -p LoadCredentialEncrypted=conet-node-kek:/etc/credstore.encrypted/conet-node-kek \
     -p LoadCredential=nodesetup:/home/<ts-service-user>/.CoNET-SI/nodeSetup.json \
     -E WALLET=0x<node wallet> -E KEYID=<16 hex> \
     /bin/sh -c 'exec /usr/lib/conet-node/conet-signer import-ts-setup \
        --setup "$CREDENTIALS_DIRECTORY/nodesetup" --keystore /var/lib/conet-signer/keystore.json \
        --expect-wallet "$WALLET" --expect-key-id "$KEYID"'
   ```

   It prints the keystore status, the wallet address and the key ID, nothing else. A mismatch with
   either expected value, a wrong password or a damaged file stops it with a fixed code and writes
   nothing.
3. `systemctl daemon-reload`, then `systemctl enable --now conet-signer conet-node`.

`signer.env` sets `CONET_NODE_REGISTRY=0x000…000`. This is a placeholder for the chat pilot (the
signer needs an address for its EIP-712 domain; NodeRegistryV2 is not deployed, the pilot requests
no statement, and `BindNode` stays refused). It must be replaced with the real address when
NodeRegistryV2 is deployed. The signer was tested to start and serve chat with the all-zero value
(`the_all_zero_verifying_contract_placeholder_starts_and_serves_chat`).

## Evidence log

`conet-node.service` passes `--evidence-log /var/lib/conet-node/evidence/evidence.jsonl` (owner
`conet-node`, mode 0640, capped at 64 MiB). One JSON line per event with a closed field set:
UTC time, the node's public route key ID, role (`entry` or `mailbox`), event, and keccak256 hashes of
the armors handled. It holds no wallet, user key ID, client address, armor text or stream key.

Hashes are `0x` plus 64 lowercase hex, keccak256 over the UTF-8 text.

- `h_raw`: the `data` string of the `/post` exactly as received.
- `h_recv`: the same after SI normalisation (trimmed, cut after the `-----END PGP MESSAGE-----` line).
- `h_fwd`: the armor an entry passed on (equal to `h_raw` when passed on unchanged).
- `h_in`: the armor as the mailbox stored and delivered it (the `data` of the SSE frame); this is the
  hash in `gossip_delivery_ack` and in the sender's delivery receipt. For mailbox work it is the inner
  armor, trimmed and cut after its END line; for a bare armor post it is the posted string byte for byte.

Rows: `post` (entry: `h_raw h_recv h_fwd next_node hops len_bucket forward`), `store` (mailbox:
`h_in stored live_sessions push_enqueued`, plus `h_raw h_recv` of the post that carried it),
`ack`, `listen_attach` (`instance` = first 8 hex of keccak256(instanceId), `sessions`),
`online_query`, `start`, `evidence_full`.

## Ports and addresses

The unit listens on `[::]:80` and `[::]:443`, dual-stack while `net.ipv6.bindv6only=0`. Check that
value before the first start. HTTPS gets its certificate in-process (ACME TLS-ALPN-01) for
`{routeKeyID}.conet.network`; the first issuance happens at the first start, and a restart reuses the
cache in `/var/lib/conet-node/acme`.

## Taking over from a CoNET-SI (TS) node

Stop and disable `conet.service` first (port 80 and 443 must be free). The TS program and
`nodeSetup.json` stay where they are as rollback material. Rollback: stop and disable
`conet-node.service` and `conet-signer.service`, then enable and start `conet.service`.

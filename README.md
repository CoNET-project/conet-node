# conet-node

Rust implementation of the CoNET node (successor of CoNET-SI). One sans-IO core, two hosts:

- **Linux node** — native daemon (entry, forwarding, mailbox, voice relay).
- **Browser node** — the same core compiled to WebAssembly, run in a Web Worker.

Status: M1 is complete (its last stage, A4, added in-process ACME HTTPS). The wire stays byte-compatible with live CoNET-SI, so clients do not change. Work after M1 is on development branches. A signed APT package of the node binary is published (see [Install via APT](#install-via-apt)); it is not yet a complete service installation (see [Pilot, not yet released](#pilot-not-yet-released)).

## Layout

| Path | What |
| --- | --- |
| `crates/si-proto` | Wire constants and plain formats (hop sigs, voice texts, armor helpers) |
| `crates/si-crypto` | OpenPGP (rPGP), Ethereum signatures (k256), AES-GCM, HMAC. No key storage, no I/O |
| `crates/si-core` | Sans-IO core: `/post` classification, `checkSign`, hop sigs, mailbox sealing, minimal node |
| `crates/conet-node` | Linux node daemon (`conet-node`): entry, forwarding, mailbox |
| `crates/si-signer` | Signer process (`conet-signer`): holds the node keys, signs only whitelisted payloads |
| `crates/conet-updater` | Update agent and offline boot guard: signed release manifests, atomic switch, rollback. The APT package does not use it |
| `crates/si-conformance` | Golden vector runner (shared by native and wasm) |
| `crates/si-conformance-cli` | Native host for the runner |
| `crates/conet-si-wasm` | wasm-bindgen host for the runner |
| `conformance/vectors` | Golden vectors generated with live CoNET-SI code and openpgp.js. **Test keys only** |
| `conformance/web` | Runs the vectors in a browser Web Worker |
| `deploy` | Unit and layout templates for the updater-managed layout. This is not what the APT package installs |

## Install via APT

Signed packages for Linux nodes are published as an APT repository.

| | |
| --- | --- |
| Repository | `https://conet-project.github.io/conet-node/` |
| Suite / component / architecture | `stable` / `main` / `amd64` (no other architecture is published) |
| Package | `conet-node` |
| Version | `0.0.1+git20261126.ca64f794-1` |
| Depends | `libc6 (>= 2.43-2ubuntu2.3)`, `libgcc-s1 (>= 16-20260322-1ubuntu1)` |
| Built from | [`ca64f79482c8b12df746439f5dfd419fd5b1b4e1`](https://github.com/CoNET-project/conet-node/commit/ca64f79482c8b12df746439f5dfd419fd5b1b4e1) on the public branch `feat/remove-solana-rpc-97c8503-20261126` (not on `main`) |
| Signing key | `CoNET APT Archive Signing`, primary fingerprint `E9A2062A1D5A3CB6634B2CEC424E83ED7A1D99CD`, signing subkey `447B80436380937CF5D2CC556B878AE7992497D9` |

Platform: **Ubuntu 26.04 LTS, amd64**. Tested on Ubuntu 26.04.1 only (see [What is verified](#what-is-verified)). Not tested: other releases, other distributions and other architectures (only `amd64` is published).

The package installs one file, `/usr/lib/conet-node/conet-node`. It has no systemd unit, no service user and no maintainer scripts, and installing it does not enable or start anything.

### First install

**1. Download the key and check its fingerprint before you trust it.** The key goes into a throw-away directory (`KEYTMP`) that is also used as the GnuPG home, so your own keyring is not touched. Run all the blocks of this step in the same shell: later blocks use `KEYTMP`.

```bash
KEYTMP="$(mktemp -d)"
export GNUPGHOME="$KEYTMP"
curl -fsSL -o "$KEYTMP/conet-archive-keyring.asc" \
  https://conet-project.github.io/conet-node/conet-archive-keyring.asc
gpg --show-keys "$KEYTMP/conet-archive-keyring.asc"
```

Expected output with gpg 2.4.8 (Ubuntu 26.04). In a fresh `GNUPGHOME`, gpg first prints two `gpg: ...` notices about the keybox and trustdb it created; ignore them. The other lines must be exactly these:

```text
pub   rsa3072 2026-11-27 [C] [expires: 2031-11-26]
      E9A2062A1D5A3CB6634B2CEC424E83ED7A1D99CD
uid                      CoNET APT Archive Signing
sub   rsa3072 2026-11-27 [S] [expires: 2028-11-26]
```

Newer gpg versions also print the subkey's fingerprint (`447B80436380937CF5D2CC556B878AE7992497D9`) under the `sub` line. Whatever the version, check the primary fingerprint line (the line under `pub`).

A scripted check of the primary fingerprint (prints `fingerprint OK`, nothing otherwise):

```bash
[ "$(gpg --show-keys --with-colons "$KEYTMP/conet-archive-keyring.asc" \
     | awk -F: '$1 == "fpr" { print $10; exit }')" = E9A2062A1D5A3CB6634B2CEC424E83ED7A1D99CD ] \
  && echo "fingerprint OK"
```

Only if the fingerprint matches, install the key as a binary keyring (`sudo` is needed for `/usr/share/keyrings`):

```bash
sudo install -d -m 0755 /usr/share/keyrings
gpg --dearmor < "$KEYTMP/conet-archive-keyring.asc" \
  | sudo tee /usr/share/keyrings/conet-archive-keyring.gpg > /dev/null
```

Remove the temporary directory, which now holds only the downloaded key, and restore your GnuPG environment (run this in the same shell as step 1):

```bash
rm -rf -- "${KEYTMP:?}"
unset KEYTMP GNUPGHOME
```

**2. Register the repository**, bound to that key with `Signed-By`:

```bash
sudo tee /etc/apt/sources.list.d/conet-node.sources > /dev/null <<'EOF'
Types: deb
URIs: https://conet-project.github.io/conet-node/
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/conet-archive-keyring.gpg
EOF
```

**3. Refresh the package lists** and look at the candidate:

```bash
sudo apt update
apt policy conet-node
```

```text
conet-node:
  Installed: (none)
  Candidate: 0.0.1+git20261126.ca64f794-1
  Version table:
     0.0.1+git20261126.ca64f794-1 500
        500 https://conet-project.github.io/conet-node stable/main amd64 Packages
```

**4. Install**, then confirm the installed version:

```bash
sudo apt install conet-node
dpkg-query -W -f='${Package} ${Version} ${Status}\n' conet-node
```

```text
conet-node 0.0.1+git20261126.ca64f794-1 install ok installed
```

### Upgrade

An upgrade is the same repository with a newer version. Refresh the lists, upgrade only this package, and check the version again:

```bash
sudo apt update
sudo apt install --only-upgrade conet-node
dpkg-query -W -f='${Package} ${Version} ${Status}\n' conet-node
```

`sudo apt upgrade` upgrades every upgradable package, including this one (only simulated here, see below). The package never restarts anything: after an upgrade, restart whatever runs the binary yourself.

### What is verified

Everything below was run on 2026-11-27 as an unprivileged user in an isolated APT directory, on Ubuntu 26.04.1 LTS (amd64) with apt 3.2.1 and gpg 2.4.8. Nothing was installed on that system and its own APT configuration was not changed. Three things are kept apart here.

**1. Actually downloaded and checked (not installed).**

- The index: `InRelease` is signed by the key above and verifies with `gpg`, and `apt update` accepts it under the `Signed-By` entry from step 2. The package entry in the index matches the table above. [`PROVENANCE.json`](https://conet-project.github.io/conet-node/dists/stable/PROVENANCE.json) records the source commit and tree, the `Cargo.lock` hash and the SHA-256 of the binary.
- The key download and the fingerprint check of step 1, and the `apt policy` output of step 3 (verbatim).
- The package itself, fetched with `apt-get download`: its size and SHA-256 equal the index entry, it contains one file, `/usr/lib/conet-node/conet-node`, and its control data has no maintainer scripts.

**2. Only simulated (`apt -s`, against a synthetic dpkg status).**

- `apt install conet-node`, `apt install --only-upgrade conet-node` and `apt upgrade`: apt printed the plan (an `Inst` and a `Conf` line for `conet-node` from `CoNET-SI Rust:stable`; for the two upgrade commands the `Inst` line shows the old version in brackets) and nothing was changed.
- The `dpkg-query` output of step 4 was produced against a synthetic dpkg status that stands in for an installed package; it is the format of the answer, not a result from a real install.

**3. A real install or upgrade of the system.**

- Not done from this repository. The only real upgrade so far ran inside an isolated Ubuntu Base 26.04.1 (amd64) guest with a local test repository: `apt-get upgrade` replaced one test version with the next, and the installed file and its digest were checked.
- Not verified: `sudo apt install conet-node` from this repository on a live system, and anything about running the binary as a service.

## Pilot, not yet released

These are in design or pilot and are **not** part of the package:

- A systemd service for the node, a dedicated service user, and the separate signer process with its own user.
- Serving on ports 80 and 443 as an unprivileged service user. The node can serve HTTP on `--listen` and HTTPS on `--tls-listen`; binding ports below 1024 without root needs the `CAP_NET_BIND_SERVICE` capability, which a service unit has to grant.
- Layout, user names and ports of such a service. Do not use the templates in [`deploy/`](deploy) as that layout: they describe an updater-managed layout under `/opt/conet-node` that the APT package does not use.

The package is built from a development branch that does not contain a Solana RPC proxy route: [`ca64f79`](https://github.com/CoNET-project/conet-node/commit/ca64f79482c8b12df746439f5dfd419fd5b1b4e1) ("Remove Solana RPC proxy route") removes it on that branch. `main` does not contain one either.

## Build and test

```bash
cargo test --workspace --release
./build-wasm.sh                      # needs wasm-bindgen-cli 0.2.130
./target/release/si-conformance-cli run conformance/vectors/golden.json
node conformance/vectors/run-wasm.mjs pkg/node conformance/vectors/golden.json run
```

Reverse check (Rust output verified by openpgp.js and SI code):

```bash
(cd conformance/vectors && npm ci --ignore-scripts)
./target/release/si-conformance-cli artifacts conformance/vectors/golden.json <64-hex seed> > art.json
node conformance/vectors/verify-rust.mjs conformance/vectors/golden.json art.json
```

## Rules

- Never commit node IP addresses, SSH accounts, home paths, key locations, or any real node or user key.
- Core crates are `#![forbid(unsafe_code)]` and must build for `wasm32-unknown-unknown`.

License: MIT.

# conet-node

Rust implementation of the CoNET node (successor of CoNET-SI). One sans-IO core, two hosts:

- **Linux node** — native daemon (entry, forwarding, mailbox, voice relay).
- **Browser node** — the same core compiled to WebAssembly, run in a Web Worker.

Status: M1 in progress. The wire stays byte-compatible with live CoNET-SI, so clients do not change.

## Layout

| Path | What |
| --- | --- |
| `crates/si-proto` | Wire constants and plain formats (hop sigs, voice texts, armor helpers) |
| `crates/si-crypto` | OpenPGP (rPGP), Ethereum signatures (k256), AES-GCM, HMAC. No key storage, no I/O |
| `crates/si-core` | Sans-IO core: `/post` classification, `checkSign`, hop sigs, mailbox sealing, minimal node |
| `crates/si-conformance` | Golden vector runner (shared by native and wasm) |
| `crates/si-conformance-cli` | Native host for the runner |
| `crates/conet-si-wasm` | wasm-bindgen host for the runner |
| `conformance/vectors` | Golden vectors generated with live CoNET-SI code and openpgp.js. **Test keys only** |
| `conformance/web` | Runs the vectors in a browser Web Worker |

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

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

## WebRTC entry

Browsers can deliver over a WebRTC data channel instead of HTTPS (no CA certificate, no
signalling server). The node listens ICE-lite on one UDP port and publishes a wallet-signed
endpoint statement (`GET /webrtc`): IP, port, DTLS fingerprint, expiry.

```bash
conet-node … --webrtc-listen 0.0.0.0:<udp port> --webrtc-public <public ipv4>:<udp port> \
  --webrtc-cert <state dir>/webrtc-cert.json   # created on first start, keep it (fingerprint)
```

Browser side (see `si_proto::webrtc` and `tools/webrtc-browser-test/index.html`):

1. Check the statement: signature by the node wallet from the node table, not expired.
2. `pc.createDataChannel(...)`, `createOffer()`, replace the offer's ICE ufrag and password with
   one random `conet1` + 32 letters/digits (`munge_offer`), `setLocalDescription`.
3. `setRemoteDescription` with `answer_sdp(ip, port, ufrag, fingerprint)` built locally.
4. One data channel per HTTP request, carrying the same bytes as TCP :80 (`/post`, SSE listens,
   voice, exit). Send in 16 KB messages; read the response by its length or stream, do not wait
   for the channel to close (SCTP's delayed ack makes the close ~200 ms late).

Local browser test with the golden test keys: `tools/webrtc-browser-test/run.sh [lan ip]`.

## HTTPS certificates

`--tls-listen <ip:port>` serves the same routes as :80 with a certificate for
`{keyId}.conet.network`. Two ACME modes (`--acme-mode`, default `auto`):

| Mode | When | How |
| --- | --- | --- |
| `alpn` | listener on 443 (`auto` picks it) | TLS-ALPN-01 answered on the listener itself |
| `dns01` | any other port (`auto` picks it) | DNS-01: the node asks the project's DNS daemon to set `_acme-challenge.{keyId}.conet.network`, with a request signed by the node wallet (`conet.acme.dns01.v1`, via the signer) |

```bash
conet-node … --tls-listen 0.0.0.0:<port> --acme-cache <state dir>/acme \
  --acme-dns-daemon <daemon url>        # dns01 only
# --acme-staging, --acme-contact <email>, --acme-directory <url>, --tls-cert/--tls-key (fixed PEM)
```

The certificate key is made on the node and stays in `--acme-cache` (mode 0600); the daemon
only writes TXT records. Renewal starts 30 days before expiry. The daemon side checks requests
with `acme_dns::verify_dns01_request` and must also confirm the wallet is the registered node
for the key ID. Test: `tests/acme_dns01.rs` against Pebble (set `PEBBLE_BIN` and
`PEBBLE_CHALLTESTSRV_BIN`; CI builds Pebble v2.10.1).

## Rules

- Never commit node IP addresses, SSH accounts, home paths, key locations, or any real node or user key.
- Core crates are `#![forbid(unsafe_code)]` and must build for `wasm32-unknown-unknown`.

License: MIT.

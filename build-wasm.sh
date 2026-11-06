#!/usr/bin/env bash
# Build the wasm module and JS glue (needs: rustup target wasm32-unknown-unknown, wasm-bindgen-cli 0.2.130).
set -euo pipefail
cd "$(dirname "$0")"
cargo build --profile wasm --target wasm32-unknown-unknown -p conet-si-wasm
W=target/wasm32-unknown-unknown/wasm/conet_si_wasm.wasm
wasm-bindgen --target nodejs --out-dir pkg/node "$W"
wasm-bindgen --target web --out-dir pkg/web "$W"
echo '{"type":"commonjs"}' > pkg/node/package.json
ls -l pkg/web/conet_si_wasm_bg.wasm

#!/usr/bin/env bash
# Local browser test of the WebRTC entry with the public golden TEST keys (never real keys).
# Usage: tools/webrtc-browser-test/run.sh [ip]   (default 127.0.0.1; a LAN IP also works)
# Then open the printed URL in each browser; results are appended to $WORK/results.jsonl.
set -euo pipefail
cd "$(dirname "$0")/../.."
IP="${1:-127.0.0.1}"
WORK="$(mktemp -d)"
G=conformance/vectors/golden.json
node -e "const g=require('./$G');process.stdout.write(g.keys.nodeA.armoredPrivate)" > "$WORK/route.asc"
KID=$(node -e "const g=require('./$G');process.stdout.write(g.keys.nodeA.encKeyId)")
echo "{\"nodes\":[{\"keyId\":\"$KID\",\"addr\":\"127.0.0.1:18080\"}]}" > "$WORK/routes.json"
cargo build -q --release -p conet-node
export CONET_DEV_ROUTE_PASS=$(node -e "const g=require('./$G');process.stdout.write(g.keys.nodeA.passphrase)")
export CONET_DEV_WALLET_KEY=$(node -e "const g=require('./$G');process.stdout.write(g.wallets.nodeA.privateKey)")
./target/release/conet-node --insecure-dev-keys --dev-route-key "$WORK/route.asc" \
  --routes "$WORK/routes.json" --listen "$IP:18080" --health-listen 127.0.0.1:18181 \
  --webrtc-listen "$IP:18443" --webrtc-cert "$WORK/webrtc-cert.json" &
NODE_PID=$!
python3 -I tools/webrtc-browser-test/harness.py 18090 "$WORK/results.jsonl" &
H_PID=$!
trap 'kill $NODE_PID $H_PID 2>/dev/null; rm -rf "$WORK"' EXIT
echo "open: http://127.0.0.1:18090/?node=http://$IP:18080&report=http://127.0.0.1:18090/result"
echo "results: $WORK/results.jsonl"
wait

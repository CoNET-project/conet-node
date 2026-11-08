#!/usr/bin/env bash
# M3 mixed-network regression (Linux, needs sudo for the network namespace).
#
# Live CoNET-SI (public repo, pinned revision) and conet-node run side by side inside a network
# namespace that has only loopback: nothing can reach the internet or a live node. The chain is
# a local anvil (chain id 224422). TEST keys only.
#
#   tools/mixnet/run.sh [si-revision]          (default 74c6cfd, the live fleet revision)
#
# Outside the namespace: fetch and build SI with tools/mixnet/si_patch.py, build conet-node and
# the scenario test. Inside: anvil, setup.mjs, 2 SI + 2 conet-node, an echo target for the exit,
# then `cargo test --test mixnet`. Logs end up in $MIXNET_WORK/logs.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
SI_REV=${1:-74c6cfd}
WORK=${MIXNET_WORK:-$(mktemp -d)}
mkdir -p "$WORK/logs"

if [ "${MIXNET_INNER:-}" != 1 ]; then
  echo "== work dir: $WORK"
  if [ ! -d "$WORK/si/dist" ]; then
    git clone --quiet https://github.com/CoNET-project/CoNET-SI "$WORK/si-repo"
    git -C "$WORK/si-repo" -c advice.detachedHead=false checkout --quiet "$SI_REV"
    mkdir -p "$WORK/si"
    git -C "$WORK/si-repo" archive "$SI_REV" | tar -x -C "$WORK/si"
    python3 tools/mixnet/si_patch.py "$WORK/si"
    (cd "$WORK/si" && npm ci --no-audit --no-fund --loglevel=error && npm install --no-save --no-audit --no-fund --loglevel=error typescript@5.4.5 && npx tsc --project tsconfig.json && cp src/endpoint/index.html dist/endpoint/)
  fi
  (cd conformance/vectors && [ -d node_modules ] || npm ci --ignore-scripts --no-audit --no-fund --loglevel=error)
  cargo build --locked -p conet-node --bin conet-node
  cargo test --locked -p conet-node --test mixnet --no-run
  echo "== entering an isolated network namespace"
  exec sudo -E env "PATH=$PATH" HOME="$HOME" MIXNET_INNER=1 MIXNET_WORK="$WORK" \
    unshare --net -- bash "$ROOT/tools/mixnet/run.sh" "$SI_REV"
fi

# ---------------------------------------------------------------- inside the namespace
ip link set lo up
ip link add dummy0 type dummy && ip link set dummy0 up
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
G=conformance/vectors/golden.json
NET=$WORK/net

anvil --host 127.0.0.1 --port 8545 --chain-id 224422 --silent > "$WORK/logs/anvil.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:8545 && break; sleep 0.2; done
node tools/mixnet/setup.mjs "$NET"

start_si() { # name ip
  (cd "$WORK/si" && HOME="$NET/$1/home" MIXNET_RPC=http://127.0.0.1:8545 MIXNET_LISTEN_HOST="$2" MIXNET_NODE_WALLETS="$NET/node-wallets.json" \
    node -e "new (require('./dist/endpoint/server').default)()") > "$WORK/logs/$1.log" 2>&1 &
  PIDS+=($!)
}
start_rust() { # name ip wallet
  CONET_DEV_ROUTE_PASS="" CONET_DEV_WALLET_KEY="$(jq -r ".wallets.$3.privateKey" $G)" RUST_LOG=conet_node=debug \
    target/debug/conet-node --insecure-dev-keys --dev-route-key "$NET/$1/route.sec" \
    --listen "$2:80" --health-listen "$2:9180" --rpc http://127.0.0.1:8545 \
    --mailbox-db "$NET/$1/mailbox.redb" --public-ip "$2" \
    --egress-policy "$WORK/policy-open.json" --egress-open-confirm --egress-no-chain-check \
    > "$WORK/logs/$1.log" 2>&1 &
  PIDS+=($!)
}
printf '{"version":1,"mode":"open"}' > "$WORK/policy-open.json"
start_si S1 127.0.0.2
start_si S2 127.0.0.3
start_rust R1 127.0.0.4 nodeC
start_rust R2 127.0.0.5 other

# Exit target: added after conet-node started, so it is not one of the node's own addresses.
sleep 2
ip addr add 9.9.9.9/32 dev dummy0
python3 - > "$WORK/logs/echo.log" 2>&1 <<'EOF' &
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("9.9.9.9", 7)); s.listen(64)
def serve(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
EOF
PIDS+=($!)

# Ready: both Rust nodes see 4 nodes, both SI nodes loaded the table.
ready() {
  for n in 4 5; do curl -s "http://127.0.0.$n:9180/healthz" | grep -q "nodes=4" || return 1; done
  for n in S1 S2; do grep -q "refresh OK nodes 0→4" "$WORK/logs/$n.log" || return 1; done
}
for _ in $(seq 60); do ready && break; sleep 1; done
ready || { echo "network did not come up"; tail -n 40 "$WORK"/logs/*.log; exit 1; }
echo "== network up"

set +e
MIXNET_CONFIG="$NET/mixnet.json" cargo test --locked --offline -p conet-node --test mixnet -- --test-threads=1
rc=$?
set -e
if [ $rc -ne 0 ]; then
  for f in "$WORK"/logs/{S1,S2,R1,R2}.log; do echo "---- $f"; grep -v "BEGIN PGP\|^\"-----" "$f" | tail -n 60; done
fi
exit $rc

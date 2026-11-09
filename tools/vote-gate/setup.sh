#!/usr/bin/env bash
# F5 vote gate cross-check setup (tests/vote_gate_anvil.rs). LOCAL anvil only, chain 224422.
# TEST keys only (golden vectors, anvil's public account 0).
#
# usage: tools/vote-gate/setup.sh <forge project with src/node-registry-v2> [rpc]
#   anvil --chain-id 224422 --port 18611 --hardfork cancun --code-size-limit 100000
# The forge project is a scratch copy of the node line's contract sources (not upstream yet),
# compiled like abi/README.md says. Writes f5.env (F5_RPC, F5_REGISTRY) in the current directory.
#
# Deploys NodeRegistryV2 and registers three nodes:
#   7 = golden nodeA (reserved/migrated, maint bit), 8 = nodeB (sponsored, no maint),
#   9 = nodeC wallet + golden "user" PGP key (sponsored, maint bit).
set -euo pipefail
PROJ="$(cd "${1:?forge project dir}" && pwd)"
OUT="$(pwd)"
R="$(cd "$(dirname "$0")/../.." && pwd)"
S="$(mktemp -d)"
trap 'rm -rf "$S"' EXIT
G=$R/conformance/vectors/golden.json
CR=$R/target/debug/conet-register
RPC=${2:-http://127.0.0.1:18611}
DEP=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil account 0 (public test key)
P=src/node-registry-v2
cd "$PROJ"
dep() { forge create --rpc-url $RPC --private-key $DEP --broadcast "$@" > "$S/f5fc.log" 2>&1 || true; awk '/Deployed to:/{print $3}' "$S/f5fc.log"; }
LIBS=()
for lib in PgpKeyIdLib RegistrationLib OfflineReportLib NodeAdminLib; do
  a=$(dep ${LIBS[@]+"${LIBS[@]}"} $P/$lib.sol:$lib); [ -n "$a" ] || { cat "$S/f5fc.log"; exit 1; }
  LIBS+=(--libraries $P/$lib.sol:$lib:$a)
done
OP=$(jq -r .wallets.other.address $G); OPK=$(jq -r .wallets.other.privateKey $G)
NA=$(jq -r .wallets.nodeA.address $G); NAK=$(jq -r .wallets.nodeA.privateKey $G)
NB=$(jq -r .wallets.nodeB.address $G); NBK=$(jq -r .wallets.nodeB.privateKey $G)
NC=$(jq -r .wallets.nodeC.address $G); NCK=$(jq -r .wallets.nodeC.privateKey $G)
GOV=$(cast wallet address $DEP)
for a in $OP $NA $NB $NC; do cast send -q --rpc-url $RPC --private-key $DEP $a --value 100ether; done
IPH=$(cast keccak "127.0.0.1"); KID=0x$(jq -r .keys.nodeA.encKeyId $G | tr A-F a-f)
BATCH=$(cast abi-encode "f(address[],(uint256,bytes32,uint16,bytes8,address,address,bool)[])" "[]" "[(7,$IPH,18080,$KID,$OP,$OP,false)]")
ZERO=0x0000000000000000000000000000000000000000000000000000000000000000
SEED=$(cast keccak "$(cast concat-hex "$(cast keccak $BATCH)" $ZERO)")
REG=$(dep "${LIBS[@]}" $P/NodeRegistryV2.sol:NodeRegistryV2 --constructor-args "($GOV,5000000000000000000,604800,1209600,$SEED,2592000,0x0000000000000000000000000000000000000000,$GOV,0)")
[ -n "$REG" ] || { grep -E "Error" -A4 "$S/f5fc.log"; exit 1; }
cast send -q --rpc-url $RPC --private-key $DEP $REG "seed(uint256,bytes,bytes32)" 0 $BATCH $ZERO
echo "reg=$REG"
jq -r .keys.nodeA.armoredPublic $G > "$S/f5-a.pub"
jq -r .keys.nodeB.armoredPublic $G > "$S/f5-b.pub"
jq -r .keys.user.armoredPublic $G > "$S/f5-c.pub"
D=$(( $(cast block --rpc-url $RPC latest -f timestamp) + 3600 ))
bind_sign() {
  jq --arg reg "$REG" '{
    types: {
      EIP712Domain: [{name:"name",type:"string"},{name:"version",type:"string"},{name:"chainId",type:"uint256"},{name:"verifyingContract",type:"address"}],
      BindNode: [{name:"operator",type:"address"},{name:"nodeId",type:"uint256"},{name:"ipHash",type:"bytes32"},{name:"keyId",type:"bytes8"},{name:"pgpHash",type:"bytes32"},{name:"nonce",type:"uint256"},{name:"deadline",type:"uint256"}]
    },
    primaryType: "BindNode",
    domain: {name:"CoNETNodeRegistry",version:"1",chainId:224422,verifyingContract:$reg},
    message: {operator:.operator,nodeId:.nodeId,ipHash:.ipHash,keyId:.keyId,pgpHash:.pgpHash,nonce:.nonce,deadline:.deadline}
  }' <<<"$1" > "$S/f5-bind.json"
  cast wallet sign --data --from-file "$S/f5-bind.json" --private-key "$2"
}
COMMON=(--legacy-id 7 --operator $OP --ip 127.0.0.1 --udp-port 18081 --node-wallet $NA --pgp-public "$S/f5-a.pub" --services 0x29 --deadline $D --rpc $RPC --registry $REG)
BIND=$($CR reserved-bind "${COMMON[@]}" | jq -c .bind)
DATA=$($CR reserved "${COMMON[@]}" --bind-sig "$(bind_sign "$BIND" $NAK)" | jq -r .calldata)
cast send -q --rpc-url $RPC --private-key $OPK $REG $DATA --value 5ether && echo "registered 7"
sponsored() { # wallet key pub ip services nonce
  $CR request --registry $REG --operator $OP --beneficiary $OP --node-wallet $1 --ip $4 \
    --tcp-port 18090 --udp-port 18091 --pgp-public "$3" --services $5 --sponsor 7 \
    --nonce $6 --deadline $D > "$S/f5-req.json"
  jq .typedData "$S/f5-req.json" > "$S/f5-req-td.json"
  OSIG=$(cast wallet sign --data --from-file "$S/f5-req-td.json" --private-key $OPK)
  cast send -q --rpc-url $RPC --private-key $OPK $REG "$(jq -r .prestakeCalldata "$S/f5-req.json")" --value 5ether
  NSIG=$(bind_sign "$(jq -c .bind "$S/f5-req.json")" $2)
  cast send -q --rpc-url $RPC --private-key $NAK $REG "$($CR register-for --request "$S/f5-req.json" --operator-sig $OSIG --node-sig $NSIG | jq -r .calldata)"
}
sponsored $NB $NBK "$S/f5-b.pub" 127.0.0.2 3 42 && echo "registered nodeB"
sponsored $NC $NCK "$S/f5-c.pub" 127.0.0.3 0x29 43 && echo "registered nodeC"
for w in $NA $NB $NC; do echo "$w -> $(cast call --rpc-url $RPC $REG 'nodeIdOfNodeWallet(address)(uint256)' $w)"; done
printf 'F5_RPC=%s\nF5_REGISTRY=%s\n' $RPC $REG > "$OUT/f5.env"
echo "wrote $OUT/f5.env"

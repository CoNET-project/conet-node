#!/usr/bin/env python3
"""Fixture patch for a scratch copy of CoNET-SI used in the mixed-network test.

Applied to an exported copy only (never to the CoNET-SI repository). Every change is listed
here and must apply exactly once, so a new SI revision that moves the code fails loudly.

1. RPC: the two CoNET RPC constants read MIXNET_RPC (a local anvil).
2. Treasury V3 vote listener: not started (it would sign bridge votes with the node wallet).
3. Listen address: bind the node's own IP (MIXNET_LISTEN_HOST), so several SI nodes can share
   port 80 on one host's loopback range.

Contract addresses are not patched: setup.mjs places the contracts at their mainnet addresses
on the local chain. Outbound HTTPS (API, IPFS) fails inside the isolated network namespace.
usage: si_patch.py <si dir>
"""
import pathlib
import sys

PATCHES = [
    (
        "src/util/util.ts",
        "export const CoNET_CancunRPC = 'https://cancun-rpc.conet.network'",
        "export const CoNET_CancunRPC = process.env.MIXNET_RPC as string",
    ),
    (
        "src/util/util.ts",
        "export const CoNET_mainnet_RPC = 'https://publicrpc.conet.network'",
        "export const CoNET_mainnet_RPC = process.env.MIXNET_RPC as string",
    ),
    (
        "src/endpoint/server.ts",
        "void startTreasuryV3VoteListen(this.nodeWallet, baseRpc, conetRpc).catch(",
        "if (!process.env.MIXNET_RPC) void startTreasuryV3VoteListen(this.nodeWallet, baseRpc, conetRpc).catch(",
    ),
    (
        "src/endpoint/server.ts",
        "server.listen ( this.initData?.ipV4Port, () => {",
        "server.listen ( this.initData?.ipV4Port, process.env.MIXNET_LISTEN_HOST as string, () => {",
    ),
]


def main() -> None:
    root = pathlib.Path(sys.argv[1])
    for rel, old, new in PATCHES:
        p = root / rel
        text = p.read_text()
        n = text.count(old)
        if n != 1:
            sys.exit(f"si_patch: {rel}: expected 1 match, found {n}: {old[:60]}")
        p.write_text(text.replace(old, new))
    print(f"si_patch: {len(PATCHES)} changes applied")


if __name__ == "__main__":
    main()

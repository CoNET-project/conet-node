#!/usr/bin/env python3
"""Refresh crates/conet-node/abi from a compiled copy of the node line's contract tree.

usage: tools/abi-refresh.py <artifacts dir containing NodeRegistryV2.sol/...>
NodeRegistryV2.json = core ABI (minus getNodeRaw: past alloy's tuple limit) + events / errors of
the linked libraries + functions / events / errors of NodeRegistryV2Ext (reached through the
core's fallback, so calls go to the registry address)."""
import json, os, sys

A = sys.argv[1]
OUT = os.path.join(os.path.dirname(__file__), "..", "crates", "conet-node", "abi")


def abi(n):
    return json.load(open(f"{A}/{n}.sol/{n}.json"))["abi"]


def key(x):
    return (x.get("type"), x.get("name"), json.dumps([i["type"] for i in x.get("inputs", [])]))


out, seen = [], set()
for x in abi("NodeRegistryV2"):
    if x.get("type") == "function" and x["name"] == "getNodeRaw":
        continue
    seen.add(key(x)); out.append(x)
for lib in ["NodeAdminLib", "RegistrationLib", "OfflineReportLib", "AdmissionLib", "OnlineVoteLib"]:
    if os.path.exists(f"{A}/{lib}.sol/{lib}.json"):
        for x in abi(lib):
            if x.get("type") in ("event", "error") and key(x) not in seen:
                seen.add(key(x)); out.append(x)
for x in abi("NodeRegistryV2Ext"):
    if x.get("type") in ("function", "event", "error") and key(x) not in seen:
        seen.add(key(x)); out.append(x)
json.dump(out, open(f"{OUT}/NodeRegistryV2.json", "w"), indent=1)
json.dump(abi("NodeRegistryLens"), open(f"{OUT}/NodeRegistryLens.json", "w"), indent=1)
print(f"NodeRegistryV2.json: {len(out)} entries")

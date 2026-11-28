# Owner signature for delegated requests

Some node commands act on a wallet's mailbox or session: `walletAddress` in the message says whose. A request may be paid for by another wallet (`billingWallet`, the paying wallet). The paying wallet signs the request as before. When the paying wallet is not the wallet the request acts on, the request also carries `ownerSignature`, a signature by the `walletAddress` wallet that authorizes this one message. The billing identity is used for billing only; it does not stand in for the owner.

## Commands

`ownerSignature` applies to these commands (`OWNER_BOUND_COMMANDS` in `crates/si-proto/src/lib.rs`):

`mailbox_listen`, `gossip_delivery_ack`, `push_device_register`, `mining`, `mining_validator`, `SaaS_Sock5`, `SaaS_Sock5_v2`, `wallet_online_query`, `wallet_native_wake_query`.

Other commands are unchanged.

## Where the field sits

The command envelope is a JSON object that is base64 encoded and sent as before:

```json
{
  "message":       "<the exact message string, JSON text with walletAddress, command, ...>",
  "signMessage":   "<signature of message by the paying wallet>",
  "ownerSignature":"<signature by walletAddress over the owner statement>"
}
```

`ownerSignature` is a sibling of `message` and `signMessage`. It is not part of `message`, so adding it does not change `message` or `signMessage`.

## What is signed

The owner statement is exactly two lines joined by a single `\n`, with no trailing newline:

```
CoNET-SI owner authorization v1
0x<64 lowercase hex>
```

The second line is the keccak256 of the UTF-8 bytes of the `message` string exactly as it appears in the envelope (the same bytes the paying wallet signs), written as `0x` plus lowercase hex. Any change to `message`, including whitespace, gives a different statement.

The statement is signed as an EIP-191 personal message (`personal_sign`, the `\x19Ethereum Signed Message:\n<length>` prefix), with the key of the `walletAddress` wallet. The signature has the same encoding as `signMessage` (65 bytes, hex).

## What the node checks

1. `message` is JSON with a valid `walletAddress` and `command`.
2. `signMessage` recovers to `billingWallet`, or to `walletAddress` when there is no `billingWallet` (unchanged).
3. For the commands above, when `billingWallet` is set and is a different address from `walletAddress`: `ownerSignature` must be present and must recover to `walletAddress` over the statement for this message. Otherwise the request is rejected as a signature failure.

## Self-paid requests

A request signed by `walletAddress` itself needs no `ownerSignature`. That covers a message without `billingWallet` and a message whose `billingWallet` equals `walletAddress`. A client that never delegates payment does not change.

## Notes for client authors

* Sign the statement with the key of the wallet named in `walletAddress`. If that wallet is a temporary wallet held by the client, the client signs both the statement (temporary wallet) and `signMessage` (paying wallet).
* The proof covers one message. Build a new one for each message; do not cache or reuse it.
* Update clients before a node enables the check: a node that enforces it rejects delegated requests that lack the field.

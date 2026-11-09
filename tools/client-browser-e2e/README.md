# CLIENT-BROWSER end-to-end test

Local Chrome (Playwright, the installed Chrome, nothing downloaded) plus a local Hardhat chain
running the node line's NodeRegistryV2 + NodeRegistryV2Ext.

| Step | What runs |
| --- | --- |
| 1 | The browser node sends its own `setOffline`. Checks: `isActive` false, Lens `getActiveNodesByType` no longer lists it, the page shows offline. |
| 3a | `markOnline` from the page and `setOnline` from an anchor, with no vote, are refused (`RecoveryVoteRequired`). |
| 2 | The page makes a DTLS certificate and computes the D8 `endpointHash`, then sends `requestRecovery`. Then 20 voters each: open a real WebRTC connection; read their own `getStats` (path id, remote candidate, both DTLS fingerprints); send a PGP-signed and encrypted challenge over the data channel. The page answers after checking the voter key on chain, the current `recId`, the endpoint and both fingerprints. The voter checks the reply and that its path is unchanged, then sends `voteRecovery`. After 5 minutes (`time.increase`) the page sends `finalizeRecovery`, and the node is online and listed again. |
| 3b | The endpoint changes mid-vote: the page makes a new certificate. An immediate new request is refused by the node line's 5-minute gap (C17). A voter connecting in the gap sees the new fingerprint and refuses on its own. After the gap the new request voids the old one, a late vote on the old `recId` reverts `AdmissionState`, and 20 fresh votes complete recovery. |

What this is not:
- The browser-node page is a **test-harness client**: no product browser-node client exists yet.
- The voters are this script, with their WebRTC ends in a second Chrome page.
- The chain is Hardhat's in-process EDR chain. Nothing is deployed anywhere else.
- The page reaches the chain only through a Playwright `exposeFunction` RPC bridge. It signs its own type-2 transactions.
- The pages are served by Playwright from `https://*.test` origins, because WebCrypto is not available on `about:blank`. No network request leaves the machine.

## Run

You need a **copy** of the node line's contract tree:
- `src/b-unit/node-registry-v2`
- `test/node-registry-v2`
- `hardhat.node-registry.config.ts`
- `package.json` with `"type": "module"`

Do not run this inside the node line's worktree. Use only `hardhat.node-registry.config.ts`: the main `hardhat.config.ts` reads a production key file.

The copy also needs `node_modules` with hardhat 3, ethers 6, openpgp 6 and playwright.

```bash
cp client-browser.e2e.test.ts client-browser-page.js <copy>/test/node-registry-v2/
```

```bash
cd <copy> && patch -p0 < <this dir>/helpers-privateArmored.patch
```

```bash
cd <copy> && npx hardhat --config hardhat.node-registry.config.ts test mocha test/node-registry-v2/client-browser.e2e.test.ts
```

The patch makes the test helpers keep each generated PGP private key, because voters and the browser node sign with PGP. The log is written to `<copy>/client-browser-e2e.log`, or to `$CLIENT_BROWSER_LOG` if set. Local addresses in the log are masked.

## D8 endpoint hash used here

`endpointHash = keccak256(0x02 ‖ keccak256(fp_norm) ‖ relay ? 0x01 : 0x00 ‖ keccak256(relay or ""))`

`fp_norm` is the SHA-256 DTLS fingerprint with `0x` and `:` removed, in upper case. It matches `Endpoint::Browser::endpoint_hash` in `crates/conet-node/src/admission.rs`. The node line has not adopted it yet (D8).

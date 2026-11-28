# Post acknowledgement: stored, duplicate, store_failed

A mailbox answers a post (`POST /post`, a bare armor or mailbox work) with HTTP 200 and a small JSON body that says what it did with the armor.

| What happened | Body |
| --- | --- |
| Stored now | `{"ok":true,"stored":true,"h":"0x<64 hex>"}` |
| Already held (same armor, byte for byte) | `{"ok":true,"duplicate":true,"h":"0x<64 hex>"}` |
| Could not be stored | `{"ok":false,"error":"store_failed"}` (no `h`) |

The mailbox replies after it has tried to write. The Rust entry relays the mailbox's body unchanged (tested); the TS entry is a pipe in the code, but forwarding the new body through it has not been verified end to end. Senders that only look for `ok:false` keep working: the two success bodies have `ok:true`, a storage failure is `ok:false` (as `no_route` already is). A sender that receives an empty 200 from an older node has no digest and must treat the post as unconfirmed.

## The digest `h`

`h` is `0x` plus the lowercase hex of keccak256 over the UTF-8 bytes of the armor exactly as the mailbox stored it. It is the same value as the `armorHash` of `gossip_delivery_ack` and as `h_in` in the evidence log.

* Bare armor post: the posted `data` string, byte for byte.
* Mailbox work (`{"data": <armor>}` encrypted to the mailbox's route key): the `data` string, trimmed and cut after the `-----END PGP MESSAGE-----` line. No line-end conversion is applied; CRLF characters inside the JSON string are kept.
* Onion (the entry decrypts a layer whose plaintext is itself an armor): the decrypted text with `\r\n` replaced by `\n` (openpgp text mode writes CRLF), trimmed and cut after the END line; the mailbox stores that form.

For a chat message built by the SDK (user armor, wrapped as mailbox work, wrapped to the entry), the user armor has no CR and ends with a newline, so the expected `h` is keccak256 of the trimmed user armor (`keccakUtf8(userArmor.trim())`); measured with the real SDK.

The TS node (`hashPgpArmor`) and the Rust node (`armor_hash`) give the same value for the same string; `crates/conet-node/tests/data/post_ack_hash_vectors.json` is checked by both.

## Retrying

Retry with the same armor; do not encrypt again. The same armor answered `duplicate` (still held) or `stored` (after a failure, or after the recipient's ACK removed it) leaves one copy; a re-encrypted message is a different armor and would be stored as a second message.

## Limits (read before relying on it)

* Scope: measured and tested on the Rust node at commit `e4d4aed1`. For the TS node this is a static reading of the code at `74c6cfda`; the TS node's current `main` is identical on this path. It has not been reproduced on deployed nodes, and a storage failure has not been reproduced outside a local test volume.
* TS `stored` means the write was handed to the operating system: no `fsync`, not an atomic write. Rust `stored` means the redb commit succeeded.
* `duplicate` means "still held now". After the recipient's ACK deletes the armor, a retry is stored again.
* `store_failed` means that durable storage is not confirmed. A retry of the same armor ends as `stored` or `duplicate`, so one copy is kept in the end. Live delivery to a connected recipient still happens and may already have taken place; clients de-duplicate by the armor digest.
* After a database I/O error (for example a full disk) the redb handle keeps failing until the process is restarted (redb: "A previous IO error occurred. The database must be closed and re-opened"). While it is stuck, posts answer `store_failed`, an ACK that would delete an armor fails as well, and reading the mailbox and live fan-out keep working. Measured: the same process answers `store_failed` for the same armor even after space was freed; after a restart the same armor ends as `stored` or `duplicate` (which one depends on whether the failed commit reached the file). Before this change those posts were answered with an empty 200 and dropped.
* An older Rust entry turns `store_failed` into `no_route`: still `ok:false`, but the reason is lost.
* The default regression run does not cover the branch where `DiskStore` maps a database error to `Failed`; `tests/post_ack_measure.rs` (ignored by default, needs a small volume it fills) does.

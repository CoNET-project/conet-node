// Baseline: the same operations with openpgp.js 6 + ethers 6 (what live SI runs).
// Usage: node bench-js.mjs golden.json op n
import * as openpgp from 'openpgp'
import { ethers } from 'ethers'
import { readFileSync } from 'fs'
import { sealMailboxStreamPayload } from './si-src/mailboxStream.ts'
const [, , gp, op, n0] = process.argv
const n = Number(n0 || 100)
const g = JSON.parse(readFileSync(gp, 'utf8'))
const vin = (id) => g.vectors.find((v) => v.id === id)
const p = await openpgp.readPrivateKey({ armoredKey: g.keys.nodeA.armoredPrivate })
const key = await openpgp.decryptKey({ privateKey: p, passphrase: g.keys.nodeA.passphrase })
const pubA = await openpgp.readKey({ armoredKey: g.keys.nodeA.armoredPublic })
const w = new ethers.Wallet(g.wallets.client.privateKey)
const cmd = vin('post-cmd-mailbox-listen').input.armor
const fwd = vin('post-not-local').input.armor
const sig = vin('eip191-ascii')
const ops = {
	classify_command: async () => {
		const m = await openpgp.readMessage({ armoredMessage: cmd })
		m.getEncryptionKeyIDs()
		const d = await openpgp.decrypt({ message: m, decryptionKeys: key, format: 'binary' })
		const c = JSON.parse(Buffer.from(Buffer.from(d.data).toString('utf8'), 'base64').toString())
		ethers.recoverAddress(ethers.id(c.message), c.signMessage)
		ethers.verifyMessage(c.message, c.signMessage)
	},
	classify_forward: async () => { (await openpgp.readMessage({ armoredMessage: fwd })).getEncryptionKeyIDs() },
	eip191_sign: async () => w.signMessage('bench message'),
	eip191_recover: async () => ethers.verifyMessage(sig.input.message, sig.expect.signature),
	encrypt_1k: async () => openpgp.encrypt({ message: await openpgp.createMessage({ text: 'x'.repeat(1024) }), encryptionKeys: pubA, config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib } }),
	seal_frame: async () => sealMailboxStreamPayload({ type: 'keepalive' }, Buffer.alloc(32, 1)),
}
await ops[op]()
const t = performance.now()
for (let i = 0; i < n; i++) await ops[op]()
const ms = performance.now() - t
console.log(`${op} n=${n} total_ms=${ms.toFixed(1)} per_op_ms=${(ms / n).toFixed(3)}`)

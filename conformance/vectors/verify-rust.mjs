// Reverse check: Rust-made artifacts must decrypt / verify with openpgp.js 6 and SI code.
// Usage: node verify-rust.mjs golden.json artifacts.json
import * as openpgp from 'openpgp'
import { ethers } from 'ethers'
import { readFileSync } from 'fs'
import { parseHopSigsFromHeaders, verifyHopSigs, hopArmorHash } from './si-src/siHopSigs.ts'
import { decryptUdpPayload } from './si-src/udpForwardCrypto.ts'
import { isVoiceChunk, chunkMac } from './si-src/voiceHelpers.ts'
import { createDecipheriv } from 'crypto'

const g = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const a = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const priv = async (k) => {
	const p = await openpgp.readPrivateKey({ armoredKey: g.keys[k].armoredPrivate })
	return p.isDecrypted() ? p : openpgp.decryptKey({ privateKey: p, passphrase: g.keys[k].passphrase })
}
const pub = (k) => openpgp.readKey({ armoredKey: g.keys[k].armoredPublic })
// SI decrypt path: format 'binary', utf8, CRLF -> LF (postOpenpgpRouteSocket)
const siDecrypt = async (armor, k, verificationKeys) => {
	const message = await openpgp.readMessage({ armoredMessage: armor })
	const r = await openpgp.decrypt({ message, decryptionKeys: await priv(k), format: 'binary', ...(verificationKeys ? { verificationKeys, expectSigned: false } : {}) })
	return { bytes: r.data, text: Buffer.from(r.data).toString('utf8').replace(/\r\n/g, '\n'), r, message }
}
const keyIds = async (armor) => (await openpgp.readMessage({ armoredMessage: armor })).getEncryptionKeyIDs().map((k) => k.toHex().toUpperCase())

const results = []
const check = async (id, fn) => {
	try {
		const detail = await fn()
		results.push({ id, pass: detail === true || detail?.pass === true, detail: detail === true ? undefined : detail })
	} catch (e) {
		results.push({ id, pass: false, error: String(e?.message ?? e) })
	}
}

await check('route-command', async () => {
	const { text } = await siDecrypt(a.routeCommand.armor, 'nodeA')
	const content = JSON.parse(Buffer.from(text, 'base64').toString())
	const signer = ethers.verifyMessage(content.message, content.signMessage)
	return { pass: signer === a.routeCommand.expectSigner && content.message === JSON.stringify(a.routeCommand.expectCommand), signer }
})
await check('mailbox-work', async () => {
	const { text } = await siDecrypt(a.mailboxWork.armor, 'nodeA')
	const rec = JSON.parse(text)
	const inner = await keyIds(rec.data)
	const innerPlain = await siDecrypt(rec.data, 'user')
	return { pass: rec.NoPush === true && inner.length === 1 && inner[0] === g.keys.user.encKeyId && innerPlain.text.includes('from rust') }
})
await check('onion', async () => {
	const { text } = await siDecrypt(a.onion.armor, 'nodeA')
	const inner = await keyIds(text.trim())
	return { pass: inner[0] === g.keys.nodeB.encKeyId }
})
await check('voice-chunk-binary-literal', async () => {
	const { bytes } = await siDecrypt(a.voiceChunk.armor, 'nodeA')
	const b = Buffer.from(bytes)
	const ok = isVoiceChunk(bytes) && b.equals(Buffer.from(a.voiceChunk.chunkB64, 'base64')) &&
		chunkMac(Buffer.from(a.voiceChunk.writeKeyB64, 'base64'), b.subarray(4, 20), b.subarray(36)).equals(b.subarray(20, 36))
	return { pass: ok }
})
await check('signed-encrypted', async () => {
	const { text, r } = await siDecrypt(a.signedEncrypted.armor, 'nodeA', await pub('user'))
	let verified = false
	try { await r.signatures[0].verified; verified = true } catch {}
	return { pass: text === a.signedEncrypted.text && verified }
})
await check('detached-text-signature', async () => {
	const v = await openpgp.verify({ message: await openpgp.createMessage({ text: a.detached.text }), signature: await openpgp.readSignature({ armoredSignature: a.detached.signature }), verificationKeys: await pub('user') })
	await v.signatures[0].verified
	return true
})
await check('cleartext-signature', async () => {
	const v = await openpgp.verify({ message: await openpgp.readCleartextMessage({ cleartextMessage: a.cleartext.armor }), verificationKeys: await pub('user') })
	await v.signatures[0].verified
	return { pass: v.data.replace(/\r\n/g, '\n') === a.cleartext.text }
})
await check('multiline-utf8', async () => {
	const { text } = await siDecrypt(a.multiline.armor, 'nodeA')
	return { pass: text === a.multiline.textLf, got: JSON.stringify(text) }
})
await check('sealed-mailbox-frame', async () => {
	// same algorithm as chat SDK openMailboxStreamFrame
	const blob = Buffer.from(a.sealed.sealed, 'base64')
	const key = await crypto.subtle.importKey('raw', Buffer.from(a.sealed.keyB64, 'base64'), { name: 'AES-GCM' }, false, ['decrypt'])
	const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(0, 12) }, key, blob.subarray(12))
	const t = new TextDecoder().decode(plain)
	return { pass: t.trim() === a.sealed.json && t.length % 256 === 0 && t.length > a.sealed.json.length }
})
await check('udp-payload', async () => {
	const out = decryptUdpPayload(Buffer.from(a.udp.keyB64, 'base64'), a.udp.payload)
	return { pass: out?.toString() === a.udp.plaintext }
})
await check('eip191', async () => ({ pass: ethers.verifyMessage(a.eip191.message, a.eip191.signature) === a.eip191.address }))
await check('entry-forward-hop-header', async () => {
	const act = a.entryForward.actions[0]
	if (act?.action !== 'forward') return { pass: false, act }
	const hops = parseHopSigsFromHeaders([act.hop_header])
	const realNow = Date.now
	Date.now = () => a.now * 1000
	const valid = verifyHopSigs(hops)
	Date.now = realNow
	return { pass: Array.isArray(hops) && hops.length === 1 && valid.length === 1 && hops[0].h === hopArmorHash(a.entryForward.armor) && hops[0].w === new ethers.Wallet(g.wallets.nodeA.privateKey).address, hops }
})

console.log(JSON.stringify({ summary: { pass: results.filter((r) => r.pass).length, fail: results.filter((r) => !r.pass).length }, results }, null, 1))

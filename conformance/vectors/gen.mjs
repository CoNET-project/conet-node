// Golden vector generator. TEST KEYS ONLY: every key and wallet below is
// generated here or derived from a public test string. Never put a real node
// or user key into this file or into golden.json.
//
// Uses the same libraries as live CoNET-SI (openpgp 6.3.0, ethers 6) through
// the `node_modules` symlink, plus verbatim copies of SI source files in
// `si-src/` (rev 74c6cfd). Run: node gen.mjs > golden.json
import * as openpgp from 'openpgp'
import { ethers } from 'ethers'
import { randomBytes } from 'crypto'
import { sealMailboxStreamPayload, MAILBOX_STREAM_PAD } from './si-src/mailboxStream.ts'
import { hopSigPayload, hopArmorHash, serializeHopSigsHeaderValue, SI_HOP_SIG_HEADER } from './si-src/siHopSigs.ts'
import { encryptUdpPayload } from './si-src/udpForwardCrypto.ts'
import { voicePayText, voiceListenText, chunkMac, VOICE_CHUNK_MAGIC, voiceCallPushText } from './si-src/voiceHelpers.ts'
import { verifyVoiceListenV3, frameLine, voiceHeaders, voiceHandshake } from './si-src/voiceListen.ts'

const zlib = { preferredCompressionAlgorithm: openpgp.enums.compression.zlib }
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')
const testWallet = (label) => new ethers.Wallet(ethers.keccak256(ethers.toUtf8Bytes(`conet-m0-TEST-ONLY:${label}`)))

// ---- keys: same options SI (generatePgpKey) and the PWA (chatRouteRegister) use
const genKey = async (name, passphrase) => {
	const { privateKey, publicKey } = await openpgp.generateKey({
		type: 'ecc', curve: 'curve25519', passphrase, userIDs: [{ name }], format: 'armored',
	})
	const pub = await openpgp.readKey({ armoredKey: publicKey })
	return {
		armoredPrivate: privateKey,
		armoredPublic: publicKey,
		passphrase,
		keyIds: pub.getKeyIDs().map((k) => k.toHex().toUpperCase()),
		encKeyId: pub.getKeyIDs()[1].toHex().toUpperCase(), // SI getPublicKeyArmoredKeyID
		fingerprint: pub.getFingerprint().toUpperCase(),
		algo: pub.getAlgorithmInfo(),
		version: pub.keyPacket.version,
	}
}

const wallets = {
	client: testWallet('client'),
	billing: testWallet('billing'),
	nodeA: testWallet('node-a'),
	nodeB: testWallet('node-b'),
	nodeC: testWallet('node-c'),
	payer: testWallet('payer'),
	temp: testWallet('temp'),
	other: testWallet('other'),
}

const keys = {
	nodeA: await genKey(wallets.nodeA.address, 'test-only-passphrase-a'),
	nodeB: await genKey(wallets.nodeB.address, 'test-only-passphrase-b'),
	user: await genKey(wallets.client.address, ''),
	user2: await genKey(wallets.other.address, ''),
}
const pub = async (k) => openpgp.readKey({ armoredKey: keys[k].armoredPublic })
const priv = async (k) => {
	const p = await openpgp.readPrivateKey({ armoredKey: keys[k].armoredPrivate })
	return p.isDecrypted() ? p : openpgp.decryptKey({ privateKey: p, passphrase: keys[k].passphrase })
}

const encText = async (text, to, extra = {}) =>
	openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: to, config: zlib, ...extra })
const encBin = async (binary, to) =>
	openpgp.encrypt({ message: await openpgp.createMessage({ binary }), encryptionKeys: to, config: zlib })

const packetTags = async (armor) => {
	const m = await openpgp.readMessage({ armoredMessage: armor })
	return m.packets.map((p) => p.constructor.tag)
}

const vectors = []
const add = (id, kind, input, expect) => vectors.push({ id, kind, input, expect })

// ---- 1. key IDs
for (const k of Object.keys(keys)) {
	add(`keyid-${k}`, 'pgp_key_ids', { key: k }, {
		keyIds: keys[k].keyIds, encKeyId: keys[k].encKeyId, fingerprint: keys[k].fingerprint,
	})
}

// ---- 2. EIP-191 sign (RFC 6979, deterministic) + raw keccak digest sign (checkSign's second path)
for (const [label, msg] of [['ascii', 'hello conet'], ['json', JSON.stringify({ command: 'mailbox_listen', walletAddress: wallets.client.address.toLowerCase() })], ['utf8', '路由 測試 ✓']]) {
	add(`eip191-${label}`, 'eip191', { wallet: 'client', message: msg }, {
		signature: await wallets.client.signMessage(msg), address: wallets.client.address,
	})
	add(`rawdigest-${label}`, 'raw_digest', { wallet: 'client', message: msg }, {
		signature: wallets.client.signingKey.sign(ethers.id(msg)).serialized, address: wallets.client.address,
	})
}

// ---- 3. /post classification (mirror of postOpenpgpRouteSocket, see classifyRef below)
const commandArmor = async (wallet, cmd, to) => {
	const message = JSON.stringify(cmd)
	const signMessage = await wallet.signMessage(message)
	return encText(b64(JSON.stringify({ message, signMessage })), to)
}
const now = Math.floor(Date.now() / 1000)
const streamKey = randomBytes(32)

const userBusiness = await encText(JSON.stringify({ v: 1, text: 'hi', from: 'inside-ciphertext-only' }), await pub('user'))
const cases = {
	// entry: key is not ours -> forward untouched
	'not-local': userBusiness,
	// signed commands
	'cmd-mailbox-listen': await commandArmor(wallets.client, {
		command: 'mailbox_listen', walletAddress: wallets.client.address.toLowerCase(), streamKey: streamKey.toString('base64'), timestamp: now,
	}, await pub('nodeA')),
	'cmd-online-query': await commandArmor(wallets.client, {
		command: 'wallet_online_query', walletAddress: wallets.client.address, targetWallet: wallets.other.address, timestamp: now,
	}, await pub('nodeA')),
	'cmd-billing': await commandArmor(wallets.billing, {
		command: 'udp_listen', walletAddress: wallets.client.address, billingWallet: wallets.billing.address, sessionId: 'a'.repeat(32), timestamp: now,
	}, await pub('nodeA')),
	'cmd-bad-signer': await (async () => {
		const message = JSON.stringify({ command: 'mining', walletAddress: wallets.client.address })
		const signMessage = await wallets.other.signMessage(message)
		return encText(b64(JSON.stringify({ message, signMessage })), await pub('nodeA'))
	})(),
	// unsigned voice command (sessionId is the capability)
	'voice-unlisten': await encText(b64(JSON.stringify({ command: 'voice_unlisten', sessionId: 'b'.repeat(32) })), await pub('nodeA')),
	// mailbox work
	'mailbox-work': await encText(JSON.stringify({ data: userBusiness }), await pub('nodeA')),
	'mailbox-work-nopush': await encText(JSON.stringify({ data: userBusiness, NoPush: true }), await pub('nodeA')),
	'mailbox-work-b64': await encText(b64(JSON.stringify({ data: userBusiness })), await pub('nodeA')),
	// onion: outer to A, inner armor to B -> forward inner
	'onion-to-b': await encText(await encText(b64(JSON.stringify({ command: 'x' })), await pub('nodeB')), await pub('nodeA')),
	// inner armor to A again -> attack
	'onion-same-node': await encText(await encText('x', await pub('nodeA')), await pub('nodeA')),
	// multi-recipient armor -> reject
	'multi-recipient': await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'x' }), encryptionKeys: [await pub('nodeA'), await pub('nodeB')], config: zlib }),
	// garbage plaintext -> reject
	'garbage': await encText('not json, not armor', await pub('nodeA')),
	// sign-then-encrypt with a PGP signature (business form some clients use)
	'pgp-signed-to-a': await openpgp.encrypt({
		message: await openpgp.createMessage({ text: JSON.stringify({ data: userBusiness }) }),
		encryptionKeys: await pub('nodeA'), signingKeys: await priv('user'), config: zlib,
	}),
}

// voice chunk: binary literal CVC2 || locator(16) || mac(16) || blob
const voiceSession = randomBytes(16)
const writeKey = randomBytes(32)
const blob = randomBytes(300)
const voiceChunk = Buffer.concat([VOICE_CHUNK_MAGIC, voiceSession, chunkMac(writeKey, voiceSession, blob), blob])
cases['voice-chunk'] = await encBin(new Uint8Array(voiceChunk), await pub('nodeA'))
const badChunk = Buffer.from(voiceChunk); badChunk[badChunk.length - 1] ^= 1
cases['voice-chunk-badmac'] = await encBin(new Uint8Array(badChunk), await pub('nodeA'))

// ---- reference classifier: a line-by-line JS mirror of SI postOpenpgpRouteSocket's branches
const asPgpMessageArmor = (text) => {
	const t = text.trim()
	if (!t.startsWith('-----BEGIN PGP MESSAGE-----')) return null
	const end = t.indexOf('-----END PGP MESSAGE-----')
	return end < 0 ? null : t.slice(0, end + '-----END PGP MESSAGE-----'.length)
}
const singleKey = (ids) => (ids?.length === 1 ? ids[0].toHex().toUpperCase() : null)
const voiceCmds = new Set(['voice_listen', 'voice_unlisten', 'voice_offer_store', 'voice_offer_fetch'])
const checkSign = (message, sig) => {
	try {
		const obj = JSON.parse(message)
		const wallet = obj.walletAddress
		if (voiceCmds.has(obj.command) && typeof obj.sessionId === 'string' && obj.sessionId.length >= 16) {
			return { ...obj, walletAddress: '', billingWallet: '' }
		}
		const billing = obj.billingWallet || wallet
		const raw = ethers.recoverAddress(ethers.id(message), sig).toLowerCase()
		const v = ethers.verifyMessage(message, sig).toLowerCase()
		if (!billing || !ethers.isAddress(billing)) return null
		if (v !== billing.toLowerCase() && raw !== billing.toLowerCase()) return null
		if (wallet && ethers.isAddress(wallet) && (obj.billingWallet || v === wallet.toLowerCase() || raw === wallet.toLowerCase())) {
			obj.walletAddress = wallet.toLowerCase()
			if (obj.billingWallet) obj.billingWallet = obj.billingWallet.toLowerCase()
			return obj
		}
		return null
	} catch { return null }
}
const classifyRef = async (armor, localKey, writeKeys) => {
	let m
	try { m = await openpgp.readMessage({ armoredMessage: armor }) } catch { return { type: 'reject', reason: 'not_pgp' } }
	const kid = singleKey(m.getEncryptionKeyIDs())
	if (!kid) return { type: 'reject', reason: 'recipient_count' }
	if (kid !== keys[localKey].encKeyId) return { type: 'forward', keyId: kid }
	let bytes
	try {
		bytes = (await openpgp.decrypt({ message: m, decryptionKeys: await priv(localKey), format: 'binary' })).data
	} catch { return { type: 'reject', reason: 'decrypt' } }
	if (bytes.length > 36 && Buffer.from(bytes.subarray(0, 4)).equals(VOICE_CHUNK_MAGIC)) {
		const loc = Buffer.from(bytes.subarray(4, 20)); const mac = Buffer.from(bytes.subarray(20, 36)); const bl = Buffer.from(bytes.subarray(36))
		const wk = writeKeys[loc.toString('hex')]
		return { type: 'voice_chunk', locator: loc.toString('hex'), macOk: !!wk && chunkMac(Buffer.from(wk, 'base64'), loc, bl).equals(mac), blobLen: bl.length }
	}
	const text = Buffer.from(bytes).toString('utf8').replace(/\r\n/g, '\n')
	// onion
	const innerArmor = asPgpMessageArmor(text)
	if (innerArmor) {
		try {
			const im = await openpgp.readMessage({ armoredMessage: innerArmor })
			const ik = singleKey(im.getEncryptionKeyIDs())
			if (!ik) return { type: 'reject', reason: 'inner_recipient_count' }
			if (ik === keys[localKey].encKeyId) return { type: 'attack_same_node' }
			return { type: 'onion_forward', keyId: ik }
		} catch { /* fall through */ }
	}
	// mailbox work
	let rec = null
	try { rec = JSON.parse(text.trim()) } catch { try { rec = JSON.parse(Buffer.from(text.trim(), 'base64').toString()) } catch {} }
	if (rec && typeof rec === 'object' && !Array.isArray(rec) && !(typeof rec.message === 'string' && rec.signMessage) && typeof rec.data === 'string') {
		const inner = asPgpMessageArmor(rec.data)
		if (inner) {
			const im = await openpgp.readMessage({ armoredMessage: inner })
			const ik = singleKey(im.getEncryptionKeyIDs())
			if (!ik) return { type: 'reject', reason: 'inner_recipient_count' }
			if (ik === keys[localKey].encKeyId) return { type: 'attack_same_node' }
			return { type: 'mailbox_work', keyId: ik, noPush: rec.NoPush === true }
		}
	}
	let content
	try { content = JSON.parse(Buffer.from(text, 'base64').toString()) } catch { return { type: 'reject', reason: 'format' } }
	if (voiceCmds.has(content.command) && typeof content.sessionId === 'string') return { type: 'voice_command', command: content }
	if (!content.message || !content.signMessage) return { type: 'reject', reason: 'format' }
	const cmd = checkSign(content.message, content.signMessage)
	if (!cmd) return { type: 'reject', reason: 'signature' }
	return { type: 'signed_command', command: cmd }
}

const writeKeys = { [voiceSession.toString('hex')]: writeKey.toString('base64') }
for (const [id, armor] of Object.entries(cases)) {
	add(`post-${id}`, 'post_classify', { armor, localKey: 'nodeA', writeKeys }, {
		decision: await classifyRef(armor, 'nodeA', writeKeys), packetTags: await packetTags(armor),
	})
}

// ---- 4. plain decrypt vectors (exact plaintext bytes after SI's CRLF->LF rule)
for (const [id, text] of [['ascii', 'hello'], ['multiline', 'a\nb\r\nc\n'], ['utf8', '你好 CoNET ✓'], ['large', 'x'.repeat(200_000)]]) {
	const armor = await encText(text, await pub('nodeA'))
	add(`decrypt-${id}`, 'pgp_decrypt', { armor, key: 'nodeA' }, { textLf: text.replace(/\r\n/g, '\n') })
}
// uncompressed + no-zlib variants (other clients may not compress)
add('decrypt-uncompressed', 'pgp_decrypt', {
	armor: await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'plain' }), encryptionKeys: await pub('nodeA') }), key: 'nodeA',
}, { textLf: 'plain' })

// ---- 5. PGP signatures (user key): inline signed+encrypted, detached, cleartext
const signedText = 'conet m0 signed text\nline 2'
add('pgpsig-sign-encrypt', 'pgp_decrypt_verify', {
	armor: await openpgp.encrypt({ message: await openpgp.createMessage({ text: signedText }), encryptionKeys: await pub('nodeA'), signingKeys: await priv('user'), config: zlib }),
	key: 'nodeA', signer: 'user',
}, { textLf: signedText, verified: true })
add('pgpsig-wrong-signer', 'pgp_decrypt_verify', {
	armor: await openpgp.encrypt({ message: await openpgp.createMessage({ text: signedText }), encryptionKeys: await pub('nodeA'), signingKeys: await priv('user2'), config: zlib }),
	key: 'nodeA', signer: 'user',
}, { textLf: signedText, verified: false })
add('pgpsig-detached', 'pgp_detached_verify', {
	text: signedText, signature: await openpgp.sign({ message: await openpgp.createMessage({ text: signedText }), signingKeys: await priv('user'), detached: true }), signer: 'user',
}, { verified: true })
add('pgpsig-detached-tampered', 'pgp_detached_verify', {
	text: signedText + '!', signature: await openpgp.sign({ message: await openpgp.createMessage({ text: signedText }), signingKeys: await priv('user'), detached: true }), signer: 'user',
}, { verified: false })
add('pgpsig-cleartext', 'pgp_cleartext_verify', {
	armor: await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: signedText }), signingKeys: await priv('user') }), signer: 'user',
}, { text: signedText, verified: true })

// ---- 6. sealed mailbox frames (SI sealMailboxStreamPayload, random IV)
for (const [id, obj] of [['handshake', { type: 'hello', ok: true }], ['message', { type: 'message', data: userBusiness }], ['keepalive', { t: 1 }], ['exact-255', { p: 'y'.repeat(255 - 8) }]]) {
	const sealed = sealMailboxStreamPayload(obj, streamKey)
	add(`seal-${id}`, 'mailbox_open', { key: streamKey.toString('base64'), sealed }, {
		json: JSON.stringify(obj), paddedLen: Math.ceil((Buffer.byteLength(JSON.stringify(obj)) + 1) / MAILBOX_STREAM_PAD) * MAILBOX_STREAM_PAD,
	})
}
add('seal-wrongkey', 'mailbox_open', { key: randomBytes(32).toString('base64'), sealed: sealMailboxStreamPayload({ a: 1 }, streamKey) }, { json: null })

// ---- 7. UDP AES-GCM payload (SI encryptUdpPayload)
const udpKey = randomBytes(32)
for (const [id, pt] of [['small', Buffer.from('udp frame')], ['bin', randomBytes(1200)]]) {
	add(`udp-${id}`, 'udp_open', { key: udpKey.toString('base64'), payload: encryptUdpPayload(udpKey, pt) }, { plaintextB64: pt.toString('base64') })
}

// ---- 8. hop signatures (SI hopSigPayload + EIP-191; deterministic signature)
const hopArmor = cases['mailbox-work']
const hopTexts = []
const hops = []
for (const w of [wallets.nodeA, wallets.nodeB]) {
	const unsigned = { w: w.address, t: now, n: Buffer.byteLength(hopArmor, 'utf8'), h: hopArmorHash(hopArmor), k: keys.nodeB.encKeyId }
	const text = hopSigPayload(unsigned)
	hopTexts.push(text)
	hops.push({ ...unsigned, s: await w.signMessage(text) })
}
add('hop-two', 'hop_sigs', { armor: hopArmor, header: `${SI_HOP_SIG_HEADER}: ${serializeHopSigsHeaderValue(hops)}`, now }, {
	payloads: hopTexts, valid: hops.map(() => true), count: 2,
})
add('hop-expired', 'hop_sigs', { armor: hopArmor, header: `${SI_HOP_SIG_HEADER}: ${serializeHopSigsHeaderValue(hops)}`, now: now + 601 }, {
	payloads: hopTexts, valid: [false, false], count: 2,
})
add('hop-sign', 'hop_sign', { wallet: 'nodeC', armor: hopArmor, nextKeyId: keys.nodeB.encKeyId, t: now }, {
	payload: hopSigPayload({ w: wallets.nodeC.address, t: now, n: Buffer.byteLength(hopArmor, 'utf8'), h: hopArmorHash(hopArmor), k: keys.nodeB.encKeyId }),
	signature: await wallets.nodeC.signMessage(hopSigPayload({ w: wallets.nodeC.address, t: now, n: Buffer.byteLength(hopArmor, 'utf8'), h: hopArmorHash(hopArmor), k: keys.nodeB.encKeyId })),
})

// ---- 9. voice v3 listen texts and signatures
const notAfter = now * 1000 + 3_600_000
const payText = voicePayText(wallets.temp.address, notAfter, 0, 0)
const listenText = voiceListenText(voiceSession.toString('hex'), writeKey.toString('base64'), keys.nodeA.encKeyId, now)
add('voice-v3-pay', 'eip191_text', { wallet: 'payer', builder: 'voicePayText', args: [wallets.temp.address, notAfter, 0, 0] }, {
	text: payText, signature: await wallets.payer.signMessage(payText), address: wallets.payer.address,
})
add('voice-v3-listen', 'eip191_text', { wallet: 'temp', builder: 'voiceListenText', args: [voiceSession.toString('hex'), writeKey.toString('base64'), keys.nodeA.encKeyId, now] }, {
	text: listenText, signature: await wallets.temp.signMessage(listenText), address: wallets.temp.address,
})

// ---- 10. epoch gossip signature (stratlivenessV2)
const epochMsg = JSON.stringify({ epoch: '1234567', wallet: wallets.client.address.toLowerCase() })
add('epoch-gossip', 'eip191', { wallet: 'nodeA', message: epochMsg }, { signature: await wallets.nodeA.signMessage(epochMsg), address: wallets.nodeA.address })

// ---- 11. NodeRegistryV2 EIP-712 (v0.1.2 §6.2). verifyingContract is a placeholder until deployment.
const REGISTRY_PLACEHOLDER = '0x00000000000000000000000000000000c0de0001'
const nrDomain = { name: 'CoNETNodeRegistry', version: '1', chainId: 224422, verifyingContract: REGISTRY_PLACEHOLDER }
const nodeStatementTypes = { NodeStatement: [
	{ name: 'nodeId', type: 'uint256' }, { name: 'epoch', type: 'uint64' }, { name: 'kind', type: 'uint8' }, { name: 'payloadHash', type: 'bytes32' },
] }
const bindNodeTypes = { BindNode: [
	{ name: 'operator', type: 'address' }, { name: 'nodeId', type: 'uint256' }, { name: 'ipHash', type: 'bytes32' }, { name: 'keyId', type: 'bytes8' },
	{ name: 'pgpHash', type: 'bytes32' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
] }
const ONLINE_PAYLOAD = ethers.keccak256(ethers.toUtf8Bytes('CONET_NODE_ONLINE_V1'))
const domainSeparator = ethers.TypedDataEncoder.hashDomain(nrDomain)
const eip712Vector = async (id, primary, types, value, wallet) => {
	const enc = ethers.TypedDataEncoder.from(types)
	add(id, 'eip712', { wallet, domain: nrDomain, primaryType: primary, value }, {
		typeHash: ethers.keccak256(ethers.toUtf8Bytes(enc.encodeType(primary))),
		domainSeparator,
		structHash: enc.hashStruct(primary, value),
		digest: ethers.TypedDataEncoder.hash(nrDomain, types, value),
		signature: await wallets[wallet].signTypedData(nrDomain, types, value),
		address: wallets[wallet].address,
	})
}
await eip712Vector('nodestatement-online', 'NodeStatement', nodeStatementTypes, { nodeId: '1', epoch: '1234567', kind: 1, payloadHash: ONLINE_PAYLOAD }, 'nodeA')
await eip712Vector('nodestatement-service', 'NodeStatement', nodeStatementTypes, { nodeId: '571', epoch: '1234568', kind: 2, payloadHash: ethers.keccak256(ethers.toUtf8Bytes('served:12345678')) }, 'nodeA')
await eip712Vector('nodestatement-capability', 'NodeStatement', nodeStatementTypes, { nodeId: '115792089237316195423570985008687907853269984665640564039457584007913129639935', epoch: '18446744073709551615', kind: 3, payloadHash: ethers.ZeroHash }, 'nodeB')
await eip712Vector('bindnode-new', 'BindNode', bindNodeTypes, {
	operator: wallets.other.address, nodeId: '0', ipHash: ethers.keccak256(ethers.toUtf8Bytes('192.0.2.10')), keyId: '0x' + keys.nodeA.encKeyId.toLowerCase(),
	pgpHash: ethers.keccak256(ethers.toUtf8Bytes(keys.nodeA.armoredPublic)), nonce: '0', deadline: String(now + 3600),
}, 'nodeA')
await eip712Vector('bindnode-existing', 'BindNode', bindNodeTypes, {
	operator: wallets.billing.address, nodeId: '42', ipHash: ethers.keccak256(ethers.toUtf8Bytes('198.51.100.7')), keyId: '0x' + keys.nodeB.encKeyId.toLowerCase(),
	pgpHash: ethers.keccak256(ethers.toUtf8Bytes(keys.nodeB.armoredPublic)), nonce: '7', deadline: String(now + 600),
}, 'nodeB')

// ---- 12. Voice v3 relay (SI voiceForward.ts verbatim excerpts): listen checks, frames, push text
const relayKeyId = keys.nodeA.encKeyId
const vSession = randomBytes(16).toString('hex')
const vWk = randomBytes(32).toString('base64')
const nowMs = now * 1000
const listenCmd = async (over = {}) => {
	const c = { command: 'voice_listen', v: 3, sessionId: vSession, wk: vWk, timestamp: now, temp: wallets.temp.address, ...over }
	const ts = c.timestamp
	c.tempSig = over.tempSig ?? await wallets.temp.signMessage(voiceListenText(c.sessionId, c.wk, over.signKeyId ?? relayKeyId, ts))
	const notAfter = over.notAfter ?? now + 3600
	const payText = voicePayText(c.temp, notAfter, 0, 0)
	c.pay = over.pay ?? { payer: wallets.payer.address, notAfter, maxBytes: 0, maxSeconds: 0, sig: await (over.paySigner ?? wallets.payer).signMessage(payText) }
	delete c.signKeyId; delete c.notAfter; delete c.paySigner
	return c
}
const listenCases = {
	'ok': await listenCmd(),
	'v2': await listenCmd({ v: 2 }),
	'bad-session': await listenCmd({ sessionId: 'ABCDEF0123456789ABCDEF0123456789' }),
	'short-wk': await listenCmd({ wk: Buffer.alloc(16).toString('base64') }),
	'stale-ts': await listenCmd({ timestamp: now - 700 }),
	'temp-sig-other-relay': await listenCmd({ signKeyId: keys.nodeB.encKeyId }),
	'pay-wrong-signer': await listenCmd({ paySigner: wallets.other }),
	'pay-expired': await listenCmd({ notAfter: now - 10 }),
	'pay-too-long': await listenCmd({ notAfter: now + 49 * 3600 }),
	'no-temp': await listenCmd({ temp: 'nope' }),
}
for (const [id, cmd] of Object.entries(listenCases)) {
	const r = verifyVoiceListenV3(cmd, relayKeyId, nowMs)
	add(`voice-listen-${id}`, 'voice_listen_verify', { command: cmd, relayKeyId, nowMs }, r.ok
		? { ok: true, sessionId: r.sessionId, temp: r.temp, notAfter: r.notAfter, writeKeyB64: r.writeKey.toString('base64') }
		: { ok: false, error: r.error })
}
add('voice-frames', 'voice_frames', { sessionId: vSession, nodeWallet: wallets.nodeA.address, blobB64: randomBytes(40).toString('base64') }, {})
{
	const v = vectors[vectors.length - 1]
	v.expect = {
		headers: voiceHeaders(),
		ready: frameLine(voiceHandshake(v.input.sessionId, wallets.nodeA)),
		chunk: frameLine({ t: 'c', d: v.input.blobB64 }),
	}
}
const pushPayload = { callId: 'call-0123456789', sessionId: vSession, calleeEoa: wallets.client.address, expiresAt: nowMs + 60_000, timestamp: now }
const pushText = voiceCallPushText(pushPayload, wallets.nodeA)
add('voice-call-push-text', 'voice_call_push', { wallet: 'nodeA', payload: pushPayload }, { text: pushText, signature: await wallets.nodeA.signMessage(pushText) })

console.log(JSON.stringify({
	meta: {
		warning: 'TEST KEYS ONLY. Generated by gen.mjs; never a real node or user key.',
		generatedAt: new Date().toISOString(),
		openpgp: JSON.parse((await import('fs')).readFileSync(new URL('./node_modules/openpgp/package.json', import.meta.url), 'utf8')).version,
		ethers: ethers.version,
		siRevision: '74c6cfd',
	},
	keys,
	wallets: Object.fromEntries(Object.entries(wallets).map(([k, w]) => [k, { privateKey: w.privateKey, address: w.address }])),
	vectors,
}, null, 1))

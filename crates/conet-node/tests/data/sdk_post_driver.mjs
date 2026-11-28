// Runs the REAL chat-sdk function postArmorOneEntryAtATime (beamio-UI/vendor/conet-chat-sdk, dist build) for the post-ack functional check.
// Lines on stdin: {"id":1,"port":1234,"armor":"..."}  ->  one JSON line on stdout: {"id":1,"ok":bool,"body":"...","attempts":n}.
// The SDK builds https://<domain>.conet.network/post; here fetch is redirected to http://127.0.0.1:<port> (the local Rust node), nothing leaves this machine.
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'
import path from 'node:path'
import { createRequire } from 'node:module'

const dist = process.env.POST_ACK_SDK_DIST
if (!dist) { console.error('POST_ACK_SDK_DIST (the SDK dist directory) is required'); process.exit(2) }
const nodes = await import(pathToFileURL(path.join(dist, 'nodes.js')).href)
const envelope = await import(pathToFileURL(path.join(dist, 'envelope.js')).href)
const crypto = await import(pathToFileURL(path.join(dist, 'crypto.js')).href)
const openpgp = createRequire(path.join(dist, 'envelope.js'))('openpgp')

let port = 0
const realFetch = globalThis.fetch
globalThis.fetch = (url, init) => {
	const u = String(url)
	if (!/^https?:\/\/[^/]+\.conet\.network\//.test(u)) throw new Error('unexpected url ' + u)
	return realFetch(u.replace(/^https?:\/\/[^/]+\.conet\.network/, `http://127.0.0.1:${port}`), init)
}

const entry = { region: 'XX', ip_addr: '127.0.0.1', armoredPublicKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nlocal\n-----END PGP PUBLIC KEY BLOCK-----', nftNumber: 1, domain: 'local' }
const rl = createInterface({ input: process.stdin })
for await (const line of rl) {
	if (!line.trim()) continue
	const cmd = JSON.parse(line)
	port = cmd.port
	nodes.markGossipNodeHealthy('local')
	if (cmd.op === 'chat') {
		// The chat send as gossip-core builds it (sendGroupMessage path): user armor to the recipient key, wrapped to the recipient's mailbox as mailbox work,
		// then posted through ONE entry with the outer entry wrap (postArmorOneEntryAtATime + wrapArmorToEntryRoute). The mailbox B is not the entry.
		const key = await openpgp.readKey({ armoredKey: cmd.userKey })
		const envl = { timestamp: Date.now(), text: cmd.text ?? 'hello', from: '0x0000000000000000000000000000000000000001', signMessage: '0x' }
		const userArmor = await envelope.armorToString(await openpgp.encrypt({
			message: await openpgp.createMessage({ text: crypto.utf8ToBase64(JSON.stringify(envl)) }),
			encryptionKeys: key,
			config: { preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed },
		}))
		const innerArmor = await envelope.wrapArmorToMailboxWork(userArmor, cmd.mailboxKey, { NoPush: cmd.noPush === true })
		const entryNode = { ...entry, armoredPublicKey: cmd.entryKey }
		const r = await nodes.postArmorOneEntryAtATime({
			nodes: [entryNode],
			exclude: new Set(),
			maxAttempts: 2,
			buildBody: async (node) => JSON.stringify(envelope.buildPostBody(await envelope.wrapArmorToEntryRoute(innerArmor, node.armoredPublicKey))),
		})
		process.stdout.write(JSON.stringify({
			id: cmd.id, ok: r.ok, body: r.body, attempts: r.attempts, userArmor,
			userArmorHasCR: userArmor.includes('\r'), userArmorEndsWithNewline: userArmor.endsWith('\n'),
			expectedH: crypto.keccakUtf8(userArmor.trim()), rawH: crypto.keccakUtf8(userArmor),
		}) + '\n')
		continue
	}
	const r = await nodes.postArmorOneEntryAtATime({
		nodes: [entry],
		exclude: new Set(),
		maxAttempts: cmd.maxAttempts ?? 2,
		buildBody: async () => JSON.stringify(envelope.buildPostBody(cmd.armor)),
	})
	process.stdout.write(JSON.stringify({ id: cmd.id, ok: r.ok, body: r.body, attempts: r.attempts }) + '\n')
}

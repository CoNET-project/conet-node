// Mixed-network setup on a LOCAL anvil (chain id 224422). TEST keys only.
//
// - Places GuardianNodesInfoV6, AddressPGP and a passport test double at their MAINNET addresses
//   (anvil_setCode) so neither CoNET-SI nor conet-node needs an address patch.
// - Registers 2 CoNET-SI nodes (golden nodeA, nodeB) and 2 conet-node nodes (keys made here),
//   records their routes, and registers two users (golden user -> mailbox R1, user2 -> S2).
// - Writes each SI node's ~/.CoNET-SI/nodeSetup.json and the config the Rust scenario test reads.
//
// usage: node setup.mjs <work dir>
import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const req = createRequire(path.join(here, '../../conformance/vectors/package.json'))
const { ethers } = req('ethers')
const openpgp = req('openpgp')
const golden = JSON.parse(fs.readFileSync(path.join(here, '../../conformance/vectors/golden.json'), 'utf8'))
const bytecode = Object.fromEntries(
	JSON.parse(fs.readFileSync(path.join(here, 'contracts/bytecode.json'), 'utf8')).map(c => [c.name, c.bytecode]),
)

const work = process.argv[2]
if (!work) throw new Error('usage: node setup.mjs <work dir>')
const RPC = process.env.MIXNET_RPC || 'http://127.0.0.1:8545'
const provider = new ethers.JsonRpcProvider(RPC, 224422, { staticNetwork: true })
// anvil account 0 (public test key)
const deployer = new ethers.NonceManager(
	new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider),
)

// Mainnet addresses (CoNET-SI and conet-node constants).
const V6 = '0xBC6b53065b5647261396d002bDBA0d3396E0722f'
const ADDRESS_PGP = '0x684b0ac760cEE9c9b85de36d69746420648Cf9e2'
const PASSPORTS = ['0x87A70eD480a2b904c607Ee68e6C3f8c54D58FB08', '0x40d64D88A86D6efb721042225B812379dc97bc89']

const send = async (p) => (await p).wait()

// Deploy at a scratch address, then copy the runtime code to the fixed address.
const place = async (name, at, args = [], argTypes = []) => {
	const data = bytecode[name] + ethers.AbiCoder.defaultAbiCoder().encode(argTypes, args).slice(2)
	const r = await send(deployer.sendTransaction({ data }))
	const code = await provider.getCode(r.contractAddress)
	await provider.send('anvil_setCode', [at, code])
	return at
}
// mapping(address => bool) at `slot`: set key -> true.
const setAdmin = async (contract, slot, who) => {
	const key = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address', 'uint256'], [who, slot]))
	await provider.send('anvil_setStorageAt', [contract, key, ethers.zeroPadValue('0x01', 32)])
}

const abiV6 = [
	'function addNode(uint256 id, string ipaddress, string regionName, string pgp, string pgpKey, address nodeAddress)',
	'function getAllNodes(uint256 start, uint256 length) view returns ((uint256 id, string PGP, string PGPKey, string ip_addr, string regionName)[])',
]
const abiPgp = [
	'function addRoute(string ipaddress)',
	'function addPublicPGPByAdmin(address to, string pgpKeyID, string publicKeyArmored, string encrypKeyArmored, string routePgpKeyID)',
	'function getRouteKeyIDByUserPgpKeyID(string userPgpKeyID) view returns (string)',
]
const abiPassport = ['function setPaid(address who, bool on)']

const main = async () => {
	fs.mkdirSync(work, { recursive: true })
	await place('GuardianNodesInfoV6', V6)
	await setAdmin(V6, 0, await deployer.getAddress())
	await place('AddressPGP', ADDRESS_PGP, [V6], ['address'])
	await setAdmin(ADDRESS_PGP, 2, await deployer.getAddress())
	for (const p of PASSPORTS) await place('PassportMock', p)

	// Rust node route keys: curve25519 like SI and the PWA make them, no passphrase.
	const rustKeys = []
	for (const n of ['R1', 'R2']) {
		const { privateKey, publicKey } = await openpgp.generateKey({
			type: 'ecc', curve: 'curve25519', userIDs: [{ name: `mixnet ${n}` }], format: 'armored',
		})
		const k = await openpgp.readKey({ armoredKey: publicKey })
		rustKeys.push({ privateKey, publicKey, keyId: k.getKeyIDs()[1].toHex().toUpperCase() })
	}

	const nodes = [
		{ name: 'S1', impl: 'si', ip: '127.0.0.2', wallet: 'nodeA', key: 'nodeA' },
		{ name: 'S2', impl: 'si', ip: '127.0.0.3', wallet: 'nodeB', key: 'nodeB' },
		{ name: 'R1', impl: 'rust', ip: '127.0.0.4', wallet: 'nodeC', rust: rustKeys[0] },
		{ name: 'R2', impl: 'rust', ip: '127.0.0.5', wallet: 'other', rust: rustKeys[1] },
	].map(n => ({
		...n,
		address: golden.wallets[n.wallet].address,
		privateKey: golden.wallets[n.wallet].privateKey,
		armoredPublic: n.rust ? n.rust.publicKey : golden.keys[n.key].armoredPublic,
		keyId: n.rust ? n.rust.keyId : golden.keys[n.key].encKeyId.toUpperCase(),
	}))

	const v6 = new ethers.Contract(V6, abiV6, deployer)
	const pgp = new ethers.Contract(ADDRESS_PGP, abiPgp, deployer)
	let id = 1
	for (const n of nodes) {
		await send(v6.addNode(id++, n.ip, 'US', Buffer.from(n.armoredPublic).toString('base64'), n.keyId, n.address))
		await send(pgp.addRoute(n.ip))
		// Node wallets pay their own presence writes (SI setUserOnlineOnMe and the like).
		await send(deployer.sendTransaction({ to: n.address, value: ethers.parseEther('100') }))
	}

	const users = [
		{ name: 'user1', key: 'user', wallet: 'client', mailbox: 'R1' },
		{ name: 'user2', key: 'user2', wallet: 'payer', mailbox: 'S2' },
	].map(u => ({
		...u,
		address: golden.wallets[u.wallet].address,
		keyId: golden.keys[u.key].encKeyId.toUpperCase(),
	}))
	for (const u of users) {
		const mb = nodes.find(n => n.name === u.mailbox)
		const pub = golden.keys[u.key].armoredPublic
		await send(pgp.addPublicPGPByAdmin(u.address, u.keyId, pub, pub, mb.keyId))
		const route = await pgp.getRouteKeyIDByUserPgpKeyID(u.keyId)
		if (route.toUpperCase() !== mb.keyId) throw new Error(`route of ${u.name}: ${route}`)
		await send(deployer.sendTransaction({ to: u.address, value: ethers.parseEther('10') }))
	}
	// The exit test pays with user1's wallet.
	for (const p of PASSPORTS) await send(new ethers.Contract(p, abiPassport, deployer).setPaid(users[0].address, true))

	// Node homes and keys.
	for (const n of nodes) {
		const dir = path.join(work, n.name)
		fs.mkdirSync(dir, { recursive: true })
		if (n.impl === 'rust') {
			fs.writeFileSync(path.join(dir, 'route.sec'), n.rust.privateKey, { mode: 0o600 })
			continue
		}
		const passwd = golden.keys[n.key].passphrase
		const keychain = JSON.parse(await new ethers.Wallet(n.privateKey).encrypt(passwd))
		const setup = {
			ipV4: n.ip, ipV4Port: 80, ipV6: '', ipV6Port: 0,
			keychain, storage_price: 0, outbound_price: 0, cpus: 1,
			pgpKey: { privateKey: golden.keys[n.key].armoredPrivate, publicKey: n.armoredPublic, keyID: n.keyId },
			passwd, platform_verison: '', dl_publicKeyArmored: '', sslDate: Date.now(), restartBlockNumber: 0,
		}
		fs.mkdirSync(path.join(dir, 'home/.CoNET-SI'), { recursive: true })
		fs.writeFileSync(path.join(dir, 'home/.CoNET-SI/nodeSetup.json'), JSON.stringify(setup), { mode: 0o600 })
	}

	const rows = await v6.getAllNodes(0, 100)
	if (rows.length !== nodes.length) throw new Error(`V6 rows: ${rows.length}`)
	const config = {
		rpc: RPC,
		nodes: nodes.map(({ name, impl, ip, address, keyId, armoredPublic }) => ({
			name, impl, addr: `${ip}:80`, wallet: address.toLowerCase(), keyId, armoredPublic,
		})),
		users: users.map(({ name, key, wallet, address, keyId, mailbox }) => ({
			name, goldenKey: key, goldenWallet: wallet, wallet: address.toLowerCase(), keyId, mailbox,
		})),
		exitTarget: '9.9.9.9:7',
	}
	fs.writeFileSync(path.join(work, 'mixnet.json'), JSON.stringify(config, null, 2))
	console.log(`mixnet setup done: ${nodes.map(n => `${n.name}=${n.keyId}@${n.ip}`).join(' ')}`)
}

main().catch(e => {
	console.error(e)
	process.exit(1)
})

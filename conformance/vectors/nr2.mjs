// NodeRegistryV2 v0.1 EIP-712 vectors (node line, Q77). TEST KEYS ONLY.
// Type strings are copied from NodeRegistryTypes.sol; the contract's own tests check that
// ethers' TypedDataEncoder digests equal the contract's (NodeRegistryLens digests).
// Fixed values only (no clock, no randomness), so the expected output never drifts.
import { ethers } from 'ethers'

export const REGISTRY_PLACEHOLDER = '0x00000000000000000000000000000000c0de0001'
export const nrDomain = { name: 'CoNETNodeRegistry', version: '1', chainId: 224422, verifyingContract: REGISTRY_PLACEHOLDER }

export const types = {
	RegisterRequest: { RegisterRequest: [
		{ name: 'operator', type: 'address' }, { name: 'beneficiary', type: 'address' }, { name: 'nodeWallet', type: 'address' },
		{ name: 'nodeType', type: 'uint8' }, { name: 'ipHash', type: 'bytes32' }, { name: 'tcpPort', type: 'uint16' },
		{ name: 'udpPort', type: 'uint16' }, { name: 'pgpHash', type: 'bytes32' }, { name: 'keyId', type: 'bytes8' },
		{ name: 'services', type: 'uint16' }, { name: 'sponsorNodeId', type: 'uint256' }, { name: 'nonce', type: 'uint256' },
		{ name: 'deadline', type: 'uint256' },
	] },
	BindNode: { BindNode: [
		{ name: 'operator', type: 'address' }, { name: 'nodeId', type: 'uint256' }, { name: 'ipHash', type: 'bytes32' }, { name: 'keyId', type: 'bytes8' },
		{ name: 'pgpHash', type: 'bytes32' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
	] },
	OnlineDeclaration: { OnlineDeclaration: [
		{ name: 'nodeId', type: 'uint256' }, { name: 'mode', type: 'uint8' }, { name: 'anchorsHash', type: 'bytes32' },
		{ name: 'servicesNow', type: 'uint16' }, { name: 'onlineUntil', type: 'uint64' }, { name: 'onlineSeq', type: 'uint64' },
		{ name: 'deadline', type: 'uint256' },
	] },
	AnchorReceipt: { AnchorReceipt: [
		{ name: 'nodeId', type: 'uint256' }, { name: 'anchorNodeId', type: 'uint256' }, { name: 'onlineSeq', type: 'uint64' },
		{ name: 'onlineUntil', type: 'uint64' },
	] },
	ExtendDeclaration: { ExtendDeclaration: [
		{ name: 'nodeId', type: 'uint256' }, { name: 'onlineSeq', type: 'uint64' }, { name: 'newUntil', type: 'uint64' },
		{ name: 'deadline', type: 'uint256' },
	] },
	PauseDeclaration: { PauseDeclaration: [
		{ name: 'nodeId', type: 'uint256' }, { name: 'onlineSeq', type: 'uint64' }, { name: 'pauseAt', type: 'uint64' },
		{ name: 'deadline', type: 'uint256' },
	] },
}

// Contract conventions: pgpHash = keccak256(canonical base64 of the armored public key);
// ipHash = keccak256(UTF-8 IP text) over canonical IP text (Q77-3);
// anchorsHash = keccak256(abi.encodePacked(uint256[])).
export const pgpField = (armored) => Buffer.from(armored, 'utf8').toString('base64')
export const pgpHash = (armored) => ethers.keccak256(ethers.toUtf8Bytes(pgpField(armored)))
export const ipHash = (ip) => ethers.keccak256(ethers.toUtf8Bytes(ip))
export const anchorsHash = (ids) => ethers.solidityPackedKeccak256(['uint256[]'], [ids])

const U64_MAX = '18446744073709551615'
const U256_MAX = '115792089237316195423570985008687907853269984665640564039457584007913129639935'
const DEADLINE = '1800000000'

/// wallets: name -> ethers.Wallet; keys: name -> { armoredPublic, encKeyId }.
export async function nr2Vectors(wallets, keys) {
	const out = []
	const domainSeparator = ethers.TypedDataEncoder.hashDomain(nrDomain)
	const vec = async (id, primary, value, wallet, extraIn = {}, extraExpect = {}) => {
		const t = types[primary]
		const enc = ethers.TypedDataEncoder.from(t)
		out.push({ id, kind: 'eip712', input: { wallet, domain: nrDomain, primaryType: primary, value, ...extraIn }, expect: {
			typeHash: ethers.keccak256(ethers.toUtf8Bytes(enc.encodeType(primary))),
			domainSeparator,
			structHash: enc.hashStruct(primary, value),
			digest: ethers.TypedDataEncoder.hash(nrDomain, t, value),
			signature: await wallets[wallet].signTypedData(nrDomain, t, value),
			address: wallets[wallet].address,
			...extraExpect,
		} })
	}
	const kA = keys.nodeA
	const keyIdA = '0x' + kA.encKeyId.toLowerCase()
	// Sponsored TCP registration: operator signs the request, the node wallet the BindNode
	// (nodeId 0, the request's nonce and deadline).
	const reqTcp = {
		operator: wallets.other.address, beneficiary: wallets.billing.address, nodeWallet: wallets.nodeA.address,
		nodeType: 1, ipHash: ipHash('192.0.2.10'), tcpPort: 8443, udpPort: 18443, pgpHash: pgpHash(kA.armoredPublic),
		keyId: keyIdA, services: 0b1011, sponsorNodeId: '7', nonce: '1', deadline: DEADLINE,
	}
	await vec('nr2-register-tcp', 'RegisterRequest', reqTcp, 'other', { pgpKey: 'nodeA' }, { pgpHash: reqTcp.pgpHash, pgpKeyId: kA.encKeyId.toUpperCase() })
	await vec('nr2-bind-for-register-tcp', 'BindNode', {
		operator: reqTcp.operator, nodeId: '0', ipHash: reqTcp.ipHash, keyId: reqTcp.keyId, pgpHash: reqTcp.pgpHash, nonce: reqTcp.nonce, deadline: reqTcp.deadline,
	}, 'nodeA')
	const kB = keys.nodeB
	const reqBrowser = {
		operator: wallets.other.address, beneficiary: wallets.other.address, nodeWallet: wallets.nodeC.address,
		nodeType: 2, ipHash: ethers.ZeroHash, tcpPort: 0, udpPort: 0, pgpHash: pgpHash(kB.armoredPublic),
		keyId: '0x' + kB.encKeyId.toLowerCase(), services: 0b0101, sponsorNodeId: '0', nonce: U256_MAX, deadline: U256_MAX,
	}
	await vec('nr2-register-browser-max', 'RegisterRequest', reqBrowser, 'other', { pgpKey: 'nodeB' }, { pgpHash: reqBrowser.pgpHash, pgpKeyId: kB.encKeyId.toUpperCase() })
	// Browser node declares itself online (WebRTC, two anchors; SSE, one anchor).
	const ids2 = ['3', '5']
	await vec('nr2-online-webrtc', 'OnlineDeclaration', {
		nodeId: '12', mode: 1, anchorsHash: anchorsHash(ids2), servicesNow: 0b0101, onlineUntil: '1790000000', onlineSeq: '4', deadline: DEADLINE,
	}, 'nodeC', { anchorNodeIds: ids2 }, { anchorsHash: anchorsHash(ids2) })
	const ids1 = [U256_MAX]
	await vec('nr2-online-sse-max', 'OnlineDeclaration', {
		nodeId: U256_MAX, mode: 2, anchorsHash: anchorsHash(ids1), servicesNow: 65535, onlineUntil: U64_MAX, onlineSeq: U64_MAX, deadline: U256_MAX,
	}, 'nodeC', { anchorNodeIds: ids1 }, { anchorsHash: anchorsHash(ids1) })
	// A TCP anchor (conet-node) signs the receipt for the declaration above.
	await vec('nr2-anchor-receipt', 'AnchorReceipt', { nodeId: '12', anchorNodeId: '5', onlineSeq: '4', onlineUntil: '1790000000' }, 'nodeA')
	await vec('nr2-extend', 'ExtendDeclaration', { nodeId: '12', onlineSeq: '4', newUntil: '1790003600', deadline: DEADLINE }, 'nodeC')
	await vec('nr2-pause', 'PauseDeclaration', { nodeId: '12', onlineSeq: '4', pauseAt: '1789990000', deadline: DEADLINE }, 'nodeC')
	// ipHash over canonical IP text (v0.1.47 §8.4.38, Q77-3). Labels are by hand from that rule;
	// accepted text hashes as its UTF-8 bytes, anything else must be refused.
	const canonical = ['192.0.2.10', '0.0.0.0', '255.255.255.255', '2001:db8::1', '2001:db8::1:0:0:1', '2001:db8:0:1:1:1:1:1', '::1', '::', 'fe80::1', '1::',
		'::102:304'] // v0.1.48 §8.4.39: deprecated IPv4-compatible ::/96 in hex form is accepted
	const refused = {
		'192.168.001.1': 'not_an_ip', '1.2.3': 'not_an_ip', '256.1.1.1': 'not_an_ip', '2001:DB8::1': 'not_canonical',
		'2001:0db8::1': 'not_canonical', '2001:db8:0:0:1:0:0:1': 'not_canonical', '2001:db8::0:1': 'not_canonical',
		'2001:db8::1:1:1:1:1': 'not_canonical', '::ffff:1.2.3.4': 'embedded_ipv4', '::ffff:102:304': 'embedded_ipv4',
		'[2001:db8::1]': 'not_an_ip', '2001:db8::1%eth0': 'not_an_ip', '192.0.2.10:443': 'embedded_ipv4', ' 192.0.2.10': 'not_an_ip',
		// v0.1.48 §8.4.39: IPv4-mapped ::ffff:0:0/96 refused in any form; dotted IPv4-compatible refused.
		'::ffff:0:0': 'embedded_ipv4', '::1.2.3.4': 'embedded_ipv4',
	}
	canonical.forEach((ip, i) => out.push({ id: `nr2-iphash-ok-${i}`, kind: 'nr2_ip_hash', input: { ip }, expect: { ok: true, ipHash: ipHash(ip) } }))
	Object.entries(refused).forEach(([ip, error], i) => out.push({ id: `nr2-iphash-bad-${i}`, kind: 'nr2_ip_hash', input: { ip }, expect: { ok: false, error } }))
	return out
}

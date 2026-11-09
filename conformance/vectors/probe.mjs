// Liveness probe EIP-712 vectors (Rust line probe protocol v0.5, P-01). TEST KEYS ONLY.
// Domain CoNET-NodeProbe (not the registry's CoNETNodeRegistry). Fixed values only, so the
// expected output never drifts. Run: node probe.mjs  (writes probe712.json)
import { readFileSync, writeFileSync } from 'fs'
import { ethers } from 'ethers'

const REGISTRY_PLACEHOLDER = '0x00000000000000000000000000000000c0de0001'
export const probeDomain = { name: 'CoNET-NodeProbe', version: '1', chainId: 224422, verifyingContract: REGISTRY_PLACEHOLDER }

export const types = {
	ProbeRequest: { ProbeRequest: [
		{ name: 'version', type: 'uint16' }, { name: 'proberNodeId', type: 'uint256' }, { name: 'proberWallet', type: 'address' },
		{ name: 'targetNodeId', type: 'uint256' }, { name: 'targetWallet', type: 'address' }, { name: 'targetIpHash', type: 'bytes32' },
		{ name: 'targetPort', type: 'uint16' }, { name: 'nonce', type: 'bytes32' }, { name: 'issuedAt', type: 'uint64' },
		{ name: 'expiresAt', type: 'uint64' },
	] },
	ProbeReply: { ProbeReply: [
		{ name: 'requestHash', type: 'bytes32' }, { name: 'replierNodeId', type: 'uint256' }, { name: 'replierWallet', type: 'address' },
		{ name: 'repliedAt', type: 'uint64' }, { name: 'expiresAt', type: 'uint64' }, { name: 'flags', type: 'uint8' },
		{ name: 'registryBlock', type: 'uint64' },
	] },
	ProbeDelegation: { ProbeDelegation: [
		{ name: 'voterNodeId', type: 'uint256' }, { name: 'voterWallet', type: 'address' }, { name: 'relayNodeId', type: 'uint256' },
		{ name: 'targetNodeId', type: 'uint256' }, { name: 'reportId', type: 'uint256' }, { name: 'challenge', type: 'bytes32' },
		{ name: 'issuedAt', type: 'uint64' }, { name: 'expiresAt', type: 'uint64' },
	] },
	OfflineEvidence: { OfflineEvidence: [
		{ name: 'reporterNodeId', type: 'uint256' }, { name: 'reporterWallet', type: 'address' }, { name: 'targetNodeId', type: 'uint256' },
		{ name: 'requestHashes', type: 'bytes32[3]' }, { name: 'issuedAts', type: 'uint64[3]' }, { name: 'publishedAt', type: 'uint64' },
	] },
}

const ipHash = (ip) => ethers.keccak256(ethers.toUtf8Bytes(ip))
const U64_MAX = '18446744073709551615'
const U256_MAX = ethers.MaxUint256.toString()

export async function probeVectors(wallets) {
	const out = []
	const domainSeparator = ethers.TypedDataEncoder.hashDomain(probeDomain)
	const vec = async (id, primary, value, wallet) => {
		const t = types[primary]
		const enc = ethers.TypedDataEncoder.from(t)
		const digest = ethers.TypedDataEncoder.hash(probeDomain, t, value)
		out.push({ id, input: { wallet, domain: probeDomain, primaryType: primary, value }, expect: {
			typeString: enc.encodeType(primary),
			typeHash: ethers.keccak256(ethers.toUtf8Bytes(enc.encodeType(primary))),
			domainSeparator,
			structHash: enc.hashStruct(primary, value),
			digest,
			signature: await wallets[wallet].signTypedData(probeDomain, t, value),
			address: wallets[wallet].address,
		} })
		return digest
	}
	const req = {
		version: 1, proberNodeId: '7', proberWallet: wallets.nodeA.address, targetNodeId: '572', targetWallet: wallets.nodeB.address,
		targetIpHash: ipHash('192.0.2.10'), targetPort: 80, nonce: ethers.keccak256(ethers.toUtf8Bytes('probe-nonce-1')),
		issuedAt: '1800000000', expiresAt: '1800000060',
	}
	const rh = await vec('probe-request', 'ProbeRequest', req, 'nodeA')
	await vec('probe-request-max', 'ProbeRequest', {
		version: 65535, proberNodeId: U256_MAX, proberWallet: wallets.nodeA.address, targetNodeId: U256_MAX, targetWallet: wallets.nodeB.address,
		targetIpHash: ipHash('2001:db8::1'), targetPort: 65535, nonce: ethers.ZeroHash, issuedAt: U64_MAX, expiresAt: U64_MAX,
	}, 'nodeA')
	await vec('probe-reply', 'ProbeReply', {
		requestHash: rh, replierNodeId: '572', replierWallet: wallets.nodeB.address, repliedAt: '1800000001', expiresAt: '1800000061',
		flags: 0, registryBlock: '2077233',
	}, 'nodeB')
	await vec('probe-reply-flags', 'ProbeReply', {
		requestHash: rh, replierNodeId: '572', replierWallet: wallets.nodeB.address, repliedAt: '1800000400', expiresAt: '1800000460',
		flags: 3, registryBlock: '0',
	}, 'nodeB')
	await vec('probe-delegation', 'ProbeDelegation', {
		voterNodeId: '573', voterWallet: wallets.nodeC.address, relayNodeId: '7', targetNodeId: '572', reportId: '41',
		challenge: ethers.keccak256(ethers.toUtf8Bytes('voter-challenge-1')), issuedAt: '1800000100', expiresAt: '1800000160',
	}, 'nodeC')
	await vec('probe-delegation-prereport', 'ProbeDelegation', {
		voterNodeId: '7', voterWallet: wallets.nodeA.address, relayNodeId: '573', targetNodeId: '572', reportId: '0',
		challenge: ethers.keccak256(ethers.toUtf8Bytes('pre-report-1')), issuedAt: '1800000200', expiresAt: '1800000260',
	}, 'nodeA')
	await vec('probe-offline-evidence', 'OfflineEvidence', {
		reporterNodeId: '7', reporterWallet: wallets.nodeA.address, targetNodeId: '572',
		requestHashes: [rh, ethers.keccak256(ethers.toUtf8Bytes('r2')), ethers.keccak256(ethers.toUtf8Bytes('r3'))],
		issuedAts: ['1800000000', '1800000070', '1800000140'], publishedAt: '1800000200',
	}, 'nodeA')
	return out
}

if (import.meta.url === `file://${process.argv[1]}`) {
	const g = JSON.parse(readFileSync(new URL('./golden.json', import.meta.url), 'utf8'))
	const wallets = Object.fromEntries(Object.entries(g.wallets).map(([k, w]) => [k, new ethers.Wallet(w.privateKey)]))
	const v = await probeVectors(wallets)
	writeFileSync(new URL('./probe712.json', import.meta.url), JSON.stringify({ note: 'Generated by probe.mjs with ethers ' + ethers.version + '. TEST KEYS ONLY.', vectors: v }, null, 1) + '\n')
	console.error(`probe vectors: ${v.length}`)
}

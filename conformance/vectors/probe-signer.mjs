// ProbeSignerAccept vector (Q117 乙, N6 §H.8.20): domain CoNET-NodeProbeSigner, as the node line's
// setProbeSigner checks it. TEST KEY ONLY. Fixed values, so the output never drifts.
// Run: node probe-signer.mjs  (writes probe-signer.json)
import { writeFileSync } from 'fs'
import { ethers } from 'ethers'

const REGISTRY_PLACEHOLDER = '0x00000000000000000000000000000000c0de0001'
const probeKey = new ethers.Wallet('0x' + '11'.repeat(32)) // test key only
const domain = { name: 'CoNET-NodeProbeSigner', version: '1', chainId: 224422, verifyingContract: REGISTRY_PLACEHOLDER }
const types = { ProbeSignerAccept: [
	{ name: 'nodeId', type: 'uint256' }, { name: 'nodeWallet', type: 'address' },
	{ name: 'probeSigner', type: 'address' }, { name: 'purpose', type: 'bytes32' },
] }
const value = { nodeId: '573', nodeWallet: '0x433c1e782436a20454967EF3A9A9586d7186BDBd', probeSigner: probeKey.address,
	purpose: ethers.keccak256(ethers.toUtf8Bytes('conet.node-probe.v1')) }
const wrong = { ...domain, name: 'CoNET-NodeProbe' } // the probe-message domain: must give another digest
const out = {
	domain, value,
	domainSeparator: ethers.TypedDataEncoder.hashDomain(domain),
	structHash: ethers.TypedDataEncoder.from(types).hash(value),
	digest: ethers.TypedDataEncoder.hash(domain, types, value),
	digestInProbeMessageDomain: ethers.TypedDataEncoder.hash(wrong, types, value),
	signature: await probeKey.signTypedData(domain, types, value),
}
writeFileSync(new URL('./probe-signer.json', import.meta.url), JSON.stringify(out, null, 1) + '\n')
console.log(out.digest)

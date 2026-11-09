// EIP-1559 signed transaction vectors for si-signer::tx1559. TEST KEY ONLY. Run: node tx1559.mjs
import { writeFileSync } from 'fs'
import { ethers } from 'ethers'
const key = new ethers.Wallet('0x' + '22'.repeat(32))
const iface = new ethers.Interface(['function topUp(uint256 nodeId) payable'])
const cases = [
  { chainId: 224422, nonce: 0, maxPriorityFeePerGas: 100000000n, maxFeePerGas: 4000000000n, gasLimit: 300000n, to: '0x00000000000000000000000000000000c0de0001', value: 5n * 10n ** 18n, data: iface.encodeFunctionData('topUp', [573]) },
  { chainId: 224422, nonce: 1234, maxPriorityFeePerGas: 1n, maxFeePerGas: 123456789012345n, gasLimit: 21000n, to: '0x00000000000000000000000000000000c0de0001', value: 0n, data: iface.encodeFunctionData('topUp', [1]) },
  { chainId: 1, nonce: 70000, maxPriorityFeePerGas: 0n, maxFeePerGas: 1n, gasLimit: 1n, to: '0x1111111111111111111111111111111111111111', value: 1n, data: '0x' },
]
const out = []
for (const c of cases) {
  const raw = await key.signTransaction({ type: 2, ...c, accessList: [] })
  out.push({ ...Object.fromEntries(Object.entries(c).map(([k, v]) => [k, v.toString()])), raw, hash: ethers.keccak256(raw), from: key.address })
}
writeFileSync(new URL('./tx1559.json', import.meta.url), JSON.stringify(out, null, 1) + '\n')
console.log(out.length, 'vectors')

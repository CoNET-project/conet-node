// EIP-712 SettlementOrder vectors (GB fork 5 draft, 8e43083c) for conet-node service_order.
// TEST KEY ONLY, offline. Run: node settlement-order.mjs
import { writeFileSync } from 'fs'
import { ethers } from 'ethers'
const user = new ethers.Wallet('0x' + '33'.repeat(32))
const types = { SettlementOrder: [
  { name: 'pool', type: 'uint8' }, { name: 'user', type: 'address' }, { name: 'nodeId', type: 'uint64' },
  { name: 'nodeWallet', type: 'address' }, { name: 'minNodeGb', type: 'uint256' }, { name: 'maxUserPay', type: 'uint256' },
  { name: 'gbBaseVersion', type: 'uint64' }, { name: 'markupVersion', type: 'uint64' },
  { name: 'freeExchangeVersion', type: 'uint64' }, { name: 'freePoolVersion', type: 'uint64' },
  { name: 'serviceBit', type: 'bytes32' }, { name: 'deadline', type: 'uint64' }, { name: 'nonce', type: 'bytes32' },
] }
const token = '0x00000000000000000000000000000000000c0de2'
const domain = { name: 'ThirdPartyStableSettlement', version: '1', chainId: 224422, verifyingContract: token }
const cases = [
  { pool: 0, user: user.address, nodeId: 101, nodeWallet: '0x00000000000000000000000000000000000a0001', minNodeGb: 500000000n, maxUserPay: 1234567n, gbBaseVersion: 3, markupVersion: 2, freeExchangeVersion: 0, freePoolVersion: 0, serviceBit: ethers.zeroPadValue('0x04', 32), deadline: 1900000000, nonce: ethers.keccak256(ethers.toUtf8Bytes('nonce-1')) },
  { pool: 1, user: user.address, nodeId: 4294967296n, nodeWallet: '0x00000000000000000000000000000000000a0002', minNodeGb: 1n, maxUserPay: 2n ** 255n, gbBaseVersion: 18446744073709551615n, markupVersion: 7, freeExchangeVersion: 5, freePoolVersion: 9, serviceBit: ethers.zeroPadValue('0x0c', 32), deadline: 1900003600, nonce: ethers.hexlify(new Uint8Array(32).fill(0xab)) },
]
const out = []
for (const c of cases) {
  const digest = ethers.TypedDataEncoder.hash(domain, types, c)
  const signature = await user.signTypedData(domain, types, c)
  out.push({ order: Object.fromEntries(Object.entries(c).map(([k, v]) => [k, v.toString()])), token, digest, signature, typeString: ethers.TypedDataEncoder.from(types).encodeType('SettlementOrder') })
}
writeFileSync(new URL('./settlement-order.json', import.meta.url), JSON.stringify(out, null, 1) + '\n')
console.log(out.length, 'vectors')

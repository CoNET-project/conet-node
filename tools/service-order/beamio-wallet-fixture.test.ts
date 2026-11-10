// Real BeamioAccount (ERC-1271) fixture for crates/conet-node/tests/beamio_wallet.rs. Local chain, test keys only.
//
// The contract is fork 4's verbatim copy of src/BeamioAccount (aac-stage1-worktree 0f8ad23,
// solidity-tests/contracts/beamio-account-fixture, source git 8cf6a697). Run in a scratch Hardhat project holding that
// directory unchanged plus a StandIn contract (code for the EntryPoint and the factory):
//
//   cp tools/service-order/beamio-wallet-fixture.test.ts <scratch>/test/
//   cd <scratch> && BEAMIO_WALLET_FIXTURE=<out.json> npx hardhat test mocha test/beamio-wallet-fixture.test.ts
//
// Orders follow GB fork 5's draft (8e43083c, SettlementOrder, domain ThirdPartyStableSettlement/1/224422/token) with the
// account as `user`. Signatures are built the way the Beamio signing protocol does for this account (eth-sign over the
// EIP-712 digest, managers in ascending order); the node never builds or parses them. For every case the script records
// the account's runtime code and the account's own answer to isValidSignature(digest, sig), keyed by calldata, so the Rust
// test replays the real contract's answers through its own call path.
import { writeFileSync } from "node:fs"
import { network } from "hardhat"

const { ethers, networkHelpers } = await network.connect()

const types = { SettlementOrder: [
  { name: "pool", type: "uint8" }, { name: "user", type: "address" }, { name: "nodeId", type: "uint64" },
  { name: "nodeWallet", type: "address" }, { name: "minNodeGb", type: "uint256" }, { name: "maxUserPay", type: "uint256" },
  { name: "gbBaseVersion", type: "uint64" }, { name: "markupVersion", type: "uint64" },
  { name: "freeExchangeVersion", type: "uint64" }, { name: "freePoolVersion", type: "uint64" },
  { name: "serviceBit", type: "bytes32" }, { name: "deadline", type: "uint64" }, { name: "nonce", type: "bytes32" },
] }
const token = "0x00000000000000000000000000000000000c0de2"
const domain = { name: "ThirdPartyStableSettlement", version: "1", chainId: 224422, verifyingContract: token }

describe("BeamioAccount ERC-1271 fixture", function () {
  this.timeout(120_000)
  it("records", async () => {
    // Three managers in ascending address order; the owner must be the first (lowest).
    const ws = [1, 2, 3, 4, 5, 6].map((i) => new ethers.Wallet(ethers.zeroPadValue(ethers.toBeHex(0x4000 + i), 32)))
    ws.sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1))
    const [owner, m2, m3, stranger] = ws
    const ep = await (await ethers.getContractFactory("StandIn")).deploy()
    const factory = await (await ethers.getContractFactory("StandIn")).deploy()
    const acc = await (await ethers.getContractFactory("BeamioAccount")).deploy(await ep.getAddress())
    await (await acc.initialize(owner.address, [owner.address], 1, await factory.getAddress())).wait()
    const account = await acc.getAddress()
    // Policy changes come through the EntryPoint (onlyEntryPoint): impersonate the stand-in.
    await networkHelpers.impersonateAccount(await ep.getAddress())
    await networkHelpers.setBalance(await ep.getAddress(), 10n ** 18n)
    const epSigner = await ethers.getSigner(await ep.getAddress())
    const policy = async (managers: string[], threshold: number) => (await acc.connect(epSigner).setThresholdPolicy(managers, threshold)).wait()

    const order = {
      pool: 0, user: account, nodeId: 101, nodeWallet: "0x00000000000000000000000000000000000a0001",
      minNodeGb: 500000000n, maxUserPay: 1234567n, gbBaseVersion: 3, markupVersion: 2,
      freeExchangeVersion: 0, freePoolVersion: 0, serviceBit: ethers.zeroPadValue("0x04", 32),
      deadline: 1900000000, nonce: ethers.keccak256(ethers.toUtf8Bytes("beamio-wallet-1")),
    }
    const digest = ethers.TypedDataEncoder.hash(domain, types, order)
    const otherDigest = ethers.TypedDataEncoder.hash({ ...domain, verifyingContract: "0x00000000000000000000000000000000000c0de3" }, types, order)
    const ethSign = (w: any, d: string) => w.signMessage(ethers.getBytes(d))
    const join = (...s: string[]) => ethers.concat(s)

    const iface = new ethers.Interface(["function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)"])
    const out: any[] = []
    const record = async (label: string, sig: string, d = digest) => {
      const data = iface.encodeFunctionData("isValidSignature", [d, sig])
      const answer = await ethers.provider.call({ to: account, data })
      const code = await ethers.provider.getCode(account)
      out.push({ label, account, digest: d, signature: sig, code, codeHash: ethers.keccak256(code), rpc: { [data.toLowerCase()]: answer }, valid: answer.startsWith("0x1626ba7e") })
      console.log(label, answer.slice(0, 10))
    }

    // Owner alone, threshold 1.
    const ownerSig = await ethSign(owner, digest)
    await record("owner eth-sign, policy [owner]/1", ownerSig)
    await record("owner signTypedData (not the Beamio protocol), policy [owner]/1", await owner.signTypedData(domain, types, order))
    await record("stranger eth-sign, policy [owner]/1", await ethSign(stranger, digest))
    await record("owner eth-sign of another token's digest, policy [owner]/1", await ethSign(owner, otherDigest), digest)
    const lowV = ethers.getBytes(ownerSig); lowV[64] -= 27
    await record("owner eth-sign with v 0/1, policy [owner]/1", ethers.hexlify(lowV))
    // Add m2, threshold 1: m2 alone is valid.
    await policy([owner.address, m2.address], 1)
    const m2Sig = await ethSign(m2, digest)
    await record("m2 eth-sign, policy [owner,m2]/1", m2Sig)
    // Threshold 2: one signature is no longer enough; two in ascending order are; descending is refused.
    await policy([owner.address, m2.address], 2)
    await record("owner alone, policy [owner,m2]/2 (threshold raised)", ownerSig)
    await record("owner+m2 ascending, policy [owner,m2]/2", join(ownerSig, m2Sig))
    await record("m2+owner descending, policy [owner,m2]/2", join(m2Sig, ownerSig))
    // m2 replaced by m3, threshold 1: m2's earlier valid signature is refused.
    await policy([owner.address, m3.address], 1)
    await record("m2 eth-sign after m2 was removed, policy [owner,m3]/1", m2Sig)
    await record("m3 eth-sign, policy [owner,m3]/1", await ethSign(m3, digest))

    const file = process.env.BEAMIO_WALLET_FIXTURE ?? "beamio-wallet-fixture.json"
    writeFileSync(file, JSON.stringify({
      note: "Generated by tools/service-order/beamio-wallet-fixture.test.ts on a local Hardhat chain from fork 4's verbatim BeamioAccount fixture (0f8ad23, source 8cf6a697); test keys only.",
      token, order: Object.fromEntries(Object.entries(order).map(([k, v]) => [k, v.toString()])), cases: out,
    }, null, 1) + "\n")
    console.log(`wrote ${file}`)
  })
})

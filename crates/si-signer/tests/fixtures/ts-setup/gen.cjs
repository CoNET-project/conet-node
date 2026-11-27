// Regenerates the TEST-ONLY fixtures with the same libraries and calls CoNET-SI uses
// (ethers 6 `Wallet.encrypt`, openpgp.js 6 `generateKey` ecc/curve25519 with a passphrase).
// Usage: CONET_SI_MODULES=/path/to/CoNET-SI/node_modules node gen.cjs
// The keys and the password below exist only in these fixtures; they protect nothing.
const modules = process.env.CONET_SI_MODULES
if (!modules) throw new Error('set CONET_SI_MODULES')
const { ethers } = require(modules + '/ethers')
const pgp = require(modules + '/openpgp')
const fs = require('fs')
const PASS = 'ts-setup-fixture-password'
async function pgpKey(addr) {
  const { privateKey, publicKey } = await pgp.generateKey({ type: 'ecc', passphrase: PASS, userIDs: [{ name: addr }], curve: 'curve25519', format: 'armored' })
  const keyID = (await pgp.readKey({ armoredKey: publicKey })).getKeyIDs()[1].toHex().toUpperCase()
  return { privateKey, publicKey, keyID }
}
function setup(keychain, pgpKey) {
  return { keychain, ipV4: '192.0.2.1', ipV6: '', ipV4Port: 80, ipV6Port: 80, storage_price: 1, outbound_price: 1, pgpKey, cpus: 2, passwd: PASS, platform_verison: 'fixture', dl_publicKeyArmored: '', restartBlockNumber: 0 }
}
;(async () => {
  const dir = __dirname
  // 1. real default shape: Wallet.createRandom().encrypt (scrypt N=131072) as TS cli.ts does
  const w1 = ethers.Wallet.createRandom()
  const k1 = await w1.encrypt(PASS)
  const p1 = await pgpKey(w1.address)
  fs.writeFileSync(dir + '/setup-default.json', JSON.stringify(setup(k1, p1)))
  // 2. small N so the unit tests are fast
  const w2 = ethers.Wallet.createRandom()
  const k2 = await ethers.encryptKeystoreJson({ address: w2.address, privateKey: w2.privateKey }, PASS, { scrypt: { N: 1024 } })
  const p2 = await pgpKey(w2.address)
  fs.writeFileSync(dir + '/setup-small.json', JSON.stringify(setup(k2, p2)))
  fs.writeFileSync(dir + '/expected.json', JSON.stringify({
    default: { wallet: w1.address, keyId: p1.keyID, privateKeyHex: w1.privateKey },
    small: { wallet: w2.address, keyId: p2.keyID, privateKeyHex: w2.privateKey },
    password: PASS,
  }, null, 1))
})()

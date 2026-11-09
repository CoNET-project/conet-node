// R-2: WebRTC direct-path check with a real browser (RECOVER-RUST). LOCAL ONLY, TEST KEYS ONLY.
//
// Two pages of the locally installed Chrome (Playwright `channel: 'chrome'`, no download):
//   page "node"  = the browser node (holds the golden nodeB test wallet, its own DTLS cert)
//   page "voter" = the voter's WebRTC end (reads its OWN getStats)
// Signaling is passed by this script (stands in for the anchor). ICE uses host candidates on
// this machine only (no STUN/TURN, no network).
// Checks:
//   1. the voter takes the remote address/port/type from its own selected candidate pair,
//      not from the node's self-reported address in signaling (a fake one is sent);
//   2. the remote DTLS fingerprint the voter sees equals the node's own certificate;
//   3. a challenge over the data channel, bound to app ID, version, voter, chain/registry,
//      pair ID, DTLS fingerprint and a random nonce, is answered with the node wallet's
//      signature, which the voter verifies;
//   4. ICE restart: the path identifier (local ICE ufrag + selected-pair change count + pair
//      id, all from the voter's own getStats) changes, so the old challenge is void and is
//      redone. A restart can keep the same pair id when addresses stay the same; the ufrag
//      catches it.
//
// Run (needs playwright and ethers resolvable, e.g. from the BeamioContract node_modules):
//   NODE_PATH=<dir with node_modules> node tools/recover-webrtc/r2.cjs
const path = require('path')
const fs = require('fs')
const { chromium } = require('playwright')

const golden = JSON.parse(fs.readFileSync(path.join(__dirname, '../../conformance/vectors/golden.json'), 'utf8'))
const ethersDir = (() => { let d = path.dirname(require.resolve('ethers')); while (path.basename(d) !== 'ethers') d = path.dirname(d); return d })()
const ethersUmd = path.join(ethersDir, 'dist/ethers.umd.min.js')
const NODE_KEY = golden.wallets.nodeB.privateKey
const NODE_ADDR = golden.wallets.nodeB.address
const CTX = { chainId: 224422, registry: '0x00000000000000000000000000000000c0de0001', appId: '0x' + '22'.repeat(32), nodeId: 573, voterNodeId: 7 }

const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a)
// Logs show only a prefix of real local addresses (comparisons use the full value).
const mask = (ip) => !ip ? ip : ip.includes(':') ? ip.split(':')[0] + ':…' : ip.split('.').slice(0, 2).join('.') + '.x.x'

// Runs in each page: the WebRTC end and the helpers the test calls.
const PAGE_LIB = () => {
  window.rtc = { pc: null, dc: null, inbox: [] }
  window.mk = (isNode) => {
    const pc = new RTCPeerConnection({ iceServers: [] })
    rtc.pc = pc
    rtc.candidates = []
    pc.onicecandidate = (e) => { if (e.candidate) rtc.candidates.push(e.candidate.toJSON()) }
    if (isNode) {
      rtc.dc = pc.createDataChannel('recover')
      rtc.dc.onmessage = (e) => rtc.inbox.push(e.data)
    } else {
      pc.ondatachannel = (e) => { rtc.dc = e.channel; rtc.dc.onmessage = (m) => rtc.inbox.push(m.data) }
    }
  }
  window.gatherDone = () => new Promise((r) => {
    if (rtc.pc.iceGatheringState === 'complete') return r()
    rtc.pc.addEventListener('icegatheringstatechange', () => rtc.pc.iceGatheringState === 'complete' && r())
  })
  window.offer = async (opts) => { const o = await rtc.pc.createOffer(opts || {}); await rtc.pc.setLocalDescription(o); await gatherDone(); return rtc.pc.localDescription.toJSON() }
  window.answer = async (desc) => { await rtc.pc.setRemoteDescription(desc); const a = await rtc.pc.createAnswer(); await rtc.pc.setLocalDescription(a); await gatherDone(); return rtc.pc.localDescription.toJSON() }
  window.accept = async (desc) => { await rtc.pc.setRemoteDescription(desc) }
  window.waitOpen = () => new Promise((r) => { const t = setInterval(() => { if (rtc.dc && rtc.dc.readyState === 'open') { clearInterval(t); r() } }, 50) })
  // The voter's own view: selected pair, remote candidate, remote certificate.
  window.observe = async () => {
    const s = await rtc.pc.getStats()
    let transport, pair, remote, local, cert
    s.forEach((r) => { if (r.type === 'transport') transport = r })
    pair = s.get(transport.selectedCandidatePairId)
    remote = s.get(pair.remoteCandidateId)
    local = s.get(pair.localCandidateId)
    cert = s.get(transport.remoteCertificateId)
    // Path identifier: ICE generation (local ufrag) + selected-pair change count + pair id.
    // The pair id alone survives an ICE restart when the addresses stay the same (seen on
    // Chrome 156), so the local ufrag is part of it.
    const pathId = `${transport.iceLocalUsernameFragment}|${transport.selectedCandidatePairChanges}|${pair.id}`
    return { pairId: pathId, remoteIp: remote.address || remote.ip, remotePort: remote.port, candidateType: remote.candidateType,
      relay: remote.candidateType === 'relay' ? (remote.url || 'unknown-relay') : null,
      dtls: cert && cert.fingerprint, dtlsAlg: cert && cert.fingerprintAlgorithm,
      localDtls: (s.get(transport.localCertificateId) || {}).fingerprint, localIp: local.address, localPort: local.port,
      iceState: rtc.pc.iceConnectionState }
  }
  window.peerCert = async () => {
    const s = await rtc.pc.getStats()
    let transport; s.forEach((r) => { if (r.type === 'transport') transport = r })
    const c = s.get(transport.remoteCertificateId)
    return c && c.fingerprint
  }
  window.ownCert = async () => {
    const s = await rtc.pc.getStats()
    let transport; s.forEach((r) => { if (r.type === 'transport') transport = r })
    const c = s.get(transport.localCertificateId)
    return c && c.fingerprint
  }
  window.send = (x) => rtc.dc.send(JSON.stringify(x))
  window.recv = () => new Promise((r) => { const t = setInterval(() => { if (rtc.inbox.length) { clearInterval(t); r(JSON.parse(rtc.inbox.shift())) } }, 20) })
}

// EIP-712 for the challenge reply (same idea as AdmissionResponse, simplified for the browser
// demo: the Rust R-1 tests cover the full PGP + EIP-712 structure).
const DOMAIN = { name: 'CoNET-NodeAdmission', version: '1', chainId: CTX.chainId, verifyingContract: CTX.registry }
const TYPES = { RecoveryWebRtcReply: [
  { name: 'appId', type: 'bytes32' }, { name: 'nodeId', type: 'uint256' }, { name: 'endpointVersion', type: 'uint64' },
  { name: 'voterNodeId', type: 'uint256' }, { name: 'pairId', type: 'string' }, { name: 'dtls', type: 'string' },
  { name: 'voterDtls', type: 'string' },
  { name: 'nonce', type: 'bytes32' }, { name: 'expiresAt', type: 'uint64' } ] }

async function main() {
  const browser = await chromium.launch({ channel: 'chrome', headless: true,
    args: ['--disable-features=WebRtcHideLocalIpsWithMdns', '--allow-loopback-in-peer-connection'] })
  log('env', `macOS`, `Chrome ${browser.version()}`, `Playwright ${require('playwright/package.json').version}`)
  const ctx = await browser.newContext()
  const node = await ctx.newPage()
  const voter = await ctx.newPage()
  for (const p of [node, voter]) { await p.goto('about:blank'); await p.evaluate(PAGE_LIB); await p.addScriptTag({ path: ethersUmd }) }
  await node.evaluate(() => mk(true))
  await voter.evaluate(() => mk(false))

  // Signaling via this script. The node adds a self-reported address: the voter must ignore it.
  const claimed = { ip: '203.0.113.77', port: 9999 }
  const off = await node.evaluate(() => offer())
  log('signal: node offer, self-reported address (ignored by the voter):', `${claimed.ip}:${claimed.port}`)
  const ans = await voter.evaluate((d) => answer(d), off)
  await node.evaluate((d) => accept(d), ans)
  await Promise.all([node.evaluate(() => waitOpen()), voter.evaluate(() => waitOpen())])
  const nodeCert = await node.evaluate(() => ownCert())

  // One round: observe, challenge, answer, verify, re-observe.
  let version = 1
  const round = async (label) => {
    const seen = await voter.evaluate(() => observe())
    log(`${label}: voter getStats selected pair`, JSON.stringify({ pairId: seen.pairId, remote: `${mask(seen.remoteIp)} port ${seen.remotePort}`, type: seen.candidateType, relay: seen.relay, ice: seen.iceState }))
    const dtlsOk = seen.dtls === nodeCert
    log(`${label}: remote DTLS ${seen.dtlsAlg} ${seen.dtls.slice(0, 23)}... equals node's own cert: ${dtlsOk}`)
    const claimedUsed = seen.remoteIp === claimed.ip && seen.remotePort === claimed.port
    log(`${label}: self-reported ${claimed.ip}:${claimed.port} used? ${claimedUsed} (observed ${mask(seen.remoteIp)} port ${seen.remotePort})`)
    const nonce = '0x' + require('crypto').randomBytes(32).toString('hex')
    const ch = { appId: CTX.appId, nodeId: CTX.nodeId, endpointVersion: version, voterNodeId: CTX.voterNodeId, pairId: seen.pairId, dtls: seen.dtls, voterDtls: seen.localDtls, nonce, expiresAt: Math.floor(Date.now() / 1000) + 60 }
    await voter.evaluate((c) => send({ challenge: c }), ch)
    // The node answers on its data channel, signing with its main wallet (golden test key).
    const got = await node.evaluate(() => recv())
    const sig = await node.evaluate(async ({ c, key, domain, types }) => {
      const own = await ownCert()
      const peer = await peerCert()
      // Both sides must see the same two certificates (no splice by the anchor).
      if (c.dtls !== own || c.voterDtls !== peer) return { refused: 'session certificates differ' }
      const w = new ethers.Wallet(key)
      return { sig: await w.signTypedData(domain, types, c), nodeDtls: own, voterDtls: peer }
    }, { c: got.challenge, key: NODE_KEY, domain: DOMAIN, types: TYPES })
    await node.evaluate((r) => send(r), sig)
    const reply = await voter.evaluate(() => recv())
    const now = await voter.evaluate(() => observe())
    const pairSame = now.pairId === ch.pairId
    const who = reply.sig ? require('ethers').verifyTypedData(DOMAIN, TYPES, ch, reply.sig) : null
    const pairOk = reply.nodeDtls === now.dtls && reply.voterDtls === now.localDtls
    log(`${label}: reply signer ${who} == node wallet ${NODE_ADDR}: ${who === NODE_ADDR}; selected pair unchanged: ${pairSame}; both DTLS fingerprints match the voter's session: ${pairOk}`)
    return { seen, ok: dtlsOk && !claimedUsed && who === NODE_ADDR && pairSame && pairOk, ch, reply }
  }

  // Wait until the voter's selected pair has been stable for 1 s before challenging.
  const settle = async () => {
    let last = null, since = Date.now()
    for (let i = 0; i < 100; i++) {
      const o = await voter.evaluate(() => observe())
      if (o.pairId !== last) { last = o.pairId; since = Date.now() }
      if (Date.now() - since >= 1000) return
      await new Promise((r) => setTimeout(r, 100))
    }
  }
  // A round whose pair changed in flight is void and redone (protocol rule), up to 3 times.
  const roundWithRedo = async (label) => {
    for (let attempt = 1; attempt <= 3; attempt++) {
      const r = await round(`${label} try ${attempt}`)
      if (r.ok) return r
      log(`${label} try ${attempt}: void (selected pair changed or check failed), redo`)
      await settle()
    }
    return { ok: false }
  }
  const r0 = await round('round 0 (no settle wait)')
  log('round 0 shows in-flight pair change handling:', r0.ok ? 'pair stayed' : 'pair changed -> void')
  await settle()
  const r1 = await roundWithRedo('round 1')
  log('round 1 result:', r1.ok ? 'PASS' : 'FAIL')

  // ICE restart, renegotiated through the script's signaling.
  const oldPair = r1.seen.pairId
  const off2 = await node.evaluate(() => offer({ iceRestart: true }))
  const ans2 = await voter.evaluate((d) => answer(d), off2)
  await node.evaluate((d) => accept(d), ans2)
  let after
  for (let i = 0; i < 100; i++) {
    after = await voter.evaluate(() => observe())
    if (after.pairId !== oldPair && after.iceState !== 'checking' && after.iceState !== 'new') break
    await new Promise((r) => setTimeout(r, 100))
  }
  const changed = after.pairId !== oldPair
  log(`ICE restart: voter path ${oldPair} -> ${after.pairId} (changed: ${changed})`)
  // The voter keeps the challenge only if its stored pair is still the selected one.
  const oldStillValid = after.pairId === r1.ch.pairId
  log(`old challenge (pair ${r1.ch.pairId}) still valid after restart: ${oldStillValid} -> ${oldStillValid ? 'keep' : 'void, redo'}`)
  version = 2
  await settle()
  const r2 = await roundWithRedo('round 2 (redo after ICE restart)')
  log('round 2 result:', r2.ok ? 'PASS' : 'FAIL')

  const pass = r1.ok && changed && !oldStillValid && r2.ok
  log('R-2 overall:', pass ? 'PASS' : 'FAIL')
  await browser.close()
  process.exit(pass ? 0 : 1)
}

main().catch((e) => { console.error(e); process.exit(2) })

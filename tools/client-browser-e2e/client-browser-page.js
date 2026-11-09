// Browser-side code for the CLIENT-BROWSER end-to-end test. Injected into two Chrome pages:
//   node page  = a TEST-HARNESS browser-node client (no product browser-node client exists yet):
//                holds the node wallet and PGP key, signs and sends its own transactions, answers
//                recovery challenges over WebRTC data channels, shows its on-chain status.
//   voter page = the WebRTC ends of the 20 voters (each voter reads its OWN getStats).
// Chain access goes through window.rpc (Playwright exposeFunction -> local Hardhat chain).
/* global ethers, openpgp */
(() => {
  const CH_PREFIX = 'CONET-ADMISSION-CHALLENGE-v1\n'
  const RP_PREFIX = 'CONET-ADMISSION-REPLY-v1\n'
  const fpNorm = (s) => String(s).replace(/^0x/, '').replace(/:/g, '').toUpperCase()
  // D8 (Rust line proposal): keccak(0x02 ‖ keccak(fp_norm) ‖ relay? ‖ keccak(relay or ""))
  const endpointHash = (fp, relay) => ethers.keccak256(ethers.concat([
    '0x02', ethers.keccak256(ethers.toUtf8Bytes(fpNorm(fp))), relay ? '0x01' : '0x00',
    ethers.keccak256(ethers.toUtf8Bytes(relay || ''))]))
  window.lib = { fpNorm, endpointHash, CH_PREFIX, RP_PREFIX }

  const eip1193 = { request: async ({ method, params }) => {
    const r = await window.rpc(method, params || [])
    if (r && r.__error) { const e = new Error(r.message); e.code = -32603; e.data = r.data; throw e }
    return r
  } }
  const errData = (e) => {
    for (const c of [e && e.data, e && e.info && e.info.error && e.info.error.data, e && e.error && e.error.data, e && e.revert && e.revert.data]) {
      if (typeof c === 'string' && c.startsWith('0x')) return c
      if (c && typeof c.data === 'string') return c.data
    }
    return null
  }

  // ---------------------------------------------------------------- statistics of one pc
  async function stats(pc) {
    const s = await pc.getStats()
    let t; s.forEach((r) => { if (r.type === 'transport') t = r })
    if (!t || !t.selectedCandidatePairId) return null
    const pair = s.get(t.selectedCandidatePairId)
    const remote = s.get(pair.remoteCandidateId)
    const rc = s.get(t.remoteCertificateId) || {}
    const lc = s.get(t.localCertificateId) || {}
    return {
      pathId: `${t.iceLocalUsernameFragment}|${t.selectedCandidatePairChanges}|${pair.id}`,
      remoteIp: remote.address || remote.ip, remotePort: remote.port, candidateType: remote.candidateType,
      relay: remote.candidateType === 'relay' ? (remote.url || 'unknown-relay') : null,
      dtls: rc.fingerprint, localDtls: lc.fingerprint, ice: pc.iceConnectionState,
    }
  }
  const gather = (pc) => new Promise((r) => {
    if (pc.iceGatheringState === 'complete') return r()
    pc.addEventListener('icegatheringstatechange', () => pc.iceGatheringState === 'complete' && r())
  })

  // ================================================================ node page (browser node)
  const N = window.N = { pcs: {}, cert: null, fp: null, log: [], answered: 0, refused: [] }
  const nlog = (...a) => N.log.push(a.join(' '))

  N.init = async (cfg) => {
    N.cfg = cfg
    N.provider = new ethers.BrowserProvider(eip1193, cfg.chainId)
    N.provider.pollingInterval = 200
    N.wallet = new ethers.Wallet(cfg.pk, N.provider)
    N.reg = new ethers.Contract(cfg.reg, cfg.abi, N.wallet)
    N.lens = new ethers.Contract(cfg.lens, cfg.lensAbi, N.provider)
    N.priv = await openpgp.readPrivateKey({ armoredKey: cfg.privArmored })
    const el = document.createElement('div'); el.id = 'status'; el.textContent = 'starting'; document.body.appendChild(el)
    const poll = async () => {
      try {
        const active = await N.reg.isActive(cfg.nodeId)
        const [views] = await N.lens.getActiveNodesByType(cfg.browserType, 0, 500)
        const inLens = views.some((v) => v.nodeId === BigInt(cfg.nodeId))
        el.textContent = `${active ? 'online' : 'offline'} lens=${inLens ? 'listed' : 'absent'}`
        N.ui = { active, inLens, at: Date.now() }
      } catch (e) { el.textContent = 'error ' + e.message }
    }
    await poll()
    N.timer = setInterval(poll, 250)
    return N.wallet.address
  }
  N.refresh = async () => { const t = Date.now(); while (!N.ui || N.ui.at <= t) await new Promise((r) => setTimeout(r, 50)); return document.getElementById('status').textContent }

  // Send a transaction the client signs itself (type 2, explicit gas so a revert is reported by the chain).
  N.tx = async (fn, args, gasLimit = 1_500_000) => {
    try {
      // Nonce straight from the chain: ethers' short request cache can hand back a stale one right
      // after a refused (but mined) transaction.
      const nonce = Number(await window.rpc('eth_getTransactionCount', [N.wallet.address, 'pending']))
      const tx = await N.reg[fn](...args, { gasLimit, nonce })
      // Receipt polled straight from the chain (no ethers cache or block subscription), 15 s limit.
      let rc = null
      for (let i = 0; i < 300 && !rc; i++) {
        rc = await window.rpc('eth_getTransactionReceipt', [tx.hash])
        if (rc && rc.__error) rc = null
        if (!rc) await new Promise((r) => setTimeout(r, 50))
      }
      if (!rc) return { ok: false, hash: tx.hash, error: 'no receipt within 15 s', pendingNonce: Number(await window.rpc('eth_getTransactionCount', [N.wallet.address, 'pending'])), nonce }
      rc.status = Number(rc.status); rc.gasUsed = BigInt(rc.gasUsed)
      const logs = rc.logs.map((l) => { try { return N.reg.interface.parseLog(l) } catch { return null } }).filter(Boolean)
      return { ok: rc.status === 1, hash: tx.hash, type: tx.type, gasUsed: rc.gasUsed.toString(), events: logs.map((l) => l.name), logs: logs.map((l) => ({ name: l.name, args: l.args.toArray().map(String) })) }
    } catch (e) {
      const d = errData(e)
      let name = null
      try { name = d ? N.reg.interface.parseError(d).name : null } catch { /* unknown */ }
      return { ok: false, error: name || e.shortMessage || e.message, data: d }
    }
  }

  // One DTLS certificate for the node's WebRTC endpoint; its fingerprint is the endpoint (D8).
  N.newCert = async () => {
    for (const k of Object.keys(N.pcs)) { try { N.pcs[k].pc.close() } catch { /* closed */ } }
    N.pcs = {}
    N.cert = await RTCPeerConnection.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' })
    const f = N.cert.getFingerprints().find((x) => x.algorithm === 'sha-256')
    N.fp = f.value.toUpperCase()
    N.ep = endpointHash(N.fp, null)
    return { fp: N.fp, endpointHash: N.ep }
  }

  N.requestRecovery = async (ttl) => {
    const r = await N.tx('requestRecovery', [N.cfg.nodeId, { tcpPort: 0, udpPort: 0, endpointHash: N.ep, mode: 1, servicesNow: N.cfg.servicesNow, ttl }, ''])
    const ev = (r.logs || []).find((l) => l.name === 'RecoveryRequested')
    r.recId = ev ? ethers.zeroPadValue(ethers.toBeHex(BigInt(ev.args[0])), 32) : null
    return r
  }

  // Key of a node from the chain's node table (pgpOf). The table keeps no separate pgpHash for a
  // listed node; the voter must also be active on chain.
  N.chainKey = async (nodeId) => {
    const bytes = await N.reg.pgpOf(nodeId)
    if (bytes === '0x') throw new Error('no PGP field for ' + nodeId)
    if (!(await N.reg.isActive(nodeId))) throw new Error('voter not active ' + nodeId)
    return openpgp.readKey({ armoredKey: atob(ethers.toUtf8String(bytes)) })
  }

  N.accept = async (voterId, offer) => {
    const pc = new RTCPeerConnection({ iceServers: [], certificates: [N.cert] })
    const slot = N.pcs[voterId] = { pc, dc: null }
    pc.ondatachannel = (e) => { slot.dc = e.channel; slot.dc.onmessage = (m) => N.onChallenge(voterId, m.data) }
    await pc.setRemoteDescription(offer)
    const a = await pc.createAnswer(); await pc.setLocalDescription(a); await gather(pc)
    return pc.localDescription.toJSON()
  }

  N.onChallenge = async (voterId, armored) => {
    const refuse = (why) => { N.refused.push({ voterId, why }); nlog('refuse', voterId, why) }
    try {
      const msg = await openpgp.readMessage({ armoredMessage: armored })
      const pre = await openpgp.decrypt({ message: msg, decryptionKeys: N.priv })
      if (!pre.data.startsWith(CH_PREFIX)) return refuse('prefix')
      const c = JSON.parse(pre.data.slice(CH_PREFIX.length))
      const vkey = await N.chainKey(c.voterNodeId)
      const ver = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: armored }), decryptionKeys: N.priv, verificationKeys: vkey, expectSigned: true })
      await ver.signatures[0].verified
      if (c.voterNodeId !== voterId) return refuse('voter id differs from channel')
      if (c.chainId !== N.cfg.chainId || c.registry.toLowerCase() !== N.cfg.reg.toLowerCase()) return refuse('domain')
      if (c.nodeId !== N.cfg.nodeId) return refuse('nodeId')
      const cur = await N.reg.currentRecovery(N.cfg.nodeId)
      if (c.recId !== cur) return refuse('recId is not the current request')
      if (c.endpointHash !== N.ep) return refuse('endpointHash')
      if (Math.floor(Date.now() / 1000) > c.expiresAt) return refuse('expired')
      const st = await stats(N.pcs[voterId].pc)
      if (fpNorm(c.seenDtls) !== fpNorm(N.fp) || fpNorm(st.localDtls) !== fpNorm(N.fp)) return refuse('voter saw another node DTLS')
      if (fpNorm(c.voterDtls) !== fpNorm(st.dtls)) return refuse('voter DTLS differs from this channel')
      const reply = { challengeHash: ethers.keccak256(ethers.toUtf8Bytes(armored)), recId: c.recId, nonce: c.nonce, voterNodeId: voterId, nodeDtls: N.fp, voterDtls: st.dtls }
      const out = await openpgp.encrypt({ message: await openpgp.createMessage({ text: RP_PREFIX + JSON.stringify(reply) }), encryptionKeys: vkey, signingKeys: N.priv })
      N.pcs[voterId].dc.send(out)
      N.answered++
    } catch (e) { refuse('error ' + e.message) }
  }

  // ================================================================ voter page
  const V = window.V = { pcs: {} }
  V.offer = async (voterId) => {
    const pc = new RTCPeerConnection({ iceServers: [] })
    const slot = V.pcs[voterId] = { pc, dc: pc.createDataChannel('recover'), inbox: [] }
    slot.dc.onmessage = (m) => slot.inbox.push(m.data)
    const o = await pc.createOffer(); await pc.setLocalDescription(o); await gather(pc)
    return pc.localDescription.toJSON()
  }
  V.accept = async (voterId, answer) => { await V.pcs[voterId].pc.setRemoteDescription(answer) }
  V.open = (voterId) => new Promise((r, j) => {
    const t0 = Date.now()
    const t = setInterval(() => {
      if (V.pcs[voterId].dc.readyState === 'open') { clearInterval(t); r(true) }
      if (Date.now() - t0 > 15000) { clearInterval(t); j(new Error('data channel did not open')) }
    }, 30)
  })
  // The voter's own view; waits until the selected pair stays the same for 500 ms.
  V.observe = async (voterId) => {
    let prev = null
    for (let i = 0; i < 40; i++) {
      const s = await stats(V.pcs[voterId].pc)
      if (s && prev && s.pathId === prev.pathId && s.dtls === prev.dtls) return s
      prev = s
      await new Promise((r) => setTimeout(r, 250))
    }
    return prev
  }
  V.send = (voterId, armored) => V.pcs[voterId].dc.send(armored)
  V.recv = (voterId, ms = 10000) => new Promise((r) => {
    const t0 = Date.now()
    const t = setInterval(() => {
      const box = V.pcs[voterId].inbox
      if (box.length) { clearInterval(t); r(box.shift()) }
      if (Date.now() - t0 > ms) { clearInterval(t); r(null) }
    }, 20)
  })
  V.close = (voterId) => { try { V.pcs[voterId].pc.close() } catch { /* closed */ } }
})()

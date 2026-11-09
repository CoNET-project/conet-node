// CLIENT-BROWSER: local Chrome (Playwright, system Chrome, nothing downloaded) + local Hardhat chain
// running the node line's current NodeRegistryV2 + NodeRegistryV2Ext.
//   1. browser node goes offline by its own setOffline
//   2. recovery: requestRecovery (D8 endpoint hash) -> 20 voters challenge the browser over real
//      WebRTC (own getStats path, both DTLS fingerprints) -> voteRecovery -> finalize -> online
//   3. reverse: markOnline / setOnline without a vote are refused; a request inside the 12-hour
//      offline cooldown or without the 0.01 online fee is refused; an endpoint change during the
//      vote voids the old request and its votes (after the node line's 5-minute request gap, C17)
// The browser-node page is a TEST-HARNESS client (no product browser-node client exists yet).
// Voters are simulated by this script (their WebRTC ends run in a second Chrome page).
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import * as openpgp from "openpgp";
import { chromium } from "playwright";
import { ethers, time, SVC, BROWSER, deployFixture, sponsorRegister, goOnline } from "./helpers.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const ethersUmd = path.join(here, "../../node_modules/ethers/dist/ethers.umd.min.js");
const pgpUmd = path.join(here, "../../node_modules/openpgp/dist/openpgp.min.js");
const pkgVer = (n: string) => JSON.parse(fs.readFileSync(path.join(here, "../../node_modules", n, "package.json"), "utf8")).version;
const LOG = process.env.CLIENT_BROWSER_LOG ?? path.join(here, "../../client-browser-e2e.log");
const CH_PREFIX = "CONET-ADMISSION-CHALLENGE-v1\n";
const RP_PREFIX = "CONET-ADMISSION-REPLY-v1\n";
const REC = { VOTING: 1n, PASSED: 2n, REJECTED: 3n, VOID: 4n };

fs.writeFileSync(LOG, "");
const log = (...a: any[]) => {
  const line = `${new Date().toISOString().slice(11, 23)} ${a.map((x) => (typeof x === "string" ? x : JSON.stringify(x, (_k, v) => (typeof v === "bigint" ? v.toString() : v)))).join(" ")}`;
  fs.appendFileSync(LOG, line + "\n");
  console.log("      " + line);
};
// Logs show only a prefix of local addresses (comparisons use the full value).
const mask = (ip?: string) => (!ip ? ip : ip.includes(":") ? ip.split(":")[0] + ":…" : ip.split(".").slice(0, 2).join(".") + ".x.x");
const fpNorm = (s: string) => String(s).replace(/^0x/, "").replace(/:/g, "").toUpperCase();
const endpointHash = (fp: string, relay: string | null) =>
  ethers.keccak256(ethers.concat(["0x02", ethers.keccak256(ethers.toUtf8Bytes(fpNorm(fp))), relay ? "0x01" : "0x00", ethers.keccak256(ethers.toUtf8Bytes(relay ?? ""))]));

// The node table stores the PGP field only; the applicant's pgpHash is in its Recovery record.
async function chainKey(reg: any, nodeId: number | bigint, pgpHash?: string) {
  const bytes = await reg.pgpOf(nodeId);
  if (pgpHash && ethers.keccak256(bytes) !== pgpHash) throw new Error(`pgpHash mismatch for node ${nodeId}`);
  return openpgp.readKey({ armoredKey: Buffer.from(ethers.toUtf8String(bytes), "base64").toString("utf8") });
}

describe("CLIENT-BROWSER · Chrome browser node + local chain end to end", function () {
  this.timeout(600_000);
  let browser: any, nodePage: any, voterPage: any, ctx: any, B: any;
  const results: Record<string, string> = {};

  before(async () => {
    ctx = await deployFixture();
    const sp = ctx.nodes[0];
    const A1 = await sponsorRegister(ctx, { sponsor: sp, operator: ctx.opA, ip: "198.51.100.1" });
    const A2 = await sponsorRegister(ctx, { sponsor: sp, operator: ctx.opB, ip: "198.51.100.2" });
    B = await sponsorRegister(ctx, { sponsor: sp, operator: ctx.signers[12], nodeType: BROWSER, services: SVC.ENTRY | SVC.FETCH | SVC.MAINT | SVC.EGRESS_TCP | SVC.CPU });
    await ctx.reg.connect(ctx.governor).setSubsidyPool(await ctx.pool.getAddress());
    ctx.A1 = A1; ctx.A2 = A2;
    const net = await ethers.provider.getNetwork();
    log("env", { chain: "Hardhat EDR (in-process local chain)", chainId: Number(net.chainId), registry: await ctx.reg.getAddress(), lens: await ctx.lens.getAddress(), browserNodeId: Number(B.id), anchors: [Number(A1.id), Number(A2.id)] });

    browser = await chromium.launch({ channel: "chrome", headless: true, args: ["--disable-features=WebRtcHideLocalIpsWithMdns", "--allow-loopback-in-peer-connection"] });
    log("env", { chrome: browser.version(), playwright: pkgVer("playwright"), openpgp: pkgVer("openpgp"), ethers: pkgVer("ethers") });
    const bctx = await browser.newContext();
    // Secure-context origins served by Playwright itself (nothing leaves the machine): WebCrypto
    // (openpgp) is not available on about:blank.
    await bctx.route("https://*.test/**", (r: any) => r.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><html><body></body></html>" }));
    nodePage = await bctx.newPage();
    voterPage = await bctx.newPage();
    // JSON-RPC bridge to the local chain. The page signs its own transactions; the bridge only relays.
    await nodePage.exposeFunction("rpc", async (method: string, params: any[]) => {
      try {
        return await ethers.provider.send(method, params);
      } catch (e: any) {
        const d = typeof e?.data === "string" ? e.data : e?.data?.data ?? e?.error?.data ?? null;
        return { __error: true, message: String(e?.message ?? e), data: d };
      }
    });
    nodePage.on("console", (m: any) => m.type() === "error" && log("node page console error", m.text()));
    for (const [p, origin] of [[nodePage, "https://browser-node.test/"], [voterPage, "https://voters.test/"]] as const) {
      await p.goto(origin);
      await p.addScriptTag({ path: ethersUmd });
      await p.addScriptTag({ path: pgpUmd });
      await p.addScriptTag({ path: path.join(here, "client-browser-page.js") });
    }
    const addr = await nodePage.evaluate((cfg: any) => (window as any).N.init(cfg), {
      pk: B.wallet.privateKey,
      privArmored: B.key.privateArmored,
      reg: await ctx.reg.getAddress(),
      lens: await ctx.lens.getAddress(),
      abi: ctx.reg.interface.formatJson(),
      lensAbi: ctx.lens.interface.formatJson(),
      nodeId: Number(B.id),
      chainId: Number(net.chainId),
      browserType: BROWSER,
      servicesNow: SVC.ENTRY,
    });
    expect(addr).to.equal(B.wallet.address);
    // Harness pre-state: the browser node declared online (node-signed declaration, anchor submits).
    await (await goOnline(ctx, B, [A1, A2], { ttl: 3600n })).tx;
    const ui = await nodePage.evaluate(() => (window as any).N.refresh());
    log("setup: browser node declared online via anchors (harness pre-state)", { isActive: await ctx.reg.isActive(B.id), ui });
    expect(ui).to.equal("online lens=listed");
  });

  after(async () => {
    await browser?.close();
    log("summary", results);
  });

  async function lensHas(id: bigint | number) {
    const [views] = await ctx.lens.getActiveNodesByType(BROWSER, 0, 500);
    return views.some((v: any) => v.nodeId === BigInt(id));
  }

  // One voter: connect over WebRTC, observe its own path, challenge, verify the reply, vote.
  async function voter(i: number, recIdExpected: string, opts: { vote?: boolean } = {}) {
    const v = ctx.nodes[i];
    const vid = Number(v.id); // page channels are keyed by the voter's chain node id
    const offer = await voterPage.evaluate((id: number) => (window as any).V.offer(id), vid);
    const answer = await nodePage.evaluate(([id, o]: any) => (window as any).N.accept(id, o), [vid, offer]);
    await voterPage.evaluate(([id, a]: any) => (window as any).V.accept(id, a), [vid, answer]);
    await voterPage.evaluate((id: number) => (window as any).V.open(id), vid);
    const obs = await voterPage.evaluate((id: number) => (window as any).V.observe(id), vid);
    const recId = await ctx.reg.currentRecovery(B.id);
    const [rec] = await ctx.reg.getRecovery(recId);
    const out: any = { voter: i, nodeId: Number(v.id), path: obs.pathId, remote: `${mask(obs.remoteIp)}:${obs.remotePort}`, type: obs.candidateType, relay: obs.relay };
    if (recId !== recIdExpected) return { ...out, refused: "chain current request differs from the expected one" };
    // The voter's own check of the endpoint: the DTLS fingerprint it sees must hash to the request.
    const seenHash = endpointHash(obs.dtls, obs.relay);
    if (seenHash !== rec.endpointHash) return { ...out, refused: "observed DTLS does not match the request endpointHash" };
    const bKey = await chainKey(ctx.reg, B.id, rec.pgpHash);
    const vPriv = await openpgp.readPrivateKey({ armoredKey: v.key.privateArmored });
    const now = Math.floor(Date.now() / 1000);
    const ch = {
      kind: 2, chainId: Number((await ethers.provider.getNetwork()).chainId), registry: await ctx.reg.getAddress(),
      nodeId: Number(B.id), recId, version: Number(rec.version ?? 0), endpointHash: rec.endpointHash,
      voterNodeId: vid, nonce: ethers.hexlify(ethers.randomBytes(32)),
      issuedAt: now, expiresAt: now + 60, pathId: obs.pathId, observationHash: ethers.keccak256(ethers.toUtf8Bytes(`${obs.remoteIp}|${obs.remotePort}|${obs.candidateType}`)),
      seenDtls: obs.dtls, voterDtls: obs.localDtls,
    };
    const armored = await openpgp.encrypt({ message: await openpgp.createMessage({ text: CH_PREFIX + JSON.stringify(ch) }), encryptionKeys: bKey, signingKeys: vPriv });
    // The node page looks up the voter key by voterNodeId on chain: the reserved test nodes' chain ids.
    await voterPage.evaluate(([id, a]: any) => (window as any).V.send(id, a), [vid, armored]);
    const replyArmored = await voterPage.evaluate((id: number) => (window as any).V.recv(id, 10000), vid);
    if (!replyArmored) return { ...out, refused: "no reply (node refused or timed out)" };
    const dec = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: replyArmored }), decryptionKeys: vPriv, verificationKeys: bKey, expectSigned: true });
    await dec.signatures[0].verified;
    const text = String(dec.data);
    if (!text.startsWith(RP_PREFIX)) return { ...out, refused: "reply prefix" };
    const rp = JSON.parse(text.slice(RP_PREFIX.length));
    if (rp.challengeHash !== ethers.keccak256(ethers.toUtf8Bytes(armored)) || rp.nonce !== ch.nonce || rp.recId !== recId) return { ...out, refused: "reply does not bind the challenge" };
    if (fpNorm(rp.nodeDtls) !== fpNorm(obs.dtls) || fpNorm(rp.voterDtls) !== fpNorm(obs.localDtls)) return { ...out, refused: "reply DTLS fingerprints differ from own stats" };
    const again = await voterPage.evaluate((id: number) => (window as any).V.observe(id), vid);
    if (again.pathId !== obs.pathId || again.dtls !== obs.dtls) return { ...out, refused: "path changed during the challenge" };
    out.checked = "pgp(sig+enc) ok, chain keys ok, path stable, both DTLS ok, endpointHash ok";
    if (opts.vote === false) return out;
    const tx = await ctx.reg.connect(v.wallet).voteRecovery(recId, true);
    const rc = await tx.wait();
    out.vote = { tx: tx.hash.slice(0, 12) + "…", gasUsed: Number(rc.gasUsed) };
    return out;
  }

  it("1. browser node goes offline by its own setOffline: isActive false, absent from Lens, UI offline", async () => {
    expect(await lensHas(B.id)).to.equal(true);
    const r = await nodePage.evaluate(() => (window as any).N.tx("setOffline", [(window as any).N.cfg.nodeId]));
    const ui = await nodePage.evaluate(() => (window as any).N.refresh());
    log("step1 setOffline from the browser page", { r, isActive: await ctx.reg.isActive(B.id), lens: await lensHas(B.id), ui });
    expect(r.ok).to.equal(true);
    expect(r.type).to.equal(2);
    expect(await ctx.reg.isActive(B.id)).to.equal(false);
    expect(await lensHas(B.id)).to.equal(false);
    expect(ui).to.equal("offline lens=absent");
    results["1 setOffline"] = "passed";
  });

  it("3a. without a vote: markOnline from the browser page and setOnline from an anchor are refused", async () => {
    const m = await nodePage.evaluate(() => (window as any).N.tx("markOnline", [(window as any).N.cfg.nodeId], 300000));
    log("step3a markOnline from the browser page", m);
    expect(m.ok).to.equal(false);
    expect(m.error).to.equal("RecoveryVoteRequired");
    let so: string | null = null;
    try {
      await (await goOnline(ctx, B, [ctx.A1, ctx.A2])).tx;
    } catch (e: any) {
      try { so = ctx.reg.interface.parseError(e.data ?? e.error?.data)?.name ?? null; } catch { so = String(e.message).match(/RecoveryVoteRequired/)?.[0] ?? String(e.message).slice(0, 200); }
    }
    log("step3a setOnline (node-signed declaration, anchor submits) after offline", { error: so });
    expect(so).to.equal("RecoveryVoteRequired");
    expect(await ctx.reg.isActive(B.id)).to.equal(false);
    results["3a markOnline/setOnline refused"] = "passed";
  });

  it("2+3b. recovery over real WebRTC; an endpoint change mid-vote voids the old request; 20 votes bring it online", async () => {
    // First request: certificate 1. Project decision "上线表决防刷": no recovery within 12 hours of
    // going offline, and the 0.01 online fee comes with the request.
    const c1 = await nodePage.evaluate(() => (window as any).N.newCert());
    const inCooldown = await nodePage.evaluate(() => (window as any).N.requestRecovery(1800));
    log("step3c requestRecovery inside the 12-hour cooldown", { ok: inCooldown.ok, error: inCooldown.error });
    // Soft check: record and go on, fail at the end, so every step still runs and is reported.
    const soft: string[] = [];
    if (inCooldown.ok || inCooldown.error !== "OfflineCooldown") {
      const raw = await ctx.reg.getNodeRaw(B.id);
      soft.push(`3c: recovery inside the 12-hour cooldown was ${inCooldown.ok ? "ACCEPTED" : inCooldown.error} (outOfServiceSince=${raw.outOfServiceSince}, onlineFrom=${raw.onlineFrom}, onlineUntil=${raw.onlineUntil} after the browser's setOffline)`);
    }
    await time.increase(43_200);
    const noFee = await nodePage.evaluate(() => (window as any).N.requestRecovery(1800, "0"));
    log("step3c requestRecovery after the cooldown without the online fee", { ok: noFee.ok, error: noFee.error });
    expect(noFee.ok).to.equal(false);
    expect(noFee.error).to.equal("OnlineFeeRequired");
    results["3c online fee enforced"] = "passed";
    results["3c 12-hour cooldown after the browser's own setOffline"] = soft.length ? "FAILED (contract)" : "passed";
    const r1 = await nodePage.evaluate(() => (window as any).N.requestRecovery(1800));
    log("step2 requestRecovery #1 from the browser page", { fp: c1.fp.slice(0, 23) + "…", endpointHash: c1.endpointHash, tx: r1.hash, ok: r1.ok, recId: r1.recId });
    expect(r1.ok).to.equal(true);
    expect((await ctx.reg.getRecovery(r1.recId))[0].endpointHash).to.equal(c1.endpointHash);
    expect(c1.endpointHash).to.equal(endpointHash(c1.fp, null));
    for (let i = 1; i <= 10; i++) {
      const o = await voter(i, r1.recId);
      log("step2 voter on #1", o);
      expect(o.refused, o.refused).to.equal(undefined);
    }
    expect((await ctx.reg.getRecovery(r1.recId))[0].agree).to.equal(10n);
    const v11 = Number(ctx.nodes[11].id);
    // Voter 11 connects to the OLD endpoint and observes it, but has not challenged yet.
    const offer = await voterPage.evaluate((id: number) => (window as any).V.offer(id), v11);
    const ans = await nodePage.evaluate(([id, o]: any) => (window as any).N.accept(id, o), [v11, offer]);
    await voterPage.evaluate(([id, a]: any) => (window as any).V.accept(id, a), [v11, ans]);
    await voterPage.evaluate((id: number) => (window as any).V.open(id), v11);
    const staleObs = await voterPage.evaluate((id: number) => (window as any).V.observe(id), v11);

    // Endpoint change: the browser regenerates its DTLS certificate and requests again.
    const c2 = await nodePage.evaluate(() => (window as any).N.newCert());
    // Node line C17 (added 2026-11-08): at least 5 minutes between two requests of one node.
    const tooSoon = await nodePage.evaluate(() => (window as any).N.requestRecovery(1800));
    log("step3b re-request at once after the endpoint change", { ok: tooSoon.ok, error: tooSoon.error });
    expect(tooSoon.ok).to.equal(false);
    expect(tooSoon.error).to.equal("RecoveryTooSoon");
    // In the gap the old request is still open for the old endpoint; a voter connecting now sees the
    // new DTLS certificate and refuses on its own (no vote).
    expect((await ctx.reg.getRecovery(r1.recId))[0].state).to.equal(REC.VOTING);
    const gap = await voter(12, r1.recId);
    log("step3b voter during the 5-minute gap", gap);
    expect(gap.refused).to.equal("observed DTLS does not match the request endpointHash");
    await voterPage.evaluate((id: number) => (window as any).V.close(id), Number(ctx.nodes[12].id));
    await time.increase(300);
    const r2 = await nodePage.evaluate(() => (window as any).N.requestRecovery(1800));
    log("step3b endpoint changed: requestRecovery #2", { fp: c2.fp.slice(0, 23) + "…", endpointHash: c2.endpointHash, recId: r2.recId, ok: r2.ok });
    expect(r2.ok).to.equal(true);
    expect(r2.recId).to.not.equal(r1.recId);
    const old = (await ctx.reg.getRecovery(r1.recId))[0];
    expect(old.state).to.equal(REC.VOID);
    expect((await ctx.reg.getRecovery(r2.recId))[0].agree).to.equal(0n);
    let lateVote: string | null = null;
    try { await ctx.reg.connect(ctx.nodes[11].wallet).voteRecovery(r1.recId, true); } catch (e: any) { lateVote = String(e.message).match(/AdmissionState/)?.[0] ?? String(e.message).slice(0, 160); }
    const staleCheck = endpointHash(staleObs.dtls, staleObs.relay) === (await ctx.reg.getRecovery(r2.recId))[0].endpointHash;
    log("step3b old request", { state: Number(old.state), agreeKept: Number(old.agree), lateVoteOnOld: lateVote, voter11OldObservationMatchesNew: staleCheck });
    expect(lateVote).to.equal("AdmissionState");
    expect(staleCheck).to.equal(false);
    await voterPage.evaluate((id: number) => (window as any).V.close(id), v11);
    results["3b endpoint change voids old votes"] = "passed";

    // 20 voters on the new request (voters 1..10 may vote again: a different recId).
    for (let i = 1; i <= 20; i++) {
      const o = await voter(i, r2.recId);
      log("step2 voter on #2", o);
      expect(o.refused, o.refused).to.equal(undefined);
    }
    const before = (await ctx.reg.getRecovery(r2.recId))[0];
    log("step2 after 20 votes", { agree: Number(before.agree), disagree: Number(before.disagree ?? 0), state: Number(before.state), isActive: await ctx.reg.isActive(B.id) });
    expect(before.agree).to.equal(20n);
    expect(await ctx.reg.isActive(B.id)).to.equal(false);
    const early = await nodePage.evaluate((rid: string) => (window as any).N.tx("finalizeRecovery", [rid]), r2.recId);
    log("step2 finalize before 5 minutes", { ok: early.ok, error: early.error });
    expect(early.ok).to.equal(false);
    await time.increase(300);
    const fin = await nodePage.evaluate((rid: string) => (window as any).N.tx("finalizeRecovery", [rid]), r2.recId);
    const ui = await nodePage.evaluate(() => (window as any).N.refresh());
    const refused = await nodePage.evaluate(() => (window as any).N.refused);
    log("step2 finalizeRecovery from the browser page", { ok: fin.ok, error: fin.error, gasUsed: fin.gasUsed, events: fin.events, isActive: await ctx.reg.isActive(B.id), lens: await lensHas(B.id), ui, nodeRefusals: refused });
    expect(fin.ok).to.equal(true);
    expect((await ctx.reg.getRecovery(r2.recId))[0].state).to.equal(REC.PASSED);
    expect(await ctx.reg.isActive(B.id)).to.equal(true);
    expect(await lensHas(B.id)).to.equal(true);
    expect(ui).to.equal("online lens=listed");
    results["2 recovery by 20 WebRTC-checked votes"] = "passed";
    log("soft failures", soft);
    expect(soft, soft.join("; ")).to.deep.equal([]);
  });
});

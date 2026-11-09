// Node line v0.4.2 comparison fixture for crates/conet-node/tests/v042_fixture.rs. Runs in a COPY of the
// node line's contract tree on Hardhat's in-process chain; test keys only. Writes $V042_FIXTURE.
//
//   cp tools/vote-gate/v042-fixture.test.ts <copy>/test/node-registry-v2/
//   cd <copy> && npx hardhat --config hardhat.node-registry.config.ts test mocha test/node-registry-v2/v042-fixture.test.ts
//
// Records, from the real contract:
//  - seal windows of finalizeRecovery / finalizeAdmission / finalizeReport: a case whose threshold was met
//    before 600 s, probed at opened+599 / +600 / +7199 / +7200 (snapshot and revert), then sealed at +600 by a
//    non-voter, with its gas;
//  - the 80% floor: a slash to exactly floor(termBase x 0.8) vs one bps more;
//  - dueBreakdown() / matureUnwithdrawnPrincipal() before and after a failed renewal and its unlock period.
import { writeFileSync } from "node:fs";
import { ethers, time, networkHelpers, E, DAY, SVC, deployFixture, fundedWallet, newKey, pgpBytes, now } from "./helpers.js";

describe("v0.4.2 comparison fixture", function () {
  this.timeout(600_000);
  it("records", async () => {
    const ctx = await deployFixture();
    const reg = ctx.reg;
    const N = ctx.nodes;
    const errName = (e: any) => {
      const d = e?.data ?? e?.error?.data ?? e?.info?.error?.data;
      try { return reg.interface.parseError(d)!.name; } catch { return `unknown: ${String(e?.message ?? e).slice(0, 120)}`; }
    };
    const answer = async (p: Promise<any>) => { try { await p; return "ok"; } catch (e) { return errName(e); } };
    const out: any = { seal: [], floor: [], due: [] };

    // Probe a finalize call at fixed offsets from the opening; then seal at +600 by a non-voter.
    async function probe(kind: string, openedAt: bigint, tally: () => Promise<any>, call: () => Promise<any>, send: () => Promise<any>) {
      const t = await tally();
      for (const off of [599n, 600n, 7199n, 7200n]) {
        // Hardhat runs eth_call at the latest block's timestamp: move the chain to exactly opened+off.
        const snap = await networkHelpers.takeSnapshot();
        await time.increaseTo(Number(openedAt + off));
        const at = BigInt(await time.latest());
        out.seal.push({ kind, offset: off.toString(), openedAt: openedAt.toString(), callTime: at.toString(), ...t, answer: await answer(call()) });
        await snap.restore();
      }
      await time.increaseTo(Number(openedAt + 599n));
      const rc = await (await send()).wait();
      out.seal.push({ kind, offset: "600-sent", gasUsed: rc!.gasUsed.toString(), ...t });
    }

    // Recovery: node 0 declares itself offline, waits 12 h, requests (pays 0.01), 20 agree votes early.
    const t0 = N[0];
    await reg.connect(t0.wallet).declareOffline(t0.id);
    await time.increase(43_200);
    const rq = await (await reg.connect(t0.wallet).requestRecovery(t0.id, { tcpPort: t0.tcpPort, udpPort: t0.udpPort, endpointHash: ethers.ZeroHash, mode: 0, servicesNow: 0, ttl: 0 }, t0.ip, { value: E("0.01") })).wait();
    const recId = rq!.logs.map((l: any) => { try { return reg.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "RecoveryRequested")!.args.recId;
    for (let i = 1; i <= 20; i++) await reg.connect(N[i].wallet).voteRecovery(recId, true);
    const recTally = async () => { const [r] = await reg.getRecovery(recId); return { agree: r.agree.toString(), disagree: r.disagree.toString(), margin: r.margin.toString() }; };
    const recOpened = BigInt((await reg.getRecovery(recId))[0].openedAt);
    await probe("recovery", recOpened, recTally, () => reg.connect(ctx.stranger).finalizeRecovery.staticCall(recId), () => reg.connect(ctx.stranger).finalizeRecovery(recId));

    // Admission: applicant pays stake + fee, proposer's proposal is 1 agree, 19 more early.
    const w = await fundedWallet();
    const key = await newKey("v042");
    await reg.connect(w).applyAdmission({ operator: ethers.ZeroAddress, beneficiary: ethers.ZeroAddress, tcpPort: 443, udpPort: 9991, services: SVC.ENTRY | SVC.MAINT, keyId: key.keyId, proposerNodeId: N[1].id, deadline: (await now()) + 3600n, termLength: 15_768_000 }, "172.31.0.2", pgpBytes(key), { value: E(5) + E("0.01") });
    const appId = await reg.pendingAdmissionOf(w.address);
    await reg.connect(N[1].wallet).proposeAdmission(appId);
    for (let i = 2; i <= 25; i++) { const [a] = await reg.getAdmission(appId); if (Number(a.agree) - Number(a.disagree) >= Number(a.margin)) break; await reg.connect(N[i].wallet).voteAdmission(appId, true); }
    const admTally = async () => { const [a] = await reg.getAdmission(appId); return { agree: a.agree.toString(), disagree: a.disagree.toString(), margin: a.margin.toString() }; };
    const admOpened = BigInt((await reg.getAdmission(appId))[0].openedAt);
    await probe("admission", admOpened, admTally, () => reg.connect(ctx.stranger).finalizeAdmission.staticCall(appId), () => reg.connect(ctx.stranger).finalizeAdmission(appId));

    // Report: reporter (1 agree) + 19 more early, against node 22.
    await reg.connect(N[21].wallet).reportOffline(N[22].id);
    const rid = await reg.reportCount();
    for (let i = 2; i <= 20; i++) await reg.connect(N[i].wallet).voteReport(rid, true);
    const repTally = async () => { const r = await reg.getReport(rid); return { agree: r.agree.toString(), disagree: r.disagree.toString(), margin: r.margin.toString(), minOpen: r.minOpen.toString(), expiresAt: r.expiresAt.toString(), state: r.state.toString() }; };
    const repOpened = BigInt((await reg.getReport(rid)).openedAt);
    await probe("report", repOpened, repTally, () => reg.connect(ctx.stranger).finalizeReport.staticCall(rid), () => reg.connect(ctx.stranger).finalizeReport(rid));

    // 80% floor: node 23 slashed 20.00% (stake exactly floor), node 24 slashed 20.01% (below).
    for (const [node, bps] of [[N[23], 2000], [N[24], 2001]] as const) {
      await reg.connect(ctx.governor).slash(node.id, bps, 1, ethers.ZeroHash, 0);
      const [, base] = await reg.termStateOf(node.id);
      out.floor.push({ bps, stake: (await reg.stakeOf(node.id)).toString(), termBase: base.toString(), active: await reg.isActive(node.id) });
    }

    // dueBreakdown: before, after a failed renewal (node 25, threshold raised, no top-up), after unlock.
    const due = async (label: string) => {
      const [mature, owed] = await reg.dueBreakdown();
      out.due.push({ label, matureUnwithdrawn: mature.toString(), owed: owed.toString(), matureUnwithdrawnPrincipal: (await reg.matureUnwithdrawnPrincipal()).toString(), node25Stake: (await reg.stakeOf(N[25].id)).toString() });
    };
    await due("start");
    await reg.connect(ctx.governor).setMinStake(E(10));
    const [end25] = await reg.termOf(N[25].id);
    await time.increaseTo(Number(end25) + 1);
    await reg.connect(ctx.stranger).settleTerms([N[25].id]);
    await due("after failed renewal");
    await time.increase(28 * DAY + 60);
    await due("after the unlock period (no exit requested)");
    // The same node with an explicit exit request by its operator, then its unbonding period.
    let exitAnswer = "ok";
    try { await (await reg.connect(N[25].operator).requestExit(N[25].id)).wait(); } catch (e) { exitAnswer = errName(e); }
    out.exitRequest = exitAnswer;
    await due("exit requested");
    await time.increase(28 * DAY + 60);
    await due("exit requested + unbonding over");

    const file = process.env.V042_FIXTURE ?? "v042-fixture.json";
    writeFileSync(file, JSON.stringify({ note: "Generated by tools/vote-gate/v042-fixture.test.ts on a local Hardhat chain from node line v0.4.2 (a1a13d46); test keys only.", ...out }, null, 1) + "\n");
    console.log(`wrote ${file}`);
    for (const c of out.seal) console.log(c.kind, c.offset, c.answer ?? `gas ${c.gasUsed}`);
    for (const f of out.floor) console.log("floor", f);
    for (const d of out.due) console.log("due", d);
  });
});

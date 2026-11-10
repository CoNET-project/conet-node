// Recovery / renewal precheck comparison fixture for crates/conet-node/tests/precheck_fixture.rs.
// Runs in a COPY of the node line's contract tree (396942ab; same behaviour as 077c78f7) on Hardhat's in-process chain; test
// keys only. Writes $PRECHECK_FIXTURE.
//
//   cp tools/vote-gate/precheck-fixture.test.ts <copy>/test/node-registry-v2/
//   cd <copy> && npx hardhat --config hardhat.node-registry.config.ts test mocha test/node-registry-v2/precheck-fixture.test.ts
//
// For each state it records the views conet-node reads (recoveryThrottle, offlineSinceOf,
// currentRecovery + getRecovery, termOf, termStateOf, stakeOf, lockCapacityOf, minStakeNow,
// nodeStatus.suspended) and the contract's answer to requestRecovery as a static call from the
// node wallet with a valid proposer (the raw contract, not the test wrapper). Renewal: termOf,
// stakeOf and minStakeAt(termEnd) just before the end, then the event settleTerms emits.
import { writeFileSync } from "node:fs";
import { ethers, time, E, deployFixture } from "./helpers.js";

describe("precheck comparison fixture", function () {
  this.timeout(600_000);
  it("records", async () => {
    const ctx = await deployFixture();
    const reg = ctx.reg;
    const raw = reg.raw;
    const N = ctx.nodes;
    const P = N[1]; // proposer: active, maintenance bit
    const errName = (e: any) => {
      const d = e?.data ?? e?.error?.data ?? e?.info?.error?.data;
      try { return raw.interface.parseError(d)!.name; } catch { return `unknown: ${String(e?.message ?? e).slice(0, 120)}`; }
    };
    const req = (n: any) => ({ proposerNodeId: P.id, tcpPort: n.tcpPort, udpPort: n.udpPort, endpointHash: ethers.ZeroHash, mode: 0, servicesNow: 0, ttl: 0 });
    const out: any = { recovery: [], renewal: [] };

    async function snap(label: string, n: any) {
      const id = n.id;
      const now = BigInt(await time.latest());
      const [notBefore, retryAt] = await reg.recoveryThrottle(id);
      const cur = await reg.currentRecovery(id);
      let caseState = 0n, openedAt = 0n, expiresAt = 0n, agree = 0n, disagree = 0n, margin = 0n;
      if (cur !== ethers.ZeroHash) { const [c] = await reg.getRecovery(cur); caseState = c.state; openedAt = c.openedAt; expiresAt = c.expiresAt; agree = c.agree; disagree = c.disagree; margin = c.margin; }
      const t = await reg.termOf(id);
      const ts = await reg.termStateOf(id);
      const st = await reg.nodeStatus(id);
      const cap = await reg.lockCapacityOf(id);
      // Raw answers of the real contract to every call the Rust read layer makes (recovery_view and
      // term_watch::read), keyed by calldata, for replay through a mock JSON-RPC.
      const calls: [string, any[]][] = [["recoveryThrottle", [id]], ["currentRecovery", [id]], ["termOf", [id]], ["termStateOf", [id]], ["nodeStatus", [id]], ["offlineSinceOf", [id]], ["stakeOf", [id]], ["lockCapacityOf", [id]], ["minStakeNow", []], ["minStakeAt", [t.termEnd]]];
      if (cur !== ethers.ZeroHash) calls.push(["getRecovery", [cur]]);
      const rpc: any = {};
      const to = await raw.getAddress();
      for (const [f, a] of calls) { const data = raw.interface.encodeFunctionData(f, a); rpc[data.toLowerCase()] = await ethers.provider.call({ to, data }); }
      const blk = await ethers.provider.getBlock("latest");
      let answer = "ok";
      try { await raw.connect(n.wallet).requestRecovery.staticCall(id, req(n), n.ip, { value: E("0.01") }); } catch (e) { answer = errName(e); }
      const row = {
        label, nodeId: String(id), now: String(now),
        offlineSince: String(await reg.offlineSinceOf(id)),
        notBefore: String(notBefore), retryAt: String(retryAt),
        caseState: String(caseState), caseOpenedAt: String(openedAt), caseExpiresAt: String(expiresAt), caseAgree: String(agree), caseDisagree: String(disagree), caseMargin: String(margin),
        stakeStop: t.stakeStop, inTerm: ts.inTerm, termBase: String(ts.termBase),
        stake: String(await reg.stakeOf(id)), freeStake: String(cap.freeStake),
        minStakeNow: String(await reg.minStakeNow()), suspended: st.suspended,
        answer, block: String(blk!.number), registry: to, rpc,
      };
      out.recovery.push(row);
      console.log(label, answer);
    }
    async function request(n: any, propose: boolean) {
      const rc = await (await raw.connect(n.wallet).requestRecovery(n.id, req(n), n.ip, { value: E("0.01") })).wait();
      const recId = rc!.logs.map((l: any) => { try { return raw.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "RecoveryRequested")!.args.recId;
      if (propose) await (await raw.connect(P.wallet).proposeRecovery(recId)).wait();
      return recId;
    }

    // A: self-declared offline; cooldown edges; a voting case; C17 gap; protected case; rejection.
    const A = N[0];
    await reg.connect(A.wallet).declareOffline(A.id);
    const offA = BigInt(await reg.offlineSinceOf(A.id));
    await snap("A just offline", A);
    await time.increaseTo(Number(offA + 43_199n));
    await snap("A offline+43199", A);
    await time.increaseTo(Number(offA + 43_200n));
    await snap("A offline+43200", A);
    const rec1 = await request(A, true);
    await snap("A right after a proposed request", A);
    await time.increase(300);
    await snap("A request+300 (case voting)", A);
    // Reject it: 21 disagree against the proposal's 1 agree (margin 20), sealed at openedAt+600.
    for (let i = 2; i <= 22; i++) await raw.connect(N[i].wallet).voteRecovery(rec1, false);
    const [c1] = await reg.getRecovery(rec1);
    await time.increaseTo(Number(c1.openedAt) + 599);
    await (await raw.connect(ctx.stranger).finalizeRecovery(rec1)).wait();
    await snap("A right after the rejection seal", A);
    const [, retryA] = await reg.recoveryThrottle(A.id);
    await time.increaseTo(Number(retryA) - 1);
    await snap("A retryAt-1", A);
    await time.increaseTo(Number(retryA));
    await snap("A retryAt", A);
    // An unproposed request (REQUESTED): replaceable after the 5-minute gap.
    await request(A, false);
    await time.increase(299);
    await snap("A unproposed request+299", A);
    await time.increase(1);
    await snap("A unproposed request+300", A);
    // A proposed case without a decided tally: protected until openedAt + 43,200, also past its
    // 7,200 s voting window (077c78f7).
    await time.increase(300);
    const rec3 = await request(A, true);
    const [c3] = await reg.getRecovery(rec3);
    for (const off of [7_199, 7_200, 43_199, 43_200]) {
      await time.increaseTo(Number(c3.openedAt) + off);
      await snap(`A undecided voting case openedAt+${off}`, A);
    }
    // A case decided early (21 disagree before 600 s, so not sealed by the votes) and never sealed:
    // protected until +43,200, then "seal first" (AdmissionState); sealed by anyone, then the
    // rejection wait.
    const rec4 = await request(A, true);
    for (let i = 2; i <= 22; i++) await raw.connect(N[i].wallet).voteRecovery(rec4, false);
    const [c4] = await reg.getRecovery(rec4);
    for (const off of [7_200, 43_199, 43_200]) {
      await time.increaseTo(Number(c4.openedAt) + off);
      await snap(`A decided unsealed case openedAt+${off}`, A);
    }
    await (await raw.connect(ctx.stranger).finalizeRecovery(rec4)).wait();
    await snap("A after sealing the decided case", A);

    // B: offline, slashed 10% inside its term (above the 80% floor, not stopped).
    const B = N[23];
    await reg.connect(B.wallet).declareOffline(B.id);
    await reg.connect(ctx.governor).slash(B.id, 1000, 1, ethers.ZeroHash, 0);
    await time.increaseTo(Number(BigInt(await reg.offlineSinceOf(B.id)) + 43_200n));
    await snap("B slashed 10% in term", B);

    // C: slashed below the floor (stopped), then topped up to the latest full amount - 1 wei, then 1 wei more.
    const C = N[24];
    await reg.connect(ctx.governor).slash(C.id, 2001, 1, ethers.ZeroHash, 0);
    await time.increaseTo(Number(BigInt(await reg.offlineSinceOf(C.id)) + 43_200n));
    await snap("C stopped below floor", C);
    const needC = (await reg.minStakeNow()) - (await reg.stakeOf(C.id));
    await reg.connect(C.wallet).topUp(C.id, { value: needC - 1n });
    await snap("C topped up to full-1wei", C);
    await reg.connect(C.wallet).topUp(C.id, { value: 1n });
    await snap("C topped up to full", C);

    // Renewal: raise the threshold, then D stays short and P tops up to the new amount.
    const D = N[25];
    await reg.connect(ctx.governor).setMinStake(E(10));
    const [endD] = await reg.termOf(D.id);
    const [endP] = await reg.termOf(P.id);
    const needP = (await reg.minStakeAt(endP)) - (await reg.stakeOf(P.id));
    if (needP > 0n) await reg.connect(P.wallet).topUp(P.id, { value: needP });
    const before: any[] = [];
    for (const n of [D, P]) {
      const [end, base, len, stop] = await reg.termOf(n.id);
      before.push({ nodeId: String(n.id), termEnd: String(end), termBase: String(base), termLength: String(len), stakeStop: stop, stake: String(await reg.stakeOf(n.id)), needAtEnd: String(await reg.minStakeAt(end)) });
    }
    await time.increaseTo(Number(endD > endP ? endD : endP) + 1);
    const rc = await (await raw.connect(ctx.stranger).settleTerms([D.id, P.id])).wait();
    const ev = rc!.logs.map((l: any) => { try { return raw.interface.parseLog(l); } catch { return null; } }).filter((e: any) => e && (e.name === "TermStarted" || e.name === "TermRenewalFailed"));
    for (const b of before) {
      const e = ev.find((x: any) => String(x.args[0]) === b.nodeId);
      const [end2, , , stop2] = await reg.termOf(BigInt(b.nodeId));
      out.renewal.push({ ...b, event: e ? e.name : "none", termEndAfter: String(end2), stakeStopAfter: stop2 });
      console.log("renewal", b.nodeId, e ? e.name : "none");
    }
    // D after its failed renewal: stopped, offline from the term end.
    await time.increaseTo(Number(BigInt(await reg.offlineSinceOf(D.id)) + 43_200n));
    await snap("D after failed renewal", D);
    await reg.connect(D.wallet).topUp(D.id, { value: (await reg.minStakeNow()) - (await reg.stakeOf(D.id)) });
    await snap("D topped up to the new full amount", D);

    const file = process.env.PRECHECK_FIXTURE ?? "precheck-fixture.json";
    writeFileSync(file, JSON.stringify({ note: "Generated by tools/vote-gate/precheck-fixture.test.ts on a local Hardhat chain from node line 396942ab; test keys only.", ...out }, null, 1) + "\n");
    console.log(`wrote ${file}`);
  });
});

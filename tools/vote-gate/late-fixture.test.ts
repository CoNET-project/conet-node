// Late seal / lapse fixture (node line 45e9c5d0 onward, regenerated on 077c78f7; "允许补封" in the contract) for
// crates/conet-node/tests/late_fixture.rs. Runs in a COPY of the node line's tree on Hardhat's in-process
// chain; test keys only. Writes $LATE_FIXTURE.
//
//   cp tools/vote-gate/late-fixture.test.ts <copy>/test/node-registry-v2/
//   cd <copy> && npx hardhat --config hardhat.node-registry.config.ts test mocha test/node-registry-v2/late-fixture.test.ts
//
// Records from the real contract:
//  - per entry (recovery, admission, report): a case whose margin was met but not sealed before 7,200 s, and
//    one whose margin was not met; after 7,200 s: a vote is refused, the finalize entry seals the first
//    (gas, events) and lapses the second (events);
//  - with frozen votes meeting the margin, refundAdmission / closeOnlineCase / settleOnlineVote / settleReport
//    revert until the case is sealed;
//  - the three early-majority switches on and off for one recovery case before 600 s.
import { writeFileSync } from "node:fs";
import { ethers, time, networkHelpers, E, SVC, deployFixture, fundedWallet, newKey, pgpBytes, now, sponsorRegister } from "./helpers.js";

const shared: any = {};

describe("late seal / lapse fixture", function () {
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
    const events = (rc: any) => rc.logs.map((l: any) => { try { return reg.interface.parseLog(l)?.name; } catch { return null; } }).filter(Boolean);
    const out: any = { cases: [], blocked: [], switches: [] };

    // ---- recovery: node 0 met (20 agree), node 1 not met (5 agree) ----
    const recovery = async (node: any, votes: number, from: number) => {
      await reg.connect(node.wallet).declareOffline(node.id);
      await time.increase(43_200);
      const rc = await (await reg.connect(node.wallet).requestRecovery(node.id, { tcpPort: node.tcpPort, udpPort: node.udpPort, endpointHash: ethers.ZeroHash, mode: 0, servicesNow: 0, ttl: 0 }, node.ip, { value: E("0.01") })).wait();
      const id = rc!.logs.map((l: any) => { try { return reg.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "RecoveryRequested")!.args.recId;
      for (let i = 0; i < votes; i++) { try { await reg.connect(N[from + i].wallet).voteRecovery(id, true); } catch { /* proposer or already voted */ } }
      return id;
    };
    // ---- admission: met (proposal + 19), not met (proposal + 3) ----
    const admission = async (votes: number, port: number) => {
      const w = await fundedWallet();
      const key = await newKey(`late${port}`);
      await reg.connect(w).applyAdmission({ operator: ethers.ZeroAddress, beneficiary: ethers.ZeroAddress, tcpPort: 443, udpPort: port, services: SVC.ENTRY | SVC.MAINT, keyId: key.keyId, proposerNodeId: N[2].id, deadline: (await now()) + 3600n, termLength: 15_768_000 }, `172.31.1.${port % 200}`, pgpBytes(key), { value: E(5) + E("0.01") });
      const id = await reg.pendingAdmissionOf(w.address);
      await reg.connect(N[2].wallet).proposeAdmission(id);
      for (let i = 0; i < votes; i++) await reg.connect(N[3 + i].wallet).voteAdmission(id, true);
      return { id, w };
    };
    // ---- report: met (reporter + 19), not met (reporter + 4) ----
    const report = async (target: any, reporter: any, votes: number, from: number) => {
      await reg.connect(reporter.wallet).reportOffline(target.id);
      const rid = await reg.reportCount();
      for (let i = 0; i < votes; i++) await reg.connect(N[from + i].wallet).voteReport(rid, true);
      return rid;
    };

    // Build all cases inside the first minutes, so all reach 7,200 s together; keep them below 600 s
    // unsealed (the margin-meeting votes land before 600 s and nobody seals).
    const recMet = await recovery(N[0], 22, 3);
    const recNot = await recovery(N[1], 5, 3);
    const { id: admMet, w: admMetWallet } = await admission(19, 9101);
    const { id: admNot } = await admission(3, 9102);
    const repMet = await report(N[24], N[23], 19, 3);
    const repNot = await report(N[25], N[22], 4, 3);
    const opened = BigInt(await time.latest());
    const tallyRec = async (id: string) => { const [r] = await reg.getRecovery(id); return { agree: r.agree.toString(), disagree: r.disagree.toString(), margin: r.margin.toString(), openedAt: r.openedAt.toString() }; };
    const tallyAdm = async (id: string) => { const [a] = await reg.getAdmission(id); return { agree: a.agree.toString(), disagree: a.disagree.toString(), margin: a.margin.toString(), openedAt: a.openedAt.toString() }; };
    const tallyRep = async (id: bigint) => { const r = await reg.getReport(id); return { agree: r.agree.toString(), disagree: r.disagree.toString(), margin: r.margin.toString(), openedAt: r.openedAt.toString(), minOpen: r.minOpen.toString(), expiresAt: r.expiresAt.toString(), state: r.state.toString() }; };

    // Move past 7,200 s of the latest opening.
    await time.increaseTo(Number(opened + 7_300n));
    const late = BigInt(await time.latest());

    // Blocked paths while the frozen votes meet the margin (before sealing).
    out.blocked.push({ call: "refundAdmission (by the applicant)", answer: await answer(reg.connect(admMetWallet).refundAdmission.staticCall(admMet)) });
    out.blocked.push({ call: "closeOnlineCase", answer: await answer(reg.connect(ctx.stranger).closeOnlineCase.staticCall(admMet)) });
    out.blocked.push({ call: "settleOnlineVote", answer: await answer(reg.connect(ctx.stranger).settleOnlineVote.staticCall(recMet, 10)) });
    out.blocked.push({ call: "settleReport", answer: await answer(reg.connect(ctx.stranger).settleReport.staticCall(repMet, 10)) });

    // Votes after 7,200 s are refused.
    out.lateVote = {
      recovery: await answer(reg.connect(N[15].wallet).voteRecovery.staticCall(recNot, true)),
      admission: await answer(reg.connect(N[15].wallet).voteAdmission.staticCall(admNot, true)),
      report: await answer(reg.connect(N[15].wallet).voteReport.staticCall(repNot, true)),
    };

    // Late seal / lapse through the same entries, by a non-voter.
    const run = async (kind: string, met: boolean, tally: any, send: () => Promise<any>) => {
      let gas = "0", ev: string[] = [], res = "ok";
      try { const rc = await (await send()).wait(); gas = rc!.gasUsed.toString(); ev = events(rc); } catch (e) { res = errName(e); }
      out.cases.push({ kind, met, now: late.toString(), ...tally, result: res, gasUsed: gas, events: ev });
    };
    await run("recovery", true, await tallyRec(recMet), () => reg.connect(ctx.stranger).finalizeRecovery(recMet));
    await run("recovery", false, await tallyRec(recNot), () => reg.connect(ctx.stranger).finalizeRecovery(recNot));
    await run("admission", true, await tallyAdm(admMet), () => reg.connect(ctx.stranger).finalizeAdmission(admMet));
    await run("admission", false, await tallyAdm(admNot), () => reg.connect(ctx.stranger).finalizeAdmission(admNot));
    await run("report", true, await tallyRep(repMet), () => reg.connect(ctx.stranger).finalizeReport(repMet));
    await run("report", false, await tallyRep(repNot), () => reg.connect(ctx.stranger).finalizeReport(repNot));

    // After sealing, the blocked settle path works.
    out.afterSeal = { settleReport: await answer(reg.connect(ctx.stranger).settleReport.staticCall(repMet, 10)) };

    shared.out = out;
    return;
    const file = process.env.LATE_FIXTURE ?? "late-fixture.json";
    writeFileSync(file, JSON.stringify({ note: "Generated by tools/vote-gate/late-fixture.test.ts on a local Hardhat chain from node line 077c78f7; test keys only.", ...out }, null, 1) + "\n");
    console.log(`wrote ${file}`);
    for (const c of out.cases) console.log(c.kind, c.met ? "met" : "not met", c.result, "gas", c.gasUsed, c.events.join(","));
    for (const b of out.blocked) console.log("blocked", b.call, b.answer);
    console.log("lateVote", JSON.stringify(out.lateVote), "afterSeal", JSON.stringify(out.afterSeal));
    console.log("switchSetup", JSON.stringify(out.switchSetup));
    for (const s of out.switches) console.log("switch", s.state, "|", s.switch, s.setAnswer, "agree", s.agree, "disagree", s.disagree, "population", s.population, "->", s.answer ?? `sealedByLastVote=${s.sealedByLastVote}`);
  });

  it("records the early-majority switches and writes the fixture", async () => {
    const ctx = await deployFixture();
    const reg = ctx.reg;
    const N = ctx.nodes;
    const out = shared.out;
    out.switches = [];
    const errName = (e: any) => {
      const d = e?.data ?? e?.error?.data ?? e?.info?.error?.data;
      try { return reg.interface.parseError(d)!.name; } catch { return `unknown: ${String(e?.message ?? e).slice(0, 120)}`; }
    };
    const answer = async (p: Promise<any>) => { try { await p; return "ok"; } catch (e) { return errName(e); } };
    const recovery = async (node: any, votes: number, from: number) => {
      await reg.connect(node.wallet).declareOffline(node.id);
      await time.increase(43_200);
      const rc = await (await reg.connect(node.wallet).requestRecovery(node.id, { tcpPort: node.tcpPort, udpPort: node.udpPort, endpointHash: ethers.ZeroHash, mode: 0, servicesNow: 0, ttl: 0 }, node.ip, { value: E("0.01") })).wait();
      return rc!.logs.map((l: any) => { try { return reg.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "RecoveryRequested")!.args.recId;
    };
    // Enough eligible voters to pass half of the population: extra nodes with the maintenance bit.
    const listed0 = Number(await reg.listedCount());
    let extra = Math.max(0, listed0 - 46);
    if ((listed0 + extra) % 2 === 1) extra += 1;
    for (let i = 0; i < extra; i++) {
      await sponsorRegister(ctx, { sponsor: N[2 + (i % 20)], operator: ctx.opA, services: SVC.ENTRY | SVC.MAINT });
    }
    // Early-majority switches, before 600 s of one fresh recovery case. The population counts every
    // registered node, so votes come from all eligible nodes (wallets impersonated, as the node line's own
    // helpers do). An even population lets mjExcludeSubject make a difference at exactly half.
    await time.increase(8 * 86_400); // past every vote cooldown
    const applicant = N[21];
    const recEarly = await recovery(applicant, 0, 0);
    const [r0] = await reg.getRecovery(recEarly);
    const P = Number(r0.population);
    const nowT = BigInt(await time.latest());
    const eligible: { id: bigint; w: string }[] = [];
    for (let id = BigInt(await reg.nextNodeId()) - 1n; id >= 100n; id--) {
      const raw = await reg.getNodeRaw(id);
      if (raw.status === 0n || id === BigInt(applicant.id) || !(await reg.isActive(id))) continue;
      if ((Number(raw.services) & SVC.MAINT) === 0 || BigInt(raw.voteEligibleAt) > nowT) continue;
      if ((await reg.recoveryVoteOf(recEarly, id)) !== 0n) continue; // the proposer's agree
      eligible.push({ id, w: raw.nodeWallet });
    }
    const vote = async (v: { id: bigint; w: string }, agree: boolean) => {
      await networkHelpers.impersonateAccount(v.w);
      await networkHelpers.setBalance(v.w, E(100));
      try { await (await reg.connect(await ethers.getSigner(v.w)).voteRecovery(recEarly, agree)).wait(); } finally { await networkHelpers.stopImpersonatingAccount(v.w); }
    };
    const evalStates = async (label: string, list: [string, [string, number][]][]) => {
      const [c] = await reg.getRecovery(recEarly);
      for (const [name, sets] of list) {
        const snap = await networkHelpers.takeSnapshot();
        let setAnswer = "ok";
        for (const [n, v] of sets) { try { await (await reg.connect(ctx.governor).setParam(ethers.encodeBytes32String(n), v)).wait(); } catch (e) { setAnswer = errName(e); } }
        out.switches.push({ state: label, switch: name, sets, setAnswer, agree: c.agree.toString(), disagree: c.disagree.toString(), margin: c.margin.toString(), population: c.population.toString(), openedAt: c.openedAt.toString(), now: String(await time.latest()), answer: await answer(reg.connect(ctx.stranger).finalizeRecovery.staticCall(recEarly)) });
        await snap.restore();
      }
    };
    const [p0] = await reg.getRecovery(recEarly);
    const already = Number(p0.agree) + Number(p0.disagree); // the proposer's agree
    out.switchSetup = { population: P, eligibleVoters: eligible.length, already };
    const base = await networkHelpers.takeSnapshot();
    // State A: participants exactly P/2, all agree.
    if (eligible.length >= P / 2 - already) {
      for (let i = 0; i < P / 2 - already; i++) await vote(eligible[i], true);
      await evalStates("exactly half", [["all off", []], ["mjExcludeSubject on", [["mjExcludeSubject", 1]]]]);
    }
    await base.restore();
    // State B: participants P/2 + 1, lead exactly the margin (some disagree).
    const total = P / 2 + 1 - already;
    const margin = Number(p0.margin);
    const agreeTotal = (P / 2 + 1 + margin) / 2;
    if (eligible.length >= total && Number.isInteger(agreeTotal)) {
      const agreeMore = agreeTotal - already;
      // All but the last vote; then, per switch setting, cast the last vote and see whether it seals
      // (the vote that first meets majority + margin seals in the same transaction).
      for (let i = 0; i < total - 1; i++) await vote(eligible[i], i < agreeMore);
      const [pre] = await reg.getRecovery(recEarly);
      for (const [name, sets] of [["all off", []], ["mjMinBase 1000", [["mjMinBase", 1000]]], ["mjIrreversible on", [["mjIrreversible", 1]]]] as [string, [string, number][]][]) {
        const snap = await networkHelpers.takeSnapshot();
        let setAnswer = "ok";
        for (const [n, v] of sets) { try { await (await reg.connect(ctx.governor).setParam(ethers.encodeBytes32String(n), v)).wait(); } catch (e) { setAnswer = errName(e); } }
        const lastAgree = total - 1 < agreeMore;
        await vote(eligible[total - 1], lastAgree);
        const [after] = await reg.getRecovery(recEarly);
        out.switches.push({ state: "last vote makes it just over half, lead = margin", switch: name, sets, setAnswer,
          agree: pre.agree.toString(), disagree: pre.disagree.toString(), lastVoteAgree: lastAgree, margin: pre.margin.toString(),
          population: pre.population.toString(), openedAt: pre.openedAt.toString(), now: String(await time.latest()),
          caseStateAfterLastVote: after.state.toString(), sealedByLastVote: Number(after.state) !== 1 });
        await snap.restore();
      }
    }
    await base.restore();

    const file = process.env.LATE_FIXTURE ?? "late-fixture.json";
    writeFileSync(file, JSON.stringify({ note: "Generated by tools/vote-gate/late-fixture.test.ts on a local Hardhat chain from node line 077c78f7; test keys only.", ...out }, null, 1) + "\n");
    console.log(`wrote ${file}`);
    console.log("switchSetup", JSON.stringify(out.switchSetup));
    for (const s of out.switches) console.log("switch", s.state, "|", s.switch, s.setAnswer, "agree", s.agree, "disagree", s.disagree, "population", s.population, "->", s.answer ?? `sealedByLastVote=${s.sealedByLastVote}`);
  });
});

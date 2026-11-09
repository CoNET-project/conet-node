// F5 vote gate fixture: real contract state + the real contract's answer, for tests/vote_gate_fixture.rs.
// Runs in a COPY of the node line's contract tree (src/b-unit/node-registry-v2 + test/node-registry-v2),
// in Hardhat's in-process chain. Test keys only. Writes $F5_FIXTURE (default ./f5-fixture.json).
//
//   cp tools/vote-gate/f5-fixture.test.ts <copy>/test/node-registry-v2/
//   cd <copy> && npx hardhat --config hardhat.node-registry.config.ts test mocha test/node-registry-v2/f5-fixture.test.ts
//
// Each case records, at the moment of an eth_call: getNodeRaw raw bytes, nodeWalletOf, isActive,
// termStateOf, lockCapacityOf of the voter; the report (if any) and the voter's choice; the target's
// isActive; and the contract's answer to the call (ok or the custom error name). The Rust side
// replays the same state through vote_gate and must give the same answer.
import { writeFileSync } from "node:fs";
import { ethers, time, E, DAY, SVC, deployFixture, sponsorRegister, fundedWallet, newKey, pgpBytes, now } from "./helpers.js";

describe("F5 vote gate fixture (stake-term, per-voter fine)", function () {
  this.timeout(600_000);
  it("records cases", async () => {
    const ctx = await deployFixture();
    const reg = ctx.reg;
    const regAddr = await reg.getAddress();
    const cases: any[] = [];
    const errName = (e: any) => {
      const d = e?.data ?? e?.error?.data ?? e?.info?.error?.data;
      try { return reg.interface.parseError(d)!.name; } catch { return `unknown: ${String(e?.message ?? e).slice(0, 120)}`; }
    };
    async function view(id: bigint) {
      const raw = await ethers.provider.call({ to: regAddr, data: reg.interface.encodeFunctionData("getNodeRaw", [id]) });
      const [inTerm, termBase] = await reg.termStateOf(id);
      const [freeStake, finePerVote, slotsLeft] = await reg.lockCapacityOf(id);
      return { id: id.toString(), raw, wallet: await reg.nodeWalletOf(id), active: await reg.isActive(id), inTerm, termBase: termBase.toString(),
        cap: { freeStake: freeStake.toString(), finePerVote: finePerVote.toString(), slotsLeft: slotsLeft.toString() } };
    }
    async function rep(rid: bigint) {
      const r = await reg.getReport(rid);
      return { rid: rid.toString(), target: r.target.toString(), reporter: r.reporter.toString(), openedAt: r.openedAt.toString(), expiresAt: r.expiresAt.toString(),
        minOpen: r.minOpen.toString(), agree: r.agree.toString(), disagree: r.disagree.toString(), margin: r.margin.toString(), state: r.state.toString(), fine: r.fine.toString() };
    }
    async function answer(p: Promise<any>) { try { await p; return "ok"; } catch (e) { return errName(e); } }
    // The gate's `now` is the block the call runs in (Hardhat: latest + 1 for eth_call on pending).
    const callTime = async () => BigInt(await time.latest()) + 1n;
    async function voteCase(label: string, voter: any, rid: bigint) {
      const id = BigInt(voter.id);
      cases.push({ label, kind: "vote", now: (await callTime()).toString(), voter: await view(id), report: await rep(rid),
        choice: (await reg.getVote(rid, id)).choice.toString(), answer: await answer(reg.connect(voter.wallet).voteReport.staticCall(rid, false)) });
    }
    async function reportCase(label: string, voter: any, target: bigint) {
      const id = BigInt(voter.id);
      const raw = await reg.getNodeRaw(target);
      const open = raw.openReportId;
      cases.push({ label, kind: "report", now: (await callTime()).toString(), voter: await view(id), target: target.toString(),
        targetServing: await reg.isActive(target), targetOpen: open === 0n ? null : await rep(open),
        answer: await answer(reg.connect(voter.wallet).reportOffline.staticCall(target)) });
    }
    const N = ctx.nodes; // trusted 472 sample (reserved, maintenance bit, no cooldown on first registration)
    const B = await sponsorRegister(ctx, { sponsor: N[0], operator: ctx.opA, services: SVC.ENTRY }); // no maintenance bit
    const C = await sponsorRegister(ctx, { sponsor: N[0], operator: ctx.opB, services: SVC.ENTRY | SVC.MAINT }); // 7-day cooldown

    // a. Fresh: a trusted node may report at once; a sponsored node is in its cooldown.
    await reportCase("trusted node reports at once (no cooldown)", N[1], BigInt(N[0].id));
    await reportCase("sponsored node in its 7-day cooldown", C, BigInt(N[0].id));

    // b. DAO raises the threshold to 10; a node admitted after the raise is approved at 10.
    await reg.connect(ctx.governor).setMinStake(E(10));
    await time.increase(30 * DAY + 60);
    const w = await fundedWallet();
    const key = await newKey("ten");
    await reg.connect(w).applyAdmission({ operator: ethers.ZeroAddress, beneficiary: ethers.ZeroAddress, tcpPort: 443, udpPort: 9990, services: SVC.ENTRY | SVC.MAINT, keyId: key.keyId, proposerNodeId: N[0].id, deadline: (await now()) + 3600n, termLength: 15_768_000 }, "172.31.0.1", pgpBytes(key), { value: E(10) + E("0.01") }); // stake + online fee
    const appId = await reg.pendingAdmissionOf(w.address);
    await reg.connect(N[0].wallet).proposeAdmission(appId);
    // The proposal is the proposer's agree vote; vote until the margin is reached (a vote after the
    // deciding one reverts: the case is closed).
    for (let i = 1; i <= 20; i++) { try { await reg.connect(N[i].wallet).voteAdmission(appId, true); } catch { break; } }
    await time.increase(300);
    await reg.finalizeAdmission(appId);
    const X = { id: await reg.nodeIdOfNodeWallet(w.address), wallet: w };
    await time.increase(7 * DAY + 60);

    // c. No maintenance bit.
    await reportCase("node without the maintenance bit", B, BigInt(N[0].id));

    // d. An open report.
    await reg.connect(N[1].wallet).reportOffline(N[0].id);
    const rid = await reg.reportCount();
    await voteCase("reporter votes again", N[1], rid);
    await voteCase("target votes", N[0], rid);
    await voteCase("trusted node votes (approved at 5, fine 1)", N[2], rid);
    await voteCase("node approved at 10 votes (fine 2)", X, rid);
    await reportCase("second report while one is open", C, BigInt(N[0].id));

    // e. Lock boundary for a node approved at 5 (stake 5, fine 1): four reports, one vote, then full.
    const rids: bigint[] = [rid];
    for (const t of [5, 6, 7, 8]) { await reg.connect(N[3].wallet).reportOffline(N[t].id); rids.push(await reg.reportCount()); }
    await voteCase("approved at 5 with 4 locked: fifth case fits", N[3], rid);
    await reg.connect(N[3].wallet).voteReport(rid, false);
    await reportCase("approved at 5, fully locked: sixth case refused", N[3], BigInt(N[9].id));

    // f. Lock boundary for the node approved at 10 (stake 10, fine 2): five cases fit, the sixth does not.
    await reg.connect(N[4].wallet).reportOffline(N[10].id);
    rids.push(await reg.reportCount());
    for (let k = 0; k < 5; k++) {
      await voteCase(`approved at 10, ${k} cases locked`, X, rids[k]);
      await reg.connect(X.wallet).voteReport(rids[k], false);
    }
    await voteCase("approved at 10, five cases locked: sixth refused", X, rids[5]);

    // g. Expiry.
    await time.increase(7 * DAY);
    await voteCase("vote after expiry", N[11], rid);

    const out = process.env.F5_FIXTURE ?? "f5-fixture.json";
    writeFileSync(out, JSON.stringify({ note: "Generated by tools/vote-gate/f5-fixture.test.ts on a local Hardhat chain; test keys only.", cases }, null, 1) + "\n");
    console.log(`wrote ${cases.length} cases to ${out}`);
  });
});

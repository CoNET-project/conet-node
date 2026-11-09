// AUTO-TOPUP fixture: the real contract's renewal and recovery behaviour around a top-up, for
// crates/conet-node/tests/auto_topup.rs. Runs in a COPY of the node line's contract tree on Hardhat's
// in-process chain; test keys only. Writes $AUTO_TOPUP_FIXTURE (default ./auto-topup-fixture.json).
//
//   cp tools/auto-topup/auto-topup-fixture.test.ts <copy>/test/node-registry-v2/
//   cd <copy> && npx hardhat --config hardhat.node-registry.config.ts test mocha test/node-registry-v2/auto-topup-fixture.test.ts
//
// A: DAO raises 5 -> 10 twenty days before the end (inside the 30-day grace period effectiveMinStake is
//    still 5); 3 days before the end
//    the node wallet sends topUp(value = minStakeAt(termEnd) - stakeOf) -> at the end: renewed.
// B: no top-up -> at the end renewal fails; requestRecovery refused until stake - locked >= the latest
//    full threshold, the 12-hour offline cooldown is over and the 0.01 online fee is sent.
import { writeFileSync } from "node:fs";
import { ethers, time, E, DAY, deployFixture } from "./helpers.js";

describe("AUTO-TOPUP fixture", function () {
  this.timeout(600_000);
  it("records the contract around a top-up", async () => {
    const ctx = await deployFixture();
    const reg = ctx.reg;
    const errName = (e: any) => {
      const d = e?.data ?? e?.error?.data ?? e?.info?.error?.data;
      try { return reg.interface.parseError(d)!.name; } catch { return `unknown: ${String(e?.message ?? e).slice(0, 120)}`; }
    };
    async function view(node: any) {
      const [termEnd, , , stakeStop] = await reg.termOf(node.id);
      const [inTerm, termBase] = await reg.termStateOf(node.id);
      return {
        now: String(await time.latest()), termEnd: termEnd.toString(), inTerm, termBase: termBase.toString(), stakeStop,
        stake: (await reg.stakeOf(node.id)).toString(), thresholdAtEnd: (await reg.minStakeAt(termEnd)).toString(),
        effectiveMin: (await reg.effectiveMinStake()).toString(), minStakeNow: (await reg.minStakeNow()).toString(),
        locked: (await reg.getNodeRaw(node.id)).voteLocked.toString(),
        wallet: (await ethers.provider.getBalance(node.wallet.address)).toString(),
        nonce: String(await ethers.provider.getTransactionCount(node.wallet.address, "latest")),
        active: await reg.isActive(node.id),
      };
    }
    const A = ctx.nodes[0], B = ctx.nodes[1];
    const [end] = await reg.termOf(A.id);
    // The raise lands 20 days before the end, so 3 days before the end the 30-day grace period is
    // still running: effectiveMinStake is the old 5, minStakeAt(termEnd) the full 10.
    await time.increaseTo(Number(end) - 20 * DAY);
    await reg.connect(ctx.governor).setMinStake(E(10));
    await time.increaseTo(Number(end) - 3 * DAY);
    const a0 = await view(A);
    const value = BigInt(a0.thresholdAtEnd) - BigInt(a0.stake); // what plan() must say
    const rc = await (await reg.connect(A.wallet).topUp(A.id, { value })).wait();
    const a1 = await view(A);
    const [, , lenBefore] = await reg.termOf(A.id);
    await time.increaseTo(Number(end) + 1);
    const a2 = await view(A);
    // Write the renewal (permissionless archive) and read the new term: same length, new end.
    await (await reg.connect(ctx.stranger).settleTerms([A.id])).wait();
    const [end2, base2, len2] = await reg.termOf(A.id);
    const renewedTerm = { endBefore: end.toString(), lenBefore: lenBefore.toString(), endAfter: end2.toString(), baseAfter: base2.toString(), lenAfter: len2.toString() };
    const b2 = await view(B);
    // Recovery precheck cases (12-hour cooldown from the chain offline moment, 0.01 online fee paid
    // with the request): each records the state and the contract's answer to requestRecovery.
    const FEE = E("0.01");
    const req = (value: bigint) => reg.connect(B.wallet).requestRecovery.staticCall(B.id, { tcpPort: B.tcpPort, udpPort: B.udpPort, endpointHash: ethers.ZeroHash, mode: 0, servicesNow: 0, ttl: 0 }, B.ip, { value });
    const ask = async (label: string, value: bigint) => {
      let answer = "ok"; try { await req(value); } catch (e) { answer = errName(e); }
      const raw = await reg.getNodeRaw(B.id);
      return { label, ...(await view(B)), outOfServiceSince: raw.outOfServiceSince.toString(), feeSent: value.toString(), answer };
    };
    const rcases: any[] = [];
    rcases.push(await ask("just after the failed renewal, stake short", FEE));
    const target = BigInt(b2.minStakeNow) + BigInt(b2.locked); // stake - locked >= latest full threshold
    await (await reg.connect(B.wallet).topUp(B.id, { value: target - BigInt(b2.stake) })).wait();
    rcases.push(await ask("topped up, still inside the 12-hour cooldown", FEE));
    const since = BigInt((await reg.getNodeRaw(B.id)).outOfServiceSince);
    await time.increaseTo(Number(since) + 43_200 - 5);
    rcases.push(await ask("5 seconds before the cooldown ends", FEE));
    await time.increaseTo(Number(since) + 43_200);
    rcases.push(await ask("cooldown over, no online fee sent", 0n));
    rcases.push(await ask("cooldown over, online fee sent", FEE));
    const before = rcases[0].answer, after = rcases[4].answer;
    const b3 = rcases[4];
    const out = process.env.AUTO_TOPUP_FIXTURE ?? "auto-topup-fixture.json";
    writeFileSync(out, JSON.stringify({
      note: "Generated by tools/auto-topup/auto-topup-fixture.test.ts on a local Hardhat chain; test keys only.",
      topupGasUsed: rc!.gasUsed.toString(),
      A: { beforeTopUp: a0, appliedValue: value.toString(), afterTopUp: a1, afterEnd: a2, renewedTerm },
      B: { afterEnd: b2, recoveryBefore: before, recoveryTarget: target.toString(), afterTopUp: b3, recoveryAfter: after, recoveryCases: rcases },
    }, null, 1) + "\n");
    console.log(`wrote ${out}: A renewed=${a2.inTerm} active=${a2.active}; B renewed=${b2.inTerm}, recovery ${before} -> ${after}; topUp gas ${rc!.gasUsed}`);
  });
});

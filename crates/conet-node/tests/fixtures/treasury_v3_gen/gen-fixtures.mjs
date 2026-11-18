// Generates tests/fixtures/treasury_v3_bridge_operation.json. The expected values come from the
// TypeScript parser in CoNET-SI at a given revision (src/vote/treasuryV3Listen.ts,
// parseBridgeOperation), run here on logs encoded with the same ABI.
//
// Usage (node 22.18 or later; type stripping runs the TypeScript source):
//   node --no-warnings --experimental-strip-types gen-fixtures.mjs \
//     --ts-repo <CoNET-SI checkout> --rev <git revision> \
//     --node-modules <dir containing ethers 6.17.0> --work <empty scratch dir> \
//     --out <fixture path>
//
// The TS files are read from git (`git show <rev>:<path>`), never from a working tree. Four
// exports are added in the scratch copy only, so the tests can call the TS parser. The fixture's
// `source` field records the revision and the git blob hash of each TS file. Each replacement must
// match exactly once, or the script stops.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function arg(name) {
  const i = process.argv.indexOf(name);
  if (i < 0 || !process.argv[i + 1]) throw new Error(`missing ${name}`);
  return process.argv[i + 1];
}
const tsRepo = arg('--ts-repo');
const rev = arg('--rev');
const nodeModules = path.resolve(arg('--node-modules'));
const work = path.resolve(arg('--work'));
const out = path.resolve(arg('--out'));
const LISTENER = 'src/vote/treasuryV3Listen.ts';
const ADDRESSES = 'src/vote/treasuryAddresses.ts';

const git = (...a) => execFileSync('git', ['-C', tsRepo, ...a], { encoding: 'utf8', maxBuffer: 1 << 26 });
const blobOf = (p) => git('rev-parse', `${rev}:${p}`).trim();
const textOf = (p) => git('show', `${rev}:${p}`);
const commit = git('rev-parse', `${rev}^{commit}`).trim();

function patch(src, from, to) {
  const n = src.split(from).length - 1;
  if (n !== 1) throw new Error(`expected one match for ${JSON.stringify(from)}, found ${n}`);
  return src.replace(from, to);
}
let listener = textOf(LISTENER);
listener = patch(listener, "from './treasuryAddresses'", "from './treasuryAddresses.ts'");
listener = patch(listener, '\nconst TREASURY_V3_ABI = [', '\nexport const TREASURY_V3_ABI = [');
listener = patch(listener, '\nconst BRIDGE_OPERATION_TOPIC = ', '\nexport const BRIDGE_OPERATION_TOPIC = ');
listener = patch(listener, '\nfunction parseBridgeOperation(', '\nexport function parseBridgeOperation(');

fs.mkdirSync(work, { recursive: true });
fs.writeFileSync(path.join(work, 'treasuryV3Listen.ts'), listener);
fs.writeFileSync(path.join(work, 'treasuryAddresses.ts'), textOf(ADDRESSES));
const link = path.join(work, 'node_modules');
if (!fs.existsSync(link)) fs.symlinkSync(nodeModules, link);

const { ethers } = await import(pathToFileURL(path.join(nodeModules, 'ethers/lib.esm/index.js')).href);
const { TREASURY_V3_ABI, BRIDGE_OPERATION_TOPIC, parseBridgeOperation } = await import(
  pathToFileURL(path.join(work, 'treasuryV3Listen.ts')).href
);
if (ethers.version !== '6.17.0') throw new Error(`ethers ${ethers.version}, expected 6.17.0`);

const iface = new ethers.Interface(TREASURY_V3_ABI);
const frag = iface.getEvent('BridgeOperation');
const TREASURY = '0xa208982212978550594A7FEEB70a61665d129003';
const H = (n) => '0x' + n.repeat(32);
const A = (n) => '0x' + n.repeat(20);
const MAX = (1n << 256n) - 1n;

function encode(args) {
  const vals = frag.inputs.map((p) => args[p.name]);
  const { topics, data } = iface.encodeEventLog(frag, vals);
  return { topics: [...topics], data };
}
function base(over = {}) {
  return {
    operationId: H('ab'), sourceChainId: 8453n, destinationChainId: 224422n, phase: 0, mode: 0,
    sourceTreasury: TREASURY, sourceAsset: A('83'), destinationAsset: A('cd'), sender: A('ee'),
    beneficiaries: [A('11')], amounts: [1000000n], grossAmount: 1000000n, feeAmount: 0n,
    netAmount: 1000000n, sourceTxHash: H('cc'), nonce: 1n, callbackTarget: '0x0000000000000000000000000000000000000000',
    ...over,
  };
}
function logOf(name, args) {
  const e = encode(args);
  const tx = H(name.length.toString(16).padStart(2, '0'));
  return { name, log: { address: TREASURY, topics: e.topics, data: e.data, blockNumber: 12345678, transactionHash: tx } };
}
function ser(v) {
  if (typeof v === 'bigint') return v.toString();
  if (Array.isArray(v)) return v.map(ser);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, ser(x)]));
  return v;
}
function expectOf(log) {
  try {
    const r = parseBridgeOperation(log);
    return r === null ? { null: true } : { ok: ser(r) };
  } catch {
    return { error: true };
  }
}

const cases = [
  logOf('base_to_conet_single', base()),
  logOf('conet_to_base_multi', base({
    sourceChainId: 224422n, destinationChainId: 8453n, mode: 1,
    beneficiaries: [A('21'), A('22'), A('23')], amounts: [5n, 0n, 1n << 200n],
    grossAmount: 123456789n, feeAmount: 987n, netAmount: 123455815n,
    callbackTarget: A('22'), nonce: 9999n, operationId: H('01'),
  })),
  logOf('phase1_is_not_initiated', base({ phase: 1 })),
  logOf('phase2_is_not_initiated', base({ phase: 2 })),
  logOf('empty_arrays', base({ beneficiaries: [], amounts: [] })),
  logOf('max_uint_values_and_mode_255', base({
    mode: 255, amounts: [MAX], grossAmount: MAX, feeAmount: MAX, netAmount: MAX, nonce: MAX,
    sourceChainId: MAX, destinationChainId: 0n, operationId: H('ff'),
  })),
  logOf('lowercase_addresses_come_back_checksummed', base({
    sourceAsset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', beneficiaries: ['0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'],
  })),
];
cases.push({
  name: 'foreign_topic_is_skipped',
  log: { address: TREASURY, topics: [ethers.id('Transfer(address,address,uint256)')], data: '0x', blockNumber: 12345679, transactionHash: H('ee') },
});
cases.push({
  name: 'truncated_data_throws',
  log: { address: TREASURY, topics: [BRIDGE_OPERATION_TOPIC, H('ab'), H('00'), H('00')], data: '0x1234', blockNumber: 12345680, transactionHash: H('dd') },
});

const fixtures = {
  schema: 'treasury-v3-bridge-operation/1',
  source: {
    repo: 'CoNET-SI',
    commit: commit,
    rev: rev,
    files: {
      [LISTENER]: blobOf(LISTENER),
      [ADDRESSES]: blobOf(ADDRESSES),
    },
    parser: 'parseBridgeOperation (treasuryV3Listen.ts)',
    ethers: ethers.version,
    generator: 'tests/fixtures/treasury_v3_gen/gen-fixtures.mjs',
  },
  cases: cases.map((c) => ({ name: c.name, log: c.log, expect: expectOf(c.log) })),
};
fs.writeFileSync(out, JSON.stringify(fixtures, null, 2) + '\n');
console.log(`wrote ${fixtures.cases.length} cases to ${out}`);

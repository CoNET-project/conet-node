// Generates tests/fixtures/epoch_readonly.json: the eth_call return data and the validatorMining
// signature check that the Rust read-only Epoch reader must reproduce.
//
// Sources (CoNET-SI commit 215afb18, copied verbatim here, blob hashes checked below):
//   epoch_info_managerABI.json  -> currentInfo() outputs, used by checkCurrentRate()
//   nodeRestartABI.json         -> restartBlockNumber() output, used by getRestart()
// validatorMining (src/util/localNodeCommand.ts, blob 0f2b038e...) is not imported: that module
// pulls in the whole node runtime. The generator evaluates the same two expressions it uses:
//   message = JSON.stringify({ epoch: validatorData.epoch.toString(), wallet: wallet.toLowerCase() })
//   nodeWallet = ethers.verifyMessage(message, validatorData.hash).toLowerCase()
//
// Usage (node 22.18 or later; run `npm ci` here first, or pass a directory with the locked ethers):
//   node --no-warnings gen-epoch-fixtures.mjs --out <fixture path> [--node-modules <dir>]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PINNED = {
  'epoch_info_managerABI.json': '986557201eaf3ec258d13260a6b4722b2e0aa080',
  'nodeRestartABI.json': 'c46de677f087d3f89a1c6f757f9733e6cd711ec5',
};
const gitBlob = (buf) =>
  crypto.createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${buf.length}\0`), buf])).digest('hex');
for (const [f, want] of Object.entries(PINNED)) {
  const h = gitBlob(fs.readFileSync(path.join(HERE, f)));
  if (h !== want) throw new Error(`${f} blob ${h}, expected ${want}`);
}

const argIdx = process.argv.indexOf('--out');
if (argIdx < 0 || !process.argv[argIdx + 1]) throw new Error('missing --out');
const out = path.resolve(process.argv[argIdx + 1]);
const nmIdx = process.argv.indexOf('--node-modules');
const nodeModules = nmIdx >= 0 ? path.resolve(process.argv[nmIdx + 1]) : path.join(HERE, 'node_modules');

const { ethers } = await import(pathToFileURL(path.join(nodeModules, 'ethers/lib.esm/index.js')).href);
if (ethers.version !== '6.17.0') throw new Error(`ethers ${ethers.version}, expected 6.17.0`);

const epochIface = new ethers.Interface(JSON.parse(fs.readFileSync(path.join(HERE, 'epoch_info_managerABI.json'), 'utf8')));
const restartIface = new ethers.Interface(JSON.parse(fs.readFileSync(path.join(HERE, 'nodeRestartABI.json'), 'utf8')));

const EPOCH_ADDR = '0x648f1a17269627C3d465fEa40b3C229f7CacE5cA';
const RESTART_ADDR = '0x64c9c9d5CAAff0693F324E02fB9B7de907540DF1';
const MAX = (1n << 256n) - 1n;

const currentInfoCases = [
  { name: 'running_epoch', values: [1234n, 17n, 25n * 10n ** 17n, 9876n] },
  { name: 'epoch_zero', values: [0n, 0n, 0n, 0n] },
  { name: 'max_values', values: [MAX, MAX, MAX, MAX] },
];
const restartCases = [
  { name: 'no_restart_scheduled', value: 0n },
  { name: 'restart_at_block', value: 26_000_000n },
];
// The node wallet: the public test key 1 (never funded, fixture only).
const signer = new ethers.Wallet('0x' + '0'.repeat(63) + '1');
const validatorCases = [
  { name: 'epoch_small', epoch: 5n, wallet: '0x1111111111111111111111111111111111111111' },
  { name: 'epoch_zero', epoch: 0n, wallet: '0xAbCdEf0123456789aBCdef0123456789ABCdef01' },
  { name: 'epoch_beyond_u64', epoch: 1n << 70n, wallet: '0x2222222222222222222222222222222222222222' },
];

const currentInfo = currentInfoCases.map((c) => ({
  name: c.name,
  returndata: epochIface.encodeFunctionResult('currentInfo', c.values),
  expect: { epoch: c.values[0].toString(), totalMiners: c.values[1].toString(), minerRateWei: c.values[2].toString(), totalUsrs: c.values[3].toString() },
}));
const restart = restartCases.map((c) => ({
  name: c.name,
  returndata: restartIface.encodeFunctionResult('restartBlockNumber', [c.value]),
  expect: { restartBlockNumber: c.value.toString() },
}));
const validator = [];
for (const c of validatorCases) {
  const wallet = c.wallet.toLowerCase();
  const message = JSON.stringify({ epoch: c.epoch.toString(), wallet });
  const hash = await signer.signMessage(message);
  const nodeWallet = ethers.verifyMessage(message, hash).toLowerCase();
  validator.push({ name: c.name, message, hash, expect: { nodeWallet } });
}
// Negative: the same hash checked against a different epoch must recover a different address.
{
  const base = validator[0];
  const other = JSON.stringify({ epoch: '6', wallet: JSON.parse(base.message).wallet });
  validator.push({ name: 'epoch_changed_recovers_other_address', message: other, hash: base.hash,
    expect: { nodeWallet: ethers.verifyMessage(other, base.hash).toLowerCase() } });
}

const fixtures = {
  schema: 'epoch-readonly/1',
  source: {
    repo: 'CoNET-SI',
    commit: '215afb185dcf0884cbf7f187833308e09ce284fd',
    files: {
      'src/util/epoch_info_managerABI.json': PINNED['epoch_info_managerABI.json'],
      'src/util/nodeRestartABI.json': PINNED['nodeRestartABI.json'],
      'src/util/localNodeCommand.ts': '0f2b038e8584ab2c9d56e544ebea7401301215c5',
    },
    ethers: ethers.version,
    generator: 'tests/fixtures/epoch_readonly_gen/gen-epoch-fixtures.mjs',
    signerNote: 'public test key 1, fixture only',
  },
  addresses: { epochInfo: EPOCH_ADDR, nodeRestart: RESTART_ADDR },
  currentInfo,
  restartBlockNumber: restart,
  validatorMining: validator,
};
fs.writeFileSync(out, JSON.stringify(fixtures, null, 2) + '\n');
console.log(`wrote ${currentInfo.length + restart.length + validator.length} cases to ${out}`);

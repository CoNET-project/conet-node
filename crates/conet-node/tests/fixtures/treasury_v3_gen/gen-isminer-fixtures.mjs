// Generates tests/fixtures/treasury_v3_isminer.json: calldata and return-data cases for the
// read-only isMiner(address) call that the Rust reader must reproduce.
//
// The signature comes from the copied TS source (treasuryV3Listen.ts, CoNET-SI 215afb18, blob
// 014febd8...), not from memory: the generator finds that exact ABI line, and stops unless it
// occurs once. The calls are encoded and decoded with ethers 6.17.0 (pinned in package.json).
//
// Usage (node 22.18 or later; run `npm ci --offline` here first, or pass a locked ethers directory):
//   node --no-warnings gen-isminer-fixtures.mjs --out <fixture path> [--node-modules <dir>]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LISTENER = 'treasuryV3Listen.ts';
const LISTENER_BLOB = '014febd8b30b8a64bc5397a6d3ae7dc4055f7c9e';
const gitBlob = (buf) =>
  crypto.createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${buf.length}\0`), buf])).digest('hex');

const listenerBuf = fs.readFileSync(path.join(HERE, LISTENER));
if (gitBlob(listenerBuf) !== LISTENER_BLOB) throw new Error(`${LISTENER} blob mismatch`);
const listenerText = listenerBuf.toString('utf8');
const sig = 'function isMiner(address account) view returns (bool)';
const found = listenerText.split(`'${sig}'`).length - 1;
if (found !== 1) throw new Error(`expected the isMiner ABI line once in ${LISTENER}, found ${found}`);

const argIdx = process.argv.indexOf('--out');
if (argIdx < 0 || !process.argv[argIdx + 1]) throw new Error('missing --out');
const out = path.resolve(process.argv[argIdx + 1]);
const nmIdx = process.argv.indexOf('--node-modules');
const nodeModules = nmIdx >= 0 ? path.resolve(process.argv[nmIdx + 1]) : path.join(HERE, 'node_modules');

const { ethers } = await import(pathToFileURL(path.join(nodeModules, 'ethers/lib.esm/index.js')).href);
if (ethers.version !== '6.17.0') throw new Error(`ethers ${ethers.version}, expected 6.17.0`);
const iface = new ethers.Interface([sig]);

const WORD = (hex64) => '0x' + hex64.padStart(64, '0');
const accounts = [
  { name: 'lower_case', account: '0x1111111111111111111111111111111111111111' },
  { name: 'checksummed', account: ethers.getAddress('0xabcdef0123456789abcdef0123456789abcdef01') },
  { name: 'zero_address', account: '0x0000000000000000000000000000000000000000' },
];
const returns = [
  { name: 'true', data: WORD('1'), expect: true },
  { name: 'false', data: WORD('0'), expect: false },
  { name: 'empty', data: '0x', expect: 'error' },
  { name: 'short_31_bytes', data: '0x' + '00'.repeat(30) + '01', expect: 'error' },
  { name: 'long_33_bytes', data: '0x' + '00'.repeat(31) + '01' + '00', expect: 'error' },
  { name: 'value_two', data: WORD('2'), expect: 'error' },
  { name: 'high_bit_set', data: '0x01' + '00'.repeat(31), expect: 'error' },
  { name: 'all_ones', data: '0x' + 'ff'.repeat(32), expect: 'error' },
];

const fixtures = {
  schema: 'treasury-v3-isminer/1',
  source: {
    repo: 'CoNET-SI',
    commit: '215afb185dcf0884cbf7f187833308e09ce284fd',
    file: 'src/vote/treasuryV3Listen.ts',
    blob: LISTENER_BLOB,
    abiLine: sig,
    ethers: ethers.version,
    generator: 'tests/fixtures/treasury_v3_gen/gen-isminer-fixtures.mjs',
  },
  selector: ethers.id('isMiner(address)').slice(0, 10),
  calls: accounts.map((a) => ({
    name: a.name,
    account: a.account,
    calldata: iface.encodeFunctionData('isMiner', [a.account]),
  })),
  returns: returns.map((r) => ({
    name: r.name,
    data: r.data,
    expect: r.expect === 'error' ? { error: true } : { value: r.expect },
  })),
};
fs.writeFileSync(out, JSON.stringify(fixtures, null, 2) + '\n');
console.log(`wrote ${fixtures.calls.length} calls and ${fixtures.returns.length} returns to ${out}`);

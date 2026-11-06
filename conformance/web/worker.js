import init, { run_vectors, bench } from '/pkg/web/conet_si_wasm.js'
const t0 = performance.now()
await init()
const initMs = performance.now() - t0
const golden = await (await fetch('/conformance/vectors/golden.json')).text()
const t1 = performance.now()
const res = JSON.parse(run_vectors(golden))
const runMs = performance.now() - t1
const timing = {}
for (const [op, n] of [['classify_command', 500], ['eip191_recover', 500], ['encrypt_1k', 500]]) {
  const a = performance.now(); bench(golden, op, 0); const base = performance.now() - a
  const b = performance.now(); bench(golden, op, n); const tot = performance.now() - b
  timing[op] = +((tot - base) / n).toFixed(4)
}
postMessage({ userAgent: navigator.userAgent, summary: res.summary, failed: res.results.filter(r => !r.pass), initMs: +initMs.toFixed(1), runAllMs: +runMs.toFixed(1), perOpMs: timing })

// Run the same golden vectors through the wasm build (wasm-bindgen nodejs target).
// Usage: node run-wasm.mjs <pkg/node dir> golden.json run|artifacts|bench [seed|op] [n]
import { readFileSync } from 'fs'
import { createRequire } from 'module'
import { resolve } from 'path'
const [, , pkgDir, goldenPath, mode, arg, n] = process.argv
const t0 = performance.now()
const w = createRequire(import.meta.url)(resolve(pkgDir, 'conet_si_wasm.js'))
const loadMs = performance.now() - t0
const golden = readFileSync(goldenPath, 'utf8')
if (mode === 'run') console.log(w.run_vectors(golden))
else if (mode === 'artifacts') console.log(w.make_artifacts(golden, arg))
else if (mode === 'bench') {
	const count = Number(n || 100)
	const t = performance.now()
	w.bench(golden, arg, count)
	const ms = performance.now() - t
	console.log(`${arg} n=${count} total_ms=${ms.toFixed(1)} per_op_ms=${(ms / count).toFixed(3)} (module load ${loadMs.toFixed(1)} ms)`)
}

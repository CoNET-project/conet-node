// Tiny static server for the conformance browser check (127.0.0.1 only).
import { createServer } from 'http'
import { readFile } from 'fs/promises'
import { extname, join, normalize } from 'path'
import { fileURLToPath } from 'url'
const root = fileURLToPath(new URL('../..', import.meta.url))
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm' }
createServer(async (req, res) => {
	const p = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '')
	const file = join(root, p.endsWith('/') ? p + 'index.html' : p)
	if (!file.startsWith(root)) { res.writeHead(403).end(); return }
	try {
		const body = await readFile(file)
		res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' }).end(body)
	} catch { res.writeHead(404).end() }
}).listen(Number(process.env.PORT || 8787), '127.0.0.1', () => console.log('serving on port', process.env.PORT || 8787))

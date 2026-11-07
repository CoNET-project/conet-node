// Refresh only the NodeRegistryV2 v0.1 vectors (ids "nr2-*") in golden.json, keeping every
// other vector as it is (gen.mjs regenerates random material). Run: node gen-nr2.mjs
import { readFileSync, writeFileSync } from 'fs'
import { ethers } from 'ethers'
import { nr2Vectors } from './nr2.mjs'

const path = new URL('./golden.json', import.meta.url)
const g = JSON.parse(readFileSync(path, 'utf8'))
const wallets = Object.fromEntries(Object.entries(g.wallets).map(([k, w]) => [k, new ethers.Wallet(w.privateKey)]))
const fresh = await nr2Vectors(wallets, g.keys)
g.vectors = g.vectors.filter((v) => !v.id.startsWith('nr2-')).concat(fresh)
writeFileSync(path, JSON.stringify(g, null, 1) + '\n')
console.error(`nr2 vectors: ${fresh.length}`)

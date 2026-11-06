// Verbatim excerpts from CoNET-SI src/util/voiceForward.ts (rev 74c6cfd), lines noted.
// The module itself imports the node runtime, so only pure pieces are copied. Keep in sync by hand.
import { ethers } from 'ethers'
import { voiceListenText, voicePayText } from './voiceHelpers.ts'
// line 26
const VOICE_TIMESTAMP_SKEW_SEC = 10 * 60
// line 36
const VOICE_V2_SESSION_RE = /^[0-9a-f]{32}$/
// line 66
const VOICE_PAY_MAX_VALID_MS = 48 * 60 * 60 * 1000
// line 69
const tempWallets = new Map<string, { sessionId: string; notAfter: number }>()
// lines 91-108
const nonNegativeInt = (value: unknown): number | null => {
	const n = Number(value)
	return Number.isSafeInteger(n) && n >= 0 ? n : null
}

const recoverSigner = (text: string, sig: unknown): string => {
	if (typeof sig !== 'string' || !sig) return ''
	try {
		return ethers.verifyMessage(text, sig).toLowerCase()
	} catch {
		return ''
	}
}

/**
 * Checks a v3 listen. Returns the write key and the temporary wallet, or the
 * error the client gets. `relayKeyId` is this node's route key ID (its domain).
 */
// lines 109-154
export const verifyVoiceListenV3 = (
	command: Record<string, unknown>,
	relayKeyId: string,
	nowMs = Date.now(),
): { ok: true; sessionId: string; writeKey: Buffer; temp: string; notAfter: number } | { ok: false; error: string } => {
	if (Number(command.v) !== 3) return { ok: false, error: 'voice_listen_v3_required' }
	const sessionId = typeof command.sessionId === 'string' ? command.sessionId.trim() : ''
	if (!VOICE_V2_SESSION_RE.test(sessionId)) return { ok: false, error: 'invalid_voice_session' }
	const wk = typeof command.wk === 'string' ? command.wk.trim() : ''
	let writeKey: Buffer
	try {
		writeKey = Buffer.from(wk, 'base64')
	} catch {
		return { ok: false, error: 'invalid_voice_session' }
	}
	if (writeKey.length !== 32) return { ok: false, error: 'invalid_voice_session' }
	const timestamp = Number(command.timestamp)
	if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(nowMs / 1000) - timestamp) > VOICE_TIMESTAMP_SKEW_SEC) {
		return { ok: false, error: 'invalid_voice_timestamp' }
	}
	const temp = typeof command.temp === 'string' && ethers.isAddress(command.temp) ? command.temp.toLowerCase() : ''
	if (!temp || !relayKeyId) return { ok: false, error: 'voice_temp_auth' }
	if (recoverSigner(voiceListenText(sessionId, wk, relayKeyId, timestamp), command.tempSig) !== temp) {
		return { ok: false, error: 'voice_temp_auth' }
	}
	const pay = (command.pay && typeof command.pay === 'object' ? command.pay : {}) as Record<string, unknown>
	const payer = typeof pay.payer === 'string' && ethers.isAddress(pay.payer) ? pay.payer.toLowerCase() : ''
	const notAfter = nonNegativeInt(pay.notAfter)
	const maxBytes = nonNegativeInt(pay.maxBytes)
	const maxSeconds = nonNegativeInt(pay.maxSeconds)
	if (!payer || notAfter === null || maxBytes === null || maxSeconds === null) {
		return { ok: false, error: 'voice_pay_auth' }
	}
	if (notAfter * 1000 <= nowMs || notAfter * 1000 > nowMs + VOICE_PAY_MAX_VALID_MS) {
		return { ok: false, error: 'voice_pay_expired' }
	}
	if (recoverSigner(voicePayText(temp, notAfter, maxBytes, maxSeconds), pay.sig) !== payer) {
		return { ok: false, error: 'voice_pay_auth' }
	}
	const used = tempWallets.get(temp)
	if (used && used.notAfter * 1000 > nowMs && used.sessionId !== sessionId) {
		return { ok: false, error: 'voice_temp_reused' }
	}
	return { ok: true, sessionId, writeKey, temp, notAfter }
}

// lines 221-223
export const frameLine = (frame: Record<string, unknown>): string =>
	`data: ${JSON.stringify(frame)}\r\n\r\n`

// handshake object and headers, from handleVoiceListen (lines 254-266)
export const voiceHeaders = (): string => {
	const headers =
		`HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n` +
		`Cache-Control: no-cache, no-transform\r\nConnection: keep-alive\r\n` +
		`X-Accel-Buffering: no\r\nAccess-Control-Allow-Origin: *\r\n\r\n`
	return headers
}
export const voiceHandshake = (sessionId: string, nodeWallet: { address: string }) => {
	const handshake = {
		type: 'voice_ready',
		ok: true,
		sessionId,
		nodeWallet: nodeWallet.address.toLowerCase(),
		// `v: 2` = chunk format; `listen: 3` = paid listen accepted.
		v: 2,
		listen: 3,
	}
	return handshake
}

// Verbatim excerpts from CoNET-SI src/util/voiceForward.ts (rev 74c6cfd).
// voiceForward.ts itself imports the whole node runtime, so only the pure
// helpers the wire depends on are copied here. Keep in sync by hand.
import { createHmac } from 'crypto'

export const VOICE_CHUNK_MAGIC = Buffer.from('CVC2', 'ascii')
const VOICE_CHUNK_HEADER = 4 + 16 + 16

export const voicePayText = (temp: string, notAfter: number, maxBytes: number, maxSeconds: number): string =>
	[
		'conet.voice.sse.pay.v3',
		`temp=${temp.toLowerCase()}`,
		`notAfter=${notAfter}`,
		`maxBytes=${maxBytes}`,
		`maxSeconds=${maxSeconds}`,
	].join('\n')

export const voiceListenText = (sessionId: string, wk: string, relayKeyId: string, timestamp: number): string =>
	['conet.voice.sse.listen.v3', sessionId, wk, relayKeyId.toUpperCase(), String(timestamp)].join('|')

export const isVoiceChunk = (data: Uint8Array): boolean =>
	data instanceof Uint8Array &&
	data.length > VOICE_CHUNK_HEADER &&
	Buffer.from(data.buffer, data.byteOffset, 4).equals(VOICE_CHUNK_MAGIC)

export const chunkMac = (key: Buffer, locator: Buffer, blob: Buffer): Buffer =>
	createHmac('sha256', key).update(locator).update(blob).digest().subarray(0, 16)

// Verbatim from CoNET-SI src/util/util.ts notifyVoiceCallPush (rev 74c6cfd): the signed text.
export const voiceCallPushText = (payload: { callId: string; sessionId: string; calleeEoa: string; expiresAt: number; timestamp: number }, nodeWallet: { address: string }): string =>
	[
				'CoNET voiceCallPush relay',
				`callId:${payload.callId}`,
				`sessionId:${payload.sessionId}`,
				`calleeEoa:${payload.calleeEoa.toLowerCase()}`,
				`expiresAt:${payload.expiresAt}`,
				`timestamp:${payload.timestamp}`,
				`nodeWallet:${nodeWallet.address.toLowerCase()}`,
			].join('\n')

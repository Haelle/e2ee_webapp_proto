// Low-level byte helpers. These MUST mirror the reference Python implementation
// (lot0/model.py) so the offline recovery tool stays wire-compatible.

/** Decode a hex string into bytes. */
export function fromHex(hex: string): Uint8Array {
	if (hex.length % 2 !== 0) throw new Error('hex length must be even');
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

/** Encode bytes as a lowercase hex string. */
export function toHex(bytes: Uint8Array): string {
	let hex = '';
	for (const b of bytes) hex += b.toString(16).padStart(2, '0');
	return hex;
}

/**
 * The 16 raw bytes of a UUID (NOT the hyphenated string). This is the exact
 * AAD material the Python reference binds to (`uuid.UUID(...).bytes`).
 */
export function uuidToBytes(uuid: string): Uint8Array {
	const hex = uuid.replace(/-/g, '');
	if (hex.length !== 32) throw new Error(`invalid UUID: ${uuid}`);
	return fromHex(hex);
}

/** Inverse of {@link uuidToBytes}: 16 raw bytes → hyphenated UUID string. */
export function bytesToUuid(bytes: Uint8Array): string {
	if (bytes.length !== 16) throw new Error('UUID must be 16 bytes');
	const h = toHex(bytes);
	return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Constant-ish byte equality (length + content). */
export function bytesEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
	if (a === null || b === null) return a === b;
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

/** 4-byte big-endian *signed* int, matching Python `struct.pack(">i", epoch_n)`. */
export function epochBE32(epoch: number): Uint8Array {
	const buf = new Uint8Array(4);
	new DataView(buf.buffer).setInt32(0, epoch, false); // false = big-endian
	return buf;
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
	const total = parts.reduce((n, p) => n + p.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8Encode(s: string): Uint8Array {
	return textEncoder.encode(s);
}

export function utf8Decode(bytes: Uint8Array): string {
	return textDecoder.decode(bytes);
}

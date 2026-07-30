/**
 * Crypto module (SPEC §9) — the ONLY code in the app that touches secrets.
 *
 * Every byte format here mirrors the reference Python implementation
 * (lot0/model.py) so the offline recovery tool (lot0/recover.py) stays
 * wire-compatible. The rest of the app deals exclusively in cleartext objects.
 *
 * Libraries (SPEC §4): age-encryption (keyblob + epoch envelopes),
 * libsodium-wrappers-sumo (AEAD, Ed25519, blake2b), cbor-x (signed statements).
 */
import { Decrypter, Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { Encoder } from 'cbor-x';
import { getSodium } from './sodium';
import {
	concatBytes,
	epochBE32,
	fromHex,
	toHex,
	utf8Decode,
	utf8Encode,
	uuidToBytes
} from './bytes';

export const KEYBLOB_VERSION = 1;
export const STMT_VERSION = 1;
export const GK_LEN = 32;
export const CEK_LEN = 32;
export const NONCE_LEN = 24; // crypto_aead_xchacha20poly1305_ietf NPUBBYTES

/**
 * cbor-x encoder tuned to produce *standard* CBOR that Python `cbor2` decodes
 * identically:
 *  - `useRecords: false`     → plain CBOR maps, not cbor-x record structures.
 *  - `tagUint8Array: false`  → bare byte strings (major type 2), not tag 64.
 *  - `variableMapSize: true` → compact map-length headers, matching cbor2.
 *
 * NOTE: this deviates from cbor-x's *default* options on purpose — the defaults
 * emit a record tag (0xd9dfff) and tag-64-wrapped byte strings, neither of which
 * `cbor2` can read. Wire-compatibility with the recovery tool wins (SPEC §7).
 */
const stmtEncoder = new Encoder({
	useRecords: false,
	tagUint8Array: false,
	variableMapSize: true
});

/** The unlocked secret of a member, held in memory only. */
export interface Keyblob {
	/** age identity string, `AGE-SECRET-KEY-1...`. */
	ageIdentity: string;
	/** The 32-byte Ed25519 seed (matches Python `bytes(SigningKey).hex()`). */
	ed25519Sk: Uint8Array;
}

interface KeyblobJson {
	v: number;
	age_identity: string;
	ed25519_sk: string; // hex of the 32-byte seed
}

// --------------------------------------------------------------------------- //
// blake2b-256 — the only hash function in the project (SPEC §6).
// --------------------------------------------------------------------------- //
export async function blake2b256(data: Uint8Array): Promise<Uint8Array> {
	const sodium = await getSodium();
	return sodium.crypto_generichash(32, data, null);
}

// --------------------------------------------------------------------------- //
// Keyblob (SPEC §3, §6) — age identity + Ed25519 key, sealed under the
// passphrase in age/scrypt (passphrase) mode. No home-grown KDF.
// --------------------------------------------------------------------------- //

/**
 * Generate a fresh keyblob for enrolment. Returns the unlocked secret plus the
 * public parts and the passphrase-wrapped blob to upload (SPEC §10).
 */
export async function createKeyblob(passphrase: string): Promise<{
	keyblob: Keyblob;
	wrappedSeed: Uint8Array;
	ageRecipient: string;
	ed25519Pub: Uint8Array;
}> {
	const sodium = await getSodium();

	const ageIdentity = await generateIdentity();
	const ageRecipient = await identityToRecipient(ageIdentity);

	const seed = sodium.randombytes_buf(sodium.crypto_sign_SEEDBYTES); // 32 bytes
	const keypair = sodium.crypto_sign_seed_keypair(seed);

	const plain: KeyblobJson = {
		v: KEYBLOB_VERSION,
		age_identity: ageIdentity,
		ed25519_sk: toHex(seed)
	};

	const enc = new Encrypter();
	enc.setPassphrase(passphrase);
	const wrappedSeed = await enc.encrypt(utf8Encode(JSON.stringify(plain)));

	return {
		keyblob: { ageIdentity, ed25519Sk: seed },
		wrappedSeed,
		ageRecipient,
		ed25519Pub: keypair.publicKey
	};
}

/**
 * SPEC §9 — the *only* function a smartcard will later replace. age passphrase
 * (scrypt) decrypt of the wrapped seed; the plaintext is the keyblob JSON.
 */
export async function unlockKeyblob(
	passphrase: string,
	wrappedSeed: Uint8Array
): Promise<Keyblob> {
	const dec = new Decrypter();
	dec.addPassphrase(passphrase);
	const plainBytes = await dec.decrypt(wrappedSeed);
	const plain = JSON.parse(utf8Decode(plainBytes)) as KeyblobJson;
	if (plain.v !== KEYBLOB_VERSION) {
		throw new Error(`unknown keyblob version: ${plain.v}`);
	}
	return {
		ageIdentity: plain.age_identity,
		ed25519Sk: fromHex(plain.ed25519_sk)
	};
}

// --------------------------------------------------------------------------- //
// GK (SPEC §6) — one multi-recipient age envelope per epoch, plaintext = the
// raw 32 bytes of the GK.
// --------------------------------------------------------------------------- //

/** age recipients decrypt → the 32-byte GK. Kept as raw bytes for iteration 1. */
export async function openEpoch(ageIdentity: string, envelope: Uint8Array): Promise<Uint8Array> {
	const dec = new Decrypter();
	dec.addIdentity(ageIdentity);
	const gk = await dec.decrypt(envelope);
	if (gk.length !== GK_LEN) throw new Error('corrupt epoch envelope');
	return gk;
}

// --------------------------------------------------------------------------- //
// CEK / notes (SPEC §6) — XChaCha20-Poly1305 IETF, random 24-byte nonce
// prepended to the ciphertext. The AAD binds each blob to its row.
// --------------------------------------------------------------------------- //

function aadNote(noteId: string): Uint8Array {
	return uuidToBytes(noteId);
}

function aadPayload(noteId: string, groupId: string, epoch: number): Uint8Array {
	return concatBytes(uuidToBytes(noteId), uuidToBytes(groupId), epochBE32(epoch));
}

async function aeadSeal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
	const sodium = await getSodium();
	const nonce = sodium.randombytes_buf(NONCE_LEN);
	const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
	return concatBytes(nonce, ct);
}

async function aeadOpen(key: Uint8Array, blob: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
	const sodium = await getSodium();
	const nonce = blob.subarray(0, NONCE_LEN);
	const ct = blob.subarray(NONCE_LEN);
	return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, key);
}

export interface NoteContent {
	title: string;
	body: string;
}

/**
 * Seal a note: fresh random CEK wrapped under the GK, content sealed under the
 * CEK. Byte layout of each blob is `nonce(24) || ciphertext` (SPEC §6).
 */
export async function sealNote(
	gk: Uint8Array,
	noteId: string,
	groupId: string,
	epoch: number,
	content: NoteContent
): Promise<{ wrappedCek: Uint8Array; payload: Uint8Array }> {
	const sodium = await getSodium();
	const cek = sodium.randombytes_buf(CEK_LEN);
	const wrappedCek = await aeadSeal(gk, cek, aadNote(noteId));
	const payload = await aeadSeal(
		cek,
		utf8Encode(JSON.stringify(content)),
		aadPayload(noteId, groupId, epoch)
	);
	return { wrappedCek, payload };
}

/** Inverse of {@link sealNote}. */
export async function openNote(
	gk: Uint8Array,
	note: {
		id: string;
		group_id: string;
		epoch_n: number;
		wrapped_cek: Uint8Array;
		payload: Uint8Array;
	}
): Promise<NoteContent> {
	const cek = await aeadOpen(gk, note.wrapped_cek, aadNote(note.id));
	const plain = await aeadOpen(cek, note.payload, aadPayload(note.id, note.group_id, note.epoch_n));
	return JSON.parse(utf8Decode(plain)) as NoteContent;
}

// --------------------------------------------------------------------------- //
// Grant chain (SPEC §7) — we sign and store the EXACT SAME bytes, never
// re-encode. Used by later iterations (cooptation, epoch rotation).
// --------------------------------------------------------------------------- //

export type GrantAction = 'found' | 'add' | 'remove';

export interface StmtFields {
	groupId: string; // UUID string → 16 raw bytes
	action: GrantAction;
	epoch: number;
	subject: string; // matricule
	keyId: string | null; // member_key UUID string → 16 raw bytes, null on remove
	gkEnvelope: Uint8Array; // `env` field = blake2b256(gkEnvelope)
	prevHash: Uint8Array | null; // hash of the previous stmt, null at seq 0
	ts: number; // unix seconds
}

/**
 * Encode a grant statement to CBOR. These exact bytes are what get signed and
 * stored (SPEC §7, §13) — never re-encode them.
 */
export async function buildStmt(fields: StmtFields): Promise<Uint8Array> {
	if (!['found', 'add', 'remove'].includes(fields.action)) {
		throw new Error(`unknown action: ${fields.action}`);
	}
	const stmt = {
		v: STMT_VERSION,
		group: uuidToBytes(fields.groupId),
		action: fields.action,
		epoch: fields.epoch,
		subject: fields.subject,
		key_id: fields.keyId === null ? null : uuidToBytes(fields.keyId),
		env: await blake2b256(fields.gkEnvelope),
		prev: fields.prevHash,
		ts: fields.ts
	};
	return stmtEncoder.encode(stmt);
}

/** Ed25519 detached signature over the exact stmt bytes (SPEC §7). */
export async function signStmt(ed25519Sk: Uint8Array, stmtBytes: Uint8Array): Promise<Uint8Array> {
	const sodium = await getSodium();
	// ed25519Sk is the 32-byte seed; derive the libsodium 64-byte secret key.
	const keypair = sodium.crypto_sign_seed_keypair(ed25519Sk);
	return sodium.crypto_sign_detached(stmtBytes, keypair.privateKey);
}

/** Sign an arbitrary challenge (e.g. an auth nonce) with the Ed25519 key. */
export async function signChallenge(
	ed25519Sk: Uint8Array,
	challenge: Uint8Array
): Promise<Uint8Array> {
	return signStmt(ed25519Sk, challenge);
}
